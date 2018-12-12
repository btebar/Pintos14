#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"

struct list_elem *clock; /*pointer for the eviction algorithm*/



unsigned
frame_hash_func(const struct hash_elem *e, void *aux)
{
    struct frame_entry *f = hash_entry(e, struct frame_entry, elem);
    return f->kpage;
}

bool
frame_hash_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
  uint32_t *first = hash_entry(a, struct frame_entry, elem)->kpage;
  uint32_t *second = hash_entry(b, struct frame_entry, elem)->kpage;
  return first < second;
}

/*initialises the frame table*/
void
frame_init()
{
  lock_init (&frame_table_lock);
  list_init (&all_frames);
  hash_init (&frame_table_map, frame_hash_func, frame_hash_less_func, NULL);
}

/* Evicts page from frame and saves where necessary,
  an assigned frame remains reserved for use */
void evict_frame (struct frame_entry *fe, bool assigned, bool store_page) {

  struct page *pg = fe->loaded_page;
  bool responsible_for_lock = false;
  if(frame_table_lock.holder != thread_current ()) {
    responsible_for_lock = true;
    lock_acquire(&frame_table_lock);
  }

  if(!pg) {
    goto done;
  }

  /* Notify subscribers of frame eviction */
  struct list_elem *e;
  if(!list_empty(&pg->subscribers)) {
    for (e = list_begin (&pg->subscribers); e != list_end (&pg->subscribers);
           e = list_next (e))
    {
      struct page *subscriber = list_entry (e, struct page, subscribe_elem);

      lock_acquire (&subscriber->lock);

      if(subscriber->is_subscribed && subscriber->pagedir) {
        pagedir_clear_page (subscriber->pagedir, pg->page_pointer);
      }

      subscriber->is_subscribed = false;
      lock_release (&subscriber->lock);
    }
  }

  /* Clear this process' pagedir */
  if(pg->pagedir) {
    pagedir_clear_page (pg->pagedir, pg->page_pointer);
  }

  if (!store_page) {
    goto done;
  }

  if (pg->is_shared) {
    goto done;
  }
  if(pg->pagedir) {
    bool dirty = pagedir_is_dirty(pg->pagedir, pg->page_pointer);

    if (pg->load_from_file && dirty) {
      pg->load_from_file = false;
    } else {
      goto done;
    }

    if (pg->all_zeros) {
      if (dirty) {
        pg->all_zeros = false;
      }

      goto done;
    }
  }

  //Some other page is the sharer
  if (pg->is_shared && pg->sharer) {
    PANIC ("This page shouldn't be in a frame");
  }
  done:

  /* Page must be put into swap now */
  pg->in_swap = true;
  pg->swap_addr = write_swap_slot (fe->kpage);

  fe->assigned = assigned;
  fe->loaded_page = NULL;
  fe->t = NULL;
  pg->cur_frame = NULL;

  if (responsible_for_lock) {
    lock_release (&frame_table_lock);
  }
}

/* Assigns a frame */
struct frame_entry *
assign_frame ()
{
  lock_acquire (&frame_table_lock);

  /* Try find a free frame */
  struct hash_iterator i;
  hash_first (&i, &frame_table_map);
  while (hash_next (&i)) {
    struct frame_entry *fe = hash_entry (hash_cur (&i), struct frame_entry, elem);
    if(!fe->assigned){
      fe->assigned = true;
      lock_release (&frame_table_lock);
      return fe;
    }
  }

  struct frame_entry *fe = choose_evicted_frame ();

  /* Evict a frame according to policy since no free ones could be found */
  evict_frame (fe, true, true);

  lock_release (&frame_table_lock);

  return fe;
}

/* Allocates a new frame, assumes by default this frame is immediately used */
struct frame_entry *
alloc_new_frame (void *kpage) {
  struct frame_entry *fe = malloc (sizeof (struct frame_entry));
  fe->kpage = kpage;
  fe->assigned = true;

  lock_acquire (&frame_table_lock);

  hash_insert (&frame_table_map, &fe->elem);
  list_push_back (&all_frames, &fe->lelem);
  lock_release (&frame_table_lock);
}

void
set_frame_dirty(struct frame_entry *frame)
{
  frame->dirty = 1;
}

void
set_frame_accessed(struct frame_entry *frame)
{
  frame->accessed = 1;
}

/*checks if the user page has been written and if so, sets
the dirty bit of the frame entry*/
bool
is_frame_dirty(const struct frame_entry *frame)
{
  lock_acquire(&frame_table_lock);
  if(pagedir_is_dirty(frame->loaded_page->page_pointer, frame->kpage)) {
      set_frame_dirty(frame);
  }
  lock_release(&frame_table_lock);
  return frame->dirty;
}

/*checks if the user page has been accessed amnd if so, sets
the accessed bit of the frame entry*/
bool
is_frame_accessed(const struct frame_entry *frame)
{
  lock_acquire(&frame_table_lock);
  if(pagedir_is_accessed(frame->loaded_page->page_pointer, frame->kpage)) {
      set_frame_accessed(frame);
  }
  lock_release(&frame_table_lock);
  return frame->accessed;
}


struct frame_entry *
choose_evicted_frame() {

  if(list_empty(&all_frames)) {
		PANIC("the frame list can't be empty");
	}

  for(int i = 0; i < list_size(&all_frames); i++) {

    if (clock == NULL || clock == list_end(&all_frames)) {
			clock = list_begin(&all_frames); /*points to the start*/
		} else {
			clock = list_next(clock); /*points to the next elem*/
	  }

		struct frame_entry *fe = list_entry(clock, struct frame_entry, lelem);

    if(list_end(&all_frames) == clock) {
      return list_entry(list_begin(&all_frames), struct frame_entry, lelem);
    }

		return fe;
  }

  if(list_end(&all_frames) == clock) {
    return list_entry(list_begin(&all_frames), struct frame_entry, lelem);
  }

	return list_entry(clock, struct frame_entry, lelem);

}


/* Translates a user address to a kernel address */
void *
uaddr_to_kaddr (void *uaddr) {
  ASSERT (frame_table_lock.holder == thread_current);
  void *upage = pg_round_down (uaddr);
  //printf("uaddr : %p, upage : %p\n", uaddr, upage);

  struct page *page = get_page (upage);
  if (!page) {
    //printf("cur page is invalid\n");
    return NULL;
  }

  if (!page->cur_frame) {
    //printf("cur page is not loaded into a frame\n");
    return NULL;
  }

  void *kpage = page->cur_frame->kpage;

  //printf("kpage: %p, ofs: %p\n", kpage, pg_ofs(uaddr));
  void *result = (kpage + pg_ofs(uaddr));
  //printf("result: %p\n", result);
  return result;
}

/* Needs frame table lock to be held */
struct frame_entry *
get_frame_entry (void *kaddr) {
  lock_acquire (&frame_table_lock);
  void *kpage = pg_round_down (kaddr);

  struct frame_entry fe_goal = {.kpage = kpage};
  struct hash_elem *e = hash_find (&frame_table_map, &fe_goal.elem);

  if (!e) {
    //printf("couldnt get frame entry\n");
    lock_release (&frame_table_lock);
    return NULL;
  }

  lock_release (&frame_table_lock);
  return hash_entry (e, struct frame_entry, elem);
}
