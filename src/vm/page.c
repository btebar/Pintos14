#include "vm/page.h"
#include "vm/frame.h"

void page_init () {
    list_init (&shared_page_files);
    lock_init (&paging_lock);
}

unsigned
hash_page_func (const struct hash_elem *e, void *aux) {
  struct page *p = hash_entry (e, struct page, elem);
  return p->page_pointer;
}

bool
hash_page_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  return hash_page_func (a, NULL) < hash_page_func (b, NULL);
}

struct page * get_page (void *page_pointer) {
  struct page temp;
  temp.page_pointer = page_pointer;
  struct hash_elem *e = hash_find (thread_current()->process->suppl_page_table, &temp.elem);
  if (!e) {
    return NULL;
  }
  return hash_entry (e, struct page, elem);
}

void
hash_page_destroy(const struct hash_elem *e, void *aux) {
  struct page *pg = hash_entry (e, struct page, elem);
}

struct pagefile get_data(void *page_pointer) {
  struct page *p = get_page (page_pointer);
  return *p->pf;
}

void
load_from_file (struct page *pg, void *kpage) {
  file_seek (pg->pf->file, pg->pf->offset);
  off_t num_bytes = file_read (pg->pf->file, kpage, pg->pf->read);
  memset (kpage + num_bytes, 0, pg->pf->zeros);
}

bool
load_page(struct page *page) {
  if(!page) {
    return false;
  }
  lock_acquire (&paging_lock);

  void *kpage = palloc_get_page (PAL_USER);

  struct frame_entry *frame = get_frame_entry (kpage);
  struct page *pg_to_load = page;

  struct lock *sharer_lock = NULL;

  lock_acquire (&frame_table_lock);

  lock_acquire (&page->lock);

  if (page->is_shared) {

    lock_acquire (&page->pf->lock);
    if(page->pf->holder) {
      /* Use sharers page */
      lock_acquire (&page->sharer->lock);
      sharer_lock = &page->sharer->lock;
      if (page->sharer->cur_frame) {
        frame->loaded_page = NULL;
        frame->assigned = false;
        frame->t = NULL;

        list_push_back (&page->sharer->subscribers, &page->subscribe_elem);
        page->is_subscribed = true;

        bool success = pagedir_set_page (page->pagedir, page->page_pointer, page->sharer->cur_frame->kpage, page->writable);

        lock_release (&page->pf->lock);
        lock_release (sharer_lock);
        lock_release (&page->lock);
        lock_release (&paging_lock);
        lock_release (&frame_table_lock);
        return success;
      } else {
        /* Sharer's page needs to be loaded */
        pg_to_load = page->sharer;
      }
    } else {
      /* The pagefile has been abandoned by original holder*/
      page->pf->holder = page;
      page->is_shared = false;
      page->sharer = NULL;
      page->load_from_file = true;
      page->is_shared = false;
    }
  }

  frame->loaded_page = pg_to_load;

  frame->t = thread_current();

  pg_to_load->cur_frame = frame;
  frame->t = thread_current();

  if (pg_to_load->all_zeros) {
    memset(frame->kpage, 0, PGSIZE);
  }

  if (pg_to_load->in_swap) {
    load_swap_slot (pg_to_load->swap_addr, frame->kpage);
    pg_to_load->in_swap = false;
    pg_to_load->swap_addr = 0;
  }

  if (pg_to_load->load_from_file) {
    load_from_file(pg_to_load, frame->kpage);
  }

  bool success = pagedir_set_page (page->pagedir, page->page_pointer, frame->kpage, page->writable);

  if (sharer_lock) {
    lock_release (sharer_lock);
  }

  if (page->is_shared) {
    lock_release (&page->pf->lock);
  }

  lock_release (&page->lock);
  lock_release (&paging_lock);
  lock_release (&frame_table_lock);
  return success;
}

/* Installs kpage into upage if upage is empty, if upage is NULL
then a upage address is assigned, the page struct is returned */
struct page *install_page (void *upage, void *kpage, bool writable) {
  struct thread *t = thread_current ();

  lock_acquire (&t->process->lock);

  int i = 1;
  while (!upage) {
    void* cur_addr = pg_round_down(PGSIZE * i);
    if(!get_page(cur_addr)) {
      upage = cur_addr;
    }
    i++;
  }

  if (pagedir_get_page(t->pagedir, upage)) {
    lock_release (&t->process->lock);
    return NULL;
  }

  struct frame_entry *fe = get_frame_entry (kpage);

  if (!fe) {
    lock_release (&t->process->lock);
    return NULL;
  }

  struct page *page = malloc (sizeof (struct page));

  page->page_pointer = upage;
  page->cur_frame = fe;
  page->writable = writable;
  page->pf = NULL;
  fe->t = thread_current();

  page->pagedir = thread_current ()->pagedir;

  list_init (&page->subscribers);
  lock_init (&page->lock);

  hash_insert (t->process->suppl_page_table, &page->elem);

  fe->t = t;
  fe->loaded_page = page;

  lock_release (&t->process->lock);
  pagedir_set_page(t->pagedir, upage, kpage, writable);

  return page;
}

/* Page must be read-only */
bool try_insert_shared (struct file *file, char *file_name, off_t ofs, uint8_t* up, uint32_t read_bytes,
              uint32_t zero_bytes)
{
  struct list_elem *e;
  struct pagefile *end_pf = NULL;

  lock_acquire (&paging_lock);

  /* Iterate through all shared page files to find if an identical one exists */
  for (e = list_begin (&shared_page_files); e != list_end (&shared_page_files);
       e = list_next (e))
  {
    struct pagefile *pf = list_entry (e, struct pagefile, elem);
    if (strcmp (pf->file_name, file_name)){
      continue;
    }

    if (pf->offset != ofs) {
      continue;
    }

    if (pf->read != read_bytes) {
      continue;
    }

    if (pf->zeros != zero_bytes) {
      continue;
    }

    end_pf = pf;
  }

  /* This page file will be unique so we can't find one to share'*/
  if (!end_pf) {
    lock_release (&paging_lock);
    return false;
  }

  lock_acquire (&end_pf->lock);

  struct page *p = malloc (sizeof(struct page));
  struct thread *t = thread_current();

  if(!end_pf->holder) {
    end_pf->holder = p;
  }

  end_pf->shared_between++;

  p->pagedir = thread_current ()->pagedir;
  list_init (&p->subscribers);
  lock_init (&p->lock);

  p->load_from_file = false;
  p->page_pointer = up;
  p->writable = false;
  p->pf = end_pf;
  p->is_shared = true;
  p->sharer = end_pf->holder;

  hash_insert (t->process->suppl_page_table, &p->elem);
  lock_release (&end_pf->lock);
  lock_release (&paging_lock);
  return true;
}

bool insert_from_file (struct file *file, char *file_name, off_t ofs, uint8_t* up, uint32_t read_bytes,
              uint32_t zero_bytes, bool write) {

  if (!write) {
    if (try_insert_shared (file, file_name, ofs, up, read_bytes, zero_bytes)) {
      return true;
    }
  }

  lock_acquire (&paging_lock);
  struct page *p = malloc (sizeof(struct page));
  struct thread *t = thread_current();

  p->pf = malloc (sizeof (struct pagefile));

  lock_init (&p->pf->lock);

  p->pf->file = file;
  p->pf->offset = ofs;
  p->pf->read = read_bytes;
  p->pf->write = write;
  p->pf->zeros = zero_bytes;
  p->pf->holder = p;
  p->pf->shared_between = 1;

  size_t name_size = (strlen (file_name) + 1) * sizeof (char);
  p->pf->file_name = calloc(1, name_size);
  strlcpy (p->pf->file_name, file_name, name_size);

  if (!write) {
    list_push_back (&shared_page_files, &p->pf->elem);
  }

  p->pagedir = thread_current ()->pagedir;

  list_init (&p->subscribers);
  lock_init (&p->lock);

  p->all_zeros = (zero_bytes == PGSIZE);
  p->page_pointer = up;
  p->in_swap = false;
  p->load_from_file = true;
  p->is_shared = false;
  p->sharer = NULL;
  p->writable = write;
  hash_insert (t->process->suppl_page_table, &p->elem);
  lock_release (&paging_lock);
  return true;
}

bool
has_page_mapping(struct thread *t, void *uaddr) {
  return get_page (uaddr);
}

struct mapping *
find_mapping_in_process(struct process *p, mapid_t mapid) {
  struct list_elem *e;
  for (e = list_begin (&p->virtual_pages); e != list_end (&p->virtual_pages);
      e = list_next (e))
  {
    struct mapping *m = list_entry (e, struct mapping, elem);

    if(m->mapid == mapid) {
      return m;
    }
  }

  return NULL;
}

struct mapping *
mmaped_file(struct process *p, int fd) {
  struct list_elem *e;
  for (e = list_begin (&p->virtual_pages); e != list_end (&p->virtual_pages);
      e = list_next (e))
  {
    struct mapping *m = list_entry (e, struct mapping, elem);
    if(m->fileid == fd) {
      return m;
    }
  }

  return NULL;
}

void free_all_mmaps (struct mapping *m) {
  struct file *f = m->file;
  if(f == NULL) {

    return;
  }

  for(size_t off = 0; off < m->size; off += PGSIZE) {

    struct page *p = get_page(m->start_addr + off);

    if (p == NULL) {
      PANIC("should be a mapping for this address");
    }

    if((p->cur_frame) != NULL) {
      if(pagedir_is_dirty(thread_current()->pagedir, p->page_pointer) || pagedir_is_dirty(thread_current()->pagedir, m->start_addr+off)) {
        lock_acquire (&filesys_lock);
        file_write_at(f, p->page_pointer, p->pf->read, p->pf->offset);
        lock_release (&filesys_lock);
      }
    }

    pagedir_clear_page(thread_current()->pagedir, p->page_pointer);
  }

}

void
check_unmap(struct mapping *m) {
  struct file *f = m->file;
  if(!f) {
    return;
  }

  for(size_t off = 0; off < m->size; off += PGSIZE) {

    struct page *p = get_page(m->start_addr + off);

    if (p == NULL) {
      PANIC("should be a mapping for this address");
    }

    if((p->cur_frame) != NULL) {
      if(pagedir_is_dirty(thread_current()->pagedir, p->page_pointer) || pagedir_is_dirty(thread_current()->pagedir, m->start_addr+off)) {
        lock_acquire (&filesys_lock);
        file_write_at(f, p->page_pointer, p->pf->read, p->pf->offset);
        lock_release (&filesys_lock);
      }
    }

    pagedir_clear_page(thread_current()->pagedir, p->page_pointer);
    hash_delete(thread_current()->process->suppl_page_table, &p->elem);
  }
}
