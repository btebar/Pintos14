#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stdint.h>
#include <debug.h>
#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "lib/debug.h"
#include "threads/thread.h"

struct frame_entry
    {
      uint32_t* kpage; /*physical address*/

      struct hash_elem elem;
	    struct list_elem lelem;

	    struct thread *t;
      struct page *loaded_page;

      bool assigned;

      /*Implementation for eviction*/
      bool accessed;
      bool dirty;
    };

struct hash frame_table_map;
struct list all_frames;
struct lock frame_table_lock;

unsigned
frame_hash_func(const struct hash_elem *e, void *aux);

bool
frame_hash_less_func(const struct hash_elem *a,
                    const struct hash_elem *b,
                    void *aux);

struct frame_entry *
get_free_frame (struct page *p);

struct frame_entry *
alloc_new_frame (void *kpage);

void
frame_init();

void evict_frame (struct frame_entry *fe, bool assigned, bool store_page);

void
set_frame_dirty(struct frame_entry *frame);

void
set_frame_accessed(struct frame_entry *frame);

bool
is_frame_dirty(const struct frame_entry *frame);

bool
is_frame_accessed(const struct frame_entry *frame);

struct frame_entry *
choose_evicted_frame();


struct frame_entry *get_frame_entry (void *kaddr);

void *kaddr_to_uaddr (void *kaddr);




#endif /* vm/frame.h */
