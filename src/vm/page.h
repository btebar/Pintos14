#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <filesys/off_t.h>
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

typedef int mapid_t;

struct list shared_page_files;
struct lock paging_lock;

struct pagefile {
  struct file *file;

  char *file_name;

  off_t offset;
  bool write;
  uint32_t read;
  uint32_t zeros;

  struct lock lock;

  struct list_elem elem;
  struct page *holder;
  int shared_between;
};

struct page
  {
    struct pagefile *pf;
    void *page_pointer;             /* Pointer to actual page */
    struct hash_elem elem;          /* Hash element so we can store in a hash */

    bool in_swap;                   /* Is the page currently in the swap */
    uint32_t swap_addr;

    bool load_from_file;          /* Is this page being loaded from file */

    bool all_zeros;                 /* Is this page all 0s */

    bool is_shared;                 /* Is this page shared from an other page */
    struct page *sharer;            /* The page that we share data with */

    bool writable;

    struct frame_entry *cur_frame;

    uint32_t *pagedir;

    struct list_elem subscribe_elem;
    bool is_subscribed;
    struct list subscribers;

    struct lock lock;
  };

struct mapping
  {
    struct file *file;
    size_t size;
    int mapid;
    struct list_elem elem;
    void *start_addr;
    int num_pages;
    int fileid;
  };

void page_init (void);

unsigned hash_page_func (const struct hash_elem *e, void *aux UNUSED);

bool hash_page_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

bool insert_from_file (struct file *file, char *file_name, off_t ofs, uint8_t* up, uint32_t read_bytes,
                  uint32_t zeros, bool write);
void
hash_page_destroy(const struct hash_elem *e, void *aux);

bool has_page_mapping(struct thread *t, void *uaddr);

struct mapping *
find_mapping_in_process(struct process *p, int mapid);

struct mapping *
mmaped_file(struct process *p, int fd);

void
load_from_file (struct page *pg, void *kpage);

bool
load_page (struct page *pg);

struct page *install_page (void *upage, void *kpage, bool writable);

struct page * get_page (void *page_pointer);

struct pagefile get_data(void *page_pointer);

void
check_unmap(struct mapping *m);

#endif
