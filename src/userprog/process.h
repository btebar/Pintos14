#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#include "vm/page.h"
#include <hash.h>
#include "threads/synch.h"
#include "threads/thread.h"
struct process
  {
    /* t might have been dereferenced  already so need to keep track of tid/pid */
    int id;                              /* pid = tid = id */
    struct thread *t;
    struct thread *parent;

    struct lock lock;
    struct semaphore sema;

    bool crashed;

    struct hash *children;               /* Hash of child processes */

    struct hash *file_descriptors;      /* Hash of file descriptors */

    struct hash_elem elem;              /* Hash elem to be used by parent */

    /* Process needs to clean up after itself if not required by parent */
    bool required_by_parent;

    bool exitted;
    int exit_code;

    #ifdef VM
    struct list virtual_pages; /*virtual pages for memory mapping */
    struct hash *suppl_page_table;
    #endif
  };

struct file_descriptor
  {
    int fd;
    char *file_name;
    struct hash_elem elem;
    struct file *file;
    struct list_elem l_elem;
  };

void init_process(struct thread *t);

/* Ensure lock is acquired before a */
struct lock filesys_lock;

struct lock kernel_buffer_lock;

void process_init (struct thread *t, struct thread *parent);
void process_update_id (struct thread *t);
int process_execute (const char *file_name);
int process_wait (int child_id);
void process_exit (void);
void process_activate (void);
int process_created (struct thread *t);
static int global_fd;
unsigned
process_hash_func (const struct hash_elem *e, void *aux);

bool
process_hash_less_func (const struct hash_elem *a,
                      const struct hash_elem *b,
                      void *aux);

unsigned
fd_hash_func (const struct hash_elem *e, void *aux);

bool
fd_hash_less_func (const struct hash_elem *a,
                   const struct hash_elem *b,
                   void *aux);

void fd_destroy_func (struct hash_elem *e, void *aux);
#endif /* userprog/process.h */
