#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "devices/timer.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "vm/page.h"

bool is_stack_overflow(void **esp, int8_t value);
static thread_func start_process NO_RETURN;
static bool load(const char *cmdline, void (**eip)(void), void **esp);

void process_init(struct thread *t, struct thread *parent)
{
  struct process *p = malloc (sizeof (struct process));

  p->suppl_page_table = malloc (sizeof (struct hash));
  hash_init(p->suppl_page_table, hash_page_func, hash_page_less_func, NULL);

  lock_init(&p->lock);
  sema_init(&p->sema, 0);

  p->exit_code = -1; /* By default exit code = -1 */
  p->required_by_parent = true;
  p->crashed = false;

  p->t = t;
  t->process = p;
  p->children = malloc(sizeof(struct hash));
  p->file_descriptors = malloc(sizeof(struct hash));

  hash_init(p->children, process_hash_func, process_hash_less_func, NULL);
  hash_init(p->file_descriptors, fd_hash_func, fd_hash_less_func, NULL);

  if (parent != NULL)
  {
    p->parent = parent;
  }

  #ifdef VM
  p->suppl_page_table = malloc(sizeof(struct hash));
  list_init(&p->virtual_pages);
  hash_init(p->suppl_page_table, hash_page_func, hash_page_less_func, NULL);
  #endif
}

void process_update_id(struct thread *t)
{
  if (t->process != NULL)
  {
    t->process->id = t->tid;
    if (t->process->parent != NULL) //if parent == NULL then t = main
    {
      lock_acquire(&thread_current()->process->lock);
      hash_insert(thread_current()->process->children, &t->process->elem);
      lock_release(&thread_current()->process->lock);
    }
  }
}

int process_created (struct thread *t) {
  /* If it's main thread then we dont have to wait */
  if (t->process == NULL)
  {
    return t->tid;
  }

  struct process *p = t->process;

  /* Wait for child to load up successfully */
  sema_down(&p->sema);

  if (p->crashed)
  {
    return TID_ERROR;
  }

  return p->id;
}


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute(const char *file_name)
{
  char *fn_copy;
  tid_t tid;

  /*Ensure we can fit everything onto the stack */
  if (strnlen(file_name, PGSIZE) >= PGSIZE)
  {
    return TID_ERROR;
  }

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  char *save_ptr;
  char *name;
  name = malloc(strlen(file_name) + 1);
  if (!name)
  {
    printf("unable to copy name of thread");
  }
  else
  {
    memcpy(name, file_name, strlen(file_name) + 1);
    file_name = strtok_r(name, " ", &save_ptr);
  }
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, fn_copy);

  free(name);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process(void *file_name_)
{
  char *file_name;
  file_name = malloc(strlen(file_name_) + 1);
  memcpy(file_name, file_name_, strlen(file_name_) + 1);
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  void *start_address; /*gets the page below PHYS_BASE*/
  int argc = 0;
  int *arguments;
  arguments = malloc(32 * sizeof(int)); /*maximum of 128 bytes*/
  if (!arguments)
  {
    printf("Unable to allocate memory");
  }
  else
  {
    char *token, *save_ptr;
    arguments[argc] = 0; /*address of the first arg*/
    for (token = strtok_r(file_name, " ", &save_ptr); token != NULL;
         token = strtok_r(NULL, " ", &save_ptr))
    {
      while (*save_ptr == ' ')
      {
        ++save_ptr; /*skips the space  sema_down(&pc->sema);*/
      }
      /* we are not getting the address of the token but the
  	 * offset from the initial pointer to the whole argument passed*/
      arguments[++argc] = save_ptr - file_name;
    }
  }

  success = load (file_name, &if_.eip, &if_.esp);
  /*setup stack*/
  if (success)
  {
    struct file *file;
    lock_acquire (&filesys_lock);
    struct process *proc = thread_current()->process;
    lock_acquire (&proc->lock);
    struct file_descriptor *file_descr = malloc(sizeof(struct file_descriptor));
    file_descr->file_name = file_name;
    file_descr->fd = (global_fd++);
    file_descr->file = filesys_open(file_name);
    hash_insert(proc->file_descriptors, &file_descr->elem);
    file = file_descr->file;
    file_deny_write(file);
    lock_release (&proc->lock);
    lock_release (&filesys_lock);
    size_t size = strlen(file_name_) + 1;
    if (is_stack_overflow(if_.esp, (int8_t)size))
    {
      goto end;
    }
    if_.esp -= size;
    memcpy(if_.esp, file_name_, size);
    for (int i = 0; i < size; i++)
    {
      char c = *(char *)(if_.esp + i);
      if (c == ' ')
      {
        *(char *)(if_.esp + i) = '\0';
      }
    }
    start_address = if_.esp;
    if (is_stack_overflow(if_.esp, size % 4))
    {
      goto end;
    }
    if_.esp -= size % 4; /*rounding*/
    if (is_stack_overflow(if_.esp, 4))
    {
      goto end;
    }
    if_.esp -= 4;
    *(int *)if_.esp = NULL; /* copying the sentinel */
    /* pushing pointers to arguments in right to left order */
    for (int i = argc - 1; i >= 0; i--)
    {
      if (is_stack_overflow(if_.esp, 4))
      {
        goto end;
      }
      if_.esp -= 4;
      *(void **)if_.esp = (start_address + arguments[i]);

      /*gets the address of the arguments*/
    }
    if (is_stack_overflow(if_.esp, 4))
    {
      goto end;
    }
    if_.esp -= 4;
    *(uint32_t *)if_.esp = if_.esp + 4; /*address of argv*/
    if (is_stack_overflow(if_.esp, 4))
    {
      goto end;
    }
    if_.esp -= 4;
    if (is_stack_overflow(if_.esp, 4))
    {
      goto end;
    }
    *(int *)if_.esp = argc; /*number of arguments*/
    if (is_stack_overflow(if_.esp, 4))
    {
      goto end;
    }
    if_.esp -= 4;
    *(int *)if_.esp = 0; /* dummy return value*/

    if (thread_current()->process != NULL)
    {
      sema_up(&thread_current()->process->sema);
    }
  } else {
    /* If load failed, quit. */
    free(arguments);
    thread_exit();
  }
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */

    free(arguments);
    palloc_free_page(file_name_);
    asm volatile("movl %0, %%esp; jmp intr_exit"
                 :
                 : "g"(&if_)
                 : "memory");
    NOT_REACHED();

    end:
    thread_exit();
    free(arguments);
    palloc_free_page(file_name_);
    asm volatile("movl %0, %%esp; jmp intr_exit"
                 :
                 : "g"(&if_)
                 : "memory");
    NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(int child_id)
{
  struct thread *t = thread_current();
  struct process *pc = NULL;

  /* Define a process we want to find */
  struct process process_goal;
  process_goal.id = child_id;

  lock_acquire (&t->process->lock);
  struct hash_elem *e = hash_find(t->process->children, &process_goal.elem);
  lock_release (&t->process->lock);
  /* child_tid is incorrect */
  if (e == NULL)
  {
    return -1;
  }

  pc = hash_entry(e, struct process, elem);

  sema_down(&pc->sema);

  /* Remove child process from hashmap so that if process_wait() has already
  been successfully called for the given TID, returns -1
  immediately, without waiting. */
  lock_acquire(&t->process->lock);
  hash_delete(t->process->children, &pc->elem);
  lock_release(&t->process->lock);

  int exit_code = pc->exit_code;

  free(pc);

  return exit_code;
}

/* Free the current process's resources. */
void process_exit(void)
{
  struct thread *cur = thread_current();
  uint32_t *pd;
  printf("%s: exit(%d)\n", cur->name, cur->process->exit_code);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  #ifdef VM
  lock_acquire (&cur->process->lock);
  while(!list_empty(&cur->process->virtual_pages)) {
      struct list_elem *e = list_begin (&cur->process->virtual_pages);
      struct mapping *m = list_entry(e, struct mapping, elem);
      free_mmap(m->mapid);
  }
  lock_release (&cur->process->lock);
  #endif
  if (pd != NULL)
  {
    /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }


  /* Ensure we release the buffer lock if we crash */
  if (kernel_buffer_lock.holder == cur) {
    lock_release (&kernel_buffer_lock);
  }

  lock_acquire (&cur->process->lock);
  struct hash_iterator iterator;

  hash_first(&iterator, cur->process->children);
  while (hash_next(&iterator) != NULL)
  {
    struct process *p = hash_entry(hash_cur(&iterator), struct process, elem);
    lock_acquire(&p->lock);
    p->required_by_parent = false;
    lock_release(&p->lock);
  }

  /* No longer require a reference to our children */
  hash_destroy(cur->process->children, NULL);


  lock_acquire (&filesys_lock);
  hash_destroy(cur->process->file_descriptors, fd_destroy_func);

  if(cur->process->suppl_page_table){
    hash_destroy(cur->process->suppl_page_table, hash_page_destroy);
  }
  lock_release (&filesys_lock);

  if (cur->process->exit_code == -1)
  {
    cur->process->crashed = true;
  }

  bool freed = false;

  /* Parent has already exitted so can't query exit code */
  if (!cur->process->required_by_parent)
  {
    /* Ensure we set thread pointer to NULL as it will be dereferenced */
    cur->process->t = NULL;
    free (cur->process->children);
    free (cur->process->file_descriptors);
    lock_release (&cur->process->lock);
    free (cur->process);
    freed = true;
  }

  /* Unblock waiting parent thread if its waiting */
  if(!freed){
    lock_release (&cur->process->lock);
    sema_up (&cur->process->sema);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate(void)
{
  struct thread *t = thread_current();

  /* Activate thread's page tables. */
  pagedir_activate(t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update();

  if (t->process == NULL)
  {
    process_init(t, NULL);
  }
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void **esp);
static bool validate_segment(const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, char *file_name, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);
static bool lazy_load (struct file *file, char *file_name, off_t ofs, uint8_t *upage,
            uint32_t read_bytes, uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char *file_name, void (**eip)(void), void **esp)
{
  struct thread *t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create();
  if (t->pagedir == NULL)

    goto done;
  process_activate();

  /* Open executable file. */
  lock_acquire(&filesys_lock);
  file = filesys_open(file_name);

  if (file == NULL)
  {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024)
  {

    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
  {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof(phdr))
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type)
    {
    case PT_NULL:
    case PT_NOTE:
    case PT_PHDR:
    case PT_STACK:
    default:
      /* Ignore this segment. */
      break;
    case PT_DYNAMIC:

    case PT_INTERP:
    case PT_SHLIB:
      goto done;
    case PT_LOAD:

      if (validate_segment(&phdr, file))
      {
        bool writable = (phdr.p_flags & PF_W) != 0;
        uint32_t file_page = phdr.p_offset & ~PGMASK;
        uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
        uint32_t page_offset = phdr.p_vaddr & PGMASK;
        uint32_t read_bytes, zero_bytes;
        if (phdr.p_filesz > 0)
        {
          /* Normal segment.
                     Read initial part from disk and zero the rest. */
          read_bytes = page_offset + phdr.p_filesz;
          zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
        }
        else
        {
          /* Entirely zero Don't read anything from disk. */
          read_bytes = 0;
          zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
        }
        if (!load_segment(file, file_name, file_page, (void *)mem_page,
                          read_bytes, zero_bytes, writable))
          goto done;
      }
      else
        goto done;
      break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;
  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  lock_release(&filesys_lock);
  return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and enFAIL tests/userprog/exec-missing
d within the
     user address space range. */
  if (!is_user_vaddr((void *)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to FAIL tests/userprog/exec-missing
system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment(struct file *file, char* file_name, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
  {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    lazy_load(file, file_name, ofs, upage, page_read_bytes, page_zero_bytes, writable);

    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;

#ifdef VM
    ofs += PGSIZE;
#endif
  }
  return true;
}

static bool lazy_load (struct file *file, char *file_name, off_t ofs, uint8_t *upage,
             uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
   return (insert_from_file(file, file_name, ofs, upage, read_bytes, zero_bytes,
         writable));

}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack(void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL)
  {
    success = install_page(((uint8_t *)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }


  return success;
}

unsigned
process_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
  struct process *p = hash_entry(e, struct process, elem);
  return p->id;
}

bool process_hash_less_func(const struct hash_elem *a,
                            const struct hash_elem *b,
                            void *aux UNUSED)
{
  int first = hash_entry(a, struct process, elem)->id;
  int second = hash_entry(b, struct process, elem)->id;
  return first < second;
}

unsigned
fd_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
  struct file_descriptor *f = hash_entry(e, struct file_descriptor, elem);
  return f->fd;
}

bool fd_hash_less_func(const struct hash_elem *a,
                       const struct hash_elem *b,
                       void *aux UNUSED)
{
  return hash_entry(a, struct file_descriptor, elem)->fd < hash_entry(b, struct file_descriptor, elem)->fd;
}

void
fd_destroy_func (struct hash_elem *e, void *aux)
{
  struct file_descriptor *fd = hash_entry (e, struct file_descriptor, elem);
  free(fd->file_name);
  file_close (fd->file);
  free(fd);
}

bool is_stack_overflow(void **esp, int8_t value)
{
  return false;
  if ((esp - value) <= (PHYS_BASE - PGSIZE))
  {
    return true;
  }
  else
  {
    return false;
  }
}
