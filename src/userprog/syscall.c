#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "lib/stdio.h"
#include "threads/palloc.h"
#include "vm/frame.h"
#include "vm/page.h"

static void syscall_handler (struct intr_frame *);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
char *get_name (int fd);
static int32_t get_arg (uint32_t *addr, int argc);
struct file *get_file (int fd);
int mmap_end (void);

uint32_t (*functions[numOfFuncs]) (uint32_t *arguments);

static struct list all_files;

static int32_t get_arg (uint32_t *base, int argc) {
  /*Create a buffer of bytes */

  uint8_t *arg = malloc (sizeof (int32_t));

  /* Locate the correct location of the argument */
  uint8_t *uaddr = ((uint8_t *)base + (4 * argc));

  /* Read a word from user memory */
  read_from_user (uaddr, arg, sizeof (int32_t), false);

  /* Cast array of bytes to int32_t */
  int32_t ret = *(int32_t *)arg;

  /* De-allocate arguments for memory*/
  free (arg);

  /* Cast buffer to (pointer to a word) and then dereference */
  return ret;
}

void set_process_status (int status) {
  struct thread *cur = thread_current ();
  struct process *proc = cur->process;
  proc->exit_code = status;
  thread_exit ();
}

void
syscall_init (void)
{

  enum intr_level old_level = intr_disable ();
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init (&filesys_lock);
  lock_init (&kernel_buffer_lock);

  functions[SYS_HALT] = &halt;
  functions[SYS_EXIT] = &exit;
  functions[SYS_EXEC] = &exec;
  functions[SYS_WAIT] = &wait;
  functions[SYS_CREATE] = &create;
  functions[SYS_REMOVE] = &remove;
  functions[SYS_OPEN] = &open;
  functions[SYS_FILESIZE] = &filesize;
  functions[SYS_READ] = &read;
  functions[SYS_SEEK] = &seek;
  functions[SYS_TELL] = &tell;
  functions[SYS_CLOSE] = &close;
  functions[SYS_WRITE] = &write;
#ifdef VM
  functions[SYS_MMAP] = &mmap;
  functions[SYS_MUNMAP] = &munmap;
 #endif
  kernel_buff_writes = 0;
  list_init (&all_files);
  intr_set_level (old_level);
  global_fd = 2;
}

static void
syscall_handler (struct intr_frame *f)
{
  //syscall number at stack pointer
  int syscall_num = (int) get_arg (f->esp, 0);
  uint32_t *arguments = (f->esp + sizeof (uint32_t));
  uint32_t return_code = functions[syscall_num] (arguments);

  #ifdef VM
  thread_current ()->esp = f->esp;
  #endif
  f->eax = return_code;
}

uint32_t
halt (uint32_t* arguments UNUSED) {
  shutdown_power_off ();
  return 0;
}

uint32_t
exit (uint32_t* arguments)
{
  struct thread *cur = thread_current ();
  int status = (int) get_arg (arguments, 0);
  lock_acquire (&cur->process->lock);
  /* Make parent aware of child exit status */
  if (cur->process) {
    struct process *proc = cur->process;
    proc->exit_code = status;
  }
  lock_release (&cur->process->lock);
  thread_exit ();
  return 0;
}

uint32_t
exec (uint32_t* arguments)
{
  char* filename = (char *) get_arg (arguments, 0);
  if (is_kernel_vaddr (filename)) {
    thread_exit ();
  }
  return (uint32_t) process_execute (filename);
}

uint32_t
wait (uint32_t* arguments)
{
  pid_t pid = (pid_t) get_arg (arguments, 0);
  return process_wait (pid);
}

uint32_t
create (uint32_t* arguments)
{
  bool success;

  char* name = (char *) get_arg (arguments, 0);
  if (!name) {
    thread_exit ();
    return false;
  }
  /* Try to calculate the lenght of the string safely (+1 for sentinel)*/
  size_t name_size = strnlen (name, PGSIZE) + 1;
  char *file_name = malloc (name_size);
  read_from_user (name, file_name, name_size, true);

  if (!file_name || !name) {
    free (file_name);
    thread_exit ();
  }

  unsigned initial_size = (unsigned) get_arg (arguments, 1);

  lock_acquire (&filesys_lock);
  success = filesys_create (name, initial_size);
  lock_release (&filesys_lock);
  free (file_name);
  return success;
}

uint32_t
close (uint32_t* arguments)
{

  struct process *process = thread_current ()->process;
  int fd = (int) get_arg (arguments, 0);

  if (fd == 0 || fd == 1) {
    return -1;
  }

  lock_acquire (&filesys_lock);
  lock_acquire (&process->lock);
  struct file_descriptor file_descr = {.fd = fd};

  struct hash_elem *e = hash_find (process->file_descriptors, &file_descr.elem);
  if (!e) {
    lock_release (&process->lock);
    lock_release (&filesys_lock);
    return -1;
  }

  struct file_descriptor *file_desc = hash_entry (e, struct file_descriptor, elem);

  if (!hash_delete (process->file_descriptors, e)) {
    lock_release (&process->lock);
    lock_release (&filesys_lock);
    return -1;
  }

  list_remove (&file_desc->l_elem);
  file_close (file_desc->file);

  lock_release (&process->lock);
  lock_release (&filesys_lock);

  return 0;
}

uint32_t
remove (uint32_t* arguments)
{
  struct process *proc = thread_current ()->process;
  bool success;
  char* name = (char *) get_arg (arguments, 0);

  /* Try to calculate the lenght of the string safely (+1 for sentinel)*/
  size_t name_size = strnlen (name, PGSIZE) + 1;
  char *file_name = malloc (name_size);
  read_from_user (name, file_name, name_size, true);

  lock_acquire (&filesys_lock);
  success = filesys_remove (file_name);
  lock_release (&filesys_lock);

  free (file_name);

  return success;
}

uint32_t
open (uint32_t* arguments)
{
  struct process *proc = thread_current ()->process;

  char* name = (char *) get_arg (arguments, 0);

  if (!name) {
    thread_exit ();
    return -1;
  }
  /* Try to calculate the length of the string safely (+1 for sentinel)*/
  size_t name_size = strnlen (name, PGSIZE);
  char *file_name = calloc (sizeof (char), name_size + 1);
  lock_acquire (&filesys_lock);
  read_from_user (name, file_name, name_size, true);

  struct file *file = filesys_open (file_name);

  if (!file) {
    lock_release (&filesys_lock);
    return -1;
  }

  lock_acquire (&proc->lock);
  struct file_descriptor *file_descr = malloc (sizeof (struct file_descriptor));
  file_descr->file_name = file_name;
  file_descr->fd = global_fd++;
  file_descr->file = file;

  list_push_back (&all_files, &file_descr->l_elem);

  hash_insert (proc->file_descriptors, &file_descr->elem);

  lock_release (&proc->lock);
  lock_release (&filesys_lock);

  return file_descr->fd;
}

uint32_t
filesize (uint32_t* arguments)
{
  int fd = (int) get_arg (arguments, 0);

  lock_acquire (&filesys_lock);

  struct file *f = get_file (fd);

  /* File doesn't exist */
  if (!f) {
    return 0;
  }

  off_t length = file_length (f);

  lock_release (&filesys_lock);

  return length;
}

/* - Reads size bytes from the file open as fd into buffer.
   - Returns the number of bytes actually read (0 at end of file), or -1 if the
      file could not be read (due to a condition other than end of file). */
uint32_t
read (uint32_t* arguments)
{
  int fd = (int) get_arg (arguments, 0);
  char *buffer = (char *) get_arg (arguments, 1);
  unsigned size = (unsigned) get_arg (arguments, 2);

  if (is_kernel_vaddr (buffer)) {
    thread_exit ();
  }

  char *temp_buff = calloc (size, sizeof (char));

  lock_acquire (&filesys_lock);

  if (fd == 0)
  {
    uint8_t c;
    unsigned size_read = 0;
    while (size_read < size && (c = input_getc ()) != 0)
    {
      temp_buff[size_read] = c;
      size_read++;
    }

    if (!put_kernel_buff ((uint8_t *) buffer, (uint8_t *) temp_buff, size_read))
    {
      lock_release (&filesys_lock);
      free (temp_buff);
      return -1;
    }
    lock_release (&filesys_lock);
    free (temp_buff);
    flush_kernel_buff ();
    return size_read;
  } else if (fd == 1)
  {
    lock_release (&filesys_lock);
    free (temp_buff);
    return -1;
  }

  struct process *process = thread_current ()->process;

  lock_acquire (&process->lock);

  struct file *f = get_file (fd);
  if (!f) {
    lock_release (&process->lock);
    lock_release (&filesys_lock);
    free (temp_buff);
    return -1;
  }

  int bytes_read = -1;
  bytes_read = file_read (f, temp_buff, size);

  if (!put_kernel_buff ((uint8_t *) buffer, (uint8_t *) temp_buff, size)) {
    lock_release (&process->lock);
    lock_release (&filesys_lock);
    free (temp_buff);
    return -1;
  }
  lock_release (&process->lock);
  lock_release (&filesys_lock);
  free (temp_buff);
  flush_kernel_buff ();
  return bytes_read;
}

/* - Writes size bytes from buffer to the open file fd
   - Returns the number of bytes actually written, which may be less than
      size if some bytes could not be written. */
uint32_t
write (uint32_t* arguments)
{
  int fd = (int) get_arg (arguments, 0);
  void *buffer = (void *) get_arg (arguments, 1);
  unsigned size = (unsigned) get_arg (arguments, 2);

  if (!buffer) {
    return 0;
  }

  /* Ensure the entire user defined buffer is valid */
  void *buffer_copy = calloc (size, sizeof (void *));
  read_from_user (buffer, buffer_copy, size, false);
  lock_acquire (&filesys_lock);
  free (buffer_copy);

  if (fd == 1) {
    putbuf (buffer, size);
    lock_release (&filesys_lock);
    return size;
  }

  struct process *process = thread_current ()->process;

  lock_acquire (&process->lock);

  struct file *f = get_file (fd);

  if (!f) {
    lock_release (&process->lock);
    lock_release (&filesys_lock);
    return 0;
  }

  int written_bytes;
  written_bytes = file_write (f, buffer, size);

  lock_release (&process->lock);
  lock_release (&filesys_lock);

  return written_bytes;
}

uint32_t seek (uint32_t* arguments) {
  int fd = (int) get_arg (arguments, 0);
  unsigned position = (unsigned) get_arg (arguments, 1);

  lock_acquire (&filesys_lock);
  char *name = get_name (fd);

  struct process *process = thread_current ()->process;
  lock_acquire (&process->lock);
  struct file_descriptor fd_goal = {.fd = fd};
  struct hash_elem *e;

  e = hash_find (process->file_descriptors, &fd_goal.elem);
  struct file *f = hash_entry (e, struct file_descriptor, elem)->file;

  /* File doesn't exist */
  if (!f) {
    lock_release (&process->lock);
    lock_release (&filesys_lock);
    return 0;
  }

  file_seek (f, position);
  lock_release (&process->lock);
  lock_release (&filesys_lock);
  return 0;
}

uint32_t
tell (uint32_t* arguments)
{
  int fd = (int) get_arg (arguments, 0);
  lock_acquire (&filesys_lock);
  char *name = get_name (fd);
  struct file *f = get_file (fd);

  /* File doesn't exist */
  if (!f) {
    lock_release (&filesys_lock);
    return 0;
  }

  off_t pos = file_tell (f);
  lock_release (&filesys_lock);
  return pos;
}

#ifdef VM
mapid_t
mmap (uint32_t* arguments)
{
  int fd = (int) get_arg (arguments, 0);
  void *addr = (void *) get_arg (arguments, 1);
  /*it must fail when fd is 0 or 1*/
  if (fd <= 1) {
    return mmap_end ();
  }
  /* addr must be page aligned and different to 0 */
  if ((uint32_t) addr % PGSIZE != 0 || addr == 0) {
    return mmap_end ();
  }
  struct process *p = thread_current ()->process;
  struct file *f = get_file (fd);
  /*the file size can't be zero*/
  if (!f || file_length (f) == 0) {
    return mmap_end ();
  }

  /* -----------------------------------------
   NEED TO CHECK IF THE RANGE OF PAGES MAPPED OVERLAPS
   ANY EXISTING SET OF MAPPED pages
   --------------------------------------------*/

  struct file *reopened = file_reopen (f);

  for (size_t size = 0; size < file_length (f); size += PGSIZE) {
     if (has_page_mapping (thread_current (), addr+size)) {
        return mmap_end ();
      }
  }

  /*add mapping*/
  int num_pages = 0;
  for (size_t size = 0; size < file_length (f); size += PGSIZE) {
    num_pages++;
    size_t page_read_bytes = (file_length (f) > PGSIZE + size) ?
                                PGSIZE : file_length(f) - size;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    if (!insert_from_file (reopened, get_name (fd), size, addr+size,
                           page_read_bytes, page_zero_bytes, true))
    {
      return mmap_end ();
    }
  }

  mapid_t mapid;
  if (!list_empty (&p->virtual_pages)) {
    mapid = (mapid_t) list_entry (list_back (&p->virtual_pages),
                                  struct mapping, elem)->mapid + 1;
  } else {
    mapid = (mapid_t) 1;
  }
  struct mapping *m = malloc (sizeof (struct mapping));
  m->start_addr = addr;
  m->file = reopened;
  m->num_pages = num_pages;
  m->mapid = mapid;
  m->fileid = fd;
  m->size = file_length (reopened);
  list_push_back (&p->virtual_pages, &m->elem);

  return mapid;
}

int mmap_end (void) {
  return -1;
}

void
free_mmap (mapid_t mapid)
{
  if (mapid <= 0) {
    mapid = 1;
  }
  struct process *p = thread_current ()->process;
  if (!list_empty (&p->virtual_pages)){
    struct mapping *m = find_mapping_in_process (p, mapid);
    if (m) {
      free_all_mmaps (m);
      list_remove (&m->elem);
      free (m);
    }
  }
}

void
munmap (uint32_t* arguments)
{
  mapid_t mapid =  arguments;
  if (mapid <= 0) {
    mapid = 1;
  }
  struct process *p = thread_current ()->process;
  if (!list_empty (&p->virtual_pages)){
    struct mapping *m = find_mapping_in_process (p, mapid);
    if (m) {
      check_unmap (m);
      list_remove (&m->elem);
    }
  }

  /*gets the mapping from the page of the current process
  needing a written flag in the file and if its been written
  saves the changes in the original file. Then removes from the
  process list of virtual pages*/
}
#endif

static int
get_user (const uint8_t *uaddr)
{
  if (is_kernel_vaddr (uaddr)) {
    return -1;
  }
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
    : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
    UDST must be below PHYS_BASE.
    Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  if (is_kernel_vaddr (udst)) {
    return false;
  }
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* A helper function that returns the name of the file open as fd */
char *
get_name (int fd)
{
  struct process *process = thread_current ()->process;
  struct file_descriptor file_desc = {.fd = fd};

  struct hash_elem *e = hash_find (process->file_descriptors, &file_desc.elem);

  /* No file name found with that file descriptor */
  if (!e) {
    return 0;
  }

  return hash_entry (e, struct file_descriptor, elem)->file_name;
}

void
flush_kernel_buff (void)
{
  lock_acquire (&kernel_buffer_lock);
  for (int i = 0; i < kernel_buff_writes; i++) {
    struct kern_buff_entry *buff = kernel_buff[i];
    for (int j = 0; j < buff->bytes; j++) {
      uint8_t *real_addr = (buff->uaddr_dest) + (j * sizeof (uint8_t));
      put_user (real_addr, buff->data[j]);
    }
    free (buff->data);
    free (buff);
  }

  kernel_buff_writes = 0;
  // Note: Lock could never be released if put_user fails
  lock_release (&kernel_buffer_lock);
}

bool
put_kernel_buff (uint8_t *uaddr, uint8_t *src, int bytes)
{
  lock_acquire (&kernel_buffer_lock);
  /* Kernel buffer needs to flush or addr is not below PHYS_BASE */
  if (kernel_buff_writes >= MAX_KERNEL_UADDRS) {
    lock_release (&kernel_buffer_lock);
    return false;
  }

  struct kern_buff_entry *buff = malloc (sizeof (struct kern_buff_entry));
  buff->bytes = bytes;
  buff->uaddr_dest = uaddr;
  buff->data = calloc (bytes, sizeof (uint8_t));

  /* Copy bytes into buffer */
  for (int i = 0; i < bytes; i++) {
    buff->data[i] = src[i];
  }

  kernel_buff[kernel_buff_writes] = buff;
  kernel_buff_writes++;

  lock_release (&kernel_buffer_lock);
  return true;
}

struct file *
get_file (int fd)
{
  if (fd < 2) {
    return NULL;
  }
  struct process *process = thread_current ()->process;
  struct file_descriptor fd_goal = {.fd = fd};
  struct hash_elem *e;

  e = hash_find (process->file_descriptors, &fd_goal.elem);
  if (!e) {
    return NULL;
  }
  return hash_entry (e, struct file_descriptor, elem)->file;
}


/* Reads from user buffer into the buffer you specified until it reaches a
sentinel or until max size - Returns number of bytes actually read */
int
read_from_user (uint8_t *uaddr,
                uint8_t *buffer,
                int max_size,
                bool sentinel_terminated)
{
  int bytes_read = 0;
  while (bytes_read < max_size) {
    uint8_t curByte = (uint8_t) get_user (uaddr);
    buffer[bytes_read] = curByte;
    bytes_read++;
    uaddr += sizeof (uint8_t);

    if (sentinel_terminated && curByte == '\0') {
      break;
    }
  }
  return bytes_read;
}
