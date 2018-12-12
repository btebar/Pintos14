#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#ifdef VM
  #define numOfFuncs 15
#else
  #define numOfFuncs 13
#endif
#define BYTE 8
typedef int pid_t;

#include <stdint.h>
#include <stdbool.h>
#include "filesys/off_t.h"
#include "userprog/process.h"

void syscall_init (void);

/* Maximum number of user addresses that the kernel can store before flushing */
#define MAX_KERNEL_UADDRS 5

struct kern_buff_entry {
  uint8_t* uaddr_dest;
  uint8_t* data;
  int bytes;
};

struct kern_buff_entry *kernel_buff[MAX_KERNEL_UADDRS];
int kernel_buff_writes;

/* Reads from src for the designated number of bytes and will write them to
  uaddr when the buffer is flushed - Does not verify src */
bool put_kernel_buff (uint8_t *uaddr, uint8_t *src, int bytes);

/* Writes the buffers to user memory and verifies and clears the buffer */
void flush_kernel_buff (void);

int read_from_user (uint8_t *uaddr,
                uint8_t *buffer,
                int max_size,
                bool sentinel_terminated);


uint32_t halt (uint32_t* arguments);
uint32_t exec (uint32_t* arguments);
uint32_t exit (uint32_t* arguments);
uint32_t wait (uint32_t* arguments);
uint32_t create (uint32_t* arguments);
uint32_t remove (uint32_t* arguments);
uint32_t open (uint32_t* arguments);
uint32_t filesize (uint32_t* arguments);
uint32_t read (uint32_t* arguments);
uint32_t seek (uint32_t* arguments);
uint32_t tell (uint32_t* arguments);
uint32_t close (uint32_t* arguments);
uint32_t write (uint32_t* arguments);
#ifdef VM
mapid_t mmap(uint32_t* arguments);
void munmap(uint32_t* arguments);
void load_into_buffer(int fd, void* buffer, size_t size);
#endif

char *get_name (int fd);

#endif /* userprog/syscall.h */
