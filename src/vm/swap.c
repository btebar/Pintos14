#include "vm/swap.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"
#include "devices/block.h"

#define BLOCKS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

struct lock lock;
struct bitmap *swap_slot_usage;

void
swap_init(void)
{
  lock_init (&lock);
  swap_slot_usage = bitmap_create (block_size (block_get_role (BLOCK_SWAP)));
  if (swap_slot_usage == NULL) {
    PANIC ("Swap slot bitmap could not be created");
  }
  bitmap_set_all (swap_slot_usage, false);
}

size_t
write_swap_slot(uint8_t *addr)
{
  lock_acquire (&lock);

  /* Finds and flips the first set of bits of length BLOCKS_PER_PAGE in the
    swap table that are all set to 0. swap_beign is the index of the first one */
  size_t first = bitmap_scan_and_flip (swap_slot_usage, 0, BLOCKS_PER_PAGE, false);
  
  if (first == BITMAP_ERROR) {
    PANIC ("No more swap slots");
  }

  /* Write to all the sectors necessary for the page
  to be swapped */
  for (int i = 0; i < BLOCKS_PER_PAGE; i++)
  {
    block_write (block_get_role (BLOCK_SWAP), first + i, addr + (i * BLOCK_SECTOR_SIZE));
  }

  lock_release (&lock);

  return first;
}

void
load_swap_slot(uint32_t addr, uint8_t *dest)
{
  lock_acquire (&lock);

  /* Read all sectors necessary for page to be loaded into memory */
  for (int i = 0; i < BLOCKS_PER_PAGE; i++)
  {
    block_read (block_get_role (BLOCK_SWAP), addr + i, dest + (i * BLOCK_SECTOR_SIZE));
  }

  /* Sets the swap slot bits to 0 */
  //bitmap_flip (swap_slot_usage, addr);
  
  bitmap_set_multiple (swap_slot_usage, addr, BLOCKS_PER_PAGE, false);
  
  
  lock_release (&lock);
}

void
free_swap_slot(block_sector_t sector)
{
  lock_acquire (&lock);

  bitmap_set_multiple (swap_slot_usage, sector, BLOCKS_PER_PAGE, false);

  lock_release (&lock);
}
