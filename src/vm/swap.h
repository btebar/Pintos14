#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"

void swap_init(void);
void load_swap_slot(uint32_t addr, uint8_t *dest);
size_t write_swap_slot(uint8_t *addr);
void free_swap_slot(block_sector_t sector);

#endif
