#ifndef METROTRK_PORTABLE_MEM_TRK_H
#define METROTRK_PORTABLE_MEM_TRK_H

#include <stddef.h>
#include "dolphin/types.h"

void TRK_fill_mem(void* dest, int value, unsigned long length);
void* TRK_memset(void* dest, int value, size_t length);

#endif /* METROTRK_PORTABLE_MEM_TRK_H */
