#ifndef MAIN_DLL_DLL_DESCRIPTOR_TABLE_H_
#define MAIN_DLL_DLL_DESCRIPTOR_TABLE_H_

#include "types.h"

/* DLL ResourceDescriptor pointer table emitted into .data (pointer entries
 * regenerate ADDR32 relocs). The u64 member forces the retail 8-byte
 * alignment: the table typically follows a string that ends 4-aligned and
 * retail pads to an 8-aligned table start. */
typedef union DllDescriptorTable
{
    void* ptrs[8];
    u64 align8;
} DllDescriptorTable;

#endif /* MAIN_DLL_DLL_DESCRIPTOR_TABLE_H_ */
