#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8028364C.h"

extern u8 *lbl_803DE344;

/*
 * --INFO--
 *
 * Function: fn_8028363C
 * EN v1.0 Address: 0x8028363C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8028364C
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8028363C(int slot, u32 valueA, u32 valueB)
{
    u8 *entry;

    slot *= 0xf4;
    entry = lbl_803DE344;
    entry += slot;
    *(u32 *)(entry + 0x94) = valueA;
    entry = lbl_803DE344;
    entry += slot;
    *(u32 *)(entry + 0x98) = valueB;
}

u8 fn_8028365C(int slot)
{
    u8 *entry;

    slot *= 0xf4;
    entry = lbl_803DE344;
    entry += slot;
    return entry[0x9c];
}

u8 fn_80283670(int slot)
{
    u8 *entry;

    slot *= 0xf4;
    entry = lbl_803DE344;
    entry += slot;
    return entry[0x90];
}

u16 fn_80283684(int slot)
{
    u8 *entry;

    slot *= 0xf4;
    entry = lbl_803DE344;
    entry += slot;
    return *(u16 *)(entry + 0x70);
}

void fn_80283698(int slot, u8 value)
{
    u8 *entry;

    slot *= 0xf4;
    entry = lbl_803DE344;
    entry += slot;
    entry[0xa0] = value;
}
