#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80282594.h"

extern int fn_80282070(int obj, int buf, u8 a, u8 b);

/*
 * --INFO--
 *
 * Function: fn_80282588
 * EN v1.0 Address: 0x80282588
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80282594
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fn_80282588(int obj)
{
    int flags;

    flags = *(int *)(obj + 0x214);
    if ((flags & 0x4) == 0) {
        return *(u16 *)(obj + 0x280);
    }
    *(int *)(obj + 0x214) = flags & ~0x4;
    return fn_80282070(obj, obj + 0x260, *(u8 *)(obj + 0x121), *(u8 *)(obj + 0x122));
}

/*
 * --INFO--
 *
 * Function: fn_802825D0
 * EN v1.0 Address: 0x802825D0
 * EN v1.0 Size: 72b
 */
int fn_802825D0(int obj)
{
    int flags;

    flags = *(int *)(obj + 0x214);
    if ((flags & 0x8) == 0) {
        return *(u16 *)(obj + 0x2a4);
    }
    *(int *)(obj + 0x214) = flags & ~0x8;
    return fn_80282070(obj, obj + 0x284, *(u8 *)(obj + 0x121), *(u8 *)(obj + 0x122));
}
