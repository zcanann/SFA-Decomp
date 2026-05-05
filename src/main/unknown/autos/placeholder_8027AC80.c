#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027AC80.h"

extern u32 fn_8027AA94(int p1, int p2, int p3);

/*
 * --INFO--
 *
 * Function: fn_8027AC34
 * EN v1.0 Address: 0x8027AC34
 * EN v1.0 Size: 132b
 */
int fn_8027AC34(int p1, int p2, int p3)
{
    u8 i;

    for (i = 0; i < 15; i++) {
        if (fn_8027AA94(p1, p2, p3) != 0) {
            return 1;
        }
    }
    return 0;
}
