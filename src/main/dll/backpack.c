#include "ghidra_import.h"
#include "main/dll/backpack.h"

extern void fn_801641B0(int obj);
extern void fn_80164940(int obj);
extern void fn_80164C44(int obj);

/*
 * --INFO--
 *
 * Function: tumbleweed_update
 * EN v1.0 Address: 0x80164EE4
 * EN v1.0 Size: 72b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void tumbleweed_update(int obj) {
    if (*(s16*)(obj + 0x46) == 0x39d) {
        fn_80164940(obj);
    } else {
        fn_801641B0(obj);
    }
    fn_80164C44(obj);
}
#pragma pop

/* 8b "li r3, N; blr" returners. */
int fn_801650D0(void) { return 0x0; }
