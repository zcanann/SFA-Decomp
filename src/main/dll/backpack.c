#include "ghidra_import.h"
#include "main/dll/backpack.h"

extern void fn_801641B0(int obj);
extern void fn_80164940(int obj);
extern void fn_80164C44(int obj);
extern int GameBit_Set(int eventId, int value);

extern void* lbl_803DCAB8;
extern void* lbl_803DCA8C;

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

/*
 * --INFO--
 *
 * Function: fn_801650D8
 * EN v1.0 Address: 0x801650D8
 * EN v1.0 Size: 176b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
int fn_801650D8(int obj, int target) {
    int *aux = *(int**)(obj + 0xb8);
    if ((s8)*(u8*)(target + 0x27a) != 0) {
        (*(int(**)(int, int, int, int))(*(int*)lbl_803DCAB8 + 0x4c))(obj, (int)*(s16*)((char*)aux + 0x3f0), -1, 0);
        (*(int(**)(int, int, int, int, int))(*(int*)lbl_803DCA8C + 0x58))(obj, target, 0x3c, 0xa, 0);
        GameBit_Set((int)*(s16*)((char*)aux + 0x3f2), 1);
        *(u8*)((char*)aux + 0x405) = 0;
    }
    return 0;
}
#pragma pop
