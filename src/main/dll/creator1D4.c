#include "ghidra_import.h"
#include "main/dll/creator1D4.h"

extern void fn_8003B8F4(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale);
extern void ObjGroup_RemoveObject(void *obj, int group);
extern void ObjPath_GetPointWorldPosition(void *obj, int idx, void *out0, void *out1, void *out2, int flag);

extern void *lbl_803DCA68;
extern f32 lbl_803E5210;

/*
 * --INFO--
 *
 * Function: nw_mammoth_free
 * EN v1.0 Address: 0x801CEFBC
 * EN v1.0 Size: 84b
 */
#pragma peephole off
#pragma scheduling off
void nw_mammoth_free(void *obj)
{
    void *node;

    node = *(void **)((char *)obj + 0xb8);
    ObjGroup_RemoveObject(obj, 0x4d);
    if ((*((u8 *)node + 0x43c) & 0x40) != 0) {
        (*(void (***)(void))lbl_803DCA68)[0x19]();
    }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: nw_mammoth_render
 * EN v1.0 Address: 0x801CF010
 * EN v1.0 Size: 156b
 */
#pragma peephole off
#pragma scheduling off
void nw_mammoth_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible)
{
    int i;
    void *node;

    node = *(void **)((char *)obj + 0xb8);
    fn_8003B8F4(obj, p2, p3, p4, p5, (double)lbl_803E5210);
    for (i = 0; i < 4; i++) {
        ObjPath_GetPointWorldPosition(obj, i,
            (char *)node + i * 0xc + 0x45c,
            (char *)node + i * 0xc + 0x460,
            (char *)node + i * 0xc + 0x464,
            0);
    }
    ObjPath_GetPointWorldPosition(obj, 4,
        (char *)node + 0xc,
        (char *)node + 0x10,
        (char *)node + 0x14,
        0);
}
#pragma scheduling reset
#pragma peephole reset
