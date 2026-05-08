#include "ghidra_import.h"
#include "main/dll/DR/DRpulley.h"

extern void fn_8003B8F4(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale);
extern void fn_801E991C(void *obj, void *path);
extern void ObjPath_GetPointWorldPosition(void *obj, int idx, void *out0, void *out1, void *out2, int flag);

extern f32 lbl_803E5AEC;

/*
 * --INFO--
 *
 * Function: fn_801ECEC4
 * EN v1.0 Address: 0x801ECEC4
 * EN v1.0 Size: 208b
 */
#pragma peephole off
#pragma scheduling off
void fn_801ECEC4(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible)
{
    void *path;

    path = *(void **)((char *)obj + 0xb8);
    fn_801E991C(obj, path);
    if (visible == -1) {
        fn_8003B8F4(obj, p2, p3, p4, p5, (double)lbl_803E5AEC);
        ObjPath_GetPointWorldPosition(obj, 0, (char *)path + 0x3e8, (char *)path + 0x3ec, (char *)path + 0x3f0, 0);
    } else {
        fn_8003B8F4(obj, p2, p3, p4, p5, (double)lbl_803E5AEC);
        ObjPath_GetPointWorldPosition(obj, 0, (char *)path + 0x3e8, (char *)path + 0x3ec, (char *)path + 0x3f0, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset
