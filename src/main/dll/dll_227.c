#include "ghidra_import.h"
#include "main/dll/dll_227.h"

extern void fn_8003B8F4(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale);
extern void fn_8001DD88(f32 x, f32 y, f32 z);
extern void fn_800604B4(void *p);
extern void ObjPath_GetPointWorldPosition(void *obj, int idx, void *out0, void *out1, void *out2, int flag);

extern void *lbl_803DCA8C;
extern int lbl_803DDBB0;
extern void *lbl_803DDB90;
extern void *pDll_expgfx;
extern f32 lbl_803E4CB8;

/*
 * --INFO--
 *
 * Function: dimbosstonsil_render
 * EN v1.0 Address: 0x801BE8F8
 * EN v1.0 Size: 324b
 */
#pragma peephole off
#pragma scheduling off
void dimbosstonsil_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible)
{
    int local_8;
    f32 outX, outY, outZ;

    if (visible != 0) {
        if (*(int *)((char *)obj + 0xf4) == 0) {
            fn_8003B8F4(obj, p2, p3, p4, p5, (double)lbl_803E4CB8);

            ObjPath_GetPointWorldPosition(obj, 1, &outX, &outY, &outZ, 0);
            (*(void (***)(void *, int, int *, int, int, int))pDll_expgfx)[2](obj, 0x4bd, &local_8, 0x200001, -1, 0);

            ObjPath_GetPointWorldPosition(obj, 0, &outX, &outY, &outZ, 0);
            (*(void (***)(void *, int, int *, int, int, int))pDll_expgfx)[2](obj, 0x4bd, &local_8, 0x200001, -1, 0);

            if (lbl_803DDB90 != NULL && *((u8 *)lbl_803DDB90 + 0x2f8) != 0 && *((u8 *)lbl_803DDB90 + 0x4c) != 0) {
                fn_8001DD88(outX, outY, outZ);
                fn_800604B4(lbl_803DDB90);
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: dimbosstonsil_hitDetect
 * EN v1.0 Address: 0x801BEA3C
 * EN v1.0 Size: 56b
 */
#pragma peephole off
#pragma scheduling off
void dimbosstonsil_hitDetect(void *obj)
{
    (*(void (***)(void *, void *, int *))lbl_803DCA8C)[3](obj, *(void **)((char *)obj + 0xb8), &lbl_803DDBB0);
}
#pragma scheduling reset
#pragma peephole reset
