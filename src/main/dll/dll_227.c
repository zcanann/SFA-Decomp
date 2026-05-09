#include "ghidra_import.h"
#include "main/dll/dll_227.h"

extern void fn_8003B8F4(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale);
extern void fn_8001DD88(f32 x, f32 y, f32 z);
extern void queueGlowRender(void *p);
extern void ObjPath_GetPointWorldPosition(void *obj, int idx, void *out0, void *out1, void *out2, int flag);
extern void *Obj_GetPlayerObject(void);
extern int fn_801BE19C(void *obj, int p2, void *p3, void *p4);
extern void fn_8001D9F4(void *p1, void *p2, void *p3, void *p4);
extern void fn_8001D71C(void *p1, u8 a, u8 b, u8 c, int d);
extern int randomGetRange(int min, int max);

extern void *lbl_803DCA8C;
extern void *lbl_803DCA54;
extern void *lbl_803DCAB8;
extern int lbl_803DDBB0;
extern void *lbl_803DDB90;
extern f32 lbl_803DDBA4;
extern void *pDll_expgfx;
extern f32 lbl_803E4CB8;
extern f32 lbl_803E4CC8;

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
                queueGlowRender(lbl_803DDB90);
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

/*
 * --INFO--
 *
 * Function: dimbosstonsil_update
 * EN v1.0 Address: 0x801BEA74
 * EN v1.0 Size: 0x1FC
 */
#pragma peephole off
#pragma scheduling off
void dimbosstonsil_update(void *obj)
{
    void *r30;
    void *r4_loc;
    int s32_temp;
    u8 b1, b2, b3, b4;

    r30 = *(void **)((char *)obj + 0xb8);
    r4_loc = *(void **)((char *)obj + 0x4c);

    if (*(int *)((char *)obj + 0xf4) != 0) return;

    if (*(int *)((char *)obj + 0xf8) == 0) {
        *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)r4_loc + 0x8);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)r4_loc + 0xc);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)r4_loc + 0x10);
        (*(void (***)(int, void *, int))lbl_803DCA54)[0x12]((s8) * (s8 *)((char *)r4_loc + 0x2e), obj, -1);
        *(int *)((char *)obj + 0xf8) = 1;
        return;
    }

    if ((*(u16 *)((char *)r30 + 0x400) & 0x2) != 0) {
        lbl_803DDBA4 = lbl_803E4CC8;
        s32_temp = 1;
        (*(void (***)(int, void *, void *, int, void *, int, int, int, int *))lbl_803DCAB8)[0xa](
            0, r30, (char *)r30 + 0x35c, *(s16 *)((char *)r30 + 0x3f4),
            (char *)r30 + 0x405, 0, 0, 0, &s32_temp);
        *(u16 *)((char *)r30 + 0x400) = (u16)(*(u16 *)((char *)r30 + 0x400) & ~0x2);
    }

    if ((*(int (***)(void *, void *, int))lbl_803DCAB8)[0xc](obj, r30, 1) == 0) return;

    *(void **)((char *)r30 + 0x2d0) = Obj_GetPlayerObject();
    fn_801BE19C(obj, 0, r30, r30);

    if (lbl_803DDB90 == NULL) return;

    fn_8001D9F4(&b4, &b3, &b2, &b1);
    fn_8001D71C(lbl_803DDB90, *((u8 *)lbl_803DDB90 + 0x13), *((u8 *)lbl_803DDB90 + 0x12), *((u8 *)lbl_803DDB90 + 0x11), 0xc0);

    if (*((u8 *)lbl_803DDB90 + 0x2f8) == 0) return;
    if (*((u8 *)lbl_803DDB90 + 0x4c) == 0) return;

    {
        s16 r30_local;
        int sum;
        sum = (int)*((u8 *)lbl_803DDB90 + 0x2f9) + (int)*((s8 *)lbl_803DDB90 + 0x2fa);
        r30_local = (s16)sum;
        if (r30_local < 0) {
            r30_local = 0;
            *((u8 *)lbl_803DDB90 + 0x2fa) = 0;
        } else if (r30_local > 0xc) {
            int rnd = randomGetRange(-0xc, 0xc);
            r30_local = (s16)(r30_local + rnd);
            if (r30_local > 0xff) {
                r30_local = 0xff;
                *((u8 *)lbl_803DDB90 + 0x2fa) = 0;
            }
        }
        *((u8 *)lbl_803DDB90 + 0x2f9) = (u8)r30_local;
    }
}
#pragma scheduling reset
#pragma peephole reset
