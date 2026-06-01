#include "ghidra_import.h"
#include "main/dll/DIM/DIMbosstonsil.h"

extern void objRenderFn_8003b8f4(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, double scale);
extern void lightVecFn_8001dd88(f32 x, f32 y, f32 z);
extern void queueGlowRender(void *p);
extern void ObjPath_GetPointWorldPosition(void *obj, int idx, void *out0, void *out1, void *out2, int flag);
extern void *Obj_GetPlayerObject(void);
extern int dimBossTonsil_newState_hitFightMain(void *obj, int p2, void *p3, void *p4);
extern void fn_8001D9F4(void *light, void *p1, void *p2, void *p3, void *p4);
extern void fn_8001D71C(void *p1, u8 a, u8 b, u8 c, int d);
extern int randomGetRange(int min, int max);

extern void *gPlayerInterface;
extern void *gObjectTriggerInterface;
extern void *gBaddieControlInterface;
extern int lbl_803DDBB0;
extern f32 lbl_803DDBA4;
extern void *gPartfxInterface;
extern f32 lbl_803E4CB8;
extern f32 lbl_803E4CC8;

/*
 * --INFO--
 *
 * Function: DIMbosstonsil_render
 * EN v1.0 Address: 0x801BE8F8
 * EN v1.0 Size: 324b
 */
#pragma peephole off
#pragma scheduling off
void DIMbosstonsil_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible)
{
    struct {
        f32 x;
        f32 y;
        f32 z;
    } pathPoint;
    int partfxArgs[3];
    f32 *outXPtr;
    f32 *outYPtr;
    f32 *outZPtr;

    if (visible != 0) {
        if (*(int *)((char *)obj + 0xf4) != 0) {
        } else {
            objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E4CB8);

            outXPtr = &pathPoint.x;
            outYPtr = &pathPoint.y;
            outZPtr = &pathPoint.z;
            ObjPath_GetPointWorldPosition(obj, 1, outXPtr, outYPtr, outZPtr, 0);
            (*(void (***)(void *, int, int *, int, int, int))gPartfxInterface)[2](obj, 0x4bd, partfxArgs, 0x200001, -1, 0);

            ObjPath_GetPointWorldPosition(obj, 0, outXPtr, outYPtr, outZPtr, 0);
            (*(void (***)(void *, int, int *, int, int, int))gPartfxInterface)[2](obj, 0x4bd, partfxArgs, 0x200001, -1, 0);

            if (gDIMbosstonsilLight != 0 && gDIMbosstonsilLight->active != 0 && gDIMbosstonsilLight->visible != 0) {
                lightVecFn_8001dd88(*outXPtr, *outYPtr, *outZPtr);
                queueGlowRender(gDIMbosstonsilLight);
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: DIMbosstonsil_hitDetect
 * EN v1.0 Address: 0x801BEA3C
 * EN v1.0 Size: 56b
 */
#pragma peephole off
#pragma scheduling off
void DIMbosstonsil_hitDetect(void *obj)
{
    (*(void (***)(void *, void *, int *))gPlayerInterface)[3](obj, *(void **)((char *)obj + 0xb8), &lbl_803DDBB0);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: DIMbosstonsil_update
 * EN v1.0 Address: 0x801BEA74
 * EN v1.0 Size: 0x1FC
 */
#pragma peephole off
#pragma scheduling off
void DIMbosstonsil_update(void *obj)
{
    void *r30;
    void *r4_loc;
    u8 b1, b2, b3, b4;

    r30 = *(void **)((char *)obj + 0xb8);
    r4_loc = *(void **)((char *)obj + 0x4c);

    if (*(int *)((char *)obj + 0xf4) != 0) return;

    if (*(int *)((char *)obj + 0xf8) == 0) {
        *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)r4_loc + 0x8);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)r4_loc + 0xc);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)r4_loc + 0x10);
        (*(void (***)(int, void *, int))gObjectTriggerInterface)[0x12]((int)*(char *)((char *)r4_loc + 0x2e), obj, -1);
        *(int *)((char *)obj + 0xf8) = 1;
        return;
    }

    if ((*(u16 *)((char *)r30 + 0x400) & 0x2) != 0) {
        lbl_803DDBA4 = lbl_803E4CC8;
        (*(void (***)(void *, void *, void *, int, void *, int, int, int, int))gBaddieControlInterface)[0xa](
            obj, r30, (char *)r30 + 0x35c, *(s16 *)((char *)r30 + 0x3f4),
            (char *)r30 + 0x405, 0, 0, 0, 1);
        *(u16 *)((char *)r30 + 0x400) = (u16)(*(u16 *)((char *)r30 + 0x400) & ~0x2);
    }

    if ((*(int (***)(void *, void *, int))gBaddieControlInterface)[0xc](obj, r30, 1) == 0) return;

    *(void **)((char *)r30 + 0x2d0) = Obj_GetPlayerObject();
    dimBossTonsil_newState_hitFightMain(obj, 0, r30, r30);

    if (gDIMbosstonsilLight == 0) return;

    fn_8001D9F4(gDIMbosstonsilLight, &b1, &b2, &b3, &b4);
    fn_8001D71C(gDIMbosstonsilLight, b1, b2, b3, 0xc0);

    if (gDIMbosstonsilLight->active == 0) return;
    if (gDIMbosstonsilLight->visible == 0) return;

    {
        s16 r30_local;
        int sum;
        sum = gDIMbosstonsilLight->glowIntensity + gDIMbosstonsilLight->glowIntensityStep;
        r30_local = (s16)sum;
        if (r30_local < 0) {
            r30_local = 0;
            gDIMbosstonsilLight->glowIntensityStep = 0;
        } else if (r30_local > 0xc) {
            int rnd = randomGetRange(-0xc, 0xc);
            r30_local = (s16)(r30_local + rnd);
            if (r30_local > 0xff) {
                r30_local = 0xff;
                gDIMbosstonsilLight->glowIntensityStep = 0;
            }
        }
        gDIMbosstonsilLight->glowIntensity = (u8)r30_local;
    }
}
#pragma scheduling reset
#pragma peephole reset
