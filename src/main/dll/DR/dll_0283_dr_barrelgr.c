#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int drbarrelgr_getExtraSize(void) { return 0x12c; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int drbarrelgr_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void drbarrelgr_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    void *heldObj = *(void **)(state + 8);

    if (heldObj != NULL) {
        gunpowderbarrel_clearHeldState((int)heldObj);
        ((DrBarrelGrFlags *)(state + 0x12a))->bit80 = 0;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drbarrelgr_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drbarrelgr_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void drbarrelgr_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void drbarrelgr_init(int obj, int setup)
{
    int one;
    int state;

    one = 1;
    state = *(int *)(obj + 0xb8);
    if (*(u8 *)(setup + 0x19) == 0) {
        *(u8 *)(setup + 0x19) = 0xa;
    }
    if (*(s16 *)(setup + 0x1a) <= 0) {
        *(s16 *)(setup + 0x1a) = 0x64;
    }
    *(int *)(state + 0) = 5;
    *(int *)(state + 8) = 0;
    ((DrBarrelGrFlags *)(state + 0x12a))->bit80 = 0;
    *(s16 *)(state + 0x128) = *(u8 *)(setup + 0x19);
    *(f32 *)(state + 0x10) = lbl_803E6CA4;
    *(int *)(state + 4) = -3;
    ((DrBarrelGrFlags *)(state + 0x12a))->bit40 = 0;
    storeZeroToFloatParam((void *)(state + 0xc));
    s16toFloat((void *)(state + 0xc), *(s16 *)(setup + 0x1a));
    *(s16 *)obj = (s16)((s8)*(s8 *)(setup + 0x18) << 8);
    (*(void (**)(int, int, f32, int *, int))(*gRomCurveInterface + 0x8c))(
        state + 0x20, obj, lbl_803E6CD0, &one, 0);
    *(f32 *)(obj + 0xc) = *(f32 *)(state + 0x88);
    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0x90);
    *(f32 *)(obj + 0x10) = *(f32 *)(state + 0x8c);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void drbarrelgr_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    int newMode = -1;
    DrBarrelGrFlags *flags = (DrBarrelGrFlags *)(state + 0x12a);
    int nearest;
    int match;
    int gbId;
    f32 vec[3];
    f32 tmp[3];

    if (*(void **)(state + 8) != 0) {
        nearest = ObjGroup_FindNearestObject(25, obj, 0);
        match = 0;
        if ((u32)nearest != 0 && *(u32 *)(state + 8) == (u32)nearest) {
            match = 1;
        }
        if (match == 0 ||
            (flags->bit80 != 0 && gunpowderbarrel_isHeld(*(int *)(state + 8)) == 0)) {
            *(int *)(state + 8) = 0;
            flags->bit80 = 0;
        }
    }

    gbId = *(s16 *)(setup + 0x20);
    if (gbId != -1 && (u32)GameBit_Get(gbId) == 0) {
        flags->bit40 = 0;
        return;
    }
    flags->bit40 = 1;
    Sfx_KeepAliveLoopedObjectSound(obj, 958);

    switch (*(int *)(state + 0)) {
    case 0:
        if (*(void **)(state + 8) == 0) {
            nearest = ObjGroup_FindNearestObject(25, obj, 0);
            if ((u32)nearest != 0 &&
                Vec_xzDistance(obj + 24, nearest + 24) < lbl_803E6CB0 &&
                *(f32 *)(nearest + 16) < *(f32 *)(obj + 16)) {
                vec[0] = *(f32 *)(nearest + 12);
                vec[1] = lbl_803E6CB4 + *(f32 *)(nearest + 16);
                vec[2] = *(f32 *)(nearest + 20);
                if (voxmaps_traceWorldLine((void *)(obj + 12), vec) != 0 &&
                    gunpowderbarrel_canBeGrabbed(nearest) != 0) {
                    Sfx_PlayFromObject(obj, 959);
                    newMode = 4;
                    *(int *)(state + 8) = nearest;
                }
                break;
            }
        }
        if (timerCountDown((void *)(state + 12)) != 0) {
            newMode = 5;
        }
        break;
    case 4:
        if (*(void **)(state + 8) == 0 ||
            gunpowderbarrel_canBeGrabbed(*(int *)(state + 8)) == 0) {
            *(int *)(state + 0) = 0;
            *(int *)(state + 8) = 0;
            flags->bit80 = 0;
            break;
        }
        if (Vec_xzDistance(obj + 24, *(int *)(state + 8) + 24) > lbl_803E6CB0) {
            newMode = *(int *)(state + 4);
            flags->bit80 = 0;
            *(int *)(state + 8) = 0;
            break;
        }
        PSVECSubtract((void *)(state + 0x14), (void *)(*(int *)(state + 8) + 12), tmp);
        if (tmp[0] != lbl_803E6CA4 || tmp[1] != lbl_803E6CA4 || tmp[2] != lbl_803E6CA4) {
            PSVECNormalize(tmp, tmp);
        }
        PSVECScale(tmp, tmp, lbl_803DC3B0);
        gunpowderbarrel_setScale(*(int *)(state + 8), tmp);
        if (PSVECDistance((void *)(state + 0x14), (void *)(*(int *)(state + 8) + 12)) < lbl_803E6CA0 ||
            *(f32 *)(*(int *)(state + 8) + 16) > *(f32 *)(state + 24)) {
            Sfx_PlayFromObject(obj, 960);
            gunpowderbarrel_setHeldState(*(int *)(state + 8));
            newMode = *(int *)(state + 4);
            flags->bit80 = 1;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E6CA4, 0);
        }
        break;
    case 5: {
        int r = Obj_UpdateRomCurveFollowVelocity(obj, state + 0x20,
                            lbl_803E6CB8 * (f32)*(s16 *)(state + 0x128) * timeDelta,
                            lbl_803E6CBC, lbl_803E6CB4, 1);
        objMove(obj, *(f32 *)(obj + 36), *(f32 *)(obj + 40), *(f32 *)(obj + 44));
        if (r != 0) {
            newMode = r - 1;
            storeZeroToFloatParam((void *)(state + 12));
            s16toFloat((void *)(state + 12), *(s16 *)(setup + 0x1a));
            *(f32 *)(obj + 36) = lbl_803E6CA4;
            *(f32 *)(obj + 40) = lbl_803E6CA4;
            *(f32 *)(obj + 44) = lbl_803E6CA4;
        }
        break;
    }
    case 2:
        if (*(s16 *)(state + 0x128) == *(u8 *)(setup + 0x19)) {
            *(s16 *)(state + 0x128) =
                (int)((f32)*(s16 *)(state + 0x128) * lbl_803E6CA8);
        } else {
            *(s16 *)(state + 0x128) = *(u8 *)(setup + 0x19);
        }
        storeZeroToFloatParam((void *)(state + 12));
        newMode = 5;
        break;
    case 1:
        if (*(void **)(state + 8) != 0) {
            newMode = 3;
        } else if (timerCountDown((void *)(state + 12)) != 0) {
            newMode = 5;
        }
        break;
    case 3:
        if (*(void **)(state + 8) != 0) {
            gunpowderbarrel_clearHeldState(*(int *)(state + 8));
            flags->bit80 = 0;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E6CA4, 0);
        }
        *(int *)(state + 8) = 0;
        newMode = *(int *)(state + 4);
        break;
    }

    ObjAnim_AdvanceCurrentMove(lbl_803E6CC0, timeDelta, obj, 0);
    if (newMode != -1 && newMode != *(int *)(state + 0)) {
        *(int *)(state + 4) = *(int *)(state + 0);
        *(int *)(state + 0) = newMode;
    }
    if ((*(u16 *)(obj + 0xb0) & 0x800) == 0 && *(void **)(state + 8) != 0) {
        *(f32 *)(state + 0x14) = *(f32 *)(obj + 12);
        *(f32 *)(state + 0x18) = *(f32 *)(obj + 16) + lbl_803DC3B4;
        *(f32 *)(state + 0x1c) = *(f32 *)(obj + 20);
        *(f32 *)(*(int *)(state + 8) + 12) = *(f32 *)(state + 0x14);
        *(f32 *)(*(int *)(state + 8) + 16) = *(f32 *)(state + 0x18);
        *(f32 *)(*(int *)(state + 8) + 20) = *(f32 *)(state + 0x1c);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void drbarrelgr_render(int obj, int p2, int p3, int p4, int p5)
{
    int state = *(int *)(obj + 0xb8);
    int i;
    int objRef;
    int nearest;
    int match;
    f32 dval;
    f32 vec[3];
    DrBarrelGrRenderParams params;

    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6CA0);
    ObjPath_GetPointWorldPosition(obj, 0, (f32 *)(state + 0x14), (f32 *)(state + 0x18),
                                  (f32 *)(state + 0x1c), 0);
    params.a = 0;
    params.c = 0;
    params.b = 0x4000;
    dval = lbl_803E6CA4;
    for (i = 0; i < 4; i++) {
        ObjPath_GetPointWorldPosition(obj, i + 1, &vec[0], &vec[1], &vec[2], 0);
        PSVECSubtract(&vec[0], (void *)(obj + 0xc), &vec[0]);
        params.d = dval;
        fn_8009837C(obj, lbl_803E6CA8, 3, 0, 0, lbl_803E6CAC, (int)&params);
    }
    objRef = *(int *)(state + 8);
    if (objRef != 0) {
        match = 0;
        nearest = ObjGroup_FindNearestObject(0x19, obj, 0);
        if (nearest != 0 && nearest == objRef) {
            match = 1;
        }
        if (match && *(int *)state != 4) {
            *(f32 *)(*(int *)(state + 8) + 0xc) = *(f32 *)(state + 0x14);
            *(f32 *)(*(int *)(state + 8) + 0x10) = *(f32 *)(state + 0x18);
            *(f32 *)(*(int *)(state + 8) + 0x14) = *(f32 *)(state + 0x1c);
            objRenderFn_8003b8f4(*(int *)(state + 8), p2, p3, p4, p5, lbl_803E6CA0);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
