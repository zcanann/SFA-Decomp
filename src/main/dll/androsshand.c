#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int androsshand_getExtraSize(void) { return 0x2c; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int androsshand_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void androsshand_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void androsshand_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E75B0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void androsshand_update(int obj)
{
    f32 fScale = lbl_803DC4F8;
    int state = *(int *)(obj + 0xb8);
    u8 changed = 0;

    if (*(int *)(state + 0) == 0) {
        *(int *)(state + 0) = ObjList_FindObjectById(0x47b77);
    }
    if (*(int *)(state + 4) == 0) {
        *(int *)(state + 4) = getArwing();
    }
    if (*(u8 *)(state + 0x27) != 0) {
        *(u8 *)(state + 0x27) -= 1;
        return;
    }

    *(u8 *)(obj + 0x36) = 0xff;
    *(s16 *)(obj + 4) = 0;
    *(s16 *)(obj + 2) = 0;
    ObjHits_SetHitVolumeSlot(obj, 5, 2, -1);
    ObjHits_EnableObject(obj);

    if (*(int *)(state + 0) != 0) {
        f32 v1c;
        f32 angle;
        f32 sv;

        *(s16 *)(obj + 0) = *(s16 *)(*(int *)(state + 0) + 0);
        if (*(u8 *)(state + 0x22) != 0) {
            fScale = fScale * lbl_803E75B4;
        }
        v1c = *(f32 *)(state + 0x1c);
        *(f32 *)(state + 0x1c) =
            v1c + ((-*(f32 *)(state + 0x18) / (f32)lbl_803DC4FC - v1c) / (f32)lbl_803DC500);
        *(f32 *)(state + 0x18) = *(f32 *)(state + 0x18) + *(f32 *)(state + 0x1c);

        angle = lbl_803E75B8 *
                (f32)(s16)(int)((f32)*(s16 *)(*(int *)(state + 0) + 0) + fScale) / lbl_803E75BC;
        fScale = fn_80293E80(angle);
        sv = sin(angle);
        *(f32 *)(obj + 0xc) = lbl_803DC4F0 * fScale + *(f32 *)(*(int *)(state + 0) + 0xc);
        *(f32 *)(obj + 0x10) = *(f32 *)(*(int *)(state + 0) + 0x10) + lbl_803DC4F4;
        *(f32 *)(obj + 0x14) =
            *(f32 *)(state + 0x18) + (lbl_803DC4F0 * sv + *(f32 *)(*(int *)(state + 0) + 0x14));
    }

    {
        u8 cur = *(u8 *)(state + 0x23);
        if ((s8)cur != *(s8 *)(state + 0x24)) {
            changed = 1;
        }
        *(u8 *)(state + 0x24) = cur;
    }

    switch (*(s8 *)(state + 0x23)) {
    case 0:
        if (changed) {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E75AC, 0);
            *(f32 *)(*(int *)(obj + 0xb8) + 0x14) = lbl_8032C270[0];
        }
        break;
    case 2:
        if (changed) {
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E75AC, 0);
            *(f32 *)(*(int *)(obj + 0xb8) + 0x14) = lbl_8032C270[4];
        }
        if (*(f32 *)(obj + 0x98) >= lbl_803E75B0) {
            *(u8 *)(state + 0x23) = 3;
            *(u8 *)(state + 0x24) = 3;
        }
        break;
    case 1:
        if (changed) {
            ObjAnim_SetCurrentMove(obj, 5, lbl_803E75AC, 0);
            *(f32 *)(*(int *)(obj + 0xb8) + 0x14) = lbl_8032C270[5];
        }
        if (*(f32 *)(obj + 0x98) >= lbl_803E75B0) {
            *(u8 *)(state + 0x23) = 3;
        }
        break;
    case 4:
        if (changed) {
            *(u8 *)(state + 0x29) = 0;
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E75AC, 0);
            *(f32 *)(*(int *)(obj + 0xb8) + 0x14) = lbl_8032C270[1];
        }
        if (*(int *)(*(int *)(obj + 0x54) + 0x50) != 0) {
            struct {
                f32 x, y, z;
            } v, w;
            v.x = *(u8 *)(state + 0x22) ? lbl_803E75C0 : lbl_803E75C4;
            v.y = lbl_803E75AC;
            v.z = lbl_803E75AC;
            w = v;
            fn_8022D4AC(*(int *)(state + 4), (int)&w);
            doRumble(lbl_803E75C8);
        }
        if (*(f32 *)(obj + 0x98) < lbl_803E75D0) {
            *(f32 *)(state + 0x14) = lbl_803E75D8;
        } else {
            *(f32 *)(state + 0x14) = lbl_803E75DC;
        }
        if (*(f32 *)(obj + 0x98) >= lbl_803E75E0 && *(u8 *)(state + 0x29) == 0) {
            *(u8 *)(state + 0x29) = 1;
            Sfx_PlayFromObject(obj, 0x471);
        }
        if (*(f32 *)(obj + 0x98) >= lbl_803E75B0) {
            andross_setPartSignal(*(int *)(state + 0), 1);
            *(u8 *)(state + 0x23) = 3;
        }
        androsshand_handleDamage(obj, state);
        break;
    case 5:
        if (changed) {
            *(u8 *)(state + 0x29) = 0;
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E75AC, 0);
            *(f32 *)(*(int *)(obj + 0xb8) + 0x14) = lbl_8032C270[2];
        }
        if (*(u8 *)(state + 0x22) != 0 && *(f32 *)(obj + 0x98) >= lbl_803E75B0) {
            andross_setPartSignal(*(int *)(state + 0), 1);
            *(u8 *)(state + 0x23) = 3;
        }
        if (*(f32 *)(obj + 0x98) < lbl_803E75E8) {
            *(f32 *)(state + 0x14) = lbl_803E75F0;
        } else {
            *(f32 *)(state + 0x14) = lbl_803E75DC;
        }
        if (*(int *)(*(int *)(obj + 0x54) + 0x50) != 0) {
            struct {
                f32 x, y, z;
            } v, w;
            v.x = lbl_803E75AC;
            v.y = lbl_803E75F4;
            v.z = lbl_803E75AC;
            w = v;
            fn_8022D4AC(*(int *)(state + 4), (int)&w);
            doRumble(lbl_803E75C8);
        }
        if (*(f32 *)(obj + 0x98) >= lbl_803E75E0 && *(f32 *)(obj + 0x98) < lbl_803E75F8 &&
            *(u8 *)(state + 0x29) == 0) {
            *(u8 *)(state + 0x29) = 1;
            Sfx_PlayFromObject(obj, 0x472);
        }
        if (*(f32 *)(obj + 0x98) >= lbl_803E75F8 && *(u8 *)(state + 0x29) != 0) {
            *(u8 *)(state + 0x29) = 0;
            Sfx_PlayFromObject(obj, 0x473);
        }
        if (*(f32 *)(obj + 0x98) >= lbl_803E75B0) {
            if (*(u8 *)(state + 0x22) != 0) {
                andross_setPartSignal(*(int *)(state + 0), 1);
            }
            *(u8 *)(state + 0x23) = 3;
        }
        androsshand_handleDamage(obj, state);
        break;
    case 6:
        if (changed) {
            ObjAnim_SetCurrentMove(obj, 3, lbl_803E75AC, 0);
            *(f32 *)(*(int *)(obj + 0xb8) + 0x14) = lbl_8032C270[3];
            *(s16 *)(state + 0x20) = -1;
        }
        *(s16 *)(state + 0x20) -= framesThisStep;
        if (*(f32 *)(obj + 0x98) < lbl_803E75D0) {
            *(f32 *)(state + 0x14) = lbl_803E75F0;
        } else {
            Sfx_KeepAliveLoopedObjectSound(obj, 0x467);
            *(f32 *)(state + 0x14) = lbl_803E75F0;
            if (*(s16 *)(state + 0x20) < 0) {
                androsshand_spawnShot(obj, state, 0);
                *(s16 *)(state + 0x20) = lbl_803DC504;
            }
        }
        if (*(f32 *)(obj + 0x98) >= lbl_803E75B0) {
            andross_setPartSignal(*(int *)(state + 0), 1);
            *(u8 *)(state + 0x23) = 3;
        }
        androsshand_handleDamage(obj, state);
        break;
    case 3:
        if (changed) {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E75AC, 0);
            *(f32 *)(*(int *)(obj + 0xb8) + 0x14) = lbl_8032C270[0];
        }
        break;
    case 9:
        andross_setPartSignal(*(int *)(state + 0), *(u8 *)(state + 0x22) ? 4 : 2);
        break;
    }

    if (*(s8 *)(state + 0x23) == 9) {
        *(s16 *)(obj + 6) |= 0x4000;
    } else {
        *(s16 *)(obj + 6) &= ~0x4000;
    }
    ObjAnim_AdvanceCurrentMove(*(f32 *)(state + 0x14), timeDelta, obj, 0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void androsshand_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void androsshand_setState(int obj, int newState, u8 force)
{
    int state;

    if ((void *)obj == NULL) {
        return;
    }
    state = *(int *)(obj + 0xb8);
    if (*(s8 *)(state + 0x23) != 9 || force != 0) {
        *(s8 *)(state + 0x23) = (s8)newState;
        if (force != 0) {
            if (force == 2) {
                *(u8 *)(state + 0x25) = 0x12;
            } else {
                *(u8 *)(state + 0x25) = 0xf;
            }
        }
    } else {
        if ((u8)newState != 0) {
            andross_setPartSignal(*(int *)state, 1);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void androsshand_handleDamage(int obj, int hand)
{
    int hitVol;
    int sphereIdx;
    int hitObj;
    f32 x;
    f32 y;
    f32 z;
    int t;

    t = *(u8 *)(hand + 0x26) - framesThisStep;
    if (t < 0) {
        t = 0;
    }
    *(u8 *)(hand + 0x26) = (u8)t;
    if (ObjHits_GetPriorityHit(obj, &hitObj, &sphereIdx, &hitVol) != 0 &&
        *(u8 *)(hand + 0x26) == 0 && sphereIdx == 0) {
        *(u8 *)(hand + 0x25) -= 1;
        *(u8 *)(hand + 0x26) = 6;
        *(f32 *)(hand + 0x1c) = (f32)lbl_803DC508;
        Sfx_PlayFromObject(obj, 0x484);
        if (*(u8 *)(hand + 0x25) == 0) {
            *(s8 *)(hand + 0x23) = 9;
            andross_setPartSignal(*(int *)hand, 1);
            Sfx_PlayFromObject(obj, 0x485);
            ObjPath_GetPointWorldPosition(obj, 0, &x, &y, &z, 0);
            DIMexplosionFn_8009a96c(obj, x, y, z, lbl_803E75A8, 1, 1, 1, 1, 0, 1, 0);
        }
    }
    if (*(u8 *)(hand + 0x25) != 0) {
        if (*(u8 *)(hand + 0x26) != 0) {
            *(u8 *)(hand + 0x28) = 1;
        } else {
            *(u8 *)(hand + 0x28) = 0;
        }
    } else {
        *(u8 *)(hand + 0x28) = 2;
    }
    {
        int *texture = objFindTexture(obj, 0, 0);
        *texture = *(u8 *)(hand + 0x28) << 8;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void androsshand_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);
    int animState;

    *(u8 *)(state + 0x22) = setup[0x1b];
    *(s8 *)(state + 0x24) = -1;
    *(u8 *)(state + 0x25) = 0xf;
    *(u8 *)(state + 0x27) = 5;
    *(u8 *)(state + 0x23) = 3;
    *(u8 *)(state + 0x24) = 3;
    animState = *(int *)(obj + 0xb8);
    ObjAnim_SetCurrentMove(obj, 4, lbl_803E75AC, 0);
    *(f32 *)(animState + 0x14) = lbl_8032C270[4];
    *(f32 *)(obj + 0x98) = lbl_803E75B0;
    ObjHits_SetTargetMask(obj, 4);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void androsshand_spawnShot(int obj, int hand, int p3)
{
    f32 pt[3];
    f32 dx, dz, dist;
    int yaw;
    int setup;

    if (Obj_IsLoadingLocked()) {
        ObjPath_GetPointWorldPosition(obj, 0, &pt[0], &pt[1], &pt[2], 0);
        dx = pt[0] - *(f32 *)(*(int *)(hand + 4) + 0xc);
        dz = pt[2] - *(f32 *)(*(int *)(hand + 4) + 0x14);
        dist = sqrtf(dx * dx + dz * dz);
        yaw = (u16)getAngle(dx, dz) + 0x8000;
        lbl_803DDDD0 = (u16)getAngle(pt[1] - *(f32 *)(*(int *)(hand + 4) + 0x10), dist) >> 8;
        setup = Obj_AllocObjectSetup(0x20, 0x7e4);
        *(f32 *)(setup + 8) = pt[0];
        *(f32 *)(setup + 0xc) = pt[1];
        *(f32 *)(setup + 0x10) = pt[2];
        *(u8 *)(setup + 0x1a) = (*(s16 *)obj + yaw) >> 8;
        *(u8 *)(setup + 0x19) = lbl_803DDDD0;
        *(u8 *)(setup + 0x18) = 0;
        *(u8 *)(setup + 4) = 1;
        *(u8 *)(setup + 5) = 1;
        obj = ((int (*)(int, int))loadObjectAtObject)(obj, setup);
        if ((void *)obj != NULL) {
            arwprojectile_setLifetime(obj, lbl_803DC510);
            arwprojectile_placeForward(obj, (f32)lbl_803DC50C);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
