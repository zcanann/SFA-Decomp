#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/objhits_types.h"

/*
 * Per-object extra state for an Andross hand
 * (androsshand_getExtraSize == 0x2C).
 */
typedef struct AndrossHandState {
    void *andross; /* main andross object */
    void *otherHand; /* sibling hand, deref'd for relative positioning */
    u8 pad08[0x14 - 0x08];
    f32 animSpeed;
    f32 unk18;
    f32 unk1C;
    s16 unk20;
    u8 unk22; /* setup[0x1B] */
    s8 handState;
    s8 prevState;
    u8 health; /* 0xF */
    u8 pad26;
    u8 unk27; /* 5 at init */
    u8 pad28;
    u8 unk29;
    u8 pad2A[2];
} AndrossHandState;

STATIC_ASSERT(sizeof(AndrossHandState) == 0x2C);


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

#pragma scheduling off
void androsshand_update(int obj)
{
    f32 fScale = lbl_803DC4F8;
    AndrossHandState *state = ((GameObject *)obj)->extra;
    u8 changed = 0;

    if (*(int *)&state->andross == 0) {
        *(int *)&state->andross = ObjList_FindObjectById(0x47b77);
    }
    if (*(int *)&state->otherHand == 0) {
        *(int *)&state->otherHand = getArwing();
    }
    if (state->unk27 != 0) {
        state->unk27 -= 1;
        return;
    }

    ((GameObject *)obj)->anim.alpha = 0xff;
    ((GameObject *)obj)->anim.rotZ = 0;
    ((GameObject *)obj)->anim.rotY = 0;
    ObjHits_SetHitVolumeSlot(obj, 5, 2, -1);
    ObjHits_EnableObject(obj);

    if (*(int *)&state->andross != 0) {
        f32 v1c;
        f32 angle;
        f32 sv;

        ((GameObject *)obj)->anim.rotX = *(s16 *)(*(int *)&state->andross + 0);
        if (state->unk22 != 0) {
            fScale = fScale * lbl_803E75B4;
        }
        v1c = state->unk1C;
        state->unk1C =
            v1c + ((-state->unk18 / (f32)lbl_803DC4FC - v1c) / (f32)lbl_803DC500);
        state->unk18 = state->unk18 + state->unk1C;

        angle = lbl_803E75B8 *
                (f32)(s16)(int)((f32)*(s16 *)(*(int *)&state->andross + 0) + fScale) / lbl_803E75BC;
        fScale = mathSinf(angle);
        sv = mathCosf(angle);
        ((GameObject *)obj)->anim.localPosX = lbl_803DC4F0 * fScale + *(f32 *)(*(int *)&state->andross + 0xc);
        ((GameObject *)obj)->anim.localPosY = *(f32 *)(*(int *)&state->andross + 0x10) + lbl_803DC4F4;
        ((GameObject *)obj)->anim.localPosZ =
            state->unk18 + (lbl_803DC4F0 * sv + *(f32 *)(*(int *)&state->andross + 0x14));
    }

    {
        u8 cur = *(u8 *)&state->handState;
        if ((s8)cur != state->prevState) {
            changed = 1;
        }
        *(u8 *)&state->prevState = cur;
    }

    switch (state->handState) {
    case 0:
        if (changed) {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E75AC, 0);
            *(f32 *)(*(int *)&((GameObject *)obj)->extra + 0x14) = lbl_8032C270[0];
        }
        break;
    case 2:
        if (changed) {
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E75AC, 0);
            *(f32 *)(*(int *)&((GameObject *)obj)->extra + 0x14) = lbl_8032C270[4];
        }
        if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E75B0) {
            *(u8 *)&state->handState = 3;
            *(u8 *)&state->prevState = 3;
        }
        break;
    case 1:
        if (changed) {
            ObjAnim_SetCurrentMove(obj, 5, lbl_803E75AC, 0);
            *(f32 *)(*(int *)&((GameObject *)obj)->extra + 0x14) = lbl_8032C270[5];
        }
        if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E75B0) {
            *(u8 *)&state->handState = 3;
        }
        break;
    case 4:
        if (changed) {
            state->unk29 = 0;
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E75AC, 0);
            *(f32 *)(*(int *)&((GameObject *)obj)->extra + 0x14) = lbl_8032C270[1];
        }
        if ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject != 0) {
            struct {
                f32 x, y, z;
            } v, w;
            v.x = state->unk22 ? lbl_803E75C0 : lbl_803E75C4;
            v.y = lbl_803E75AC;
            v.z = lbl_803E75AC;
            w = v;
            fn_8022D4AC(*(int *)&state->otherHand, (int)&w);
            doRumble(lbl_803E75C8);
        }
        if (((GameObject *)obj)->anim.currentMoveProgress < lbl_803E75D0) {
            state->animSpeed = lbl_803E75D8;
        } else {
            state->animSpeed = lbl_803E75DC;
        }
        if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E75E0 && state->unk29 == 0) {
            state->unk29 = 1;
            Sfx_PlayFromObject(obj, 0x471);
        }
        if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E75B0) {
            andross_setPartSignal(*(int *)&state->andross, 1);
            *(u8 *)&state->handState = 3;
        }
        androsshand_handleDamage(obj, (int)state);
        break;
    case 5:
        if (changed) {
            state->unk29 = 0;
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E75AC, 0);
            *(f32 *)(*(int *)&((GameObject *)obj)->extra + 0x14) = lbl_8032C270[2];
        }
        if (state->unk22 != 0 && ((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E75B0) {
            andross_setPartSignal(*(int *)&state->andross, 1);
            *(u8 *)&state->handState = 3;
        }
        if (((GameObject *)obj)->anim.currentMoveProgress < lbl_803E75E8) {
            state->animSpeed = lbl_803E75F0;
        } else {
            state->animSpeed = lbl_803E75DC;
        }
        if ((*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->lastHitObject != 0) {
            struct {
                f32 x, y, z;
            } v, w;
            v.x = lbl_803E75AC;
            v.y = lbl_803E75F4;
            v.z = lbl_803E75AC;
            w = v;
            fn_8022D4AC(*(int *)&state->otherHand, (int)&w);
            doRumble(lbl_803E75C8);
        }
        if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E75E0 && ((GameObject *)obj)->anim.currentMoveProgress < lbl_803E75F8 &&
            state->unk29 == 0) {
            state->unk29 = 1;
            Sfx_PlayFromObject(obj, 0x472);
        }
        if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E75F8 && state->unk29 != 0) {
            state->unk29 = 0;
            Sfx_PlayFromObject(obj, 0x473);
        }
        if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E75B0) {
            if (state->unk22 != 0) {
                andross_setPartSignal(*(int *)&state->andross, 1);
            }
            *(u8 *)&state->handState = 3;
        }
        androsshand_handleDamage(obj, (int)state);
        break;
    case 6:
        if (changed) {
            ObjAnim_SetCurrentMove(obj, 3, lbl_803E75AC, 0);
            *(f32 *)(*(int *)&((GameObject *)obj)->extra + 0x14) = lbl_8032C270[3];
            state->unk20 = -1;
        }
        state->unk20 -= framesThisStep;
        if (((GameObject *)obj)->anim.currentMoveProgress < lbl_803E75D0) {
            state->animSpeed = lbl_803E75F0;
        } else {
            Sfx_KeepAliveLoopedObjectSound(obj, 0x467);
            state->animSpeed = lbl_803E75F0;
            if (state->unk20 < 0) {
                androsshand_spawnShot(obj, (int)state, 0);
                state->unk20 = lbl_803DC504;
            }
        }
        if (((GameObject *)obj)->anim.currentMoveProgress >= lbl_803E75B0) {
            andross_setPartSignal(*(int *)&state->andross, 1);
            *(u8 *)&state->handState = 3;
        }
        androsshand_handleDamage(obj, (int)state);
        break;
    case 3:
        if (changed) {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E75AC, 0);
            *(f32 *)(*(int *)&((GameObject *)obj)->extra + 0x14) = lbl_8032C270[0];
        }
        break;
    case 9:
        andross_setPartSignal(*(int *)&state->andross, state->unk22 ? 4 : 2);
        break;
    }

    if (state->handState == 9) {
        ((GameObject *)obj)->anim.flags |= 0x4000;
    } else {
        ((GameObject *)obj)->anim.flags &= ~0x4000;
    }
    ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)(obj, state->animSpeed, timeDelta, 0);
}
#pragma scheduling reset

#pragma peephole on
#pragma scheduling on
void androsshand_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void androsshand_setState(int obj, int newState, u8 force)
{
    AndrossHandState *state;

    if ((void *)obj == NULL) {
        return;
    }
    state = ((GameObject *)obj)->extra;
    if (state->handState != 9 || force != 0) {
        state->handState = (s8)newState;
        if (force != 0) {
            if (force == 2) {
                state->health = 0x12;
            } else {
                state->health = 0xf;
            }
        }
    } else {
        if ((u8)newState != 0) {
            andross_setPartSignal(*(int *)&state->andross, 1);
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

#pragma peephole off
#pragma scheduling off
void androsshand_init(int obj, u8 *setup)
{
    AndrossHandState *state = ((GameObject *)obj)->extra;
    int animState;

    state->unk22 = setup[0x1b];
    state->prevState = -1;
    state->health = 0xf;
    state->unk27 = 5;
    *(u8 *)&state->handState = 3;
    *(u8 *)&state->prevState = 3;
    animState = *(int *)&((GameObject *)obj)->extra;
    ObjAnim_SetCurrentMove(obj, 4, lbl_803E75AC, 0);
    *(f32 *)(animState + 0x14) = lbl_8032C270[4];
    ((GameObject *)obj)->anim.currentMoveProgress = lbl_803E75B0;
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
