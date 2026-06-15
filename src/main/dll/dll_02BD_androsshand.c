#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

/*
 * Per-object extra state for an Andross hand
 * (androsshand_getExtraSize == 0x2C).
 */
typedef struct AndrossHandState
{
    int androssObj;
    int arwingObj;
    u8 pad08[0x14 - 0x08];
    f32 animSpeed;
    f32 zSpringOffset;
    f32 zSpringVelocity;
    s16 shotTimer;
    u8 sideFlag; /* setup[0x1B] */
    s8 handState;
    s8 prevState;
    u8 health;
    u8 hitCooldown;
    u8 startupDelay;
    u8 damageTextureState;
    u8 soundGate;
    u8 pad2A[2];
} AndrossHandState;

STATIC_ASSERT(sizeof(AndrossHandState) == 0x2C);


int androsshand_getExtraSize(void) { return 0x2c; }

int androsshand_getObjectTypeId(void) { return 0; }

void androsshand_free(void)
{
}

void androsshand_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E75B0);
}

void androsshand_update(int obj)
{
    f32 fScale = lbl_803DC4F8;
    AndrossHandState* state = ((GameObject*)obj)->extra;
    u8 changed = 0;

    if (state->androssObj == 0)
    {
        state->androssObj = ObjList_FindObjectById(0x47b77);
    }
    if (state->arwingObj == 0)
    {
        state->arwingObj = getArwing();
    }
    if (state->startupDelay != 0)
    {
        state->startupDelay -= 1;
        return;
    }

    ((GameObject*)obj)->anim.alpha = 0xff;
    ((GameObject*)obj)->anim.rotZ = 0;
    ((GameObject*)obj)->anim.rotY = 0;
    ObjHits_SetHitVolumeSlot(obj, 5, 2, -1);
    ObjHits_EnableObject(obj);

    if (state->androssObj != 0)
    {
        f32 v1c;
        f32 angle;
        f32 sv;

        ((GameObject*)obj)->anim.rotX = *(s16*)(state->androssObj + 0);
        if (state->sideFlag != 0)
        {
            fScale = fScale * lbl_803E75B4;
        }
        v1c = state->zSpringVelocity;
        state->zSpringVelocity =
            v1c + ((-state->zSpringOffset / (f32)lbl_803DC4FC - v1c) / (f32)lbl_803DC500);
        state->zSpringOffset = state->zSpringOffset + state->zSpringVelocity;

        angle = lbl_803E75B8 *
            (f32)(s16)(int)((f32) * (s16*)(state->androssObj + 0) + fScale) / lbl_803E75BC;
        fScale = mathSinf(angle);
        sv = mathCosf(angle);
        ((GameObject*)obj)->anim.localPosX = lbl_803DC4F0 * fScale + *(f32*)(state->androssObj + 0xc);
        ((GameObject*)obj)->anim.localPosY = *(f32*)(state->androssObj + 0x10) + lbl_803DC4F4;
        ((GameObject*)obj)->anim.localPosZ =
            state->zSpringOffset + (lbl_803DC4F0 * sv + *(f32*)(state->androssObj + 0x14));
    }

    {
        u8 cur = *(u8*)&state->handState;
        if ((s8)cur != state->prevState)
        {
            changed = 1;
        }
        *(u8*)&state->prevState = cur;
    }

    switch (state->handState)
    {
    case 0:
        if (changed)
        {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E75AC, 0);
            *(f32*)(*(int*)&((GameObject*)obj)->extra + 0x14) = lbl_8032C270[0];
        }
        break;
    case 2:
        if (changed)
        {
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E75AC, 0);
            *(f32*)(*(int*)&((GameObject*)obj)->extra + 0x14) = lbl_8032C270[4];
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75B0)
        {
            *(u8*)&state->handState = 3;
            *(u8*)&state->prevState = 3;
        }
        break;
    case 1:
        if (changed)
        {
            ObjAnim_SetCurrentMove(obj, 5, lbl_803E75AC, 0);
            *(f32*)(*(int*)&((GameObject*)obj)->extra + 0x14) = lbl_8032C270[5];
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75B0)
        {
            *(u8*)&state->handState = 3;
        }
        break;
    case 4:
        if (changed)
        {
            state->soundGate = 0;
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E75AC, 0);
            *(f32*)(*(int*)&((GameObject*)obj)->extra + 0x14) = lbl_8032C270[1];
        }
        {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            if (hitState->lastHitObject != 0)
            {
                struct
                {
                    f32 x, y, z;
                } v, w;
                v.x = state->sideFlag ? lbl_803E75C0 : lbl_803E75C4;
                v.y = lbl_803E75AC;
                v.z = lbl_803E75AC;
                w = v;
                arwarwing_setVelocity(state->arwingObj, (int)&w);
                doRumble(lbl_803E75C8);
            }
        }
        if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E75D0)
        {
            state->animSpeed = lbl_803E75D8;
        }
        else
        {
            state->animSpeed = lbl_803E75DC;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75E0 && state->soundGate == 0)
        {
            state->soundGate = 1;
            Sfx_PlayFromObject(obj, 0x471);
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75B0)
        {
            andross_setPartSignal(state->androssObj, 1);
            *(u8*)&state->handState = 3;
        }
        androsshand_handleDamage(obj, (int)state);
        break;
    case 5:
        if (changed)
        {
            state->soundGate = 0;
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E75AC, 0);
            *(f32*)(*(int*)&((GameObject*)obj)->extra + 0x14) = lbl_8032C270[2];
        }
        if (state->sideFlag != 0 && ((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75B0)
        {
            andross_setPartSignal(state->androssObj, 1);
            *(u8*)&state->handState = 3;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E75E8)
        {
            state->animSpeed = lbl_803E75F0;
        }
        else
        {
            state->animSpeed = lbl_803E75DC;
        }
        {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            if (hitState->lastHitObject != 0)
            {
                struct
                {
                    f32 x, y, z;
                } v, w;
                v.x = lbl_803E75AC;
                v.y = lbl_803E75F4;
                v.z = lbl_803E75AC;
                w = v;
                arwarwing_setVelocity(state->arwingObj, (int)&w);
                doRumble(lbl_803E75C8);
            }
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75E0 && ((GameObject*)obj)->anim.currentMoveProgress
            < lbl_803E75F8 &&
            state->soundGate == 0)
        {
            state->soundGate = 1;
            Sfx_PlayFromObject(obj, 0x472);
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75F8 && state->soundGate != 0)
        {
            state->soundGate = 0;
            Sfx_PlayFromObject(obj, 0x473);
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75B0)
        {
            if (state->sideFlag != 0)
            {
                andross_setPartSignal(state->androssObj, 1);
            }
            *(u8*)&state->handState = 3;
        }
        androsshand_handleDamage(obj, (int)state);
        break;
    case 6:
        if (changed)
        {
            ObjAnim_SetCurrentMove(obj, 3, lbl_803E75AC, 0);
            *(f32*)(*(int*)&((GameObject*)obj)->extra + 0x14) = lbl_8032C270[3];
            state->shotTimer = -1;
        }
        state->shotTimer -= framesThisStep;
        if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E75D0)
        {
            state->animSpeed = lbl_803E75F0;
        }
        else
        {
            Sfx_KeepAliveLoopedObjectSound(obj, 0x467);
            state->animSpeed = lbl_803E75F0;
            if (state->shotTimer < 0)
            {
                androsshand_spawnShot(obj, (int)state, 0);
                state->shotTimer = lbl_803DC504;
            }
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75B0)
        {
            andross_setPartSignal(state->androssObj, 1);
            *(u8*)&state->handState = 3;
        }
        androsshand_handleDamage(obj, (int)state);
        break;
    case 3:
        if (changed)
        {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E75AC, 0);
            *(f32*)(*(int*)&((GameObject*)obj)->extra + 0x14) = lbl_8032C270[0];
        }
        break;
    case 9:
        andross_setPartSignal(state->androssObj, state->sideFlag ? 4 : 2);
        break;
    }

    if (state->handState == 9)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    }
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, state->animSpeed, timeDelta, 0);
}

void androsshand_hitDetect(void)
{
}

void androsshand_setState(int obj, int newState, u8 force)
{
    AndrossHandState* state;

    if ((void*)obj == NULL)
    {
        return;
    }
    state = ((GameObject*)obj)->extra;
    if (state->handState != 9 || force != 0)
    {
        state->handState = (s8)newState;
        if (force != 0)
        {
            if (force == 2)
            {
                state->health = 0x12;
            }
            else
            {
                state->health = 0xf;
            }
        }
    }
    else
    {
        if ((u8)newState != 0)
        {
            andross_setPartSignal(state->androssObj, 1);
        }
    }
}

void androsshand_handleDamage(int obj, int hand)
{
    AndrossHandState* state = (AndrossHandState*)hand;
    uint hitVol;
    int sphereIdx;
    int hitObj;
    f32 x;
    f32 y;
    f32 z;
    int t;

    t = state->hitCooldown - framesThisStep;
    if (t < 0)
    {
        t = 0;
    }
    state->hitCooldown = (u8)t;
    if (ObjHits_GetPriorityHit(obj, &hitObj, &sphereIdx, &hitVol) != 0 &&
        state->hitCooldown == 0)
    {
        switch (sphereIdx)
        {
        case 0:
            state->health -= 1;
            state->hitCooldown = 6;
            state->zSpringVelocity = (f32)lbl_803DC508;
            Sfx_PlayFromObject(obj, 0x484);
            if (state->health == 0)
            {
                state->handState = 9;
                andross_setPartSignal(state->androssObj, 1);
                Sfx_PlayFromObject(obj, 0x485);
                ObjPath_GetPointWorldPosition(obj, 0, &x, &y, &z, 0);
                DIMexplosionFn_8009a96c(obj, x, y, z, lbl_803E75A8, 1, 1, 1, 1, 0, 1, 0);
            }
            break;
        }
    }
    if (state->health != 0)
    {
        if (state->hitCooldown != 0)
        {
            state->damageTextureState = 1;
        }
        else
        {
            state->damageTextureState = 0;
        }
    }
    else
    {
        state->damageTextureState = 2;
    }
    {
        ObjTextureRuntimeSlot* texture = objFindTexture((void*)obj, 0, 0);
        texture->textureId = state->damageTextureState << 8;
    }
}

void androsshand_init(int obj, u8* setup)
{
    AndrossHandState* state = ((GameObject*)obj)->extra;

    state->sideFlag = setup[0x1b];
    state->prevState = -1;
    state->health = 0xf;
    state->startupDelay = 5;
    *(u8*)&state->handState = 3;
    *(u8*)&state->prevState = 3;
    state = ((GameObject*)obj)->extra;
    ObjAnim_SetCurrentMove(obj, 4, lbl_803E75AC, 0);
    state->animSpeed = lbl_8032C270[4];
    ((GameObject*)obj)->anim.currentMoveProgress = lbl_803E75B0;
    ObjHits_SetTargetMask(obj, 4);
}

void androsshand_spawnShot(int obj, int hand, int p3)
{
    AndrossHandState* state = (AndrossHandState*)hand;
    f32 pt[3];
    f32 dx, dz, dist;
    int yaw;
    int setup;

    if (Obj_IsLoadingLocked())
    {
        ObjPath_GetPointWorldPosition(obj, 0, &pt[0], &pt[1], &pt[2], 0);
        dx = pt[0] - *(f32*)(state->arwingObj + 0xc);
        dz = pt[2] - *(f32*)(state->arwingObj + 0x14);
        dist = sqrtf(dx * dx + dz * dz);
        yaw = (u16)getAngle(dx, dz) + 0x8000;
        lbl_803DDDD0 = (u16)getAngle(pt[1] - *(f32*)(state->arwingObj + 0x10), dist) >> 8;
        setup = Obj_AllocObjectSetup(0x20, 0x7e4);
        ((ObjPlacement*)setup)->posX = pt[0];
        ((ObjPlacement*)setup)->posY = pt[1];
        ((ObjPlacement*)setup)->posZ = pt[2];
        *(u8*)(setup + 0x1a) = (*(s16*)obj + yaw) >> 8;
        *(u8*)(setup + 0x19) = lbl_803DDDD0;
        *(u8*)(setup + 0x18) = 0;
        *(u8*)(setup + 4) = 1;
        *(u8*)(setup + 5) = 1;
        obj = ((int (*)(int, int))loadObjectAtObject)(obj, setup);
        if ((void*)obj != NULL)
        {
            arwprojectile_setLifetime(obj, lbl_803DC510);
            arwprojectile_placeForward(obj, (f32)lbl_803DC50C);
        }
    }
}
