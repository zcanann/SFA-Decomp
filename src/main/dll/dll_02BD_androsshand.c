/*
 * androsshand (DLL 0x2BD) - one of Andross's two hands in the Arwing
 * boss fight. Tracks the Andross body object (id 0x47b77) and the
 * player's Arwing, mirrors the body's facing, and applies a damped
 * spring to its Z position so the hand bobs relative to the body.
 *
 * handState drives an animation/attack state machine (set externally
 * via androsshand_setState): 0/3 idle, 1/2 enter/exit, 4 swipe, 5 grab,
 * 6 shoot (spawns projectiles type 0x7e4 on a timer), 9 dead/hidden.
 * sideFlag selects the left/right hand (mirrors swipe velocity and the
 * part signal). Damage is taken on hit sphere 0 with a cooldown; at 0
 * health the hand explodes (DIMexplosionFn) and goes to state 9. The
 * damage texture index is written into the model's texture slot.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_trigger_ids.h"

/* Andross body object id, located once and cached in androssObj. */
#define ANDROSS_OBJ_ID 0x47b77

enum AndrossHandHealth
{
    ANDROSSHAND_HEALTH_NORMAL = 0xf,
    ANDROSSHAND_HEALTH_PHASE2 = 0x12
};

enum AndrossHandStateId
{
    ANDROSSHAND_STATE_IDLE = 0,
    ANDROSSHAND_STATE_ENTER = 1,
    ANDROSSHAND_STATE_EXIT = 2,
    ANDROSSHAND_STATE_IDLE2 = 3,
    ANDROSSHAND_STATE_SWIPE = 4,
    ANDROSSHAND_STATE_GRAB = 5,
    ANDROSSHAND_STATE_SHOOT = 6,
    ANDROSSHAND_STATE_DEAD = 9
};

/*
 * Per-object extra state for an Andross hand
 * (androsshand_getExtraSize == 0x2C).
 */
typedef struct AndrossHandState
{
    int androssObj;          /* 0x00: cached Andross body GameObject */
    int arwingObj;           /* 0x04: cached player Arwing GameObject */
    u8 pad08[0x14 - 0x08];   /* 0x08-0x13: unknown */
    f32 animSpeed;           /* 0x14 */
    f32 zSpringOffset;       /* 0x18 */
    f32 zSpringVelocity;     /* 0x1C */
    s16 shotTimer;           /* 0x20 */
    u8 sideFlag;             /* 0x22: setup[0x1B], left/right hand select */
    s8 handState;            /* 0x23: read signed, written via *(u8*)& */
    s8 prevState;            /* 0x24: read signed, written via *(u8*)& */
    u8 health;               /* 0x25 */
    u8 hitCooldown;          /* 0x26 */
    u8 startupDelay;         /* 0x27 */
    u8 damageTextureState;   /* 0x28: 0 clean, 1 hit-flash, 2 destroyed */
    u8 soundGate;            /* 0x29: one-shot gate for per-move sfx */
    u8 pad2A[2];
} AndrossHandState;

/* Spawn-setup buffer for an Andross-hand shot: ObjPlacement head (pos/color)
 * plus the class-specific yaw/pitch/flag bytes the parent seeds at +0x18. */
typedef struct AndrossHandShotSetup
{
    ObjPlacement head; /* 0x00: pos/color/mapId */
    u8 flag18;         /* 0x18 */
    u8 pitch;          /* 0x19 */
    u8 yaw;            /* 0x1a */
} AndrossHandShotSetup;

STATIC_ASSERT(offsetof(AndrossHandState, animSpeed) == 0x14);
STATIC_ASSERT(offsetof(AndrossHandState, shotTimer) == 0x20);
STATIC_ASSERT(offsetof(AndrossHandState, handState) == 0x23);
STATIC_ASSERT(offsetof(AndrossHandState, soundGate) == 0x29);
STATIC_ASSERT(sizeof(AndrossHandState) == 0x2C);

int androsshand_getExtraSize(void) { return sizeof(AndrossHandState); }

int androsshand_getObjectTypeId(void) { return 0; }

void androsshand_free(void)
{
}

void androsshand_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E75B0);
}

#pragma opt_common_subs off
void androsshand_update(int obj)
{
    f32 fScale = lbl_803DC4F8;
    AndrossHandState* state = ((GameObject*)obj)->extra;
    u8 changed = 0;
    SunVec3 va;
    SunVec3 vb;

    if (state->androssObj == 0u)
    {
        state->androssObj = ObjList_FindObjectById(ANDROSS_OBJ_ID);
    }
    if (state->arwingObj == 0u)
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

    if (state->androssObj != 0u)
    {
        f32 prevVel;
        f32 angle;
        f32 cosAngle;

        ((GameObject*)obj)->anim.rotX = ((GameObject*)state->androssObj)->anim.rotX;
        if (state->sideFlag != 0)
        {
            fScale = fScale * lbl_803E75B4;
        }
        prevVel = state->zSpringVelocity;
        state->zSpringVelocity =
            prevVel + ((-state->zSpringOffset / lbl_803DC4FC - prevVel) / lbl_803DC500);
        state->zSpringOffset = state->zSpringOffset + state->zSpringVelocity;

        angle = gAndrossHandPi *
            (f32)(s16)(int)((f32)((GameObject*)state->androssObj)->anim.rotX + fScale) / gAndrossHandHalfAngleScale;
        fScale = mathSinf(angle);
        cosAngle = mathCosf(angle);
        ((GameObject*)obj)->anim.localPosX =
            lbl_803DC4F0 * fScale + ((GameObject*)state->androssObj)->anim.localPosX;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)state->androssObj)->anim.localPosY + lbl_803DC4F4;
        ((GameObject*)obj)->anim.localPosZ =
            state->zSpringOffset + (lbl_803DC4F0 * cosAngle + ((GameObject*)state->androssObj)->anim.localPosZ);
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
    case ANDROSSHAND_STATE_IDLE:
        if (changed)
        {
            GameObject* h = (GameObject*)((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E75AC, 0);
            h->anim.localPosZ = gAndrossHandMoveAnimSpeeds[0];
        }
        break;
    case ANDROSSHAND_STATE_EXIT:
        if (changed)
        {
            GameObject* h = (GameObject*)((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 4, lbl_803E75AC, 0);
            h->anim.localPosZ = gAndrossHandMoveAnimSpeeds[4];
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75B0)
        {
            *(u8*)&state->handState = ANDROSSHAND_STATE_IDLE2;
            *(u8*)&state->prevState = ANDROSSHAND_STATE_IDLE2;
        }
        break;
    case ANDROSSHAND_STATE_ENTER:
        if (changed)
        {
            GameObject* h = (GameObject*)((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 5, lbl_803E75AC, 0);
            h->anim.localPosZ = gAndrossHandMoveAnimSpeeds[5];
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75B0)
        {
            *(u8*)&state->handState = ANDROSSHAND_STATE_IDLE2;
        }
        break;
    case ANDROSSHAND_STATE_SWIPE:
        if (changed)
        {
            GameObject* h;
            state->soundGate = 0;
            h = (GameObject*)((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 1, lbl_803E75AC, 0);
            h->anim.localPosZ = gAndrossHandMoveAnimSpeeds[1];
        }
        {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            if (hitState->lastHitObject != 0)
            {
                SunVec3 w;
                va.x = state->sideFlag ? lbl_803E75C0 : lbl_803E75C4;
                va.y = lbl_803E75AC;
                va.z = lbl_803E75AC;
                w = va;
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
            Sfx_PlayFromObject(obj, SFXTRIG_and_ring_lp);
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75B0)
        {
            andross_setPartSignal(state->androssObj, 1);
            *(u8*)&state->handState = ANDROSSHAND_STATE_IDLE2;
        }
        androsshand_handleDamage(obj, (int)state);
        break;
    case ANDROSSHAND_STATE_GRAB:
        if (changed)
        {
            GameObject* h;
            state->soundGate = 0;
            h = (GameObject*)((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E75AC, 0);
            h->anim.localPosZ = gAndrossHandMoveAnimSpeeds[2];
        }
        if (state->sideFlag != 0 && ((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75B0)
        {
            andross_setPartSignal(state->androssObj, 1);
            *(u8*)&state->handState = ANDROSSHAND_STATE_IDLE2;
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
                SunVec3 w;
                vb.x = lbl_803E75AC;
                vb.y = lbl_803E75F4;
                vb.z = lbl_803E75AC;
                w = vb;
                arwarwing_setVelocity(state->arwingObj, (int)&w);
                doRumble(lbl_803E75C8);
            }
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75E0 && ((GameObject*)obj)->anim.currentMoveProgress
            < lbl_803E75F8 &&
            state->soundGate == 0)
        {
            state->soundGate = 1;
            Sfx_PlayFromObject(obj, SFXTRIG_and_chompf);
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75F8 && state->soundGate != 0)
        {
            state->soundGate = 0;
            Sfx_PlayFromObject(obj, SFXTRIG_rockshat16);
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E75B0)
        {
            if (state->sideFlag != 0)
            {
                andross_setPartSignal(state->androssObj, 1);
            }
            *(u8*)&state->handState = ANDROSSHAND_STATE_IDLE2;
        }
        androsshand_handleDamage(obj, (int)state);
        break;
    case ANDROSSHAND_STATE_SHOOT:
        if (changed)
        {
            GameObject* h = (GameObject*)((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 3, lbl_803E75AC, 0);
            h->anim.localPosZ = gAndrossHandMoveAnimSpeeds[3];
            state->shotTimer = -1;
        }
        state->shotTimer -= framesThisStep;
        if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E75D0)
        {
            state->animSpeed = lbl_803E75F0;
        }
        else
        {
            Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_roar1);
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
            *(u8*)&state->handState = ANDROSSHAND_STATE_IDLE2;
        }
        androsshand_handleDamage(obj, (int)state);
        break;
    case ANDROSSHAND_STATE_IDLE2:
        if (changed)
        {
            GameObject* h = (GameObject*)((GameObject*)obj)->extra;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E75AC, 0);
            h->anim.localPosZ = gAndrossHandMoveAnimSpeeds[0];
        }
        break;
    case ANDROSSHAND_STATE_DEAD:
        andross_setPartSignal(state->androssObj, state->sideFlag ? 4 : 2);
        break;
    }

    if (state->handState == ANDROSSHAND_STATE_DEAD)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    }
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, state->animSpeed, timeDelta, 0);
}
#pragma opt_common_subs reset


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
    if (state->handState != ANDROSSHAND_STATE_DEAD || force != 0)
    {
        state->handState = newState;
        if (force != 0)
        {
            if (force == 2)
            {
                state->health = ANDROSSHAND_HEALTH_PHASE2;
            }
            else
            {
                state->health = ANDROSSHAND_HEALTH_NORMAL;
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
    u32 hitVol;
    int sphereIdx;
    int hitObj;
    f32 x;
    f32 y;
    f32 z;
    int cooldown;

    cooldown = state->hitCooldown - framesThisStep;
    if (cooldown < 0)
    {
        cooldown = 0;
    }
    state->hitCooldown = cooldown;
    if (ObjHits_GetPriorityHit(obj, &hitObj, &sphereIdx, &hitVol) != 0 &&
        state->hitCooldown == 0)
    {
        switch (sphereIdx)
        {
        case 0:
            state->health -= 1;
            state->hitCooldown = 6;
            state->zSpringVelocity = lbl_803DC508;
            Sfx_PlayFromObject(obj, SFXTRIG_wmap_nameoff);
            if (state->health == 0)
            {
                state->handState = ANDROSSHAND_STATE_DEAD;
                andross_setPartSignal(state->androssObj, 1);
                Sfx_PlayFromObject(obj, SFXTRIG_en_barrelblow11);
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
    GameObject* gobj = (GameObject*)obj;
    AndrossHandState* state = gobj->extra;

    state->sideFlag = setup[0x1b];
    state->prevState = -1;
    state->health = ANDROSSHAND_HEALTH_NORMAL;
    state->startupDelay = 5;
    *(u8*)&state->handState = ANDROSSHAND_STATE_IDLE2;
    *(u8*)&state->prevState = ANDROSSHAND_STATE_IDLE2;
    state = gobj->extra;
    ObjAnim_SetCurrentMove(obj, 4, lbl_803E75AC, 0);
    state->animSpeed = gAndrossHandMoveAnimSpeeds[4];
    gobj->anim.currentMoveProgress = lbl_803E75B0;
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
        dx = pt[0] - ((GameObject*)state->arwingObj)->anim.localPosX;
        dz = pt[2] - ((GameObject*)state->arwingObj)->anim.localPosZ;
        dist = sqrtf(dx * dx + dz * dz);
        yaw = (u16)getAngle(dx, dz) + 0x8000;
        gAndrossHandShotPitch = (u16)getAngle(pt[1] - ((GameObject*)state->arwingObj)->anim.localPosY, dist) >> 8;
        setup = Obj_AllocObjectSetup(0x20, 0x7e4);
        ((AndrossHandShotSetup*)setup)->head.posX = pt[0];
        ((AndrossHandShotSetup*)setup)->head.posY = pt[1];
        ((AndrossHandShotSetup*)setup)->head.posZ = pt[2];
        ((AndrossHandShotSetup*)setup)->yaw = (((GameObject*)obj)->anim.rotX + yaw) >> 8;
        ((AndrossHandShotSetup*)setup)->pitch = gAndrossHandShotPitch;
        ((AndrossHandShotSetup*)setup)->flag18 = 0;
        ((AndrossHandShotSetup*)setup)->head.color[0] = 1;
        ((AndrossHandShotSetup*)setup)->head.color[1] = 1;
        obj = ((int (*)(int, int))loadObjectAtObject)(obj, setup);
        if ((void*)obj != NULL)
        {
            arwprojectile_setLifetime(obj, lbl_803DC510);
            arwprojectile_placeForward(obj, lbl_803DC50C);
        }
    }
}

f32 gAndrossHandMoveAnimSpeeds[7] = { 0.02f, 0.007f, 0.007f, 0.003f, 0.02f, 0.013f, 0.007f };
