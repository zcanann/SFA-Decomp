/*
 * ring (DLL 0x2A0) - the collectible flight rings for the Arwing
 * sequences. One object covers every ring variant, selected at init by
 * the placement's seqId: Arwing gold/silver rings, the silver "and"
 * ring, and the WeatherControl sun/moon rings (RING_OBJ_*, RING_MODE_*).
 *
 * Each ring follows a placement-chosen route (RING_ROUTE_*): a stationary
 * or moving target the player shoots, or a moving-axis ring the Arwing
 * flies through. It steps through RING_PHASE_HIDDEN -> ACTIVE ->
 * PULL_TO_ARWING -> COLLECTED: hidden rings fade in once their activation
 * game bit is set (or the Arwing exists); active rings fade to full alpha,
 * test shot/Arwing collisions and award score; collected rings are pulled
 * toward the Arwing with a spiralling particle burst before snapping back
 * to their placement position and hiding.
 *
 * Per-mode timing/particle parameters come from lbl_8032B720[mode]
 * (RingTable); the optional glow is a ModelLightStruct.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#define RING_OBJ_ARW_GOLD 0x060b
#define RING_OBJ_ARW_SILVER 0x060c
#define RING_OBJ_WC_SUN 0x07fb
#define RING_OBJ_WC_MOON 0x07fc
#define RING_OBJ_AND_SILVER 0x0819

#define RING_MODE_SILVER 0
/* mode 1 is unused/internal (no object type maps to it) */
#define RING_MODE_GOLD 2
#define RING_MODE_WC_MOON 3
#define RING_MODE_WC_SUN 4

#define RING_ROUTE_MOVING_AXIS_B 1 /* shares the moving-axis update with RING_ROUTE_MOVING_AXIS_A */
#define RING_ROUTE_STATIONARY_SHOT 2
#define RING_ROUTE_MOVING_SHOT_A 3
#define RING_ROUTE_MOVING_AXIS_A 4
#define RING_ROUTE_MOVING_SHOT_B 5

#define RING_PHASE_HIDDEN 0
#define RING_PHASE_ACTIVE 1
#define RING_PHASE_PULL_TO_ARWING 2
#define RING_PHASE_COLLECTED 3

#define RING_ALPHA_OPAQUE 0xff
#define RING_SCORE_VALUE 0xf
#define RING_SHOT_TYPE_A 0x604
#define RING_SHOT_TYPE_B 0x605
#define RING_PARTFX_FLAGS 0x200001
#define RING_MODEL_DEFAULT 0
#define RING_MODEL_ALT 1
#define RING_OBJFLAG_HIDDEN 0x4000

int ring_getExtraSize(void) { return sizeof(RingState); }

int ring_getObjectTypeId(void) { return 0; }

void ring_free(int obj)
{
    RingState* state = ((GameObject*)obj)->extra;
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
}

void ring_hitDetect(void)
{
}

void ring_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    RingState* state = ((GameObject*)obj)->extra;
    if (state->light != NULL && modelLightStruct_getActiveState(state->light) != 0)
    {
        queueGlowRender(state->light);
    }
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E70B0);
}

void ring_release(void)
{
}

void ring_initialise(void)
{
}

void ring_init(int obj, int setup)
{
    RingState* state = ((GameObject*)obj)->extra;
    RingPlacement* p = (RingPlacement*)setup;
    RingFlags* f = &state->flags;
    s16 type = ((GameObject*)obj)->anim.seqId;
    if (type == RING_OBJ_ARW_SILVER)
    {
        state->mode = RING_MODE_SILVER;
    }
    else if (type == RING_OBJ_AND_SILVER)
    {
        state->mode = RING_MODE_SILVER;
        f->bit10 = 1;
    }
    else if (type == RING_OBJ_ARW_GOLD)
    {
        state->mode = RING_MODE_GOLD;
    }
    else if (type == RING_OBJ_WC_MOON)
    {
        state->mode = RING_MODE_WC_MOON;
    }
    else if (type == RING_OBJ_WC_SUN)
    {
        state->mode = RING_MODE_WC_SUN;
    }
    else
    {
        state->mode = RING_MODE_GOLD;
    }
    state->route = p->route;
    if (state->route == RING_ROUTE_STATIONARY_SHOT || state->route == RING_ROUTE_MOVING_SHOT_A ||
        state->route == RING_ROUTE_MOVING_SHOT_B)
    {
        f->bit80 = 0;
        Obj_SetActiveModelIndex(obj, RING_MODEL_ALT);
    }
    else
    {
        f->bit80 = 1;
        ObjHits_DisableObject(obj);
    }
    state->linkId = p->linkId;
    state->pullHeight = (f32)p->pullHeight / lbl_803E70C4;
    state->origX = ((GameObject*)obj)->anim.localPosX;
    state->origY = ((GameObject*)obj)->anim.localPosY;
    if (p->modeFlag != 0)
        f->bit20 = 1;
    else
        f->bit20 = 0;
    ((GameObject*)obj)->anim.rotX = -32768;
    if (state->mode == RING_MODE_WC_MOON || state->mode == RING_MODE_WC_SUN)
    {
        f->bit10 = 1;
        state->arwingYOffset = lbl_803E70D8;
    }
    else
    {
        ((GameObject*)obj)->anim.flags |= RING_OBJFLAG_HIDDEN;
        ((GameObject*)obj)->anim.alpha = 0;
    }
}

void ring_update(int obj)
{
    RingState* state = ((GameObject*)obj)->extra;
    int arwing;
    RingPlacement* setup;
    int bit;
    int r;
    int hitA;
    int hitB;
    int hit;
    int ang;
    f32 dir[3];
    f32 spawnBuf[6];
    f32 mtx[12];

    arwing = getArwing();
    setup = (RingPlacement*)((GameObject*)obj)->anim.placementData;
    if (arwing == 0u)
        arwing = Obj_GetPlayerObject();

    switch (state->phase)
    {
    case RING_PHASE_HIDDEN:
        r = (int)((f32)(u32)((GameObject*)obj)->anim.alpha - lbl_803E70B4 * timeDelta);
        if (r < 0)
        {
            r = 0;
            ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | RING_OBJFLAG_HIDDEN);
        }
        ((GameObject*)obj)->anim.alpha = r;
        bit = setup->activateBit;
        if (bit > -1)
        {
            if (GameBit_Get(bit) != 0u)
            {
                ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~RING_OBJFLAG_HIDDEN);
                state->phase = RING_PHASE_ACTIVE;
            }
        }
        else
        {
            if (getArwing() != 0u)
            {
                ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~RING_OBJFLAG_HIDDEN);
                state->phase = RING_PHASE_ACTIVE;
            }
        }
        return;
    case RING_PHASE_ACTIVE:
        r = (int)((f32)(u32)((GameObject*)obj)->anim.alpha + lbl_803E70B4 * timeDelta);
        if (r > RING_ALPHA_OPAQUE) r = RING_ALPHA_OPAQUE;
        ((GameObject*)obj)->anim.alpha = r;
        bit = setup->activateBit;
        if (bit > -1)
        {
            if (GameBit_Get(bit) == 0u)
                state->phase = RING_PHASE_ACTIVE; /* original re-stores ACTIVE here (no-op write is intentional) */
        }
        switch (state->route)
        {
        case RING_ROUTE_MOVING_SHOT_A:
        case RING_ROUTE_MOVING_SHOT_B:
            if (ObjHits_GetPriorityHit(obj, &hitA, 0, 0) != 0 && (void*)(hit = hitA) != NULL &&
                (((GameObject*)hit)->anim.seqId == RING_SHOT_TYPE_A || ((GameObject*)hit)->anim.seqId == RING_SHOT_TYPE_B))
            {
                arwarwing_addScore(getArwing(), RING_SCORE_VALUE);
                ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
                Obj_SetActiveModelIndex(obj, RING_MODEL_DEFAULT);
                ObjHits_DisableObject(obj);
                state->flags.bit80 = 1;
                if (state->light != NULL)
                {
                    ModelLightStruct_free(state->light);
                    state->light = NULL;
                }
            }
            arwbombcoll_updateMovingAxis(obj, state);
            break;
        case RING_ROUTE_STATIONARY_SHOT:
            if (ObjHits_GetPriorityHit(obj, &hitB, 0, 0) != 0 && (void*)(hit = hitB) != NULL &&
                (((GameObject*)hit)->anim.seqId == RING_SHOT_TYPE_A || ((GameObject*)hit)->anim.seqId == RING_SHOT_TYPE_B))
            {
                arwarwing_addScore(getArwing(), RING_SCORE_VALUE);
                ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
                Obj_SetActiveModelIndex(obj, RING_MODEL_DEFAULT);
                ObjHits_DisableObject(obj);
                state->flags.bit80 = 1;
                if (state->light != NULL)
                {
                    ModelLightStruct_free(state->light);
                    state->light = NULL;
                }
            }
            break;
        case RING_ROUTE_MOVING_AXIS_B:
        case RING_ROUTE_MOVING_AXIS_A:
            arwbombcoll_updateMovingAxis(obj, state);
            break;
        }
        if (state->flags.bit80 != 0)
        {
            if (arwarwing_isDead(arwing) == 0 && arwarwing_isExplodingOrWarping(arwing) == 0 &&
                arwbombcoll_checkArwingCollision(obj, state, arwing) != 0)
            {
                arwbombcoll_handleArwingHit(obj, state, arwing);
            }
        }
        ((GameObject*)obj)->anim.rotX =
            (f32)(int)((GameObject*)obj)->anim.rotX + lbl_803E70B8 * timeDelta;
        break;
    case RING_PHASE_PULL_TO_ARWING:
        if (state->pullTimer > lbl_803E70A0)
        {
            if ((void*)arwing != NULL)
            {
                ((GameObject*)obj)->anim.velocityX =
                    oneOverTimeDelta * (((GameObject*)arwing)->anim.localPosX - ((GameObject*)obj)->anim.localPosX);
                ((GameObject*)obj)->anim.velocityY =
                    oneOverTimeDelta *
                    (state->arwingYOffset + (((GameObject*)arwing)->anim.localPosY - ((GameObject*)obj)->anim.localPosY));
                ((GameObject*)obj)->anim.velocityZ =
                    oneOverTimeDelta * (((GameObject*)arwing)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ);
                objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                        ((GameObject*)obj)->anim.velocityY * timeDelta,
                        ((GameObject*)obj)->anim.velocityZ * timeDelta);
            }
            {
                f32 sixty;
                if (state->pullTimer > (sixty = lbl_803E70BC))
                {
                    ((GameObject*)obj)->anim.rotX =
                        (s16)(((GameObject*)obj)->anim.rotX + lbl_8032B720[state->mode].f10);
                    {
                        f32 frac = (state->pullTimer - sixty) / sixty;
                        ((GameObject*)obj)->anim.rootMotionScale = frac *
                            ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
                    }
                    if (lbl_803E70C0 != state->pullTimer)
                    {
                        Obj_BuildWorldTransformMatrix(obj, mtx, 0);
                        for (ang = -0x7fff; ang < 0x7fff;
                             ang += lbl_8032B720[state->mode].f8)
                        {
                            dir[0] = 10.0f *
                                mathCosf(3.1415927f *
                                    (f32)(ang +
                                        (int)(state->pullTimer *
                                            lbl_8032B720[state->mode].f14)) /
                                    32768.0f);
                            dir[1] = 10.0f *
                                mathSinf(3.1415927f *
                                    (f32)(ang +
                                        (int)(state->pullTimer *
                                            lbl_8032B720[state->mode].f14)) /
                                    32768.0f);
                            dir[2] = 0.0f;
                            PSMTXMultVecSR(mtx, dir, dir);
                            spawnBuf[3] = dir[0] + ((GameObject*)obj)->anim.localPosX;
                            spawnBuf[4] = dir[1] + ((GameObject*)obj)->anim.localPosY;
                            spawnBuf[5] = dir[2] + ((GameObject*)obj)->anim.localPosZ;
                            (*gPartfxInterface)->spawnObject((void*)obj, lbl_8032B720[state->mode].f0,
                                                             spawnBuf, RING_PARTFX_FLAGS, -1,
                                                             (void*)(obj + 0x24));
                            (*gPartfxInterface)->spawnObject((void*)obj, lbl_8032B720[state->mode].f0,
                                                             spawnBuf, RING_PARTFX_FLAGS, -1,
                                                             (void*)(obj + 0x24));
                            (*gPartfxInterface)->spawnObject((void*)obj, lbl_8032B720[state->mode].f0,
                                                             spawnBuf, RING_PARTFX_FLAGS, -1,
                                                             (void*)(obj + 0x24));
                        }
                    }
                    state->flags.bit40 = 1;
                }
                else
                {
                    if (state->flags.bit40 != 0)
                    {
                        for (ang = 0; ang < lbl_8032B720[state->mode].fc; ang++)
                        {
                            (*gPartfxInterface)->spawnObject((void*)obj, lbl_8032B720[state->mode].f4,
                                                             NULL, 2, -1, NULL);
                        }
                    }
                    state->flags.bit40 = 0;
                    ((GameObject*)obj)->anim.alpha = 0;
                }
            }
            state->pullTimer -= timeDelta;
            if (state->pullTimer <= lbl_803E70A0)
            {
                f32 fz = lbl_803E70A0;
                state->pullTimer = fz;
                ((GameObject*)obj)->anim.localPosX = setup->base.posX;
                ((GameObject*)obj)->anim.localPosY = setup->base.posY;
                ((GameObject*)obj)->anim.localPosZ = setup->base.posZ;
                ((GameObject*)obj)->anim.rotX = 0;
                ((GameObject*)obj)->anim.alpha = RING_ALPHA_OPAQUE;
                ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
                ((GameObject*)obj)->anim.velocityX = fz;
                ((GameObject*)obj)->anim.velocityY = fz;
                ((GameObject*)obj)->anim.velocityZ = fz;
                state->phase = RING_PHASE_COLLECTED;
                ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | RING_OBJFLAG_HIDDEN);
            }
        }
        else
        {
            state->pullTimer = lbl_803E70C0;
        }
        break;
    case RING_PHASE_COLLECTED:
        break;
    }

    if (state->light != NULL && modelLightStruct_getActiveState(state->light) != 0)
    {
        modelLightStruct_updateGlowAlpha(state->light);
    }
}
