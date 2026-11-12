/*
 * DLL 672 - the collectible flight rings for the Arwing
 * sequences. One object covers every ring variant, selected at init by
 * the placement's romDefNo: Arwing gold/silver rings, the silver "and"
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
 * Per-mode timing/particle parameters come from gRingModeParams[mode]
 * (RingTable); the optional glow is a ModelLightStruct.
 */
#include "main/dll/dll_0000_gameui.h"
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_trigger_ids.h"
#include "MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx.h"
#include "main/frame_timing.h"
#include "sys/objects.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/dll/dll_02A0_ring.h"
#include "main/object_render.h"
#include "main/audio/sfx_play_legacy_api.h"
#include "main/dll/headdisplay.h"
#include "main/gamebits_api.h"
#include "main/gameloop_gamebit_api.h"
#include "main/objhits.h"
#include "main/model_light.h"

#define RING_SEQID_ARW_ARWING 0x601 /* "ARWArwing" (DLL 0x29A) */
#define RING_OBJ_ARW_GOLD   0x060b
#define RING_OBJ_ARW_SILVER 0x060c
#define RING_OBJ_WC_SUN     0x07fb
#define RING_OBJ_WC_MOON    0x07fc
#define RING_OBJ_AND_SILVER 0x0819

#define RING_MODE_SILVER  0 //Arwing silver ring
/* mode 1 is unused/internal (no object type maps to it) */
#define RING_MODE_GOLD    2 //Arwing gold ring
#define RING_MODE_WC_MOON 3
#define RING_MODE_WC_SUN  4

#define RING_ROUTE_MOVING_AXIS_B   1 /* shares the moving-axis update with RING_ROUTE_MOVING_AXIS_A */
#define RING_ROUTE_STATIONARY_SHOT 2
#define RING_ROUTE_MOVING_SHOT_A   3
#define RING_ROUTE_MOVING_AXIS_A   4
#define RING_ROUTE_MOVING_SHOT_B   5

#define RING_PHASE_HIDDEN         0
#define RING_PHASE_ACTIVE         1
#define RING_PHASE_PULL_TO_ARWING 2
#define RING_PHASE_COLLECTED      3

#define RING_SCORE_VALUE    15
#define RING_SHOT_TYPE_A    0x604
#define RING_SHOT_TYPE_B    0x605
#define RING_PARTFX_FLAGS   0x200001
#define RING_MODEL_DEFAULT  0
#define RING_MODEL_ALT      1

RingTable gRingModeParams[] = {
    {0x7A4, 0x7A5, 0x2000, 100, -0x1000, 1850.0f},
    {0x7A2, 0x7A3, 0x4000, 50, 0x1000, 732.0f},
    {0x7A2, 0x7A3, 0x4000, 50, 0x1000, 732.0f},
    {0x7A4, 0x7A5, 0x2000, 100, -0x1000, 1850.0f},
    {0x7A2, 0x7A3, 0x4000, 50, 0x1000, 732.0f},
};

ObjectDescriptor gRingObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)ring_initialise,
    (ObjectDescriptorCallback)ring_release,
    NULL,
    (ObjectDescriptorCallback)ring_init,
    (ObjectDescriptorCallback)ring_update,
    (ObjectDescriptorCallback)ring_hitDetect,
    (ObjectDescriptorCallback)ring_render,
    (ObjectDescriptorCallback)ring_free,
    (ObjectDescriptorCallback)ring_getObjectTypeId,
    ring_getExtraSize,
};

void ring_updateMovingAxis(GameObject* obj, RingState* state)
{
    u8 mode = state->route;
    if (mode == 1 || mode == 3)
    {
        f32 edge, cur, lim;
        obj->anim.localPosX = state->pullHeight * timeDelta + obj->anim.localPosX;
        cur = obj->anim.localPosX;
        lim = state->origX;
        edge = lim + (f32)(u32)state->linkId;
        if (cur > edge)
        {
            obj->anim.localPosX = edge - (cur - edge);
            state->pullHeight = -state->pullHeight;
        }
        else
        {
            edge = lim - (f32)(u32)state->linkId;
            if (cur < edge)
            {
                obj->anim.localPosX = edge - (cur - edge);
                state->pullHeight = -state->pullHeight;
            }
        }
    }
    else if (mode == 4 || mode == 5)
    {
        f32 edge, cur, lim;
        obj->anim.localPosY = state->pullHeight * timeDelta + obj->anim.localPosY;
        cur = obj->anim.localPosY;
        lim = state->origY;
        edge = lim + (f32)(u32)state->linkId;
        if (cur > edge)
        {
            obj->anim.localPosY = edge - (cur - edge);
            state->pullHeight = -state->pullHeight;
        }
        else
        {
            edge = lim - (f32)(u32)state->linkId;
            if (cur < edge)
            {
                obj->anim.localPosY = edge - (cur - edge);
                state->pullHeight = -state->pullHeight;
            }
        }
    }
}

void ring_onCollect(GameObject* obj, RingState* state, GameObject* arwing)
{
    GameObject* arwingObj = arwing;
    RingPlacement* setup = (RingPlacement*)obj->anim.placementData;
    u8 mode = state->mode;
    if (mode == 0)
    {
        Sfx_PlayFromObject(arwing, SFXTRIG_ar_lsrhitobj16);
        if (arwingObj->anim.romDefNo == RING_SEQID_ARW_ARWING)
        {
            arwarwing_addHealth(arwingObj, 1);
            arwarwing_addScore(arwingObj, 0xa);
        }
    }
    else if (mode == 1)
    {
        Sfx_PlayFromObject(arwing, SFXTRIG_ar_lsrhitobj16);
        if (arwingObj->anim.romDefNo == RING_SEQID_ARW_ARWING)
        {
            arwarwing_addMaxHealth(arwingObj, 1);
            arwarwing_addHealth(arwingObj, arwarwing_getMaxHealth(arwingObj));
        }
    }
    else if (mode == 3 || mode == 4)
    {
        Sfx_PlayFromObject(arwing, SFXTRIG_ar_lsrhitobj16);
        gameBitIncrement(setup->counterGameBit);
    }
    else
    {
        Sfx_PlayFromObject(arwing, SFXTRIG_ar_laser216);
        if (arwingObj->anim.romDefNo == RING_SEQID_ARW_ARWING)
        {
            int seg;
            int collected;
            arwarwing_incrementCollectedRingCount(arwingObj);
            arwarwing_addHealth(arwingObj, 1);
            arwarwing_addScore(arwingObj, 0x14);
            seg = arwarwing_getRequiredRingCount(arwingObj);
            collected = arwarwing_getCollectedRingCount(arwingObj);
            if (collected == seg)
            {
                if (state->flags.bMissed)
                    headDisplayOpen(HEADDISP_FORCEFIELDDOWN);
            }
            else
            {
                if (state->flags.bMissed)
                    headDisplayOpen(HEADDISP_GOODJOBFOX);
            }
        }
    }
    state->phase = RING_PHASE_PULL_TO_ARWING;
}

int ring_checkArwingCollision(GameObject* obj, RingState* state, GameObject* arwing)
{
    ObjAnimComponent* objAnim = &obj->anim;
    ObjAnimComponent* arwingAnim = &arwing->anim;
    RingFlags* flags = &state->flags;
    if (flags->bit10)
    {
        f32 dx = objAnim->localPosX - arwingAnim->localPosX;
        f32 dy = objAnim->localPosY - arwingAnim->localPosY;
        f32 dz;
        if (dy < 0.0f)
            dy = -dy;
        dz = objAnim->localPosZ - arwingAnim->localPosZ;
        if (dy <= 100.0f)
        {
            if (dx * dx + dz * dz < 1600.0f)
                return 1;
        }
    }
    else
    {
        f32 objZ;
        f32 currentZDelta = (objZ = objAnim->localPosZ) - arwingAnim->localPosZ;
        f32 previousZDelta = objZ - arwingAnim->previousLocalPosZ;
        if (currentZDelta <= 0.0f && previousZDelta >= 0.0f)
        {
            f32 dx = objAnim->localPosX - arwingAnim->localPosX;
            f32 dy = objAnim->localPosY - arwingAnim->localPosY;
            if (sqrtf(dx * dx + dy * dy) < 55.0f)
                return 1;
            if (state->mode == RING_MODE_GOLD && flags->bMissed)
                headDisplayOpen(HEADDISP_MISSEDGOLDRING);
        }
    }
    return 0;
}

int ring_getExtraSize(void)
{
    return sizeof(RingState);
}


int ring_getObjectTypeId(void)
{
    return 0;
}


void ring_free(GameObject* obj)
{
    RingState* state = obj->extra;
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
}


void ring_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale)
{
    RingState* state = obj->extra;
    if (state->light != NULL && modelLightStruct_getActiveState(state->light) != 0)
    {
        queueGlowRender(state->light);
    }
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}


void ring_hitDetect(void)
{
}


void ring_update(GameObject* obj)
{
    RingState* state = obj->extra;
    GameObject* player;
    RingPlacement* setup;
    int bit;
    int alpha;
    GameObject* hitA;
    GameObject* hitB;
    GameObject* hit;
    int ang;
    f32 dir[3];
    PartFxSpawnParams spawnBuf;
    f32 mtx[12];

    player = (GameObject*)getArwing();
    setup = (RingPlacement*)obj->anim.placementData;
    if (player == NULL)
        player = Obj_GetPlayerObject();

    switch (state->phase)
    {
    case RING_PHASE_HIDDEN:
        alpha = (int)((f32)(u32)obj->anim.alpha - 3.0f * timeDelta);
        if (alpha < 0)
        {
            alpha = 0;
            obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
        }
        obj->anim.alpha = alpha;
        bit = setup->activateBit;
        if (bit > -1)
        {
            if (mainGetBit(bit) != 0u)
            {
                obj->anim.flags = (s16)(obj->anim.flags & ~OBJANIM_FLAG_HIDDEN);
                state->phase = RING_PHASE_ACTIVE;
            }
        }
        else
        {
            if (getArwing() != 0u)
            {
                obj->anim.flags = (s16)(obj->anim.flags & ~OBJANIM_FLAG_HIDDEN);
                state->phase = RING_PHASE_ACTIVE;
            }
        }
        return;
    case RING_PHASE_ACTIVE:
        alpha = (int)((f32)(u32)obj->anim.alpha + 3.0f * timeDelta);
        if(alpha > 0xff) alpha = 0xff;
        obj->anim.alpha = alpha;
        bit = setup->activateBit;
        if (bit > -1)
        {
            if (mainGetBit(bit) == 0u)
                state->phase = RING_PHASE_ACTIVE; /* original re-stores ACTIVE here (no-op write is intentional) */
        }
        switch (state->route)
        {
        case RING_ROUTE_MOVING_SHOT_A:
        case RING_ROUTE_MOVING_SHOT_B:
            if (ObjHits_GetPriorityHit(obj, &hitA, 0, 0) != 0 && (hit = hitA) != NULL &&
                (hit->anim.romDefNo == RING_SHOT_TYPE_A ||
                 hit->anim.romDefNo == RING_SHOT_TYPE_B))
            {
                arwarwing_addScore(getArwing(), RING_SCORE_VALUE);
                obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase;
                Obj_SetActiveModelIndex(obj, RING_MODEL_DEFAULT);
                ObjHits_DisableObject(obj);
                state->flags.bIntangible = 1;
                if (state->light != NULL)
                {
                    ModelLightStruct_free(state->light);
                    state->light = NULL;
                }
            }
            ring_updateMovingAxis(obj, state);
            break;
        case RING_ROUTE_STATIONARY_SHOT:
            if (ObjHits_GetPriorityHit(obj, &hitB, 0, 0) != 0 && (hit = hitB) != NULL &&
                (hit->anim.romDefNo == RING_SHOT_TYPE_A ||
                 hit->anim.romDefNo == RING_SHOT_TYPE_B))
            {
                arwarwing_addScore(getArwing(), RING_SCORE_VALUE);
                obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase;
                Obj_SetActiveModelIndex(obj, RING_MODEL_DEFAULT);
                ObjHits_DisableObject(obj);
                state->flags.bIntangible = 1;
                if (state->light != NULL)
                {
                    ModelLightStruct_free(state->light);
                    state->light = NULL;
                }
            }
            break;
        case RING_ROUTE_MOVING_AXIS_B:
        case RING_ROUTE_MOVING_AXIS_A:
            ring_updateMovingAxis(obj, state);
            break;
        }
        if (state->flags.bIntangible != 0)
        {
            if (arwarwing_isDead(player) == 0
            && arwarwing_isExplodingOrWarping(player) == 0
            && ring_checkArwingCollision(obj, state, player) != 0)
            {
                ring_onCollect(obj, state, player);
            }
        }
        obj->anim.rotX = (f32)(int)obj->anim.rotX + 1000.0f * timeDelta;
        break;
    case RING_PHASE_PULL_TO_ARWING:
        if (state->pullTimer > 0.0f)
        {
            if (player != NULL)
            {
                obj->anim.velocityX = oneOverTimeDelta * (player->anim.localPosX - obj->anim.localPosX);
                obj->anim.velocityY =
                    oneOverTimeDelta * (state->arwingYOffset +
                                        (player->anim.localPosY - obj->anim.localPosY));
                obj->anim.velocityZ = oneOverTimeDelta * (player->anim.localPosZ - obj->anim.localPosZ);
                objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                        obj->anim.velocityZ * timeDelta);
            }
            {
                f32 sixty;
                if (state->pullTimer > (sixty = 60.0f))
                {
                    obj->anim.rotX = (s16)(obj->anim.rotX + gRingModeParams[state->mode].spinStep);
                    {
                        f32 frac = (state->pullTimer - sixty) / sixty;
                        obj->anim.rootMotionScale = frac * obj->anim.modelInstance->rootMotionScaleBase;
                    }
                    if (state->pullTimer != 120.0f)
                    {
                        Obj_BuildWorldTransformMatrix(obj, mtx, 0);
                        for (ang = -0x7fff; ang < 0x7fff; ang += gRingModeParams[state->mode].spiralAngleStep)
                        {
                            dir[0] =
                                10.0f * mathCosf(3.1415927f *
                                                 (f32)(ang + (int)(state->pullTimer * gRingModeParams[state->mode].spiralPhaseSpeed)) /
                                                 32768.0f);
                            dir[1] =
                                10.0f * mathSinf(3.1415927f *
                                                 (f32)(ang + (int)(state->pullTimer * gRingModeParams[state->mode].spiralPhaseSpeed)) /
                                                 32768.0f);
                            dir[2] = 0.0f;
                            PSMTXMultVecSR((MtxP)mtx, (const Vec*)dir, (Vec*)dir);
                            spawnBuf.posX = dir[0] + obj->anim.localPosX;
                            spawnBuf.posY = dir[1] + obj->anim.localPosY;
                            spawnBuf.posZ = dir[2] + obj->anim.localPosZ;
                            (*gPartfxInterface)
                                ->spawnEffect(obj, gRingModeParams[state->mode].spiralEffectId, &spawnBuf,
                                              RING_PARTFX_FLAGS, -1, &obj->anim.velocityX);
                            (*gPartfxInterface)
                                ->spawnEffect(obj, gRingModeParams[state->mode].spiralEffectId, &spawnBuf,
                                              RING_PARTFX_FLAGS, -1, &obj->anim.velocityX);
                            (*gPartfxInterface)
                                ->spawnEffect(obj, gRingModeParams[state->mode].spiralEffectId, &spawnBuf,
                                              RING_PARTFX_FLAGS, -1, &obj->anim.velocityX);
                        }
                    }
                    state->flags.bSpawnParticles = 1;
                }
                else
                {
                    if (state->flags.bSpawnParticles != 0)
                    {
                        for (ang = 0; ang < gRingModeParams[state->mode].burstCount; ang++)
                        {
                            (*gPartfxInterface)
                                ->spawnEffect(obj, gRingModeParams[state->mode].burstEffectId, NULL, 2, -1, NULL);
                        }
                    }
                    state->flags.bSpawnParticles = 0;
                    obj->anim.alpha = 0;
                }
            }
            state->pullTimer -= timeDelta;
            if (state->pullTimer <= 0.0f)
            {
                f32 fz = 0.0f;
                state->pullTimer = fz;
                obj->anim.localPosX = setup->base.posX;
                obj->anim.localPosY = setup->base.posY;
                obj->anim.localPosZ = setup->base.posZ;
                obj->anim.rotX = 0;
                obj->anim.alpha = 0xff;
                obj->anim.rootMotionScale = obj->anim.modelInstance->rootMotionScaleBase;
                obj->anim.velocityX = fz;
                obj->anim.velocityY = fz;
                obj->anim.velocityZ = fz;
                state->phase = RING_PHASE_COLLECTED;
                obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
            }
        }
        else
        {
            state->pullTimer = 120.0f;
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


void ring_init(GameObject* obj, RingPlacement* setup)
{
    RingState* state = obj->extra;
    RingPlacement* placement = setup;
    RingFlags* flags = &state->flags;
    s16 type = obj->anim.romDefNo;
    if (type == RING_OBJ_ARW_SILVER)
    {
        state->mode = RING_MODE_SILVER;
    }
    else if (type == RING_OBJ_AND_SILVER)
    {
        state->mode = RING_MODE_SILVER;
        flags->bit10 = 1;
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
    state->route = placement->route;
    if (state->route == RING_ROUTE_STATIONARY_SHOT || state->route == RING_ROUTE_MOVING_SHOT_A ||
        state->route == RING_ROUTE_MOVING_SHOT_B)
    {
        flags->bIntangible = 0;
        Obj_SetActiveModelIndex(obj, RING_MODEL_ALT);
    }
    else
    {
        flags->bIntangible = 1;
        ObjHits_DisableObject(obj);
    }
    state->linkId = placement->linkId;
    state->pullHeight = placement->pullHeight / 10.0f;
    state->origX = obj->anim.localPosX;
    state->origY = obj->anim.localPosY;
    if (placement->modeFlag != 0)
        flags->bMissed = 1;
    else
        flags->bMissed = 0;
    obj->anim.rotX = -32768;
    if (state->mode == RING_MODE_WC_MOON || state->mode == RING_MODE_WC_SUN)
    {
        flags->bit10 = 1;
        state->arwingYOffset = 20.0f;
    }
    else
    {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        obj->anim.alpha = 0;
    }
}


void ring_release(void)
{
}


void ring_initialise(void)
{
}
