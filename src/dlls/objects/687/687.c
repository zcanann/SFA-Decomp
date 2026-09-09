/*
 * DLL 687 controls scenery sway, hit reactions and particle bursts. Up to three
 * AppleOnTree children follow its path points. The object ID chooses a burst
 * offset and radius; offsets are scaled and rotated before particle spawning.
 * Tree remains an internal family name for this numbered DLL.
 */
#include "dlls/objects/687.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dlls/objects/279_AppleOnTree.h"
#include "main/frame_timing.h"
#include "main/objHitReact.h"
#include "main/shader_api.h"
#include "sys/objects.h"
#include "main/objfx.h"
#include "main/dll/partfx_interface.h"
#include "main/object_render.h"
#include "main/obj_path.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/vecmath.h"
#include "sys/objects/lifecycle.h"

/* Tree variant object IDs (anim.romDefNo; retail names, all DLL 0x2AF). */
#define TREE_OBJECT_SMALL_FERN      0x798 /* "smallfern" */
#define TREE_OBJECT_TALL_PALM_TREE  0x799 /* "tallpalmtre..." */
#define TREE_OBJECT_SNOW_TREE_4     0x70d /* "SnowTree4" */
#define TREE_OBJECT_SNOW_TREE_3     0x70c /* "SnowTree3" */
#define TREE_OBJECT_SNOW_FRUIT_TREE 0x625 /* "SnowFruitTr..." */
#define TREE_OBJECT_JUNGLE_TREE     0x77a /* "JungleTree" */
#define TREE_OBJECT_SNOW_TREE_2     0x624 /* "SnowTree2" */
#define TREE_OBJECT_SNOW_TREE_1     0x39  /* "SnowTree1" */
#define TREE_OBJECT_SH_FERN_TREE    0x10b /* "SH_FernTree" */
#define TREE_OBJECT_FERN_TREE       0x5d1 /* "FernTree" */
#define TREE_FLAG_BURST_MODE_MASK        0x0f
#define TREE_FLAG_PLAYER_PROXIMITY_BURST 0x10
#define TREE_FLAG_HIT_ENABLED            0x20
/* two-bit mask (0x40|0x80); intentionally includes the APPLES bit */
#define TREE_FLAG_HIT_WITH_POSITION        0xc0
#define TREE_FLAG_APPLES          0x80
#define TREE_FLAG_DISABLE_PLAYER_PROXIMITY 0x100

void tree_spawnApple(GameObject* obj, TreeState* state, s8 index)
{
    TreePlacementPrefix* setup = (TreePlacementPrefix*)obj->anim.placementData;
    TreeState* ts = state;
    AppleOnTreePlacement* applePlacement;
    int idx;

    if ((u8)Obj_CanSetupObject())
    {
        applePlacement =
            (AppleOnTreePlacement*)Obj_AllocObjectSetup(APPLE_ON_TREE_PLACEMENT_SIZE, APPLE_ON_TREE_OBJECT_ID);
        applePlacement->base.color[0] = setup->base.color[0];
        applePlacement->base.color[2] = setup->base.color[2];
        applePlacement->base.color[1] = setup->base.color[1];
        applePlacement->base.color[3] = setup->base.color[3] - 0xa;
        idx = index;
        applePlacement->base.posX = ts->applePositions[idx][0];
        applePlacement->base.posY = ts->applePositions[idx][1];
        applePlacement->base.posZ = ts->applePositions[idx][2];
        applePlacement->phaseDuration = randomGetRange(0x708, 0x1770);
        applePlacement->initialElapsedTime = 0;
        applePlacement->growthEndFraction = 0xa;
        applePlacement->ripeEndFraction = 0x28;
        applePlacement->fallEndFraction = 0x32;
        applePlacement->landedEndFraction = 0xa;
        applePlacement->fadeEndFraction = 0x32;
        applePlacement->waterAccelerationPercent = -0x28;
        applePlacement->despawnGameBit = -1;
        applePlacement->unk18 = 0;
        ts->apples[idx] =
            objSetupObject(&applePlacement->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
    }
}

void tree_updateApples(GameObject* obj, TreeState* state)
{
    int i;
    TreeState* ts;

    if (obj->userData2 != 0) {
        ts = state;
        for (i = 0; i < TREE_APPLE_COUNT; i++)
        {
            if (state->apples[i] == NULL)
            {
                state->appleRespawnTimers[i] -= timeDelta;
                if (state->appleRespawnTimers[i] <= 0.0f)
                {
                    state->appleRespawnTimers[i] = randomGetRange(0x3c, 0x12c);
                    tree_spawnApple(obj, state, i);
                }
            }
            else
            {
                if (APPLE_ON_TREE_INTERFACE(state->apples[i])
                        ->getAnimState(state->apples[i]) > 3)
                {
                    state->apples[i] = 0;
                }
                else
                {
                    APPLE_ON_TREE_INTERFACE(state->apples[i])
                        ->setPosition(state->apples[i],
                                      &ts->applePositions[i][0]);
                }
            }
        }
    }
}

int tree_getExtraSize(void)
{
    return sizeof(TreeState);
}

void tree_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    TreePlacementPrefix* setup = (TreePlacementPrefix*)obj->anim.placementData;
    TreeState* state = obj->extra;
    int i;

    if (visible != 0)
    {
        /* Preserve reads beyond this prefix: secondary retail placements are
         * 0x20 bytes, so these tint reads cross their serialized boundary. */
        objSetColorFilter(((u8*)setup)[0x20], ((u8*)setup)[0x21], ((u8*)setup)[0x22]);
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        if (state->flags & TREE_FLAG_APPLES)
        {
            for (i = 0; i < TREE_APPLE_COUNT; i++)
            {
                ObjPath_GetPointWorldPosition(obj, i, &state->applePositions[i][0],
                                              &state->applePositions[i][1],
                                              &state->applePositions[i][2], 0);
            }
        }
        obj->userData2 = 1;
    }
}

void tree_update(GameObject* obj)
{
    TreeState* state = obj->extra;
    int hit;
    GameObject* player;
    int i;
    u16 playerDist;
    f32 dx, dz, dist;
    GameObject* hitObject; /* out-param required by API, not read by this fn */
    int hitSphereIndex; /* out-params required by API, not read by this fn */
    u32 hitVolume;      /* out-params required by API, not read by this fn */
    f32 effectScale;
    f32* offsetPtr;
    ObjAnimEventList animOut;
    PartFxSpawnParams burstParams; /* Reused for a hit position and the scaled, rotated burst offset. */

    ObjAnim_AdvanceCurrentMove(obj, state->swayAnimationStep, timeDelta, &animOut);
    if (state->flags != 0)
    {
        if (state->playerBurstCooldown > 0.0f)
        {
            state->playerBurstCooldown -= timeDelta;
        }
        if (state->swayAnimationStep > 0.0025f)
        {
            state->swayAnimationStep -= 0.001f;
        }
        if (state->flags & TREE_FLAG_APPLES)
        {
            tree_updateApples(obj, state);
        }
        if (state->flags & TREE_FLAG_HIT_ENABLED)
        {
            if (state->flags & TREE_FLAG_HIT_WITH_POSITION)
            {
                hit = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &hitSphereIndex, &hitVolume,
                                                         &burstParams.posX, &burstParams.posY, &burstParams.posZ);
            }
            else
            {
                hit = ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129,
                                                                &state->hitEffectCooldown);
            }
            if (state->hitCooldownTimer >= 0.0f)
            {
                state->hitCooldownTimer -= timeDelta;
            }
            if (hit != 0 && hit != OBJHITREACT_COLLISION_SKIP_REACTION && state->hitCooldownTimer <= 0.0f)
            {
                if (state->flags & TREE_FLAG_HIT_WITH_POSITION)
                {
                    burstParams.posX += playerMapOffsetX;
                    burstParams.posZ += playerMapOffsetZ;
                    objDoHitParticleFx((void*)obj, 0.014f, &burstParams, 1, 0);
                    Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
                }
                if (state->flags & TREE_FLAG_BURST_MODE_MASK)
                {
                    effectScale = state->scale;
                    *(offsetPtr = &burstParams.posX) = effectScale * gTreeEffectBursts[state->burstProfileIndex].offset.x;
                    burstParams.posY = effectScale * gTreeEffectBursts[state->burstProfileIndex].offset.y;
                    burstParams.posZ = effectScale * gTreeEffectBursts[state->burstProfileIndex].offset.z;
                    vecRotateZXY(&obj->anim.rotX, offsetPtr);
                    objfx_spawnRandomBurst(obj, state->flags & TREE_FLAG_BURST_MODE_MASK, 0x14, &burstParams,
                                           state->scale * gTreeEffectBursts[state->burstProfileIndex].radius, 0);
                }
                state->swayAnimationStep = 0.0225f;
                state->hitCooldownTimer = 20.0f;
                if (state->flags & TREE_FLAG_APPLES)
                {
                    if (hit != 0)
                    {
                        for (i = 0; i < TREE_APPLE_COUNT; i++)
                        {
                            if (state->apples[i] != NULL)
                            {
                                if (APPLE_ON_TREE_INTERFACE(state->apples[i])
                                        ->getAnimState(state->apples[i]) > 1)
                                {
                                    ObjHits_RecordObjectHit(state->apples[i], obj, 0xe, 1, 0);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        player = Obj_GetPlayerObject();
        if (player == NULL || (state->flags & TREE_FLAG_DISABLE_PLAYER_PROXIMITY) ||
            !(state->flags & TREE_FLAG_BURST_MODE_MASK))
        {
            return;
        }
        {
            dx = obj->anim.localPosX - player->anim.localPosX;
            dz = obj->anim.localPosZ - player->anim.localPosZ;
            dist = sqrtf(dx * dx + dz * dz);
            playerDist = dist;
            if (playerDist < state->proximityRadius)
            {
                if ((state->flags & TREE_FLAG_PLAYER_PROXIMITY_BURST) &&
                    state->lastPlayerDistance >= state->proximityRadius && state->playerBurstCooldown <= 0.0f)
                {
                    effectScale = state->scale;
                    *(offsetPtr = &burstParams.posX) = effectScale * gTreeEffectBursts[state->burstProfileIndex].offset.x;
                    burstParams.posY = effectScale * gTreeEffectBursts[state->burstProfileIndex].offset.y;
                    burstParams.posZ = effectScale * gTreeEffectBursts[state->burstProfileIndex].offset.z;
                    vecRotateZXY(&obj->anim.rotX, offsetPtr);
                    objfx_spawnRandomBurst(obj, state->flags & TREE_FLAG_BURST_MODE_MASK, 0x14, &burstParams,
                                           state->scale * gTreeEffectBursts[state->burstProfileIndex].radius, 1);
                    state->playerBurstCooldown = 340.0f;
                }
                state->ambientBurstTimer -= timeDelta;
                if (state->ambientBurstTimer <= 0.0f)
                {
                    effectScale = state->scale;
                    *(offsetPtr = &burstParams.posX) = effectScale * gTreeEffectBursts[state->burstProfileIndex].offset.x;
                    burstParams.posY = effectScale * gTreeEffectBursts[state->burstProfileIndex].offset.y;
                    burstParams.posZ = effectScale * gTreeEffectBursts[state->burstProfileIndex].offset.z;
                    vecRotateZXY(&obj->anim.rotX, offsetPtr);
                    objfx_spawnRandomBurst(obj, state->flags & TREE_FLAG_BURST_MODE_MASK, 1, &burstParams,
                                           state->scale * gTreeEffectBursts[state->burstProfileIndex].radius, 0);
                    state->ambientBurstTimer += 60.0f;
                }
            }
            state->lastPlayerDistance = playerDist;
        }
    }
}

void tree_init(GameObject* obj, TreePlacementPrefix* setup)
{
    TreePlacementPrefix* setupData = setup;
    TreeState* state = obj->extra;
    ObjAnimEventList animOut;
    f32 zero = 0.0f;

    state->swayAnimationStep = 0.0025f;
    state->ambientBurstTimer = 0.0f;
    state->proximityRadius = setupData->proximityRadiusHalf << 1;
    state->flags = setupData->flagsHi;
    state->flags = state->flags << 8;
    state->flags |= setupData->flagsLo;
    state->playerBurstCooldown = 0.0f;
    obj->anim.rotZ = (s16)(setupData->rotZ << 8);
    obj->anim.rotY = (s16)(setupData->rotY << 8);
    obj->anim.rotX = (s16)(setupData->rotX << 8);
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    obj->userData2 = 0;
    if (setupData->scale != 0)
    {
        state->scale = (f32)(u32)setupData->scale / 255.0f;
        obj->anim.rootMotionScale = state->scale;
        if (obj->anim.rootMotionScale == zero)
        {
            obj->anim.rootMotionScale = 1.0f;
        }
        obj->anim.rootMotionScale *= obj->anim.modelInstance->rootMotionScaleBase;
    }
    else
    {
        state->scale = 1.0f;
    }
    ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
    ObjAnim_AdvanceCurrentMove(obj, 1.0f, 1.0f, &animOut);
    if (state->flags & TREE_FLAG_APPLES)
    {
        state->flags |= TREE_FLAG_HIT_ENABLED;
    }
    switch (obj->anim.romDefNo)
    {
    case TREE_OBJECT_SMALL_FERN:
        state->burstProfileIndex = 0xa;
        break;
    case TREE_OBJECT_TALL_PALM_TREE:
        state->burstProfileIndex = 0x9;
        break;
    case TREE_OBJECT_SNOW_TREE_4:
        state->burstProfileIndex = 0x8;
        break;
    case TREE_OBJECT_SNOW_TREE_3:
        state->burstProfileIndex = 0x7;
        ObjHitbox_SetCapsuleBounds(&obj->anim, (int)(6.0f * obj->anim.rootMotionScale), -0x5,
                                   0x64);
        break;
    case TREE_OBJECT_SNOW_FRUIT_TREE:
        state->burstProfileIndex = 0x6;
        break;
    case TREE_OBJECT_JUNGLE_TREE:
        state->burstProfileIndex = 0x5;
        break;
    case TREE_OBJECT_SNOW_TREE_2:
        state->burstProfileIndex = 0x4;
        break;
    case TREE_OBJECT_SNOW_TREE_1:
        state->burstProfileIndex = 0x3;
        break;
    case TREE_OBJECT_SH_FERN_TREE:
        state->burstProfileIndex = 0x2;
        break;
    case TREE_OBJECT_FERN_TREE:
        state->burstProfileIndex = 0x1;
        break;
    default:
        state->burstProfileIndex = 0x0;
        break;
    }
    if (!(state->flags & TREE_FLAG_HIT_ENABLED))
    {
        ObjHits_DisableObject(obj);
    }
}

TreeEffectBurst gTreeEffectBursts[TREE_BURST_PROFILE_COUNT] = {
    {{0.0f, 250.0f, 0.0f}, 80.0f},  {{0.0f, 250.0f, 0.0f}, 110.0f}, {{25.0f, 200.0f, 0.0f}, 80.0f},
    {{0.0f, 100.0f, 0.0f}, 60.0f},  {{0.0f, 200.0f, 0.0f}, 140.0f}, {{0.0f, 250.0f, 0.0f}, 160.0f},
    {{0.0f, 200.0f, 0.0f}, 100.0f}, {{0.0f, 350.0f, 0.0f}, 130.0f}, {{0.0f, 350.0f, 0.0f}, 130.0f},
    {{25.0f, 300.0f, 0.0f}, 80.0f}, {{0.0f, 50.0f, 0.0f}, 50.0f},
};

ObjectDescriptor gTreeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    NULL,
    NULL,
    NULL,
    (ObjectDescriptorCallback)tree_init,
    (ObjectDescriptorCallback)tree_update,
    NULL,
    (ObjectDescriptorCallback)tree_render,
    NULL,
    NULL,
    tree_getExtraSize,
};
