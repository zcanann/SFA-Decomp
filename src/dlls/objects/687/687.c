/*
 * DLL 687 - placeable scenery tree / foliage object.
 *
 * Drives swaying motion, hit reactions, and particle bursts. The setup
 * record's flag word (flagsHi:flagsLo) selects behaviour: a burst-mode
 * nibble picks the spawned particle effect, TREE_FLAG_HIT_ENABLED arms
 * hit polling, TREE_FLAG_AMBIENT_EFFECTS spawns up to three drifting
 * ambient effect objects tracked along the object's path points, and
 * TREE_FLAG_PLAYER_PROXIMITY_BURST fires a burst when the player crosses
 * the proximity radius. romDefNo selects an effect-colour profile index into
 * gTreeEffectBursts.
 *
 * The ambient effect objects are AppleOnTree instances, driven through that
 * DLL's interface (setPosition / getAnimState).
 */
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dlls/objects/279_AppleOnTree.h"
#include "main/frame_timing.h"
#include "main/objHitReact.h"
#include "main/shader_api.h"
#include "main/dll/dll_02AF_tree.h"
#include "sys/objects.h"
#include "main/objfx.h"
#include "main/dll/partfx_interface.h"
#include "main/object_render.h"
#include "main/obj_path.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/vecmath.h"
#include "sys/objects/lifecycle.h"

/* tree variant seqIds (retail OBJECTS.bin names, all DLL 0x2AF) */
#define TREE_SEQID_SMALL_FERN      0x798 /* "smallfern" */
#define TREE_SEQID_TALL_PALM_TREE  0x799 /* "tallpalmtre..." */
#define TREE_SEQID_SNOW_TREE_4     0x70d /* "SnowTree4" */
#define TREE_SEQID_SNOW_TREE_3     0x70c /* "SnowTree3" */
#define TREE_SEQID_SNOW_FRUIT_TREE 0x625 /* "SnowFruitTr..." */
#define TREE_SEQID_JUNGLE_TREE     0x77a /* "JungleTree" */
#define TREE_SEQID_SNOW_TREE_2     0x624 /* "SnowTree2" */
#define TREE_SEQID_SNOW_TREE_1     0x39  /* "SnowTree1" */
#define TREE_SEQID_SH_FERN_TREE    0x10b /* "SH_FernTree" */
#define TREE_SEQID_FERN_TREE       0x5d1 /* "FernTree" */
#define TREE_FLAG_BURST_MODE_MASK        0x0f
#define TREE_FLAG_PLAYER_PROXIMITY_BURST 0x10
#define TREE_FLAG_HIT_ENABLED            0x20
/* two-bit mask (0x40|0x80); intentionally includes the AMBIENT_EFFECTS bit */
#define TREE_FLAG_HIT_WITH_POSITION        0xc0
#define TREE_FLAG_AMBIENT_EFFECTS          0x80
#define TREE_FLAG_DISABLE_PLAYER_PROXIMITY 0x100

void tree_spawnAmbientEffect(GameObject* obj, TreeState* state, s8 index)
{
    TreeSetup* setup = (TreeSetup*)obj->anim.placementData;
    TreeState* ts = state;
    TreeAmbientEffectSetup* effectSetup;
    int idx;

    if ((u8)Obj_CanSetupObject())
    {
        effectSetup =
            (TreeAmbientEffectSetup*)Obj_AllocObjectSetup(TREE_AMBIENT_EFFECT_SETUP_SIZE, APPLE_ON_TREE_OBJECT_ID);
        effectSetup->base.color[0] = setup->base.color[0];
        effectSetup->base.color[2] = setup->base.color[2];
        effectSetup->base.color[1] = setup->base.color[1];
        effectSetup->base.color[3] = setup->base.color[3] - 0xa;
        idx = index;
        effectSetup->base.posX = ts->ambientEffectPos[idx][0];
        effectSetup->base.posY = ts->ambientEffectPos[idx][1];
        effectSetup->base.posZ = ts->ambientEffectPos[idx][2];
        effectSetup->animFrame = randomGetRange(0x708, 0x1770);
        effectSetup->unk1E = 0;
        effectSetup->colorA[0] = 0xa;
        effectSetup->colorA[1] = 0x28;
        effectSetup->colorA[2] = 0x32;
        effectSetup->colorB[0] = 0xa;
        effectSetup->colorB[1] = 0x32;
        effectSetup->verticalDrift = -0x28;
        effectSetup->modelId = -1;
        effectSetup->sourceObject = 0;
        ts->ambientEffectHandles[idx] =
            (int)objSetupObject(&effectSetup->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
    }
}

void tree_updateAmbientEffects(GameObject* obj, TreeState* state)
{
    int i;
    TreeState* ts;

    if (obj->userData2 != 0) {
        ts = state;
        for (i = 0; i < TREE_AMBIENT_EFFECT_COUNT; i++)
        {
            if ((void*)state->ambientEffectHandles[i] == NULL)
            {
                state->ambientSpawnTimers[i] -= timeDelta;
                if (state->ambientSpawnTimers[i] <= 0.0f)
                {
                    state->ambientSpawnTimers[i] = randomGetRange(0x3c, 0x12c);
                    tree_spawnAmbientEffect(obj, state, i);
                }
            }
            else
            {
                if (APPLE_ON_TREE_INTERFACE(state->ambientEffectHandles[i])
                        ->getAnimState((GameObject*)state->ambientEffectHandles[i]) > 3)
                {
                    state->ambientEffectHandles[i] = 0;
                }
                else
                {
                    APPLE_ON_TREE_INTERFACE(state->ambientEffectHandles[i])
                        ->setPosition((GameObject*)state->ambientEffectHandles[i],
                                      &ts->ambientEffectPos[i][0]);
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
    TreeSetup* setup = (TreeSetup*)obj->anim.placementData;
    TreeState* state = obj->extra;
    int i;

    if (visible != 0)
    {
        objSetColorFilter(setup->colorR, setup->colorG, setup->colorB);
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
        if (state->flags & TREE_FLAG_AMBIENT_EFFECTS)
        {
            for (i = 0; i < TREE_AMBIENT_EFFECT_COUNT; i++)
            {
                ObjPath_GetPointWorldPosition(obj, i, &state->ambientEffectPos[i][0],
                                              &state->ambientEffectPos[i][1],
                                              &state->ambientEffectPos[i][2], 0);
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
    f32 intensity;
    f32* colorPtr;
    ObjAnimEventList animOut;
    PartFxSpawnParams burstParams; /* pos slots: hit world-position outparams, then the scaled effect colour */

    ObjAnim_AdvanceCurrentMove(obj, state->swayTimer, timeDelta, &animOut);
    if (state->flags != 0)
    {
        if (state->playerBurstCooldown > 0.0f)
        {
            state->playerBurstCooldown -= timeDelta;
        }
        if (state->swayTimer > 0.0025f)
        {
            state->swayTimer -= 0.001f;
        }
        if (state->flags & TREE_FLAG_AMBIENT_EFFECTS)
        {
            tree_updateAmbientEffects(obj, state);
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
                    intensity = state->scale;
                    *(colorPtr = &burstParams.posX) = intensity * gTreeEffectBursts[state->effectProfileIndex].offset.x;
                    burstParams.posY = intensity * gTreeEffectBursts[state->effectProfileIndex].offset.y;
                    burstParams.posZ = intensity * gTreeEffectBursts[state->effectProfileIndex].offset.z;
                    vecRotateZXY(&obj->anim.rotX, colorPtr);
                    objfx_spawnRandomBurst(obj, state->flags & TREE_FLAG_BURST_MODE_MASK, 0x14, &burstParams,
                                           state->scale * gTreeEffectBursts[state->effectProfileIndex].radius, 0);
                }
                state->swayTimer = 0.0225f;
                state->hitCooldownTimer = 20.0f;
                if (state->flags & TREE_FLAG_AMBIENT_EFFECTS)
                {
                    if (hit != 0)
                    {
                        for (i = 0; i < TREE_AMBIENT_EFFECT_COUNT; i++)
                        {
                            if ((void*)state->ambientEffectHandles[i] != NULL)
                            {
                                if (APPLE_ON_TREE_INTERFACE(state->ambientEffectHandles[i])
                                        ->getAnimState((GameObject*)state->ambientEffectHandles[i]) > 1)
                                {
                                    ObjHits_RecordObjectHit((GameObject*)state->ambientEffectHandles[i], obj, 0xe, 1, 0);
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
                    intensity = state->scale;
                    *(colorPtr = &burstParams.posX) = intensity * gTreeEffectBursts[state->effectProfileIndex].offset.x;
                    burstParams.posY = intensity * gTreeEffectBursts[state->effectProfileIndex].offset.y;
                    burstParams.posZ = intensity * gTreeEffectBursts[state->effectProfileIndex].offset.z;
                    vecRotateZXY(&obj->anim.rotX, colorPtr);
                    objfx_spawnRandomBurst(obj, state->flags & TREE_FLAG_BURST_MODE_MASK, 0x14, &burstParams,
                                           state->scale * gTreeEffectBursts[state->effectProfileIndex].radius, 1);
                    state->playerBurstCooldown = 340.0f;
                }
                state->ambientBurstTimer -= timeDelta;
                if (state->ambientBurstTimer <= 0.0f)
                {
                    intensity = state->scale;
                    *(colorPtr = &burstParams.posX) = intensity * gTreeEffectBursts[state->effectProfileIndex].offset.x;
                    burstParams.posY = intensity * gTreeEffectBursts[state->effectProfileIndex].offset.y;
                    burstParams.posZ = intensity * gTreeEffectBursts[state->effectProfileIndex].offset.z;
                    vecRotateZXY(&obj->anim.rotX, colorPtr);
                    objfx_spawnRandomBurst(obj, state->flags & TREE_FLAG_BURST_MODE_MASK, 1, &burstParams,
                                           state->scale * gTreeEffectBursts[state->effectProfileIndex].radius, 0);
                    state->ambientBurstTimer += 60.0f;
                }
            }
            state->lastPlayerDistance = playerDist;
        }
    }
}

void tree_init(GameObject* obj, TreeSetup* setup)
{
    TreeSetup* setupData = setup;
    TreeState* state = obj->extra;
    ObjAnimEventList animOut;
    f32 zero = 0.0f;

    state->swayTimer = 0.0025f;
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
        obj->anim.rootMotionScale = obj->anim.rootMotionScale * obj->anim.modelInstance->rootMotionScaleBase;
    }
    else
    {
        state->scale = 1.0f;
    }
    ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
    ObjAnim_AdvanceCurrentMove(obj, 1.0f, 1.0f, &animOut);
    if (state->flags & TREE_FLAG_AMBIENT_EFFECTS)
    {
        state->flags |= TREE_FLAG_HIT_ENABLED;
    }
    switch (obj->anim.romDefNo)
    {
    case TREE_SEQID_SMALL_FERN:
        state->effectProfileIndex = 0xa;
        break;
    case TREE_SEQID_TALL_PALM_TREE:
        state->effectProfileIndex = 0x9;
        break;
    case TREE_SEQID_SNOW_TREE_4:
        state->effectProfileIndex = 0x8;
        break;
    case TREE_SEQID_SNOW_TREE_3:
        state->effectProfileIndex = 0x7;
        ObjHitbox_SetCapsuleBounds(&obj->anim, (int)(6.0f * obj->anim.rootMotionScale), -0x5,
                                   0x64);
        break;
    case TREE_SEQID_SNOW_FRUIT_TREE:
        state->effectProfileIndex = 0x6;
        break;
    case TREE_SEQID_JUNGLE_TREE:
        state->effectProfileIndex = 0x5;
        break;
    case TREE_SEQID_SNOW_TREE_2:
        state->effectProfileIndex = 0x4;
        break;
    case TREE_SEQID_SNOW_TREE_1:
        state->effectProfileIndex = 0x3;
        break;
    case TREE_SEQID_SH_FERN_TREE:
        state->effectProfileIndex = 0x2;
        break;
    case TREE_SEQID_FERN_TREE:
        state->effectProfileIndex = 0x1;
        break;
    default:
        state->effectProfileIndex = 0x0;
        break;
    }
    if (!(state->flags & TREE_FLAG_HIT_ENABLED))
    {
        ObjHits_DisableObject(obj);
    }
}

TreeEffectBurst gTreeEffectBursts[] = {
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
