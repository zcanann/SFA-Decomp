/*
 * tree (DLL 0x2AF) - placeable scenery tree / foliage object.
 *
 * Drives swaying motion, hit reactions, and particle bursts. The setup
 * record's flag word (flagsHi:flagsLo) selects behaviour: a burst-mode
 * nibble picks the spawned particle effect, TREE_FLAG_HIT_ENABLED arms
 * hit polling, TREE_FLAG_AMBIENT_EFFECTS spawns up to three drifting
 * ambient effect objects tracked along the object's path points, and
 * TREE_FLAG_PLAYER_PROXIMITY_BURST fires a burst when the player crosses
 * the proximity radius. seqId selects an effect-colour profile index into
 * gTreeEffectColors.
 *
 * The ambient effect objects are driven through an interface at +0x68
 * (vtable slots 0x24 = setPosition, 0x28 = getState).
 *
 * The target binary has no ObjectDescriptor global nor lifecycle stubs for
 * this DLL - the .text holds only the functions below.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/dll_02B0_brokenpipe.h"
#include "main/dll/dll_02AF_tree.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/objfx.h"
#include "main/objhits.h"

#define TREE_AMBIENT_EFFECT_OBJECT_ID    0x210
#define TREE_OBJECT_FLAGS_INIT           0x2000
#define TREE_RESET_HITBOX_FLAG           INTERACT_FLAG_DISABLED /* 0x08 */
#define TREE_FLAG_BURST_MODE_MASK        0x0f
#define TREE_FLAG_PLAYER_PROXIMITY_BURST 0x10
#define TREE_FLAG_HIT_ENABLED            0x20
/* two-bit mask (0x40|0x80); intentionally includes the AMBIENT_EFFECTS bit */
#define TREE_FLAG_HIT_WITH_POSITION        0xc0
#define TREE_FLAG_AMBIENT_EFFECTS          0x80
#define TREE_FLAG_DISABLE_PLAYER_PROXIMITY 0x100

#define objfx_spawnRandomBurstLegacy(obj, type, count, origin, mult, flags)                                      \
    ((void (*)(void*, int, int, void*, f32, int))objfx_spawnRandomBurst)(                                       \
        (void*)(obj), (type), (count), (origin), (mult), (flags))

int tree_getExtraSize(void)
{
    return sizeof(TreeState);
}

void tree_spawnAmbientEffect(GameObject* obj, TreeState* state, s8 index)
{
    TreeSetup* setup = (TreeSetup*)(obj)->anim.placementData;
    TreeState* ts = state;
    TreeAmbientEffectSetup* effectSetup;
    int idx;

    if (Obj_IsLoadingLocked())
    {
        effectSetup = (TreeAmbientEffectSetup*)Obj_AllocObjectSetup(TREE_AMBIENT_EFFECT_SETUP_SIZE,
                                                                    TREE_AMBIENT_EFFECT_OBJECT_ID);
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
            (int)Obj_SetupObject(&effectSetup->base, 5, (obj)->anim.mapEventSlot, -1, (obj)->anim.parent);
    }
}

void tree_updateAmbientEffects(GameObject* obj, TreeState* state)
{
    int i;
    TreeState* ts;

    if ((obj)->unkF8 != 0)
    {
        ts = state;
        for (i = 0; i < TREE_AMBIENT_EFFECT_COUNT; i++)
        {
            if ((void*)state->ambientEffectHandles[i] == NULL)
            {
                state->ambientSpawnTimers[i] -= timeDelta;
                if (state->ambientSpawnTimers[i] <= lbl_803E72F8)
                {
                    state->ambientSpawnTimers[i] = randomGetRange(0x3c, 0x12c);
                    tree_spawnAmbientEffect(obj, state, i);
                }
            }
            else
            {
                if ((*(int (**)(int))(*(int*)(*(int*)(state->ambientEffectHandles[i] + 0x68)) + 0x28))(
                        state->ambientEffectHandles[i]) > 3)
                {
                    state->ambientEffectHandles[i] = 0;
                }
                else
                {
                    (*(void (**)(int, int))(*(int*)(*(int*)(state->ambientEffectHandles[i] + 0x68)) +
                                            0x24))(state->ambientEffectHandles[i],
                                                   (int)&ts->ambientEffectPos[i][0]);
                }
            }
        }
    }
}

void tree_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    TreeSetup* setup = (TreeSetup*)obj->anim.placementData;
    TreeState* state = obj->extra;
    int i;

    if (visible != 0)
    {
        fn_8003B608(setup->colorR, setup->colorG, setup->colorB);
        objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E7308);
        if (state->flags & TREE_FLAG_AMBIENT_EFFECTS)
        {
            for (i = 0; i < TREE_AMBIENT_EFFECT_COUNT; i++)
            {
                ((void (*)(GameObject*, int, f32*, f32*, f32*, int))ObjPath_GetPointWorldPosition)(
                    obj, i, &state->ambientEffectPos[i][0], &state->ambientEffectPos[i][1],
                    &state->ambientEffectPos[i][2], 0);
            }
        }
        obj->unkF8 = 1;
    }
}

void tree_init(GameObject* obj, TreeSetup* setup)
{
    TreeSetup* setupData = setup;
    TreeState* state = obj->extra;
    ObjAnimEventList animOut;

    state->swayTimer = lbl_803E730C;
    state->ambientBurstTimer = lbl_803E72F8;
    state->proximityRadius = setupData->proximityRadiusHalf << 1;
    state->flags = setupData->flagsHi;
    state->flags = state->flags << 8;
    state->flags |= setupData->flagsLo;
    state->playerBurstCooldown = lbl_803E72F8;
    obj->anim.rotZ = (s16)(setupData->rotZ << 8);
    obj->anim.rotY = (s16)(setupData->rotY << 8);
    obj->anim.rotX = (s16)(setupData->rotX << 8);
    *(u8*)&obj->anim.resetHitboxMode |= TREE_RESET_HITBOX_FLAG;
    obj->objectFlags |= TREE_OBJECT_FLAGS_INIT;
    obj->unkF8 = 0;
    if (setupData->scale != 0)
    {
        state->scale = (f32)(u32)setupData->scale / gTreeScaleByteNormalizer;
        obj->anim.rootMotionScale = state->scale;
        if (obj->anim.rootMotionScale == lbl_803E72F8)
        {
            obj->anim.rootMotionScale = lbl_803E7308;
        }
        obj->anim.rootMotionScale = obj->anim.rootMotionScale * obj->anim.modelInstance->rootMotionScaleBase;
    }
    else
    {
        state->scale = lbl_803E7308;
    }
    ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E72F8, 0);
    ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E7308, *(f32*)&lbl_803E7308, &animOut);
    if (state->flags & TREE_FLAG_AMBIENT_EFFECTS)
    {
        state->flags |= TREE_FLAG_HIT_ENABLED;
    }
    switch (obj->anim.seqId)
    {
    case 0x798:
        state->effectProfileIndex = 0xa;
        break;
    case 0x799:
        state->effectProfileIndex = 0x9;
        break;
    case 0x70d:
        state->effectProfileIndex = 0x8;
        break;
    case 0x70c:
        state->effectProfileIndex = 0x7;
        ObjHitbox_SetCapsuleBounds((ObjAnimComponent*)obj, (int)(lbl_803E732C * obj->anim.rootMotionScale), -0x5,
                                   0x64);
        break;
    case 0x625:
        state->effectProfileIndex = 0x6;
        break;
    case 0x77a:
        state->effectProfileIndex = 0x5;
        break;
    case 0x624:
        state->effectProfileIndex = 0x4;
        break;
    case 0x39:
        state->effectProfileIndex = 0x3;
        break;
    case 0x10b:
        state->effectProfileIndex = 0x2;
        break;
    case 0x5d1:
        state->effectProfileIndex = 0x1;
        break;
    default:
        state->effectProfileIndex = 0x0;
        break;
    }
    if (!(state->flags & TREE_FLAG_HIT_ENABLED))
    {
        ObjHits_DisableObject((u32)obj);
    }
}

#pragma opt_common_subs off
void tree_update(GameObject* obj)
{
    TreeState* state = obj->extra;
    int hit;
    GameObject* player;
    int i;
    u16 playerDist;
    f32 dx, dz, dist;
    int hitObject;      /* out-params required by API, not read by this fn */
    int hitSphereIndex; /* out-params required by API, not read by this fn */
    u32 hitVolume;      /* out-params required by API, not read by this fn */
    f32 colorVec[3];    /* dual role: hit world-position outparam, then scaled effect colour */
    f32 burstVec[3];
    f32 intensity;
    f32* colorPtr;
    ObjAnimEventList animOut;

    ObjAnim_AdvanceCurrentMove((int)obj, state->swayTimer, timeDelta, &animOut);
    if (state->flags != 0)
    {
        if (state->playerBurstCooldown > lbl_803E72F8)
        {
            state->playerBurstCooldown -= timeDelta;
        }
        if (state->swayTimer > lbl_803E730C)
        {
            state->swayTimer -= lbl_803E7310;
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
                                                         &colorVec[0], &colorVec[1], &colorVec[2]);
            }
            else
            {
                hit = ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129,
                                                                &state->hitEffectCooldown);
            }
            if (state->hitCooldownTimer >= lbl_803E72F8)
            {
                state->hitCooldownTimer -= timeDelta;
            }
            if (hit != 0 && hit != OBJHITREACT_COLLISION_SKIP_REACTION && state->hitCooldownTimer <= lbl_803E72F8)
            {
                if (state->flags & TREE_FLAG_HIT_WITH_POSITION)
                {
                    colorVec[0] += playerMapOffsetX;
                    colorVec[2] += playerMapOffsetZ;
                    objLightFn_8009a1dc((void*)obj, lbl_803E7314, burstVec, 1, 0);
                    Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
                }
                if (state->flags & TREE_FLAG_BURST_MODE_MASK)
                {
                    intensity = state->scale;
                    *(colorPtr = &colorVec[0]) = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 0];
                    colorVec[1] = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 1];
                    colorVec[2] = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 2];
                    vecRotateZXY((int)obj, colorPtr);
                    objfx_spawnRandomBurstLegacy(obj, state->flags & TREE_FLAG_BURST_MODE_MASK, 0x14, burstVec,
                                                 state->scale * gTreeEffectColors[state->effectProfileIndex * 4 + 3],
                                                 0);
                }
                state->swayTimer = lbl_803E7318;
                state->hitCooldownTimer = lbl_803E731C;
                if (state->flags & TREE_FLAG_AMBIENT_EFFECTS)
                {
                    if (hit != 0)
                    {
                        for (i = 0; i < TREE_AMBIENT_EFFECT_COUNT; i++)
                        {
                            if ((void*)state->ambientEffectHandles[i] != NULL)
                            {
                                if ((*(int (**)(int))(*(int*)(*(int*)(state->ambientEffectHandles[i] + 0x68)) + 0x28))(
                                        state->ambientEffectHandles[i]) > 1)
                                {
                                    ObjHits_RecordObjectHit(state->ambientEffectHandles[i], (int)obj, 0xe, 1, 0);
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
                    state->lastPlayerDistance >= state->proximityRadius && state->playerBurstCooldown <= lbl_803E72F8)
                {
                    intensity = state->scale;
                    *(colorPtr = &colorVec[0]) = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 0];
                    colorVec[1] = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 1];
                    colorVec[2] = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 2];
                    vecRotateZXY((int)obj, colorPtr);
                    objfx_spawnRandomBurstLegacy(obj, state->flags & TREE_FLAG_BURST_MODE_MASK, 0x14, burstVec,
                                                 state->scale * gTreeEffectColors[state->effectProfileIndex * 4 + 3],
                                                 1);
                    state->playerBurstCooldown = lbl_803E7320;
                }
                state->ambientBurstTimer -= timeDelta;
                if (state->ambientBurstTimer <= lbl_803E72F8)
                {
                    intensity = state->scale;
                    *(colorPtr = &colorVec[0]) = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 0];
                    colorVec[1] = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 1];
                    colorVec[2] = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 2];
                    vecRotateZXY((int)obj, colorPtr);
                    objfx_spawnRandomBurstLegacy(obj, state->flags & TREE_FLAG_BURST_MODE_MASK, 1, burstVec,
                                                 state->scale * gTreeEffectColors[state->effectProfileIndex * 4 + 3],
                                                 0);
                    state->ambientBurstTimer += lbl_803E7324;
                }
            }
            state->lastPlayerDistance = playerDist;
        }
    }
}
#pragma opt_common_subs reset

f32 gTreeEffectColors[] = {
    0.0f, 250.0f, 0.0f, 80.0f,  0.0f,  250.0f, 0.0f, 110.0f, 25.0f, 200.0f, 0.0f, 80.0f,  0.0f, 100.0f, 0.0f, 60.0f,
    0.0f, 200.0f, 0.0f, 140.0f, 0.0f,  250.0f, 0.0f, 160.0f, 0.0f,  200.0f, 0.0f, 100.0f, 0.0f, 350.0f, 0.0f, 130.0f,
    0.0f, 350.0f, 0.0f, 130.0f, 25.0f, 300.0f, 0.0f, 80.0f,  0.0f,  50.0f,  0.0f, 50.0f,
};

/* descriptor/ptr table auto 0x8032bc90-0x8032bd00 */
ObjectDescriptor gTreeObjDescriptor = {
    0,
    0,
    0,
    0x00090000,
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

ObjectDescriptor gBrokenPipeObjDescriptor = {
    0,
    0,
    0,
    0x00090000,
    NULL,
    NULL,
    NULL,
    (ObjectDescriptorCallback)brokenpipe_init,
    (ObjectDescriptorCallback)brokenpipe_update,
    NULL,
    NULL,
    NULL,
    NULL,
    brokenpipe_getExtraSize,
};
