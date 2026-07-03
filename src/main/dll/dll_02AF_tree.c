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
#include "main/game_object.h"

#define TREE_AMBIENT_EFFECT_COUNT 3
#define TREE_AMBIENT_EFFECT_OBJECT_ID 0x210
#define TREE_AMBIENT_EFFECT_SETUP_SIZE 0x28
#define TREE_OBJECT_FLAGS_INIT 0x2000
#define TREE_RESET_HITBOX_FLAG INTERACT_FLAG_DISABLED /* 0x08 */
#define TREE_FLAG_BURST_MODE_MASK 0x0f
#define TREE_FLAG_PLAYER_PROXIMITY_BURST 0x10
#define TREE_FLAG_HIT_ENABLED 0x20
/* two-bit mask (0x40|0x80); intentionally includes the AMBIENT_EFFECTS bit */
#define TREE_FLAG_HIT_WITH_POSITION 0xc0
#define TREE_FLAG_AMBIENT_EFFECTS 0x80
#define TREE_FLAG_DISABLE_PLAYER_PROXIMITY 0x100

typedef struct TreeSetup
{
    ObjPlacement base;
    u8 rotZ;
    u8 rotY;
    u8 rotX;
    u8 scale;
    u8 flagsLo;
    u8 proximityRadiusHalf;
    u8 flagsHi;
    u8 pad1F;
    u8 colorR;
    u8 colorG;
    u8 colorB;
} TreeSetup;

typedef struct TreeAmbientEffectSetup
{
    ObjPlacement base;
    int sourceObject;
    u16 animFrame;
    s16 unk1E; /* always 0 at spawn */
    u8 colorA[3]; /* opaque setup channels consumed by the ambient-effect DLL */
    u8 colorB[2]; /* opaque setup channels consumed by the ambient-effect DLL */
    s8 verticalDrift;
    s16 modelId;
} TreeAmbientEffectSetup;

typedef struct TreeState
{
    int ambientEffectHandles[TREE_AMBIENT_EFFECT_COUNT];
    f32 ambientEffectPos[TREE_AMBIENT_EFFECT_COUNT][3];
    f32 ambientSpawnTimers[TREE_AMBIENT_EFFECT_COUNT];
    f32 playerBurstCooldown;
    f32 ambientBurstTimer;
    f32 swayTimer;
    f32 scale;
    f32 hitCooldownTimer;
    f32 hitEffectCooldown;
    u16 proximityRadius;
    u16 lastPlayerDistance;
    u16 flags;
    u16 effectProfileIndex;
} TreeState;

STATIC_ASSERT(offsetof(TreeSetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(TreeSetup, scale) == 0x1b);
STATIC_ASSERT(offsetof(TreeSetup, flagsLo) == 0x1c);
STATIC_ASSERT(offsetof(TreeSetup, proximityRadiusHalf) == 0x1d);
STATIC_ASSERT(offsetof(TreeSetup, flagsHi) == 0x1e);
STATIC_ASSERT(offsetof(TreeSetup, colorR) == 0x20);
STATIC_ASSERT(offsetof(TreeSetup, colorB) == 0x22);
STATIC_ASSERT(offsetof(TreeAmbientEffectSetup, sourceObject) == 0x18);
STATIC_ASSERT(offsetof(TreeAmbientEffectSetup, animFrame) == 0x1c);
STATIC_ASSERT(offsetof(TreeAmbientEffectSetup, colorA) == 0x20);
STATIC_ASSERT(sizeof(TreeAmbientEffectSetup) == TREE_AMBIENT_EFFECT_SETUP_SIZE);
STATIC_ASSERT(offsetof(TreeState, ambientEffectPos) == 0xc);
STATIC_ASSERT(offsetof(TreeState, ambientSpawnTimers) == 0x30);
STATIC_ASSERT(offsetof(TreeState, playerBurstCooldown) == 0x3c);
STATIC_ASSERT(offsetof(TreeState, scale) == 0x48);
STATIC_ASSERT(offsetof(TreeState, hitEffectCooldown) == 0x50);
STATIC_ASSERT(offsetof(TreeState, proximityRadius) == 0x54);
STATIC_ASSERT(offsetof(TreeState, lastPlayerDistance) == 0x56);
STATIC_ASSERT(offsetof(TreeState, flags) == 0x58);
STATIC_ASSERT(sizeof(TreeState) == 0x5c);

int tree_getExtraSize(void) { return sizeof(TreeState); }

void tree_spawnAmbientEffect(int obj, int p2, s8 index)
{
    TreeSetup* setup = (TreeSetup*)((GameObject*)obj)->anim.placementData;
    TreeState* state = (TreeState*)p2;
    TreeAmbientEffectSetup* effectSetup;
    int idx;
    int newObj;

    if (Obj_IsLoadingLocked())
    {
        newObj = Obj_AllocObjectSetup(TREE_AMBIENT_EFFECT_SETUP_SIZE, TREE_AMBIENT_EFFECT_OBJECT_ID);
        effectSetup = (TreeAmbientEffectSetup*)newObj;
        effectSetup->base.color[0] = setup->base.color[0];
        effectSetup->base.color[2] = setup->base.color[2];
        effectSetup->base.color[1] = setup->base.color[1];
        effectSetup->base.color[3] = setup->base.color[3] - 0xa;
        idx = index;
        effectSetup->base.posX = state->ambientEffectPos[idx][0];
        effectSetup->base.posY = state->ambientEffectPos[idx][1];
        effectSetup->base.posZ = state->ambientEffectPos[idx][2];
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
        state->ambientEffectHandles[idx] =
            Obj_SetupObject(newObj, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                            *(int*)&((GameObject*)obj)->anim.parent);
    }
}

void tree_updateAmbientEffects(int obj, int state)
{
    int i;
    TreeState* ts;

    if (((GameObject*)obj)->unkF8 != 0)
    {
        ts = (TreeState*)state;
        for (i = 0; i < TREE_AMBIENT_EFFECT_COUNT; i++)
        {
            if ((void*)((TreeState*)state)->ambientEffectHandles[i] == NULL)
            {
                ((TreeState*)state)->ambientSpawnTimers[i] -= timeDelta;
                if (((TreeState*)state)->ambientSpawnTimers[i] <= lbl_803E72F8)
                {
                    ((TreeState*)state)->ambientSpawnTimers[i] = randomGetRange(0x3c, 0x12c);
                    tree_spawnAmbientEffect(obj, state, i);
                }
            }
            else
            {
                if ((*(int (**)(int))(*(int*)(*(int*)(((TreeState*)state)->ambientEffectHandles[i] + 0x68)) + 0x28))(
                    ((TreeState*)state)->ambientEffectHandles[i]) > 3)
                {
                    ((TreeState*)state)->ambientEffectHandles[i] = 0;
                }
                else
                {
                    (*(void (**)(int, int))(*(int*)(*(int*)(((TreeState*)state)->ambientEffectHandles[i] + 0x68)) + 0x24))(
                        ((TreeState*)state)->ambientEffectHandles[i], (int)&ts->ambientEffectPos[i][0]);
                }
            }
        }
    }
}

void tree_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    TreeSetup* setup = (TreeSetup*)((GameObject*)obj)->anim.placementData;
    TreeState* state = ((GameObject*)obj)->extra;
    int i;

    if (visible != 0)
    {
        fn_8003B608(setup->colorR, setup->colorG, setup->colorB);
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7308);
        if (state->flags & TREE_FLAG_AMBIENT_EFFECTS)
        {
            for (i = 0; i < TREE_AMBIENT_EFFECT_COUNT; i++)
            {
                ObjPath_GetPointWorldPosition(obj, i, &state->ambientEffectPos[i][0],
                                              &state->ambientEffectPos[i][1], &state->ambientEffectPos[i][2], 0);
            }
        }
        ((GameObject*)obj)->unkF8 = 1;
    }
}

void tree_init(int obj, u8* setup)
{
    GameObject* object = (GameObject*)obj;
    TreeSetup* setupData = (TreeSetup*)setup;
    TreeState* state = object->extra;
    ObjAnimEventList animOut;

    state->swayTimer = lbl_803E730C;
    state->ambientBurstTimer = lbl_803E72F8;
    state->proximityRadius = setupData->proximityRadiusHalf << 1;
    state->flags = setupData->flagsHi;
    state->flags = state->flags << 8;
    state->flags |= setupData->flagsLo;
    state->playerBurstCooldown = lbl_803E72F8;
    object->anim.rotZ = (s16)(setupData->rotZ << 8);
    object->anim.rotY = (s16)(setupData->rotY << 8);
    object->anim.rotX = (s16)(setupData->rotX << 8);
    *(u8*)&object->anim.resetHitboxMode |= TREE_RESET_HITBOX_FLAG;
    object->objectFlags |= TREE_OBJECT_FLAGS_INIT;
    object->unkF8 = 0;
    if (setupData->scale != 0)
    {
        state->scale = (f32)(u32)setupData->scale / gTreeScaleByteNormalizer;
        object->anim.rootMotionScale = state->scale;
        if (object->anim.rootMotionScale == lbl_803E72F8)
        {
            object->anim.rootMotionScale = lbl_803E7308;
        }
        object->anim.rootMotionScale = object->anim.rootMotionScale * object->anim.modelInstance->rootMotionScaleBase;
    }
    else
    {
        state->scale = lbl_803E7308;
    }
    ObjAnim_SetCurrentMove(obj, 0, lbl_803E72F8, 0);
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E7308, *(f32*)&lbl_803E7308, &animOut);
    if (state->flags & TREE_FLAG_AMBIENT_EFFECTS)
    {
        state->flags |= TREE_FLAG_HIT_ENABLED;
    }
    switch (object->anim.seqId)
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
        ObjHitbox_SetCapsuleBounds(obj, (int)(lbl_803E732C * object->anim.rootMotionScale), -0x5, 0x64);
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
        ObjHits_DisableObject(obj);
    }
}

void tree_update(int obj)
{
    GameObject* object = (GameObject*)obj;
    TreeState* state = object->extra;
    int hit;
    int player;
    int i;
    u16 playerDist;
    f32 dx, dz, dist;
    int hitObject;      /* out-params required by API, not read by this fn */
    int hitSphereIndex; /* out-params required by API, not read by this fn */
    u32 hitVolume;     /* out-params required by API, not read by this fn */
    f32 colorVec[3]; /* dual role: hit world-position outparam, then scaled effect colour */
    f32 burstVec[3];
    f32 intensity;
    f32* p;
    ObjAnimEventList animOut;

    ObjAnim_AdvanceCurrentMove(state->swayTimer, timeDelta, obj, &animOut);
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
            tree_updateAmbientEffects(obj, (int)state);
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
                    *(p = &colorVec[0]) = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 0];
                    colorVec[1] = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 1];
                    colorVec[2] = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 2];
                    vecRotateZXY(obj, p);
                    objfx_spawnRandomBurst(obj, state->flags & TREE_FLAG_BURST_MODE_MASK, 0x14, burstVec,
                                           state->scale * gTreeEffectColors[state->effectProfileIndex * 4 + 3], 0);
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
                                    ObjHits_RecordObjectHit(state->ambientEffectHandles[i], obj, 0xe, 1, 0);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        player = Obj_GetPlayerObject();
        if ((void*)player == NULL || (state->flags & TREE_FLAG_DISABLE_PLAYER_PROXIMITY) ||
            !(state->flags & TREE_FLAG_BURST_MODE_MASK))
        {
            return;
        }
        {
            dx = object->anim.localPosX - ((GameObject*)player)->anim.localPosX;
            dz = object->anim.localPosZ - ((GameObject*)player)->anim.localPosZ;
            dist = sqrtf(dx * dx + dz * dz);
            playerDist = dist;
            if (playerDist < state->proximityRadius)
            {
                if ((state->flags & TREE_FLAG_PLAYER_PROXIMITY_BURST) &&
                    state->lastPlayerDistance >= state->proximityRadius &&
                    state->playerBurstCooldown <= lbl_803E72F8)
                {
                    intensity = state->scale;
                    *(p = &colorVec[0]) = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 0];
                    colorVec[1] = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 1];
                    colorVec[2] = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 2];
                    vecRotateZXY(obj, p);
                    objfx_spawnRandomBurst(obj, state->flags & TREE_FLAG_BURST_MODE_MASK, 0x14, burstVec,
                                           state->scale * gTreeEffectColors[state->effectProfileIndex * 4 + 3], 1);
                    state->playerBurstCooldown = lbl_803E7320;
                }
                state->ambientBurstTimer -= timeDelta;
                if (state->ambientBurstTimer <= lbl_803E72F8)
                {
                    intensity = state->scale;
                    *(p = &colorVec[0]) = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 0];
                    colorVec[1] = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 1];
                    colorVec[2] = intensity * gTreeEffectColors[state->effectProfileIndex * 4 + 2];
                    vecRotateZXY(obj, p);
                    objfx_spawnRandomBurst(obj, state->flags & TREE_FLAG_BURST_MODE_MASK, 1, burstVec,
                                           state->scale * gTreeEffectColors[state->effectProfileIndex * 4 + 3], 0);
                    state->ambientBurstTimer += lbl_803E7324;
                }
            }
            state->lastPlayerDistance = playerDist;
        }
    }
}
