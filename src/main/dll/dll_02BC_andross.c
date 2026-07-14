/*
 * andross (DLL 0x2BC) - the final Andross boss, fought from the Arwing.
 *
 * andross_update is the whole fight: it caches the player's Arwing
 * (getArwing) plus the two hand objects (0x47b78 / 0x47b6a) and the brain
 * light-anchor object (0x47dd9), then runs a two-level state machine over
 * AndrossState - an outer fightPhase (1..6) selecting the move set and an
 * inner actionState driving each animation move via ObjAnim_SetCurrentMove.
 * Each tick it tracks a swaying target position (K*sin(t) + home + clamped
 * Arwing delta), applies a spring toward it, advances the move, spawns hand
 * shots / projectiles, drives the screen distortion filter, and feeds the
 * Arwing's aim toward nearby helper objects. Fade-out and the final warp
 * (0x4e) happen once the boss-clear game bits (2/3/4) are set.
 *
 * Game bits: game bit 0xD is the attack-window flag (set/cleared around
 * phase transitions and move entry, distinct from actionState case 0xD),
 * 0xF/0x10 sequence sub-
 * moves, 0x12 the spawn cooldown, 0x108..0x10D the six random hit cues, and
 * 0x405/0x4B1/1 the clear/credits transition.
 */
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/pi_dolphin_api.h"
#include "main/map_load.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objtexture.h"
#include "main/vecmath.h"
#include "main/dll/tricky.h"
#include "main/newshadows.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/obj_group.h"
#include "main/obj_list.h"
#include "main/obj_path.h"
#include "main/dll/dll_02BC_andross.h"

s16 gAndrossSwayPhaseX;
s16 gAndrossSwayPhaseY;
s16 gGfLevelConRingProjectilePitchSource;
s16 gGfLevelConProjectileYaw;
int gGfLevelConRingProjectilePitch;
int gGfLevelConProjectilePitch;
f32 gAndrossDistortPhase;
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/dll/dll_02BE_androssbrain.h"
#include "main/dll/dll_02BB_gflevelcon.h"
#include "main/dll/dll_02BD_androsshand.h"
#include "main/dll/ARW/dll_029F_arwbombcoll.h"
#include "main/model.h"
#include "main/rcp_dolphin_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/object_render_legacy.h"

#define GAMEBIT_ANDROSS_HIT_CUE_BASE 0x108 /* six consecutive random-hit cue bits */

#define ANDROSS_CHILD_OBJ_SPAWNED 0x819 /* cached into state->spawnedObj w/ spawnedObjLifetime */

#define ANDROSS_CHILD_OBJ_PROJECTILE_SPREAD 0x80d
#define ANDROSS_CHILD_OBJ_PROJECTILE_AIMED  0x7e4
#define ANDROSS_CHILD_OBJ_PROJECTILE_RING   0x859
#define ANDROSS_CHILD_OBJ_MARKER_ATTACH     0x608

#define ANDROSS_MAP_SHRINE 0xb /* Krazoa shrine map warped to on fight completion */

typedef struct AndrossChildSetup
{
    ObjPlacement base;
    u8 unk18[8];
    s16 flags;
} AndrossChildSetup;

extern int animatedObjGetSeqId(int obj);
extern void turnOnDistortionFilter(f32* pos, f32 a, u32* color, f32 c);

#pragma dont_inline on
void fn_80239DD8(GameObject* obj, AndrossState* state)
{
    f32 maxDist;
    GameObject* nearObj;
    ObjPlacement* newObj;

    maxDist = 10000.0f;
    if (Obj_IsLoadingLocked())
    {
        nearObj = ObjList_FindNearestObjectByDefNo(obj, 0x7e5, &maxDist);
        if (nearObj != NULL)
        {
            newObj = Obj_AllocObjectSetup(0x24, ANDROSS_CHILD_OBJ_MARKER_ATTACH);
            newObj->posX = nearObj->anim.localPosX;
            newObj->posY = nearObj->anim.localPosY;
            newObj->posZ = nearObj->anim.localPosZ;
            newObj->color[0] = 1;
            newObj->color[1] = 1;
            state->effectHandle = loadObjectAtObject(obj, newObj);
            if (state->effectHandle != NULL)
            {
                state->effectHandle->anim.alpha = 0xff;
                *(u8*)((int)state->effectHandle + 0x37) = 0xff;
                state->effectLifetime = 0x12c;
            }
        }
    }
}
#pragma dont_inline reset

void fn_80239EAC(GameObject* obj, AndrossState* state)
{
    f32 dx, dy, dz;
    int* objs;
    int cur;
    int i;
    int count;
    int defNo;

    {
        u32* objList = ObjGroup_GetObjects(2, &count);
        for (i = 0, objs = (int*)objList; i < count; i++)
        {
            cur = *objs;
            defNo = *(s16*)(*(int*)&((GameObject*)cur)->anim.placementData);
            if (defNo == ANDROSS_CHILD_OBJ_PROJECTILE_SPREAD || defNo == ANDROSS_CHILD_OBJ_PROJECTILE_RING)
            {
                dy = state->cachedPosY - ((GameObject*)cur)->anim.localPosY;
                dz = state->cachedPosZ - ((GameObject*)cur)->anim.localPosZ;
                dx = state->cachedPosX - ((GameObject*)cur)->anim.localPosX;
                ((GameObject*)cur)->anim.rotX = getAngle(dx, dz);
                ((GameObject*)cur)->anim.rotY = -(s16)getAngle(dy, dz);
                arwprojectile_placeForward((GameObject*)(cur), (f32)(int)gAndrossProjectileForwardStep);
            }
            objs++;
        }
    }
}

void fn_80239FCC(GameObject* obj, AndrossState* state)
{
    f32 ang;
    int rndDur;
    GfProjectileSetup* newObj;
    int proj;
    int yaw;
    s16 rndYaw;

    if (Obj_IsLoadingLocked())
    {
        yaw = gGfLevelConProjectileYaw;
        gGfLevelConRingProjectilePitch = gGfLevelConRingProjectilePitchSource;
        rndYaw = randomGetRange(-0x8000, 0x7fff);
        rndDur = randomGetRange(0x64, 0x12c);
        newObj = (GfProjectileSetup*)Obj_AllocObjectSetup(0x20, ANDROSS_CHILD_OBJ_PROJECTILE_RING);
        ang = 3.1415927f * (f32)(int)rndYaw / 32768.0f;
        newObj->head.posX = (f32)(int)rndDur * mathSinf(ang) + state->arwingObj->anim.localPosX;
        newObj->head.posY = (f32)(int)rndDur * mathCosf(ang) + state->arwingObj->anim.localPosY;
        newObj->head.posZ = state->cachedPosZ - 500.0f;
        newObj->yawHi = (obj->anim.rotX + yaw) >> 8;
        newObj->pitch = gGfLevelConRingProjectilePitch;
        newObj->roll = 0;
        newObj->head.color[0] = 1;
        newObj->head.color[1] = 1;
        proj = (int)loadObjectAtObject(obj, &newObj->head);
        if ((u32)proj != 0)
        {
            ((GameObject*)proj)->anim.rootMotionScale = gAndrossRingProjectileScale;
            arwprojectile_setLifetime((GameObject*)(proj), gAndrossRingProjectileLifetime);
            arwprojectile_placeForward((GameObject*)(proj), 7.0f);
        }
    }
}

void fn_8023A168(GameObject* obj, AndrossState* state)
{
    int proj;
    int yawRnd;
    int pitchRnd;
    GfProjectileSetup* newObj;

    if (Obj_IsLoadingLocked())
    {
        yawRnd = (s16)(randomGetRange(-0x1f40, 0x1f40) - 0x8000);
        pitchRnd = randomGetRange(-0x1f40, 0x1f40) >> 8;
        newObj = (GfProjectileSetup*)Obj_AllocObjectSetup(0x20, ANDROSS_CHILD_OBJ_PROJECTILE_SPREAD);
        newObj->head.posX = state->cachedPosX;
        newObj->head.posY = state->cachedPosY;
        newObj->head.posZ = state->cachedPosZ;
        newObj->yawHi = (obj->anim.rotX + yawRnd) >> 8;
        newObj->pitch = pitchRnd;
        newObj->roll = 0;
        newObj->head.color[0] = 1;
        newObj->head.color[1] = 1;
        proj = (int)loadObjectAtObject(obj, &newObj->head);
        if ((void*)proj != NULL)
        {
            ((GameObject*)proj)->anim.rootMotionScale = 5.0f;
            arwprojectile_setLifetime((GameObject*)(proj), 0x6e);
            arwprojectile_placeForward((GameObject*)(proj), 7.0f);
        }
    }
}

void fn_8023A268(GameObject* obj, AndrossState* state, int p3)
{
    f32 dx, dz, dist;
    int yaw;
    GfProjectileSetup* newObj;

    if (Obj_IsLoadingLocked())
    {
        dx = state->cachedPosX - state->arwingObj->anim.localPosX;
        dz = state->cachedPosZ - state->arwingObj->anim.localPosZ;
        dist = sqrtf(dx * dx + dz * dz);
        yaw = (u16)getAngle(dx, dz);
        gGfLevelConProjectilePitch = (u16)getAngle(state->cachedPosY - state->arwingObj->anim.localPosY, dist) >> 8;
        newObj = (GfProjectileSetup*)Obj_AllocObjectSetup(0x20, ANDROSS_CHILD_OBJ_PROJECTILE_AIMED);
        newObj->head.posX = state->cachedPosX;
        newObj->head.posY = state->cachedPosY;
        newObj->head.posZ = state->cachedPosZ;
        newObj->yawHi = (obj->anim.rotX + yaw) >> 8;
        newObj->pitch = gGfLevelConProjectilePitch;
        newObj->roll = 0;
        newObj->head.color[0] = 1;
        newObj->head.color[1] = 1;
        obj = loadObjectAtObject(obj, &newObj->head);
        if (obj != NULL)
        {
            arwprojectile_setLifetime(obj, gAndrossAimedProjectileLifetime);
            arwprojectile_placeForward(obj, (f32)(int)gAndrossAimedProjectileSpeed);
        }
    }
}

void fn_8023A3E4(GameObject* obj, AndrossState* stateData)
{
    u32 hitVol;
    int hitType;
    int hitObj;
    int got;
    u8 partState;
    u8 texIdx;
    s8 textureState;
    u8* stateBytes = (u8*)stateData;
    ObjTextureRuntimeSlot* tex;

    got = ObjHits_GetPriorityHit(obj, &hitObj, &hitType, &hitVol);
    {
        u8 j;
        int off;
        for (j = 0; j < 4; j++)
        {
            int v = stateBytes[off = j + offsetof(AndrossState, partHitTimer)] - framesThisStep;
            if (v < 0)
                v = 0;
            stateBytes[off] = v;
        }
    }
    if (got != 0)
    {
        int ht = hitType;
        switch (ht)
        {
        case 0:
        case 1:
        case 2:
        {
            if (stateData->partHealth[ht] != 0 && stateData->partHitTimer[ht] == 0)
            {
                stateData->partHealth[ht] -= 1;
                stateData->partHitTimer[hitType] = 6;
                if (stateData->partHealth[hitType] != 0)
                    Sfx_PlayFromObject((int)obj, SFXTRIG_wmap_nameoff);
                else
                    Sfx_PlayFromObject((int)obj, SFXTRIG_en_barrelblow11);
                switch (hitType)
                {
                case 0:
                    stateData->rotXSpeed = -0xfa;
                    break;
                case 1:
                    stateData->rotXSpeed = 0xfa;
                    break;
                case 2:
                    stateData->rotYSpeed = -0xc8;
                    break;
                }
            }
            break;
        }
        case 3:
        {
            if (((GameObject*)hitObj)->anim.seqId == 0x605)
            {
                if (stateData->partHitTimer[ht] == 0 && stateData->partHealth[ht] != 0 && stateData->actionState == 0xc)
                {
                    Obj_SetModelColorFadeRecursive(obj, 0x19, 0xc8, 0, 0, 1);
                    stateData->partHealth[hitType] -= 1;
                    stateData->partHitTimer[hitType] = 0xc8;
                }
            }
            break;
        }
        }
    }
    {
        u8 i;
        for (i = 0; i < 3; i++)
        {
            int idx = i;
            if (stateData->partHealth[idx] != 0)
            {
                if (stateData->partHitTimer[idx] != 0)
                    stateData->partTextureState[idx] = 1;
                else
                    stateData->partTextureState[idx] = 0;
            }
            else
            {
                stateData->partTextureState[idx] = 2;
            }
            textureState = stateData->partTextureState[idx];
            partState = textureState;
            texIdx = gAndrossPartTextureIndices[idx];
            if ((u32)texIdx < 2 && (u8)textureState == 1)
                partState = 0;
            tex = objFindTexture(obj, texIdx * 2, 0);
            tex->textureId = partState << 8;
            if ((u32)texIdx == 2 && (u8)textureState == 1)
                textureState = 0;
            tex = objFindTexture(obj, texIdx * 2 + 1, 0);
            tex->textureId = (u8)textureState << 8;
        }
    }
}

void andross_setPartSignal(GameObject* obj, u8 signal)
{
    AndrossState* state;

    if ((void*)obj == NULL)
    {
        return;
    }
    state = (AndrossState*)obj->extra;
    state->signalFlags |= signal;
}
int fn_8023A6A4(AndrossState* state, f32 clampRange, f32 scale, f32 zVel)
{
    f32 mag, ang;
    f32 dx, dy, dz, dist;
    int yaw;
    int result;
    Vec3f vel;

    result = 0;
    dx = state->cachedPosX - state->arwingObj->anim.localPosX;
    dy = state->cachedPosY - state->arwingObj->anim.localPosY;
    dz = state->cachedPosZ - state->arwingObj->anim.localPosZ;
    dist = sqrtf(dx * dx + dy * dy);
    yaw = (s16)getAngle(dx, dy);
    if ((s16)getAngle(dist, dz) > 0x2ee0 && dz > gAndrossForwardDistanceThreshold)
        result = 1;
    mag = (dist / scale < -clampRange) ? -clampRange : ((dist / scale > clampRange) ? clampRange : dist / scale);
    ang = 3.1415927f * yaw / 32768.0f;
    state->velX = mag * mathSinf(ang);
    state->velY = mag * mathCosf(ang);
    arwarwing_getVelocity(&vel, state->arwingObj);
    state->velX -= vel.x * gAndrossArwingVelDamp;
    state->velY -= vel.y * gAndrossArwingVelDamp;
    state->velZ = zVel;
    return result;
}
void fn_8023A87C(GameObject* obj, AndrossState* andross)
{
    GameObject* spawned;

    spawned = andross->effectHandle;
    if (spawned != NULL)
    {
        spawned->anim.localPosZ -= 3.0f;
        andross->effectLifetime -= framesThisStep;
        if (andross->effectLifetime < 0)
        {
            arwbombcoll_setLifetime(andross->effectHandle, 5);
            andross->effectLifetime = 0;
            andross->effectHandle = 0;
        }
    }
    else
    {
        f32 cooldown = andross->spawnCooldown;
        f32 zero = gAndrossZero;
        if (cooldown >= zero)
        {
            andross->spawnCooldown = cooldown - timeDelta;
            if (andross->spawnCooldown < zero)
                fn_80239DD8(obj, andross);
        }
        else if ((u32)mainGetBit(GAMEBIT_AndrossRelated0012) != 0)
        {
            andross->spawnCooldown = (f32)(int)randomGetRange(1, 0x14);
            mainSetBits(GAMEBIT_AndrossRelated0012, 0);
        }
    }
}
int andross_SeqFn(GameObject* obj)
{
    AndrossState* state = obj->extra;
    int i;
    f32 fade;
    f32 alpha;
    int model;
    ModelRenderOp* op;

    state->fadeAlpha = gAndrossZero;
    fade = state->fadeAlpha;
    model = *(int*)Obj_GetActiveModel(obj);
    i = 0;
    alpha = 255.0f * fade;
    for (; i < ((ModelFileHeader*)model)->renderOpCount; i++)
    {
        op = ObjModel_GetRenderOp((ModelFileHeader*)model, i);
        op->alphaOverride = alpha;
    }
    return 0;
}
int andross_getExtraSize(void)
{
    return 0xec;
}
int andross_getObjectTypeId(void)
{
    return 0;
}
void andross_free(int obj)
{
    fn_8006CB24();
    Rcp_DisableDistortionFilter();
}
void andross_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}
void andross_hitDetect(void)
{
}
int gAndrossSpawnObjectIds[] = {
    0x0004AA57,
    0x0004AA66,
    0x0004AA96,
    0x0004AA97,
};

f32 gAndrossMoveAnimSpeeds[23] = {
    0.01f, 0.01f, 0.005f, 0.005f, 0.08f, 0.007f, 0.007f, 0.007f, 0.007f, 0.007f, 0.007f, 0.007f,
    0.03f, 0.03f, 0.02f,  0.02f,  0.01f, 0.02f,  0.02f,  0.02f,  0.02f,  0.007f, 0.003f,
};

ObjectDescriptor gAndrossObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)andross_init,
    (ObjectDescriptorCallback)andross_update,
    (ObjectDescriptorCallback)andross_hitDetect,
    (ObjectDescriptorCallback)andross_render,
    (ObjectDescriptorCallback)andross_free,
    (ObjectDescriptorCallback)andross_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)andross_getExtraSize,
};

void andross_update(int obj)
{
    GameObject* boss;
    AndrossState* state;
    u8 actionChanged;
    u8 phaseChanged;
    u8 spawnIndex;
    u8 pathIndex;
    s16 durationBeforeStep;
    u8 cueIndex;
    u8 delayIndex;
    u8 signalReceived;
    int index;
    GameObject* aimTarget;
    GameObject** spawnSlot;
    AndrossState* signalState;
    ModelFileHeader* model = NULL;
    ModelRenderOp* renderOp;
    AndrossChildSetup* childSetup;
    int rotationDelta;
    u32 val;
    u32 spawnArrayIndex;
    f32 fval;
    f32 fc;
    s16 sval;
    int found;
    s8 bval;
    int objId;
    f32 fa;
    f32 fb;
    s16 delayPair[2];
    Vec3f thrustB;
    Vec3f thrustA;
    Vec3f thrustBArg;
    Vec3f thrustAArg;
    Vec3f velAdd;
    Vec3f velArg3;
    Vec3f velCalc3;
    Vec3f velArg2;
    Vec3f velCalc2;
    Vec3f velArg1;
    Vec3f velCalc1;
    Vec3f velArg0;
    Vec3f velCalc0;
    f32 camActionParam;
    f32 searchDist0;
    f32 searchDist1;
    f32 searchDist2;
    f32 searchDist3;
    f32 searchDist;
    boss = (GameObject*)obj;
    state = boss->extra;
    actionChanged = 0;
    phaseChanged = 0;
    pathIndex = 0;
    if (state->startupDelay != 0)
    {
        state->startupDelay -= 1;
        return;
    }
    if (state->handObjA == NULL)
    {
        state->handObjA = ObjList_FindObjectById(0x47b78);
    }
    if (state->handObjB == NULL)
    {
        state->handObjB = ObjList_FindObjectById(0x47b6a);
    }
    if (state->lightAnchorObj == NULL)
    {
        state->lightAnchorObj = ObjList_FindObjectById(0x47dd9);
    }
    if (state->arwingObj == NULL)
    {
        state->arwingObj = (GameObject*)getArwing();
        if (state->arwingObj != NULL)
        {
            state->savedPosZ = state->arwingObj->anim.localPosZ;
            arwarwing_setFlightHalfWidth(state->arwingObj, gAndrossFlightHalfWidth);
        }
        else
        {
            return;
        }
    }
    for (spawnIndex = 0; spawnIndex < 4; spawnIndex++)
    {
        spawnArrayIndex = spawnIndex;
        spawnSlot = &state->spawnObj[spawnArrayIndex];
        if (*spawnSlot == NULL)
        {
            *spawnSlot = ObjList_FindObjectById(gAndrossSpawnObjectIds[spawnArrayIndex]);
            if (*spawnSlot != NULL)
            {
                state->spawnDelta[spawnArrayIndex].x = (*spawnSlot)->anim.localPosX - boss->anim.localPosX;
                state->spawnDelta[spawnArrayIndex].y = (*spawnSlot)->anim.localPosY - boss->anim.localPosY;
                state->spawnDelta[spawnArrayIndex].z = (*spawnSlot)->anim.localPosZ - boss->anim.localPosZ;
            }
        }
        else
        {
            (*spawnSlot)->anim.localPosX = boss->anim.localPosX + state->spawnDelta[spawnArrayIndex].x;
            (*spawnSlot)->anim.localPosY = boss->anim.localPosY + state->spawnDelta[spawnArrayIndex].y;
            (*spawnSlot)->anim.localPosZ = boss->anim.localPosZ + state->spawnDelta[spawnArrayIndex].z;
        }
    }
    index = state->fightPhase;
    if (index != state->prevFightPhase)
    {
        phaseChanged = 1;
    }
    state->prevFightPhase = index;
    fval = gAndrossZero;
    state->velX = gAndrossZero;
    state->velY = fval;
    state->velZ = fval;
    if (-0x4000 < state->targetRotX && boss->anim.rotX < 0x4000)
    {
        pathIndex = 1;
    }
    ObjPath_GetPointWorldPosition((GameObject*)obj, pathIndex, &state->cachedPosX, &state->cachedPosY,
                                  &state->cachedPosZ, 0);
    if (pathIndex == 1)
    {
        state->cachedPosY += 30.0f;
        state->cachedPosZ += 30.0f;
    }
    switch (state->fightPhase)
    {
    case 1:
        if (phaseChanged)
        {
            if (state->handsInitialized != 0)
            {
                state->handsInitialized = 0;
            }
            else
            {
                androsshand_setState(state->handObjA, 2, 1);
                androsshand_setState(state->handObjB, 2, 1);
            }
            state->hitsRemaining0 = 10;
            state->hitsRemaining1 = 10;
            state->hitsRemaining2 = 10;
        }
        if (state->actionPending != 0)
        {
            switch (state->actionState)
            {
            default:
            case 3:
            case 0x17:
                state->actionState = 0;
                break;
            case 0:
                state->actionState = 1;
                break;
            case 0x16:
                if (state->arwingFlightActive != 0)
                {
                    state->actionState = 0x17;
                }
                else
                {
                    state->actionState = 0;
                }
                break;
            }
            state->actionPending = 0;
        }
        break;
    case 2:
        if (phaseChanged)
        {
            state->signalFlags &= ~0x6;
            if (state->actionState == 0x16)
            {
                androsshand_setState(state->handObjA, 1, 1);
                androsshand_setState(state->handObjB, 1, 1);
            }
        }
        if (state->actionPending != 0)
        {
            switch (state->actionState)
            {
            default:
            case 5:
            case 0x16:
                state->actionState = 6;
                break;
            case 6:
                state->actionState = 7;
                break;
            case 7:
                state->actionState = 10;
                break;
            case 10:
                state->actionState = 0x12;
                break;
            case 0x14:
                state->actionState = 0xb;
                break;
            case 0x11:
                state->actionState = 0x16;
                state->targetRotX = 0x8000;
                state->fightPhase--;
            }
            state->actionPending = 0;
        }
        break;
    case 3:
        if (phaseChanged)
        {
            state->hitsRemaining0 = 0xf;
            state->hitsRemaining1 = 0xf;
            state->hitsRemaining2 = 0xf;
            state->actionState = 0;
            state->attackCycleCount = 0;
        }
        if (state->actionPending != 0)
        {
            switch (state->actionState)
            {
            default:
            case 0:
                state->actionState = 1;
                break;
            case 3:
                state->actionState = 4;
                break;
            case 4:
                state->attackCycleCount++;
                if (state->attackCycleCount > 3)
                {
                    state->fightPhase--;
                    state->actionState = 0x16;
                    state->targetRotX = 0;
                }
                else
                {
                    state->actionState = 0;
                }
                break;
            }
            state->actionPending = 0;
        }
        break;
    case 4:
        if (state->actionPending != 0)
        {
            switch (state->actionState)
            {
            default:
            case 5:
            case 0x16:
                state->actionState = 6;
                break;
            case 6:
                state->actionState = 7;
                break;
            case 7:
                state->actionState = 10;
                break;
            case 10:
                state->actionState = 0x12;
                break;
            case 0x14:
                state->actionState = 0xb;
                break;
            case 0xf:
                state->actionState = 9;
                break;
            case 9:
                state->actionState = 8;
                break;
            case 0x11:
                state->actionState = 0x18;
            }
            state->actionPending = 0;
        }
        break;
    case 5:
        if (phaseChanged)
        {
            state->actionState = 0xd;
            state->actionToggle = 0;
        }
        if (state->actionPending != 0)
        {
            switch (state->actionState)
            {
            default:
            case 0x1b:
                state->centralHealth = 3;
            case 0xf:
                state->actionState = 0x12;
                state->actionToggle = 0;
                break;
            case 0x14:
                switch (state->actionToggle)
                {
                case 0:
                    state->actionState = 0x15;
                    break;
                case 1:
                    state->actionState = 0xb;
                    break;
                }
                state->actionToggle ^= 1;
                break;
            case 0x15:
                state->actionState = 0x12;
                break;
            case 0x11:
                state->actionState = 0x18;
                break;
            case 0x19:
                state->fightPhase = 6;
                break;
            case 0x1a:
                state->actionState = 0x1b;
            }
            state->actionPending = 0;
        }
        break;
    case 6:
        if (phaseChanged)
        {
            state->actionState = 0x1c;
            state->actionToggle = 0;
        }
        break;
    }
    index = state->actionState;
    if (index != state->prevActionState)
    {
        actionChanged += 1;
    }
    state->prevActionState = index;
    switch (state->actionState)
    {
    case 0:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[0];
            }
            if (state->fightPhase == 1)
            {
                state->durationTimer = 180.0f;
            }
            else
            {
                state->durationTimer = 100.0f;
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -300.0f) ? -300.0f : ((fb > 300.0f) ? 300.0f : fb);
        fb = (fa < -50.0f) ? -50.0f : ((fa > 50.0f) ? 50.0f : fa);
        fa = mathSinf(3.1415927f * gAndrossSwayPhaseX / 32768.0f);
        state->targetPosX = gAndrossSwayAmplitudeX * fa + (state->homePosX + fc);
        fc = mathSinf(3.1415927f * gAndrossSwayPhaseY / 32768.0f);
        state->targetPosY = gAndrossSwayAmplitudeY * fc + (state->homePosY + fb);
        state->targetPosZ = state->homePosZ;
        state->durationTimer -= timeDelta;
        if (state->durationTimer < gAndrossZero)
        {
            state->actionPending = 1;
        }
        val = state->hitsRemaining0;
        val += state->hitsRemaining1;
        val += state->hitsRemaining2;
        if ((val & 0xffff) == 0)
        {
            state->fightPhase++;
            state->actionState = 5;
            state->actionPending = 0;
            mainSetBits(0xd, 0);
        }
        break;
    case 1:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0xc, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[12];
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -300.0f) ? -300.0f : ((fb > 300.0f) ? 300.0f : fb);
        fb = (fa < -50.0f) ? -50.0f : ((fa > 50.0f) ? 50.0f : fa);
        fa = mathSinf(3.1415927f * gAndrossSwayPhaseX / 32768.0f);
        state->targetPosX = gAndrossSwayAmplitudeX * fa + (state->homePosX + fc);
        fc = mathSinf(3.1415927f * gAndrossSwayPhaseY / 32768.0f);
        state->targetPosY = gAndrossSwayAmplitudeY * fc + (state->homePosY + fb);
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= 1.0f)
        {
            state->actionState = 2;
            state->actionPending = 0;
        }
        val = state->hitsRemaining0;
        val += state->hitsRemaining1;
        val += state->hitsRemaining2;
        if ((val & 0xffff) == 0)
        {
            state->fightPhase++;
            state->actionState = 5;
            state->actionPending = 0;
            mainSetBits(0xd, 0);
        }
        break;
    case 2:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0xe, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[14];
            }
            state->durationTimer = 300.0f;
            state->actionTimer = 0xffff;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = fb < -300.0f ? -300.0f : fb > 300.0f ? 300.0f : fb;
        fb = fa < -50.0f ? -50.0f : fa > 50.0f ? 50.0f : fa;
        fa = mathSinf(3.1415927f * gAndrossSwayPhaseX / 32768.0f);
        state->targetPosX = gAndrossSwayAmplitudeX * fa + (state->homePosX + fc);
        fc = mathSinf(3.1415927f * gAndrossSwayPhaseY / 32768.0f);
        state->targetPosY = (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_roar1);
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0)
        {
            fn_8023A268((GameObject*)obj, state, 0);
            state->actionTimer = gAndrossRingSpawnInterval;
        }
        state->durationTimer -= timeDelta;
        if (state->durationTimer < gAndrossZero)
        {
            state->actionState = 3;
            state->actionPending = 0;
        }
        val = state->hitsRemaining0;
        val += state->hitsRemaining1;
        val += state->hitsRemaining2;
        if ((val & 0xffff) == 0)
        {
            state->fightPhase++;
            state->actionState = 5;
            state->actionPending = 0;
            mainSetBits(0xd, 0);
        }
        break;
    case 3:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0xd, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[13];
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -300.0f) ? -300.0f : ((fb > 300.0f) ? 300.0f : fb);
        fb = (fa < -200.0f) ? -200.0f
                                        : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= 1.0f)
        {
            state->actionPending = 1;
        }
        break;
    case 4:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[0];
            }
            mainSetBits(0xd, 1);
            state->durationTimer = 400.0f;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -300.0f) ? -300.0f : ((fb > 300.0f) ? 300.0f : fb);
        fb = (fa < -200.0f) ? -200.0f
                                        : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        state->durationTimer -= timeDelta;
        if (state->durationTimer < gAndrossZero)
        {
            state->actionPending = 1;
            mainSetBits(0xd, 0);
        }
        val = state->hitsRemaining0;
        val += state->hitsRemaining1;
        val += state->hitsRemaining2;
        if ((val & 0xffff) == 0)
        {
            state->fightPhase++;
            state->actionState = 5;
            state->actionPending = 0;
            mainSetBits(0xd, 0);
        }
        break;
    case 0x15:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[0];
            }
            mainSetBits(0xd, 1);
            state->durationTimer = 400.0f;
        }
        {
            for (cueIndex = 0; cueIndex < 6; cueIndex++)
            {
                if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    goto cue_done_0;
                }
            }
            state->timer -= framesThisStep;
            if (state->timer <= 0)
            {
                mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                state->timer = 0x3c;
            }
        cue_done_0:;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -300.0f) ? -300.0f : ((fb > 300.0f) ? 300.0f : fb);
        fb = (fa < -200.0f) ? -200.0f
                                        : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        state->durationTimer -= timeDelta;
        if (state->durationTimer < gAndrossZero)
        {
            state->actionPending = 1;
            mainSetBits(0xd, 0);
        }
        break;
    case 6:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[0];
            }
            androsshand_setState(state->handObjB, 4, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -150.0f) ? -150.0f
                                          : ((fb > 150.0f) ? 150.0f : fb);
        fb = (fa < -50.0f) ? -50.0f : ((fa > 50.0f) ? 50.0f : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (100.0f * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        signalReceived = 0;
        signalState = boss->extra;
        if ((signalState->signalFlags & 1) != 0)
        {
            signalState->signalFlags &= ~1;
            signalReceived = 1;
        }
        if (signalReceived)
        {
            state->actionPending = 1;
        }
        break;
    case 7:
        if (actionChanged)
        {
            androsshand_setState(state->handObjA, 4, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -150.0f) ? -150.0f
                                          : ((fb > 150.0f) ? 150.0f : fb);
        fb = (fa < -50.0f) ? -50.0f : ((fa > 50.0f) ? 50.0f : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (100.0f * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        signalReceived = 0;
        signalState = boss->extra;
        if ((signalState->signalFlags & 1) != 0)
        {
            signalState->signalFlags &= ~1;
            signalReceived = 1;
        }
        if (signalReceived)
        {
            state->actionPending = 1;
        }
        break;
    case 9:
        if (actionChanged)
        {
            androsshand_setState(state->handObjA, 6, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -300.0f) ? -300.0f : ((fb > 300.0f) ? 300.0f : fb);
        fb = (fa < -200.0f) ? -200.0f
                                        : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        signalReceived = 0;
        signalState = boss->extra;
        if ((signalState->signalFlags & 1) != 0)
        {
            signalState->signalFlags &= ~1;
            signalReceived = 1;
        }
        if (signalReceived)
        {
            state->actionPending = 1;
        }
        break;
    case 8:
        if (actionChanged)
        {
            androsshand_setState(state->handObjB, 6, 0);
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -300.0f) ? -300.0f : ((fb > 300.0f) ? 300.0f : fb);
        fb = (fa < -200.0f) ? -200.0f
                                        : ((fa > gAndrossSwayAmplitudeX) ? gAndrossSwayAmplitudeX : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (gAndrossSwayAmplitudeX * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        signalReceived = 0;
        signalState = boss->extra;
        if ((signalState->signalFlags & 1) != 0)
        {
            signalState->signalFlags &= ~1;
            signalReceived = 1;
        }
        if (signalReceived)
        {
            state->actionPending = 1;
        }
        break;
    case 10:
        if ((state->signalFlags & 6) == 6)
        {
            state->fightPhase++;
            if (state->fightPhase < 5)
            {
                Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
                state->actionState = 0x16;
                state->targetRotX = 0x8000;
            }
        }
        else
        {
            gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
            gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
            fb = (state->arwingObj->anim.localPosX - state->homePosX);
            fa = (state->arwingObj->anim.localPosY - state->homePosY);
            fc = (fb < -150.0f) ? -150.0f
                                              : ((fb > 150.0f) ? 150.0f : fb);
            fb = (fa < -50.0f) ? -50.0f : ((fa > 50.0f) ? 50.0f : fa);
            fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
            state->targetPosX = (100.0f * fa + (state->homePosX + fc));
            fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
            state->targetPosY = (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
            state->targetPosZ = state->homePosZ;
            if (actionChanged)
            {
                androsshand_setState(state->handObjA, 5, 0);
                androsshand_setState(state->handObjB, 5, 0);
            }
            signalReceived = 0;
            signalState = boss->extra;
            if ((signalState->signalFlags & 1) != 0)
            {
                signalState->signalFlags &= ~1;
                signalReceived = 1;
            }
            if (signalReceived)
            {
                state->actionPending = 1;
            }
        }
        break;
    case 0xb:
    case 0xd:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 1, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[1];
            }
            if (state->fightPhase < 5)
            {
                androsshand_setState(state->handObjA, 0, 0);
                androsshand_setState(state->handObjB, 0, 0);
            }
            else
            {
                androsshand_setState(state->handObjA, 9, 1);
                androsshand_setState(state->handObjB, 9, 1);
                state->signalFlags |= 6;
            }
        }
        if ((state->fightPhase == 5) && (state->actionState == 0xb))
        {
            for (cueIndex = 0; cueIndex < 6; cueIndex++)
            {
                if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    goto cue_done_1;
                }
            }
            state->timer -= framesThisStep;
            if (state->timer <= 0)
            {
                mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                state->timer = 0x3c;
            }
        cue_done_1:;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -20.0f) ? -20.0f
                           : ((fb > gAndrossSwayAmplitudeY) ? gAndrossSwayAmplitudeY : fb);
        fb = (fa < -50.0f) ? -50.0f : ((fa > 50.0f) ? 50.0f : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (gAndrossSwayAmplitudeY * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (10.0f * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= 1.0f)
        {
            switch (state->actionState)
            {
            default:
            case 0xb:
                state->actionState = 0xc;
                break;
            case 0xd:
                state->actionState = 0xe;
                break;
            }
        }
        fval = 0.5f * boss->anim.currentMoveProgress;
        if (fval < 0.5f)
        {
            fc = 1000.0f - 2.0f * (800.0f * fval);
            if (fval < 0.01f)
            {
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
            }
        }
        else
        {
            fc = 200.0f;
        }
        gAndrossDistortPhase += gAndrossDistortPhaseStep;
        if (gAndrossDistortPhase > 6.28318f)
        {
            gAndrossDistortPhase -= 6.28318f;
        }
        turnOnDistortionFilter(&state->cachedPosX, fc, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        break;
    case 0xe:
        fval = 0.5f * boss->anim.currentMoveProgress + 0.5f;
        if (fval < 0.5f)
        {
            fc = 1000.0f - 2.0f * (800.0f * fval);
            if (fval < 0.01f)
            {
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
            }
        }
        else
        {
            fc = 200.0f;
        }
        gAndrossDistortPhase += gAndrossDistortPhaseStep;
        if (gAndrossDistortPhase > 6.28318f)
        {
            gAndrossDistortPhase -= 6.28318f;
        }
        turnOnDistortionFilter(&state->cachedPosX, fc, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 2, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[2];
            }
            state->centralHealth = 0;
            mainSetBits(0x10, 0);
            state->actionTimer = gAndrossMissileAttackDuration;
            state->durationTimer = gAndrossZero;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -300.0f) ? -300.0f : ((fb > 300.0f) ? 300.0f : fb);
        fb = (fa < -150.0f) ? -150.0f
                                          : ((fa > 150.0f) ? 150.0f : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (20.0f * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (10.0f * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        fn_8023A6A4(state, gAndrossMissileClampRange, gAndrossMissileVelocityScale, gAndrossMissileForwardVelocity);
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_missileloop);
        if ((state->actionTimer != 0) && (state->actionTimer -= framesThisStep, state->actionTimer <= 0))
        {
            state->actionTimer = 0;
            mainSetBits(0xf, 1);
        }
        state->durationTimer -= timeDelta;
        if (state->durationTimer < gAndrossZero)
        {
            fn_80239FCC((GameObject*)obj, state);
            state->durationTimer += gAndrossMissileSpawnInterval;
        }
        fn_80239EAC((GameObject*)obj, state);
        if (mainGetBit(0x10) != 0)
        {
            mainSetBits(0x10, 0);
            state->actionState = 0x1a;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            gAndrossDistortPhase += gAndrossDistortPhaseStep;
            if (gAndrossDistortPhase > 6.28318f)
            {
                gAndrossDistortPhase -= 6.28318f;
            }
            turnOnDistortionFilter(&state->cachedPosX, 1000.0f, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        break;
    case 0xc:
        fval = 0.5f * boss->anim.currentMoveProgress + 0.5f;
        if (fval < 0.5f)
        {
            fc = 1000.0f - 2.0f * (800.0f * fval);
            if (fval < 0.01f)
            {
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
            }
        }
        else
        {
            fc = 200.0f;
        }
        gAndrossDistortPhase += gAndrossDistortPhaseStep;
        if (gAndrossDistortPhase > 6.28318f)
        {
            gAndrossDistortPhase -= 6.28318f;
        }
        turnOnDistortionFilter(&state->cachedPosX, fc, &gAndrossDistortFilterParam, gAndrossDistortPhase);
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 2, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[2];
            }
            if (state->fightPhase < 5)
            {
                state->centralHealth = 1;
            }
            state->actionTimer = gAndrossCentralAttackDuration;
            state->durationTimer = gAndrossZero;
        }
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_missileloop);
        if (state->fightPhase == 5)
        {
            for (cueIndex = 0; cueIndex < 6; cueIndex++)
            {
                if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    goto cue_done_2;
                }
            }
            state->timer -= framesThisStep;
            if (state->timer <= 0)
            {
                mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                state->timer = 0x3c;
            }
        cue_done_2:;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -50.0f) ? -50.0f : ((fb > 50.0f) ? 50.0f : fb);
        fb = (fa < -20.0f) ? -20.0f : ((fa > 20.0f) ? 20.0f : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (20.0f * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (10.0f * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        bval = fn_8023A6A4(state, gAndrossCentralMissileClampRange, gAndrossCentralMissileVelocityScale, gAndrossCentralMissileForwardVelocity);
        if (bval != 0)
        {
            state->actionState = 0xf;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            gAndrossDistortPhase += gAndrossDistortPhaseStep;
            if (gAndrossDistortPhase > 6.28318f)
            {
                gAndrossDistortPhase -= 6.28318f;
            }
            turnOnDistortionFilter(&state->cachedPosX, 1000.0f, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        state->durationTimer -= timeDelta;
        if (state->durationTimer < gAndrossZero)
        {
            fn_80239FCC((GameObject*)obj, state);
            state->durationTimer += gAndrossCentralMissileSpawnInterval;
        }
        fn_80239EAC((GameObject*)obj, state);
        if (state->hitReactionFlag != 0)
        {
            if (state->fightPhase == 5)
            {
                state->actionState = 0x19;
            }
            else
            {
                state->actionState = 0xf;
            }
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            gAndrossDistortPhase += gAndrossDistortPhaseStep;
            if (gAndrossDistortPhase > 6.28318f)
            {
                gAndrossDistortPhase -= 6.28318f;
            }
            turnOnDistortionFilter(&state->cachedPosX, 1000.0f, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        else
        {
            if (state->arwingObj->anim.localPosZ > state->cachedPosZ)
            {
                state->actionState = 0x10;
                state->arwingFlightActive = 1;
                state->arwingObj->anim.localPosZ = state->cachedPosZ;
                state->velZ = gAndrossZero;
                gAndrossDistortPhase = gAndrossDistortPhaseReset;
                gAndrossDistortPhase += gAndrossDistortPhaseStep;
                if (gAndrossDistortPhase > 6.28318f)
                {
                    gAndrossDistortPhase -= 6.28318f;
                }
                turnOnDistortionFilter(&state->cachedPosX, 1000.0f, &gAndrossDistortFilterParam,
                                       gAndrossDistortPhase);
                Rcp_DisableDistortionFilter();
                break;
            }
        }
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0)
        {
            state->actionState = 0xf;
            gAndrossDistortPhase = gAndrossDistortPhaseReset;
            gAndrossDistortPhase += gAndrossDistortPhaseStep;
            if (gAndrossDistortPhase > 6.28318f)
            {
                gAndrossDistortPhase -= 6.28318f;
            }
            turnOnDistortionFilter(&state->cachedPosX, 1000.0f, &gAndrossDistortFilterParam,
                                   gAndrossDistortPhase);
            Rcp_DisableDistortionFilter();
        }
        break;
    case 0xf:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x10, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[16];
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -200.0f) ? -200.0f
                                        : ((fb > 200.0f) ? 200.0f : fb);
        fb = (fa < -50.0f) ? -50.0f : ((fa > 50.0f) ? 50.0f : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (100.0f * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= 1.0f)
        {
            state->actionPending = 1;
        }
        break;
    case 0x10:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x10, gAndrossZero, 0);
                animState->animSpeed = 0.04f;
            }
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        {
            f32 deltaX = state->arwingObj->anim.localPosX - state->homePosX;
            f32 deltaY = state->arwingObj->anim.localPosY - state->homePosY;
            fc = (deltaX < 0.0f) ? 0.0f : ((deltaX > 0.0f) ? 0.0f : deltaX);
            fb = (deltaY < 0.0f) ? 0.0f : ((deltaY > 0.0f) ? 0.0f : deltaY);
        }
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (gAndrossZero * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (gAndrossZero * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        fc = state->cachedPosX - state->arwingObj->anim.localPosX;
        velCalc3.x = fc * gAndrossArwingApproachVelocityScale;
        fc = state->cachedPosY - state->arwingObj->anim.localPosY;
        velCalc3.y = fc * gAndrossArwingApproachVelocityScale;
        fc = state->cachedPosZ - state->arwingObj->anim.localPosZ;
        velCalc3.z = fc * gAndrossArwingApproachVelocityScale;
        velArg3 = velCalc3;
        arwarwing_setVelocity(state->arwingObj, (int)&velArg3);
        fval = (-300.0f > -(5.0f * timeDelta - state->camOffsetAccum))
                   ? -300.0f
                   : -(5.0f * timeDelta - state->camOffsetAccum);
        state->camOffsetAccum = fval;
        if (boss->anim.currentMoveProgress >= 1.0f)
        {
            state->arwingObj->anim.flags |= 0x4000;
            state->actionState = 0x11;
        }
        break;
    case 0x11:
        if (actionChanged)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_and_falcoflyby);
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x15, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[21];
            }
            arwarwing_addHealth(state->arwingObj, 0xfffffffc);
        }
        fval = (-300.0f > -(5.0f * timeDelta - state->camOffsetAccum))
                   ? -300.0f
                   : -(5.0f * timeDelta - state->camOffsetAccum);
        state->camOffsetAccum = fval;
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        {
            f32 deltaX = state->arwingObj->anim.localPosX - state->homePosX;
            f32 deltaY = state->arwingObj->anim.localPosY - state->homePosY;
            fc = (deltaX < 0.0f) ? 0.0f : ((deltaX > 0.0f) ? 0.0f : deltaX);
            fb = (deltaY < 0.0f) ? 0.0f : ((deltaY > 0.0f) ? 0.0f : deltaY);
        }
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (gAndrossZero * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (gAndrossZero * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= 1.0f)
        {
            state->actionPending = 1;
        }
        break;
    case 0x12:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x12, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[18];
            }
            androsshand_setState(state->handObjA, 0, 0);
            androsshand_setState(state->handObjB, 0, 0);
            if ((state->fightPhase == 5) && (state->actionToggle != 0))
            {
                mainSetBits(0xe, 1);
            }
        }
        state->fadeAlpha -= 0.05f;
        fval = (gAndrossZero > state->fadeAlpha) ? gAndrossZero : state->fadeAlpha;
        state->fadeAlpha = fval;
        {
            f32 fade = state->fadeAlpha;
            f32 alpha;

            model = *(ModelFileHeader**)Obj_GetActiveModel((GameObject*)obj);
            index = 0;
            alpha = 255.0f * fade;
            for (; index < model->renderOpCount; index++)
            {
                renderOp = ObjModel_GetRenderOpLegacy((int)model, index);
                renderOp->alphaOverride = alpha;
            }
        }
        if ((state->fightPhase == 5) && (state->actionToggle == 0))
        {
            for (cueIndex = 0; cueIndex < 6; cueIndex++)
            {
                if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    goto cue_done_3;
                }
            }
            state->timer -= framesThisStep;
            if (state->timer <= 0)
            {
                mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                state->timer = 0x3c;
            }
        cue_done_3:;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -300.0f) ? -300.0f : ((fb > 300.0f) ? 300.0f : fb);
        fb = (fa < -50.0f) ? -50.0f : ((fa > 50.0f) ? 50.0f : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (100.0f * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= 1.0f)
        {
            state->actionState = 0x13;
        }
        break;
    case 0x13:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x13, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[19];
            }
            if (state->fightPhase == 5)
            {
                state->durationTimer = 500.0f;
            }
            else
            {
                state->durationTimer = 300.0f;
            }
            state->actionTimer = 0xffff;
        }
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_and_spitout);
        if ((state->fightPhase == 5) && (state->actionToggle == 0))
        {
            for (cueIndex = 0; cueIndex < 6; cueIndex++)
            {
                if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    goto cue_done_4;
                }
            }
            state->timer -= framesThisStep;
            if (state->timer <= 0)
            {
                mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                state->timer = 0x3c;
            }
        cue_done_4:;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -500.0f) ? -500.0f
                                         : ((fb > 500.0f) ? 500.0f : fb);
        fb = (fa < -70.0f) ? -70.0f
                                          : ((fa > 70.0f) ? 70.0f : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (100.0f * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        state->actionTimer -= framesThisStep;
        durationBeforeStep = state->durationTimer;
        state->durationTimer -= framesThisStep;
        if (state->fightPhase == 5)
        {
            delayPair[0] = 300;
            delayPair[1] = 600;
        }
        else
        {
            delayPair[0] = 0x122;
            delayPair[1] = 0x28;
        }
        for (delayIndex = 0; delayIndex < 2; delayIndex++)
        {
            if ((((state->spawnedObj == NULL) && (state->actionTimer <= delayPair[delayIndex])) &&
                 (durationBeforeStep > delayPair[delayIndex])) &&
                (Obj_IsLoadingLocked() != 0))
            {
                childSetup =
                    (AndrossChildSetup*)Obj_AllocObjectSetup(sizeof(AndrossChildSetup), ANDROSS_CHILD_OBJ_SPAWNED);
                childSetup->base.posX = state->cachedPosX;
                childSetup->base.posY = state->cachedPosY;
                childSetup->base.posZ = state->cachedPosZ;
                childSetup->base.color[0] = 1;
                childSetup->base.color[1] = 1;
                childSetup->flags = -1;
                state->spawnedObj = loadObjectAtObject((GameObject*)obj, &childSetup->base);
                if (state->spawnedObj != NULL)
                {
                    state->spawnedObj->anim.alpha = 0xff;
                    state->spawnedObj->anim.pad37[0] = 0xff;
                    state->spawnedObjLifetime = gAndrossSpawnedObjectLifetime;
                }
            }
        }
        if (state->actionTimer < 0)
        {
            fn_8023A168((GameObject*)obj, state);
            state->actionTimer = gAndrossAsteroidSpawnInterval;
        }
        if (state->durationTimer < gAndrossZero)
        {
            state->actionState = 0x14;
        }
        break;
    case 0x14:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x14, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[20];
            }
        }
        if ((state->fightPhase == 5) && (state->actionToggle == 0))
        {
            for (cueIndex = 0; cueIndex < 6; cueIndex++)
            {
                if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    goto cue_done_5;
                }
            }
            state->timer -= framesThisStep;
            if (state->timer <= 0)
            {
                mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                state->timer = 0x3c;
            }
        cue_done_5:;
        }
        gAndrossSwayPhaseX += gAndrossSwayPhaseStepX;
        gAndrossSwayPhaseY += gAndrossSwayPhaseStepY;
        fb = (state->arwingObj->anim.localPosX - state->homePosX);
        fa = (state->arwingObj->anim.localPosY - state->homePosY);
        fc = (fb < -300.0f) ? -300.0f : ((fb > 300.0f) ? 300.0f : fb);
        fb = (fa < -100.0f) ? -100.0f
                                           : ((fa > 100.0f) ? 100.0f : fa);
        fa = mathSinf(((3.1415927f * gAndrossSwayPhaseX) / 32768.0f));
        state->targetPosX = (200.0f * fa + (state->homePosX + fc));
        fc = mathSinf(((3.1415927f * gAndrossSwayPhaseY) / 32768.0f));
        state->targetPosY = (gAndrossSwayAmplitudeY * fc + (state->homePosY + fb));
        state->targetPosZ = state->homePosZ;
        if (boss->anim.currentMoveProgress >= 1.0f)
        {
            state->actionPending = 1;
        }
        break;
    case 0x19:
    case 0x1a:
        if (actionChanged)
        {
            Sfx_PlayFromObject(obj, SFXTRIG__UNK_832);
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 4, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[4];
            }
        }
        if (boss->anim.currentMoveProgress >= 1.0f)
        {
            state->actionPending = 1;
        }
        break;
    case 0x1b:
        if (actionChanged)
        {
            mainSetBits(0x10, 0);
            state->actionTimer = 0x1e;
            arwarwing_resetFlightState(state->arwingObj);
            state->arwingObj->anim.localPosZ = state->savedPosZ;
            state->camOffsetAccum = gAndrossZero;
        }
        state->targetPosX = state->homePosX;
        state->targetPosY = state->homePosY;
        state->targetPosZ = state->homePosZ;
        if ((mainGetBit(0x10) != 0) && (state->actionTimer-- == 0))
        {
            mainSetBits(0x10, 0);
            state->actionPending = 1;
        }
        break;
    case 0x1c:
        if (actionChanged)
        {
            androssbrain_setState(state->lightAnchorObj, ANDROSSBRAIN_VULNERABLE, 0);
            ObjHits_DisableObject(obj);
            state->actionTimer = 0x3c;
            state->durationTimer = 3.0f;
            state->targetPosX = state->homePosX;
            state->targetPosY = state->homePosY;
            state->targetPosZ = state->homePosZ;
            fval = gAndrossZero;
            boss->anim.velocityX = gAndrossZero;
            boss->anim.velocityY = fval;
            boss->anim.velocityZ = fval;
            state->springStiffness = 0.01f;
            state->springDamping = 0.93f;
        }
        state->fadeAlpha += 0.05f;
        fval = (0.8f < state->fadeAlpha) ? 0.8f : state->fadeAlpha;
        state->fadeAlpha = fval;
        {
            for (cueIndex = 0; cueIndex < 6; cueIndex++)
            {
                if (mainGetBit(cueIndex + GAMEBIT_ANDROSS_HIT_CUE_BASE) != 0)
                {
                    state->timer = 0x3c;
                    goto cue_done_6;
                }
            }
            state->timer -= framesThisStep;
            if (state->timer <= 0)
            {
                mainSetBits(randomGetRange(0, 5) + GAMEBIT_ANDROSS_HIT_CUE_BASE, 1);
                state->timer = 0x3c;
            }
        cue_done_6:;
        }
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0)
        {
            state->durationTimer -= 1.0f;
            if (state->durationTimer < gAndrossZero)
            {
                state->actionToggle += 1;
                if (state->actionToggle > 3)
                {
                    state->fightPhase = 5;
                    state->prevFightPhase = 5;
                    state->actionToggle = 0;
                    state->actionState = 0x12;
                    androssbrain_setState(state->lightAnchorObj, ANDROSSBRAIN_SHIELDED, 0);
                    ObjHits_EnableObject(obj);
                }
                else
                {
                    state->actionState = 0x1d;
                }
            }
            else
            {
                state->actionTimer = randomGetRange(0x14, 0x1e);
                state->targetPosX =
                    (f32)(int)randomGetRange((int)-gAndrossSpawnRandX, gAndrossSpawnRandX) + state->homePosX;
                state->targetPosY =
                    (f32)(int)randomGetRange((int)-gAndrossSpawnRandY, gAndrossSpawnRandY) + state->homePosY;
                state->targetPosZ =
                    (f32)(int)randomGetRange((int)-gAndrossSpawnRandZ, gAndrossSpawnRandZ) + state->homePosZ;
            }
        }
        if ((state->signalFlags & 8) != 0)
        {
            arwingHudSetVisible(2);
            mainSetBits(1, 1);
            mainSetBits(0x4b1, 1);
            state->actionState = 0x1e;
            unlockLevel(0, 0, 1);
            objId = mapGetDirIdx(ANDROSS_MAP_SHRINE);
            mapUnload(objId, 0x20000000);
            Music_Trigger(MUSICTRIG_Mound_Music, 0);
        }
        {
            f32 fade = state->fadeAlpha;
            f32 alpha;

            model = *(ModelFileHeader**)Obj_GetActiveModel((GameObject*)obj);
            index = 0;
            alpha = 255.0f * fade;
            for (; index < model->renderOpCount; index++)
            {
                renderOp = ObjModel_GetRenderOpLegacy((int)model, index);
                renderOp->alphaOverride = alpha;
            }
        }
        break;
    case 0x1d:
        if (actionChanged)
        {
            androssbrain_setState(state->lightAnchorObj, ANDROSSBRAIN_VULNERABLE, 0);
            ObjHits_DisableObject(obj);
            state->actionTimer = gAndrossBrainAttackDuration;
            state->targetPosX = state->arwingObj->anim.localPosX;
            state->targetPosY = state->arwingObj->anim.localPosY + gAndrossSpawnOffsetY;
            state->targetPosZ = state->arwingObj->anim.localPosZ + gAndrossSpawnOffsetZ;
            fval = gAndrossZero;
            boss->anim.velocityX = gAndrossZero;
            boss->anim.velocityY = fval;
            boss->anim.velocityZ = fval;
            Sfx_PlayFromObject((int)boss,
                               randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
        }
        state->actionTimer -= framesThisStep;
        if (state->actionTimer < 0)
        {
            state->actionState = 0x1c;
        }
        break;
    case 0x16:
        if (actionChanged)
        {
            Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[0];
            }
        }
        if (state->arwingFlightActive != 0)
        {
            fc = state->cachedPosX - state->arwingObj->anim.localPosX;
            velCalc2.x = fc * gAndrossArwingReturnVelocityScale;
            fc = state->cachedPosY - state->arwingObj->anim.localPosY;
            velCalc2.y = fc * gAndrossArwingReturnVelocityScale;
            fc = state->cachedPosZ - state->arwingObj->anim.localPosZ;
            velCalc2.z = fc * gAndrossArwingReturnVelocityScale;
            velArg2 = velCalc2;
            arwarwing_setVelocity(state->arwingObj, (int)&velArg2);
            fval = (-600.0f > -(15.0f * timeDelta - state->camOffsetAccum))
                       ? -600.0f
                       : -(15.0f * timeDelta - state->camOffsetAccum);
            state->camOffsetAccum = fval;
        }
        sval = state->targetRotX - (u16)boss->anim.rotX;
        if (0x8000 < sval)
        {
            sval = sval - 0xffff;
        }
        if (sval < -0x8000)
        {
            sval = sval + 0xffff;
        }
        rotationDelta = sval;
        if (rotationDelta < 0)
        {
            rotationDelta = -rotationDelta;
        }
        if (rotationDelta < 2000)
        {
            AndrossHandState* leftHandState = state->handObjA->extra;
            AndrossHandState* rightHandState = state->handObjB->extra;

            bval = leftHandState->handState;
            if ((((bval != 2) && (bval != 1)) && (bval = rightHandState->handState, bval != 2)) && (bval != 1))
            {
                state->actionPending = 1;
            }
        }
        break;
    case 5:
    {
        AndrossHandState* rightHandState;
        AndrossHandState* leftHandState;
        AndrossState* animState;

        leftHandState = state->handObjA->extra;
        rightHandState = state->handObjB->extra;

        if (actionChanged)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_drak_roar1);
            {
                animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x16, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[22];
            }
            state->laughPlayed = 0;
            state->ringPlayed = 0;
        }
        fc = boss->anim.currentMoveProgress;
        if (fc < 0.6)
        {
            fc = mathSinf(
                ((3.1415927f * (float)(65536.0 * (0.25 * (fc / 0.6)))) /
                 32768.0f));
            state->targetPosZ = (500.0f * fc + state->homePosZ);
        }
        else
        {
            fc = mathSinf(
                ((3.1415927f * (float)(65536.0 *
                                       (0.75 * ((fc - 0.6) / 0.4) +
                                        0.25))) /
                 32768.0f));
            state->targetPosZ = gAndrossMoveTailDistance * fc + state->homePosZ;
        }
        if ((boss->anim.currentMoveProgress > 0.5) && (state->ringPlayed == 0))
        {
            Sfx_PlayFromObject(obj, randomGetRange(0, 1) != 0 ? SFXTRIG_and_ring_lp : SFXTRIG_and_chompf);
            state->ringPlayed = 1;
        }
        if ((boss->anim.currentMoveProgress > 0.65) && (state->laughPlayed == 0))
        {
            Sfx_PlayFromObject(obj, SFXTRIG_and_laugh);
            state->laughPlayed = 1;
        }
        bval = leftHandState->handState;
        if ((((bval != 2) && (bval != 1)) && (bval = rightHandState->handState, bval != 2)) && (bval != 1))
        {
            if (boss->anim.currentMoveProgress >= 1.0f)
            {
                state->actionPending = 1;
            }
            else if (boss->anim.currentMoveProgress > 0.5)
            {
                state->targetRotX = 0;
                androsshand_setState(state->handObjA, 1, (state->fightPhase == 4) + 1);
                androsshand_setState(state->handObjB, 1, (state->fightPhase == 4) + 1);
                state->signalFlags &= ~0x6;
            }
        }
        break;
    }
    case 0x17:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 3, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[3];
            }
            state->soundTimer = gAndrossZero;
            state->roarPlayed = 0;
        }
        state->soundTimer += timeDelta;
        if ((state->soundTimer > 60.0f) && (state->roarPlayed == 0))
        {
            Sfx_PlayFromObject(obj, SFXTRIG_drak_pain1);
            state->roarPlayed = 1;
        }
        if (boss->anim.currentMoveProgress <= gAndrossArwingPullProgressLimit)
        {
            state->cachedPosX = boss->anim.localPosX;
            state->cachedPosY = boss->anim.localPosY - 130.0f;
            state->cachedPosZ = boss->anim.localPosZ - 350.0f;
            fc = state->cachedPosX - state->arwingObj->anim.localPosX;
            velCalc1.x = fc * gAndrossArwingPullVelocityScale;
            fc = state->cachedPosY - state->arwingObj->anim.localPosY;
            velCalc1.y = fc * gAndrossArwingPullVelocityScale;
            fc = state->cachedPosZ - state->arwingObj->anim.localPosZ;
            velCalc1.z = fc * gAndrossArwingPullVelocityScale;
            velArg1 = velCalc1;
            arwarwing_setVelocity(state->arwingObj, (int)&velArg1);
        }
        else
        {
            fc = (state->savedPosZ - state->arwingObj->anim.localPosZ);
            fval = (gAndrossZero < 15.0f * timeDelta + state->camOffsetAccum)
                       ? gAndrossZero
                       : 15.0f * timeDelta + state->camOffsetAccum;
            state->camOffsetAccum = fval;
            state->arwingFlightActive = 0;
            state->arwingObj->anim.flags &= ~0x4000;
            rotationDelta = (int)((f32)(s16)arwarwing_getRotY(state->arwingObj) + fc * gAndrossArwingRotationScale);
            arwarwing_setRotY(state->arwingObj, rotationDelta);
            thrustB.x = gAndrossZero;
            thrustB.y = gAndrossZero;
            thrustB.z = fc * gAndrossArwingThrustScale;
            thrustBArg = thrustB;
            arwarwing_setVelocity(state->arwingObj, (int)&thrustBArg);
        }
        if (boss->anim.currentMoveProgress >= 1.0f)
        {
            state->actionPending = 1;
        }
        break;
    case 0x18:
        if (actionChanged)
        {
            {
                AndrossState* animState = boss->extra;
                ObjAnim_SetCurrentMove(obj, 0x11, gAndrossZero, 0);
                animState->animSpeed = gAndrossMoveAnimSpeeds[17];
            }
            state->roarPlayed = 0;
        }
        if (boss->anim.currentMoveProgress <= gAndrossArwingReleaseProgressLimit)
        {
            fc = state->cachedPosX - state->arwingObj->anim.localPosX;
            velCalc0.x = fc * gAndrossArwingReleaseVelocityScale;
            fc = state->cachedPosY - state->arwingObj->anim.localPosY;
            velCalc0.y = fc * gAndrossArwingReleaseVelocityScale;
            fc = state->cachedPosZ - state->arwingObj->anim.localPosZ;
            velCalc0.z = fc * gAndrossArwingReleaseVelocityScale;
            velArg0 = velCalc0;
            arwarwing_setVelocity(state->arwingObj, (int)&velArg0);
        }
        else
        {
            fc = (state->savedPosZ - state->arwingObj->anim.localPosZ);
            fval = (gAndrossZero < 10.0f * timeDelta + state->camOffsetAccum)
                       ? gAndrossZero
                       : 10.0f * timeDelta + state->camOffsetAccum;
            state->camOffsetAccum = fval;
            state->arwingFlightActive = 0;
            state->arwingObj->anim.flags &= ~0x4000;
            rotationDelta = (int)((f32)(s16)arwarwing_getRotY(state->arwingObj) + fc * gAndrossArwingReleaseRotationScale);
            arwarwing_setRotY(state->arwingObj, rotationDelta);
            thrustA.x = gAndrossZero;
            thrustA.y = gAndrossZero;
            thrustA.z = fc * gAndrossArwingReleaseThrustScale;
            thrustAArg = thrustA;
            arwarwing_setVelocity(state->arwingObj, (int)&thrustAArg);
            if (state->roarPlayed == 0)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_drak_pain1);
                state->roarPlayed = 1;
            }
        }
        if (boss->anim.currentMoveProgress >= 1.0f)
        {
            state->actionPending = 1;
        }
        break;
    case 0x1e:
        if ((mainGetBit(2) != 0) || (mainGetBit(3) != 0) || (mainGetBit(4) != 0))
        {
            mainSetBits(GAMEBIT_WM_ObjGroups, 0);
            (*gMapEventInterface)->setMapAct(ANDROSS_MAP_SHRINE, 7);
            unlockLevel(0, 0, 1);
            loadMapAndParent(mapGetDirIdx(ANDROSS_MAP_SHRINE));
            objId = mapGetDirIdx(ANDROSS_MAP_SHRINE);
            lockLevel(objId, 1);
            warpToMap(0x4e, 0);
            state->fadeAlpha = gAndrossZero;
            state->actionState = 0x1f;
        }
        break;
    case 0x1f:
        break;
    }
    camActionParam = -180.0f + state->camOffsetAccum;
    (*gCameraInterface)->releaseAction(&camActionParam, 4);
    boss->anim.velocityX += state->springStiffness * (state->targetPosX - boss->anim.localPosX);
    boss->anim.velocityY += state->springStiffness * (state->targetPosY - boss->anim.localPosY);
    boss->anim.velocityZ += state->springStiffness * (state->targetPosZ - boss->anim.localPosZ);
    boss->anim.velocityX *= state->springDamping;
    boss->anim.velocityY *= state->springDamping;
    boss->anim.velocityZ *= state->springDamping;
    boss->anim.localPosX += boss->anim.velocityX;
    boss->anim.localPosY += boss->anim.velocityY;
    boss->anim.localPosZ += boss->anim.velocityZ;

    if (gAndrossZero == state->velZ)
    {
        if (state->arwingFlightActive != 0)
        {
            fn_8023A6A4(state, gAndrossArwingFlightClampRange, gAndrossArwingFlightVelocityScale, gAndrossZero);
        }
        else
        {
            state->velZ = gAndrossArwingFollowScale * (state->savedPosZ - state->arwingObj->anim.localPosZ);
        }
    }

    if (state->arwingObj->pendingParentObj == NULL)
    {
        velAdd = state->velocity;
        arwarwing_addVelocity(state->arwingObj, &velAdd);
    }

    sval = state->targetRotX - (u16)boss->anim.rotX;
    if (0x8000 < sval)
    {
        sval = sval - 0xffff;
    }

    if (sval < -0x8000)
    {
        sval = sval + 0xffff;
    }

    state->rotXSpeed += (sval / gAndrossRotationTargetDivisor - state->rotXSpeed) / gAndrossRotationSmoothingDivisor;
    state->rotYSpeed += (-boss->anim.rotY / gAndrossRotationTargetDivisor - state->rotYSpeed) / gAndrossRotationSmoothingDivisor;
    boss->anim.rotX += state->rotXSpeed;
    boss->anim.rotY += state->rotYSpeed;

    ObjAnim_AdvanceCurrentMove(obj, state->animSpeed, timeDelta, 0);
    fn_8023A3E4((GameObject*)obj, state);
    fn_8023A87C(boss, state);
    if (state->spawnedObj != NULL)
    {
        state->spawnedObj->anim.localPosZ -= 3.0f;
        state->spawnedObjLifetime -= framesThisStep;
        if (state->spawnedObjLifetime < 0)
        {
            Obj_FreeObject(state->spawnedObj);
            state->spawnedObjLifetime = 0;
            state->spawnedObj = NULL;
        }
    }
    if (state->fightPhase < 6)
    {
        searchDist0 = 10000.0f;
        aimTarget = ObjList_FindNearestObjectByDefNo(boss, 0x7e5, &searchDist0);
        if (aimTarget != NULL)
        {
            if (aimTarget->pendingParentObj != NULL)
            {
                aimTarget = (GameObject*)aimTarget->pendingParentObj;
            }
            if ((aimTarget->anim.classId != 0x10) ||
                (found = animatedObjGetSeqId((int)aimTarget->extra), found != 0x598))
            {
                aimTarget->anim.placement->posX = boss->anim.localPosX;
                aimTarget->anim.placement->posY = boss->anim.localPosY;
                aimTarget->anim.placement->posZ = boss->anim.localPosZ;
            }
        }
        searchDist1 = 10000.0f;
        aimTarget = ObjList_FindNearestObjectByDefNo(boss, 0x1e, &searchDist1);
        if (aimTarget != NULL)
        {
            if (aimTarget->pendingParentObj != NULL)
            {
                aimTarget = (GameObject*)aimTarget->pendingParentObj;
            }
            if ((aimTarget->anim.classId != 0x10) ||
                (found = animatedObjGetSeqId((int)aimTarget->extra), found != 0x598))
            {
                aimTarget->anim.placement->posX = boss->anim.localPosX;
                aimTarget->anim.placement->posY = boss->anim.localPosY;
                aimTarget->anim.placement->posZ = boss->anim.localPosZ;
            }
        }
        searchDist2 = 10000.0f;
        aimTarget = ObjList_FindNearestObjectByDefNo(boss, 0x76f, &searchDist2);
        if (aimTarget != NULL)
        {
            if (aimTarget->pendingParentObj != NULL)
            {
                aimTarget = (GameObject*)aimTarget->pendingParentObj;
            }
            if ((aimTarget->anim.classId != 0x10) ||
                (found = animatedObjGetSeqId((int)aimTarget->extra), found != 0x598))
            {
                aimTarget->anim.placement->posX = boss->anim.localPosX;
                aimTarget->anim.placement->posY = boss->anim.localPosY;
                aimTarget->anim.placement->posZ = boss->anim.localPosZ;
            }
        }
        searchDist3 = 10000.0f;
        aimTarget = ObjList_FindNearestObjectByDefNo(boss, 0x814, &searchDist3);
        if (aimTarget != NULL)
        {
            if (aimTarget->pendingParentObj != NULL)
            {
                aimTarget = (GameObject*)aimTarget->pendingParentObj;
            }
            if ((aimTarget->anim.classId != 0x10) ||
                (found = animatedObjGetSeqId((int)aimTarget->extra), found != 0x598))
            {
                aimTarget->anim.placement->posX = boss->anim.localPosX;
                aimTarget->anim.placement->posY = boss->anim.localPosY;
                aimTarget->anim.placement->posZ = boss->anim.localPosZ;
            }
        }
        searchDist = 10000.0f;
        aimTarget = ObjList_FindNearestObjectByDefNo(boss, 0x6cf, &searchDist);
        if (aimTarget != NULL)
        {
            if (aimTarget->pendingParentObj != NULL)
            {
                aimTarget = (GameObject*)aimTarget->pendingParentObj;
            }
            if ((aimTarget->anim.classId != 0x10) ||
                (found = animatedObjGetSeqId((int)aimTarget->extra), found != 0x598))
            {
                aimTarget->anim.placement->posX = boss->anim.localPosX;
                aimTarget->anim.placement->posY = boss->anim.localPosY;
                aimTarget->anim.placement->posZ = boss->anim.localPosZ;
            }
        }
    }
    return;
}

void andross_init(int obj, ObjPlacement* setup)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int i;
    int model;
    int val;

    ((AndrossState*)state)->homePosX = setup->posX;
    ((AndrossState*)state)->homePosY = setup->posY;
    ((AndrossState*)state)->homePosZ = setup->posZ;
    ((AndrossState*)state)->actionTimer = 0;
    ((AndrossState*)state)->actionState = 0;
    ((AndrossState*)state)->prevActionState = -1;
    ((AndrossState*)state)->animSpeed = 0.005f;
    ((AndrossState*)state)->startupDelay = 5;
    ((AndrossState*)state)->fightPhase = 1;
    ((AndrossState*)state)->prevFightPhase = -1;
    ((AndrossState*)state)->targetRotX = -0x8000;
    ((GameObject*)obj)->anim.rotX = -0x8000;
    ((AndrossState*)state)->spawnCooldown = -1.0f;
    ((AndrossState*)state)->camOffsetAccum = gAndrossZero;
    ((AndrossState*)state)->springStiffness = 0.003f;
    ((AndrossState*)state)->springDamping = 0.93f;
    ((AndrossState*)state)->handsInitialized = 1;
    ObjHits_SetTargetMask(obj, 4);
    ((GameObject*)obj)->animEventCallback = andross_SeqFn;
    fn_8006CB50();
    i = (int)Obj_GetActiveModel((GameObject*)obj);
    model = *(int*)i;
    for (i = 0, val = i; i < *(u8*)(model + 0xf8); i++)
    {
        ObjModel_GetRenderOp((ModelFileHeader*)model, i)->alphaOverride = val;
    }
    mainSetBits(0xd, 0);
    unlockLevel(0, 0, 1);
}

int gAndrossRotationTargetDivisor = 20;
int gAndrossRotationSmoothingDivisor = 10;
int gAndrossFlightHalfWidth = 600;
int gAndrossRingSpawnInterval = 2;
f32 gAndrossMissileClampRange = 3.0f;
f32 gAndrossMissileVelocityScale = 5.0f;
f32 gAndrossMissileForwardVelocity = 0.02f;
int gAndrossMissileAttackDuration = 200;
int gAndrossMissileSpawnInterval = 10;
f32 gAndrossCentralMissileClampRange = 2.0f;
f32 gAndrossCentralMissileVelocityScale = 120.0f;
f32 gAndrossCentralMissileForwardVelocity = 0.03f;
int gAndrossCentralAttackDuration = 600;
int gAndrossCentralMissileSpawnInterval = 10;
f32 gAndrossArwingApproachVelocityScale = 0.1f;
int gAndrossAsteroidSpawnInterval = 2;
f32 gAndrossSpawnRandX = 300.0f;
f32 gAndrossSpawnRandY = 200.0f;
f32 gAndrossSpawnRandZ = 50.0f;
f32 gAndrossSpawnOffsetY = -100.0f;
f32 gAndrossSpawnOffsetZ = 280.0f;
int gAndrossBrainAttackDuration = 40;
f32 gAndrossArwingReturnVelocityScale = 0.01f;
int gAndrossMoveTailDistance = 300;
f32 gAndrossArwingPullProgressLimit = 0.38f;
f32 gAndrossArwingPullVelocityScale = 0.07f;
f32 gAndrossArwingThrustScale = 0.05f;
f32 gAndrossArwingRotationScale = 10.0f;
f32 gAndrossArwingReleaseProgressLimit = 0.38f;
f32 gAndrossArwingReleaseVelocityScale = 0.04f;
f32 gAndrossArwingReleaseThrustScale = 0.05f;
f32 gAndrossArwingReleaseRotationScale = 10.0f;
f32 gAndrossArwingFollowScale = 0.0005f;
f32 gAndrossArwingFlightClampRange = 2.0f;
f32 gAndrossArwingFlightVelocityScale = 100.0f;
s16 gAndrossSwayPhaseStepX = 150;
s16 gAndrossSwayPhaseStepY = 280;
f32 gAndrossForwardDistanceThreshold = 50.0f;
f32 gAndrossArwingVelDamp = 0.2f;
u8 gAndrossPartTextureIndices[4] = {1, 0, 2, 0};
u32 gAndrossDistortFilterParam = 0x0000ff00;
f32 gAndrossDistortPhaseStep = 0.006f;
f32 gAndrossDistortPhaseReset = 3.142f;
int gAndrossAimedProjectileSpeed = 10;
int gAndrossAimedProjectileLifetime = 90;
int gAndrossRingProjectileLifetime = 110;
f32 gAndrossRingProjectileScale = 5.0f;
int gAndrossProjectileForwardStep = 7;
int gAndrossSpawnedObjectLifetime = 200;
