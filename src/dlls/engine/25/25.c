#include "dlls/object_descriptor.h"
#include "main/dll/player_api.h"
#include "main/track_bbox_api.h"
#include "main/frame_timing.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
#include "main/shader_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/mapEventTypes.h"
#include "main/mm.h"
#include "main/vecmath.h"
#include "main/voxmaps.h"
#include "string.h"

/* object group this object joins */
#define DLL19_OBJGROUP        3
#define DLL19_TARGET_OBJGROUP 4

/* reward objects spawned on hit (retail OBJECTS.bin names) */
#define DLL19_CHILD_OBJ_MAGIC_DUST  717  /* 0x2cd "MagicDustMi..." (DLL 0xFF magicgem) */
#define DLL19_CHILD_OBJ_ENERGY_GEM1 9    /* "EnergyGem1" (DLL 0x12A) */
#define DLL19_CHILD_OBJ_ENERGY_EGG  11   /* 0xb "EnergyEgg" (DLL 0xED) */
#define DLL19_CHILD_OBJ_MOON_SEED   1702 /* 0x6a6 "MoonSeedCol..." (DLL 0xED) */
#define DLL19_ADVANCE_MSG     0xe0001 /* notify the struck object to advance its hit reaction */

#include "main/camera_interface.h"
#include "dlls/objects/237.h"
#include "game/objects/object_setup.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/player_status.h"
#include "main/dll/dll19_state.h"
#include "main/dll/partfx_interface.h"
#include "main/dll/baddie_state.h"
#include "main/object_transform.h"
#include "main/player_control_interface.h"
#include "main/dll/dll_0019_dll19func0.h"
#include "main/dll/dll_0004_dummy04.h"
#include "main/objtype.h"
#include "main/lightmap_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/obj_message.h"
#include "main/objhits.h"

GameObject* gDll19NearestObj;
f32 gDll19SegmentRadius;
s8 gDll19SeqStallCount;
f32 gDll19SeqMinDist;

f32 gDll19LocalPointRadius = 25.0f;

typedef struct Dll19Placement
{
    GroundBaddiePlacement base;
    u16 spawnCount;
    u8 pad36[0x38 - 0x36];
} Dll19Placement;

STATIC_ASSERT(offsetof(Dll19Placement, spawnCount) == 0x34);

/* bits in the Dll19State flags word at +0x400 */
#define DLL19_FLAG_YAW_ALIGNED 0x10 /* yaw delta within facing cone */
#define DLL19_FLAG_OSC_RISING  0x20 /* oscillation phase 1 (initial rise) */
#define DLL19_FLAG_OSC_ACTIVE  0x40 /* oscillation phase 2 (active/return) */

typedef struct Dll19ChildObjectIdTable
{
    s16 ids[5];
} Dll19ChildObjectIdTable;

STATIC_ASSERT(sizeof(Dll19ChildObjectIdTable) == 0xA);

typedef struct
{
    u32 w0, w1;
} IdPair;

const IdPair sDll19DropObjectIds = {0x02C402CD, 0x02CE02CF};
const IdPair sDll19DropObjectIdsAlt = {0x000B000B, 0x000B000B};
union Dll19ConstU32 { u32 u; };
const union Dll19ConstU32 gDll19DefaultCurveMode = { 2 };


const Dll19ChildObjectIdTable gDll19ChildObjectIds = {{0x23, 0x69, 0x33, 0x64, 0x1D}};
f32 gDll19SegmentLocalPoints[3] = {0.0f, 0.0f, 0.0f};
f32 gDll19LocalPointPositions[3] = {0.0f, 0.0f, 0.0f};

int dll_19_isBaddieControlObject(GameObject* obj)
{
    s16 v = (obj)->anim.romDefNo;
    switch (v)
    {
    case 341:
    case 365:
    case 368:
    case 474:
    case 512:
    case 588:
    case 589:
    case 635:
    case 636:
    case 653:
    case 658:
    case 683:
    case 697:
    case 714:
    case 774:
    case 823:
    case 864:
    case 905:
    case 906:
    case 1021:
    case 1197:
    case 1209:
    case 1235:
    case 1276:
    case 1286:
        return 1;
    }
    return 0;
}

f32 dll_19_getHealthFraction(GameObject* obj)
{
    Dll19State* p_b8 = (Dll19State*)(obj)->extra;
    GroundBaddiePlacement* p_4c = (GroundBaddiePlacement*)(obj)->anim.placementData;
    u8 denom = p_4c->hitPoints;
    if (denom != 0)
    {
        s8 numer = p_b8->progressNumerator;
        if (numer != 0)
        {
            return (f32)numer / denom;
        }
    }
    return 0.0f;
}

void dll_19_changeWeapon(GameObject* cam, u8* ctx)
{
    Dll19ChildObjectIdTable childObjectIds = gDll19ChildObjectIds;

    if ((s8)ctx[1031] == (s8)ctx[1033])
    {
        return;
    }
    if (cam->anim.alpha == 0)
    {
        return;
    }
    if (cam->childObjs[0] != NULL)
    {
        Obj_FreeObject(cam->childObjs[0]);
        cam->childObjs[0] = NULL;
    }
    if (Obj_IsLoadingLocked() != 0)
    {
        if ((s8)ctx[1031] > 0)
        {
            ObjPlacement* setup = Obj_AllocObjectSetup(24, childObjectIds.ids[(s8)ctx[1031] - 1]);
            cam->childObjs[0] =
                objSetupObject(setup, 4, -1, -1, cam->anim.parent);
            ((GameObject*)cam->childObjs[0])->objectFlags = cam->objectFlags & 7;
        }
        ctx[1033] = ctx[1031];
    }
    else
    {
        ctx[1033] = 0;
    }
}

void dll_19_releaseState(GameObject* obj, GroundBaddieState* state, u8 flag)
{
    Sfx_StopObjectChannel(obj, 127);
    if ((state->configFlags & flag) == 0)
    {
        s16 soundId;
        soundId = state->soundIdB;
        if (soundId != 0)
        {
            gTitleMenuControlInterfaceCopy->vtable->func05(obj, soundId, 0, 0, 0);
        }
        soundId = state->soundIdA;
        if (soundId != 0)
        {
            gTitleMenuControlInterfaceCopy->vtable->func05(obj, soundId, 0, 0, 0);
        }
    }
    voxmaps_freeRouteWork(&state->routeState);
    if (*(u32*)&state->path != 0)
    {
        mm_free((void*)*(u32*)&state->path);
        state->path = 0;
    }
}

void dll_19_initGroundBaddie(GameObject* obj, GroundBaddiePlacement* config, u8* state, int moveArg0, int moveArg1, int pathFlags,
                   u8 initFlags, f32 pathRadius)
{
    u8 flags;
    int b1;
    u8* path;
    int curveLocal;
    u8 byteLocal;

    curveLocal = gDll19DefaultCurveMode.u;
    byteLocal = 1;
    ((GroundBaddieState*)state)->control = (void*)(state + sizeof(GroundBaddieState));
    ((GroundBaddieState*)state)->targetState = 0;

    flags = initFlags;
    b1 = flags & 1;
    if (b1 == 0 && (flags & 0x20) == 0)
    {
        objAddObjectType(obj, DLL19_OBJGROUP);
        ObjMsg_AllocQueue(obj, 4);
    }
    (*gPlayerInterface)->init(obj, state, moveArg0, moveArg1);
    ((BaddieState*)state)->flags0 = 0;
    ((BaddieState*)state)->hasTarget = 0;
    ((BaddieState*)state)->animSpeedA = 0.0f;
    ((BaddieState*)state)->animSpeedB = 0.0f;
    if (config->hitPoints != 0)
    {
        ((BaddieState*)state)->hitPoints = config->hitPoints;
    }
    else
    {
        ((BaddieState*)state)->hitPoints = 6;
    }
    ((GroundBaddieState*)state)->gameBitB = config->gameBitB;
    ((GroundBaddieState*)state)->gameBitC = config->gameBitC;
    ((GroundBaddieState*)state)->gameBitD = config->gameBitD;
    if (((GroundBaddieState*)state)->gameBitB != -1)
    {
        mainSetBits(((GroundBaddieState*)state)->gameBitB, 0);
    }
    path = state + 4;
    if ((flags & 2) != 0)
    {
        (*gPathControlInterface)->init(path, 0, pathFlags | 0x200000, 1);
    }
    else
    {
        (*gPathControlInterface)->init(path, 0, 0, 0);
    }
    (*gPathControlInterface)->setLocalPointCollision(path, 1, gDll19LocalPointPositions, &gDll19LocalPointRadius, 4);
    if ((flags & 4) != 0)
    {
        (*gPathControlInterface)->setup(path, 1, gDll19SegmentLocalPoints, &gDll19SegmentRadius, &byteLocal);
    }
    (*gPathControlInterface)->attachObject((void*)obj, path);
    ((GroundBaddieState*)state)->configFlags = config->flags;
    ((GroundBaddieState*)state)->triggerId = config->triggerId;
    ((GroundBaddieState*)state)->aggression = config->aggression;
    state[1031] = config->initialWeaponId;
    state[1032] = config->unk28;
    obj->objectFlags = obj->objectFlags | ((s8)state[1032] & 7);
    if ((flags & 8) != 0)
    {
        ((GroundBaddieState*)state)->soundIdA = config->soundIdA;
        ((GroundBaddieState*)state)->soundIdB = config->soundIdB;
    }
    else
    {
        ((GroundBaddieState*)state)->soundIdA = 0;
        ((GroundBaddieState*)state)->soundIdB = 0;
    }
    ((GroundBaddieState*)state)->flags400 = 0;
    ((GroundBaddieState*)state)->aggroRange = (u16)(config->aggroRange << 3);
    ((GroundBaddieState*)state)->subMode = 0;
    ((GroundBaddieState*)state)->pathRadius = pathRadius;
    obj->anim.rotX = (s16)((s8)config->rotX << 8);
    obj->anim.alpha = 255;
    obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED;
    ((GroundBaddieState*)state)->gameBitA = config->gameBitA;
    if (((GroundBaddieState*)state)->gameBitA != -1)
    {
        if (obj->anim.romDefNo == 636)
        {
            obj->userData1 = (mainGetBit(((GroundBaddieState*)state)->gameBitA) == 0);
        }
        else
        {
            obj->userData1 = mainGetBit(((GroundBaddieState*)state)->gameBitA);
        }
    }
    else
    {
        obj->userData1 = 0;
    }
    if ((*gMapEventInterface)->shouldNotSaveTime(config->base.ident) == 0)
    {
        obj->userData1 = 1;
    }
    if (obj->userData1 != 0)
    {
        ObjHits_DisableObject(obj);
        obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
        return;
    }
    obj->anim.flags = obj->anim.flags & ~OBJANIM_FLAG_HIDDEN;
    ObjHits_EnableObject(obj);
    if (config->sequenceId == -1)
    {
        obj->userData2 = 1;
    }
    else
    {
        obj->userData2 = 0;
    }
    if (b1 == 0 && (flags & 0x20) == 0)
    {
        voxmaps_allocRouteWork(&((GroundBaddieState*)state)->routeState);
        ((GroundBaddieState*)state)->routeNav.maxIters = 4;
        ((GroundBaddieState*)state)->routeNav.budget = 20;
    }
    if ((flags & 0x10) != 0)
    {
        if (((GroundBaddieState*)state)->path == NULL && (flags & 0x20) == 0)
        {
            ((GroundBaddieState*)state)->path = mmAlloc(264, 26, 0);
        }
        if (((GroundBaddieState*)state)->path != NULL)
        {
            memset(((GroundBaddieState*)state)->path, 0, 264);
        }
        if ((*gRomCurveInterface)
                ->initCurve(((GroundBaddieState*)state)->path, (void*)obj,
                            (f32)(u32)((GroundBaddieState*)state)->aggroRange, &curveLocal, -1) == 0)
        {
            ((GroundBaddieState*)state)->flags400 = ((GroundBaddieState*)state)->flags400 | BADDIE_FLAG400_PATH_ACTIVE;
        }
    }
    else
    {
        ((GroundBaddieState*)state)->path = NULL;
    }
}

void dll_19_pollCameraTarget(GameObject* obj, void* state, u16* flags, int modeA, int modeB, s16 soundIdA, s16 soundIdB)
{
    (void)(*gCameraInterface)->getOverrideTarget();
}

int dll_19_processMessages(GameObject* obj, void* state, void* hitbox, s16 gameBit, u8* flagOut, s16 substateIdle,
                  s16 substateActive, s16 moveMode)
{
    u32 msgData;
    int msgType;
    int extra;

    extra = 0;
    while (ObjMsg_Pop(obj, (u32*)&msgType, &msgData, (u32*)&extra) != 0)
    {
        switch (msgType)
        {
        case 4:
            ObjMsg_SendToObject((void*)msgData, 5, obj, 0);
            break;
        case 0xE0000:
            if (msgData == (int)((BaddieState*)state)->targetObj)
            {
                ((BaddieState*)state)->substate = substateIdle;
                ((BaddieState*)state)->targetObj = 0;
                ((BaddieState*)state)->hasTarget = 0;
            }
            break;
        case 11:
            ((BaddieState*)state)->unk34E = extra;
            break;
        case 1:
        case 0xA0001:
            if (((BaddieState*)state)->substate != substateActive)
            {
                dll_19_startHitReaction(obj, state, hitbox, gameBit, flagOut, substateIdle, moveMode, 0, 1);
                ((BaddieState*)state)->substate = substateActive;
                ((BaddieState*)state)->hasTarget = 0;
                ((BaddieState*)state)->targetObj = (void*)msgData;
                return 1;
            }
            break;
        case 3:
            if (((BaddieState*)state)->substate == substateActive)
            {
                ((BaddieState*)state)->hasTarget = 0;
                ((BaddieState*)state)->targetObj = 0;
                ((BaddieState*)state)->substate = substateIdle;
                return 2;
            }
            break;
        }
    }
    return 0;
}

int dll_19_updateHitReaction(GameObject* obj, void* baddieState, void* hitbox, s16 gameBit, int* tableA, u8* tableB,
                  s16 substate, void* hitPosOut)
{
    u8* state = obj->extra;
    GameObject* player = Obj_GetPlayerObject();
    int hit;
    int sphereIndex;
    int v24;
    GameObject* hitObject;
    f32 posX;
    f32 posY;
    f32 posZ;

    if (((Dll19State*)state)->oscValue > 0.0f)
    {
        ((Dll19State*)state)->oscValue =
            timeDelta * ((Dll19State*)state)->oscVelocity + ((Dll19State*)state)->oscValue;
        if ((((Dll19State*)state)->flags & DLL19_FLAG_OSC_RISING) != 0)
        {
            ((Dll19State*)state)->flags = ((Dll19State*)state)->flags & ~DLL19_FLAG_OSC_RISING;
            ((Dll19State*)state)->flags = ((Dll19State*)state)->flags | DLL19_FLAG_OSC_ACTIVE;
            if (((Dll19State*)state)->oscValue > 2.0f)
            {
                ((Dll19State*)state)->oscValue = 0.0f;
                ((Dll19State*)state)->flags = ((Dll19State*)state)->flags & ~DLL19_FLAG_OSC_ACTIVE;
            }
        }
        else if ((((Dll19State*)state)->flags & DLL19_FLAG_OSC_ACTIVE) != 0)
        {
            if (((Dll19State*)state)->oscValue > 2.0f)
            {
                GroundBaddiePlacement* other = (GroundBaddiePlacement*)obj->anim.placementData;
                ((Dll19State*)state)->oscValue = 0.0f;
                ((Dll19State*)state)->flags = ((Dll19State*)state)->flags & ~DLL19_FLAG_OSC_ACTIVE;
                ((BaddieState*)baddieState)->hitPoints = 0;
                obj->anim.alpha = 0;
                obj->userData1 = 1;
                obj->anim.flags = obj->anim.flags | OBJANIM_FLAG_HIDDEN;
                (*gMapEventInterface)->addTime(other->base.ident, (f32)(s32)(other->respawnDelay * 60));
            }
        }
        else
        {
            if (((Dll19State*)state)->oscValue < 0.0f)
            {
                ((Dll19State*)state)->oscValue = 0.0f;
            }
            else if (((Dll19State*)state)->oscValue > 120.0f)
            {
                ((Dll19State*)state)->oscValue = 120.0f - (((Dll19State*)state)->oscValue - 120.0f);
                ((Dll19State*)state)->oscVelocity = -((Dll19State*)state)->oscVelocity;
            }
        }
    }

    if (((BaddieState*)baddieState)->hitPoints == 0)
    {
        return 0;
    }
    hit = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &sphereIndex, (u32*)&v24, &posX, &posY, &posZ);
    ((GroundBaddieState*)state)->lastHitSphereIndex = sphereIndex;
    if (hit != 0)
    {
        if (hitPosOut != NULL)
        {
            ((PartFxSpawnParams*)hitPosOut)->posX = posX + playerMapOffsetX;
            ((PartFxSpawnParams*)hitPosOut)->posY = posY;
            ((PartFxSpawnParams*)hitPosOut)->posZ = posZ + playerMapOffsetZ;
        }
        if (tableB != NULL)
        {
            int hitVal = (s8)tableB[hit - 2];
            if (hitVal != -1)
            {
                v24 = hitVal;
            }
        }
        else
        {
            v24 = 0;
        }
        ((BaddieState*)baddieState)->hitPoints = ((BaddieState*)baddieState)->hitPoints - v24;
        if (((BaddieState*)baddieState)->hitPoints < 1)
        {
            ((Dll19State*)state)->flags = ((Dll19State*)state)->flags | DLL19_FLAG_OSC_RISING;
            ((Dll19State*)state)->oscValue = 1.0f;
            ((Dll19State*)state)->oscVelocity = 0.01f;
            ((BaddieState*)baddieState)->substate = substate;
            ((BaddieState*)baddieState)->hitPoints = 0;
        }
        else
        {
            if (v24 != 0)
            {
                if (((BaddieState*)baddieState)->targetObj == NULL)
                {
                    if (playerGetStateValue(player, 1) != 0)
                    {
                        ((BaddieState*)baddieState)->targetObj = player;
                        ((BaddieState*)baddieState)->hasTarget = 0;
                    }
                }
                ((Dll19State*)state)->oscValue = 1.0f;
                ((Dll19State*)state)->oscVelocity = 12.0f;
                if (tableA != NULL)
                {
                    if (tableA[hit - 2] != -1)
                    {
                        (*gPlayerInterface)->setState(obj, baddieState, tableA[hit - 2]);
                        ((BaddieState*)baddieState)->substate = substate;
                    }
                }
                ((BaddieState*)baddieState)->lastHitPriority = hit;
            }
        }
        Sfx_StopObjectChannel(obj, 16);
        ObjMsg_SendToObject(hitObject, DLL19_ADVANCE_MSG, obj, 0);
    }
    return hit;
}


GameObject* dll_19_dropCollectable(GameObject* obj, int spawnType, int unused, int alt)
{
    GameObject* source = obj;
    GroundBaddiePlacement* state = (GroundBaddiePlacement*)obj->anim.placementData;
    CollectibleSetup* setup;
    u16 ids1[4];
    u16 ids2[4];
    int idx;
    f32 savedX, savedY, savedZ;
    f32 nearDist;
    f32 scale;

    scale = 0.0f;
    *(IdPair*)ids1 = sDll19DropObjectIds;
    *(IdPair*)ids2 = sDll19DropObjectIdsAlt;
    if (spawnType == 0)
    {
        return 0;
    }
    if (Obj_IsLoadingLocked() == 0)
    {
        return 0;
    }
    if ((state->triggerId & 0xf00) != 0)
    {
        idx = ((spawnType & 0xf00) >> 8) - 1;
        if (idx > 3)
        {
            idx = 3;
        }
        setup = (CollectibleSetup*)Obj_AllocObjectSetup(sizeof(CollectibleSetup), ids1[idx]);
        scale = 30.0f;
    }
    if ((state->triggerId & 0xf000) != 0)
    {
        idx = ((spawnType & 0xf000) >> 12) - 1;
        if (idx > 3)
        {
            idx = 3;
        }
        setup = (CollectibleSetup*)Obj_AllocObjectSetup(sizeof(CollectibleSetup), ids2[idx]);
        scale = 30.0f;
    }
    if ((int)(u8)state->triggerId != 0)
    {
        switch (spawnType)
        {
        case 1:
            setup = (CollectibleSetup*)Obj_AllocObjectSetup(sizeof(CollectibleSetup), DLL19_CHILD_OBJ_MAGIC_DUST);
            scale = 30.0f;
            break;
        case 2:
            setup = (CollectibleSetup*)Obj_AllocObjectSetup(sizeof(CollectibleSetup), DLL19_CHILD_OBJ_ENERGY_GEM1);
            scale = 30.0f;
            break;
        case 3:
            setup = (CollectibleSetup*)Obj_AllocObjectSetup(sizeof(CollectibleSetup), DLL19_CHILD_OBJ_ENERGY_EGG);
            scale = 30.0f;
            break;
        case 4:
            setup = (CollectibleSetup*)Obj_AllocObjectSetup(sizeof(CollectibleSetup), DLL19_CHILD_OBJ_MAGIC_DUST);
            scale = 30.0f;
            break;
        case 5:
            savedX = source->anim.worldPosX;
            savedY = source->anim.worldPosY;
            savedZ = source->anim.worldPosZ;
            {
                ObjPlacement* pl = source->anim.placement;
                if (pl != NULL)
                {
                    source->anim.worldPosX = pl->posX;
                    source->anim.worldPosY = pl->posY;
                    source->anim.worldPosZ = pl->posZ;
                }
            }
            nearDist = 750.0f;
            gDll19NearestObj = objGetNearestTypeTo(DLL19_TARGET_OBJGROUP, obj, &nearDist);
            source->anim.worldPosX = savedX;
            source->anim.worldPosY = savedY;
            source->anim.worldPosZ = savedZ;
            if (gDll19NearestObj != NULL)
            {
                f32 xx, yy, zz;
                f32 yOffset = 15.0f;
                xx = source->anim.localPosX;
                gDll19NearestObj->anim.worldPosX = xx;
                gDll19NearestObj->anim.localPosX = xx;
                yy = source->anim.localPosY + yOffset;
                gDll19NearestObj->anim.worldPosY = yy;
                gDll19NearestObj->anim.localPosY = yy;
                zz = source->anim.localPosZ;
                gDll19NearestObj->anim.worldPosZ = zz;
                gDll19NearestObj->anim.localPosZ = zz;
            }
            return gDll19NearestObj;
        case 6:
            setup = (CollectibleSetup*)Obj_AllocObjectSetup(sizeof(CollectibleSetup), DLL19_CHILD_OBJ_MOON_SEED);
            setup->rotXByte = 0;
            setup->rotYByte = 0;
            setup->rotZByte = 64;
            scale = 25.0f;
            break;
        default:
            return 0;
        }
    }
    setup->unk1A = 20;
    setup->counterGameBit = -1;
    setup->hideGameBit = -1;
    setup->visibilityGameBit = -1;
    setup->base.posX = source->anim.localPosX;
    setup->base.posY = source->anim.localPosY + scale;
    setup->base.posZ = source->anim.localPosZ;
    if ((u8)alt != 0)
    {
        setup->spawnMode = 2;
    }
    else
    {
        setup->spawnMode = 1;
    }
    setup->base.color[0] = ((u8*)state)[4];
    setup->base.color[2] = ((u8*)state)[6];
    setup->base.color[1] = ((u8*)state)[5];
    setup->base.color[3] = ((u8*)state)[7];
    gDll19NearestObj = objSetupObject(&setup->base, 5, obj->anim.mapEventSlot, -1, source->anim.parent);
    return gDll19NearestObj;
}

void dll_19_startHitReaction(GameObject* obj, void* state, void* hitbox, s16 gameBit, u8* flagOut, s16 substate, s16 moveMode,
                   int animMove, s8 field25f)
{
    if (hitbox != NULL)
    {
        ((u8*)hitbox)[0x24] = 0;
        ((u8*)hitbox)[0x25] = 0;
        ((u8*)hitbox)[0x26] = 4;
        ((u8*)hitbox)[0x27] = 20;
    }
    if (substate != -1)
    {
        ((BaddieState*)state)->substate = substate;
        ((BaddieState*)state)->moveJustStartedB = 1;
    }
    if (moveMode != -1)
    {
        (*gPlayerInterface)->setState(obj, state, moveMode);
    }
    if (flagOut != NULL)
    {
        flagOut[0] = 2;
    }
    if (animMove != 0)
    {
        ObjAnim_SetCurrentMove(obj, animMove, 0.0f, 0);
    }
    (*gPathControlInterface)->attachObject((void*)obj, (u8*)state + 4);
    if (field25f != -1)
    {
        ((BaddieState*)state)->physicsActive = field25f;
    }
    if (gameBit != -1)
    {
        mainSetBits(gameBit, 1);
    }
}

GameObject* dll_19_findAggroTarget(GameObject* self, void* state, f32 frange, int halfAngle)
{
    f32 bboxOut[20];
    GameObject* objs[3];
    f32 diff[3];
    f32 gridIn[3];
    int gridB[2];
    int gridA[2];
    u8 losOut;
    f32* dp;
    GameObject** list;
    int negHalfAngle;
    GameObject* obj;
    int found = 0;
    int delta;
    u8 traced;

    objs[0] = Obj_GetPlayerObject();
    objs[1] = NULL;
    dp = diff;
    list = objs;
    negHalfAngle = -halfAngle;

    while (found == 0 && (obj = *list) != NULL)
    {
        dp[0] = obj->anim.worldPosX - self->anim.worldPosX;
        dp[1] = obj->anim.worldPosY - self->anim.worldPosY;
        dp[2] = obj->anim.worldPosZ - self->anim.worldPosZ;
        if (sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1])) < frange)
        {
            if ((s8)((BaddieState*)state)->hitPoints != 0)
            {
                if (playerGetAnimSpeed(obj) > 0.5f)
                {
                    found = 1;
                }
                delta = getAngle(-dp[0], -dp[2]) & 0xffff;
                if (self->anim.parent != NULL)
                {
                    delta -= (self->anim.rotX + *(s16*)(self->anim.parentAddress)) & 0xffff;
                    if (delta > 0x8000)
                    {
                        delta -= 0xffff;
                    }
                    if (delta < -0x8000)
                    {
                        delta += 0xffff;
                    }
                }
                else
                {
                    delta -= self->anim.rotX & 0xffff;
                    if (delta > 0x8000)
                    {
                        delta -= 0xffff;
                    }
                    if (delta < -0x8000)
                    {
                        delta += 0xffff;
                    }
                }
                if (delta < halfAngle && delta > negHalfAngle)
                {
                    found = 1;
                }
                if (playerGetStateValue(obj, 1) == 0)
                {
                    found = 0;
                }
                if (Player_GetCurrentHealth((int)obj) <= 0)
                {
                    found = 0;
                }
                else
                {
                    gridIn[0] = self->anim.localPosX;
                    gridIn[1] = 10.0f + self->anim.localPosY;
                    gridIn[2] = self->anim.localPosZ;
                    voxmaps_worldToGrid(gridIn, (s16*)gridA);
                    gridIn[0] = obj->anim.localPosX;
                    gridIn[1] = 10.0f + obj->anim.localPosY;
                    gridIn[2] = obj->anim.localPosZ;
                    voxmaps_worldToGrid(gridIn, (s16*)gridB);
                    traced = voxmaps_traceLine((VoxPos*)gridB, (VoxPos*)gridA, NULL, &losOut, 0);
                    if (losOut == 1 || traced != 0)
                    {
                        if (trackGetLineIntersect(&self->anim.localPosX, gridIn, 1.0f, 0, (TrackBBoxHit*)bboxOut,
                                               self, 4, -1, 0, 0) != 0)
                        {
                            found = 0;
                        }
                    }
                    else
                    {
                        found = 0;
                    }
                }
            }
        }
        list++;
    }
    return obj;
}

int dll_19_shouldDropTarget(GameObject* obj, void* state, f32 distThreshold, int requireFar)
{
    GameObject* player = Obj_GetPlayerObject();
    int result = 0;

    if (((BaddieState*)state)->moveDone != 0)
    {
        if (((BaddieState*)state)->targetObj == player && (s8)((BaddieState*)state)->hitPoints != 0)
        {
            if (((BaddieState*)state)->targetDistance > distThreshold && requireFar != 0)
            {
                result = 1;
            }
            else if (playerGetStateValue(player, 1) == 0)
            {
                result = 1;
            }
            else if (Player_GetCurrentHealth((int)player) <= 0)
            {
                result = 1;
            }
            else
            {
                f32 pos[3];
                f32 out[22];
                pos[0] = player->anim.localPosX;
                pos[1] = 10.0f + player->anim.localPosY;
                pos[2] = player->anim.localPosZ;
                if (trackGetLineIntersect(&obj->anim.localPosX, pos, 1.0f, 0, (TrackBBoxHit*)out,
                                       obj, 4, -1, 0, 0) != 0)
                {
                    result = 1;
                }
            }
        }
        else
        {
            result = 1;
        }
    }
    return result;
}

int dll_19_isObjectValid(GameObject* obj, void* state, u8 checkDead)
{
    if (checkDead != 0 && (s8)((BaddieState*)state)->hitPoints <= 0 && (obj)->anim.alpha == 0)
    {
        return 0;
    }
    if (obj->anim.parent == NULL)
    {
        if (objPosToMapBlockIdx((double)(obj)->anim.localPosX, (double)(obj)->anim.localPosY,
                                (double)(obj)->anim.localPosZ) < 0)
        {
            return 0;
        }
    }
    return 1;
}

void dll_19_updateGravity(GameObject* obj, void* state, f32 gravity, s8 field25f)
{
    f32 fz;
    *(u32*)state |= 0x8000;
    ((BaddieState*)state)->cameraYaw = 0;
    if (obj->anim.hitReactState != NULL)
    {
        ObjHits_SetHitVolumeSlot(&obj->anim, 0, 0, -1);
    }
    if (field25f != -1)
    {
        ((BaddieState*)state)->physicsActive = field25f;
    }
    ((BaddieState*)state)->gravity = gravity;
    fz = 0.0f;
    ((BaddieState*)state)->moveInputX = fz;
    ((BaddieState*)state)->moveInputZ = fz;
    ((BaddieState*)state)->pressedButtons = 0;
    ((BaddieState*)state)->heldButtons = 0;
}

int dll_19_func10(GameObject* obj, u8* state, int moveArg0, int moveArg1, s16 controlMode, f32* destX, f32* destZ,
                  int* reachedOut)
{
    f32 dx, dz, dist;
    f32 zero;

    if (state[897] != 0)
    {
        ((BaddieState*)state)->heldButtons = 0;
        ((BaddieState*)state)->pressedButtons = 0;
        ((BaddieState*)state)->cameraYaw = 0;
        zero = 0.0f;
        ((BaddieState*)state)->moveInputX = zero;
        ((BaddieState*)state)->moveInputZ = zero;
        *reachedOut = 1;
        dx = *destX - (obj)->anim.localPosX;
        dz = *destZ - (obj)->anim.localPosZ;
        dist = sqrtf(dx * dx + dz * dz);
        if (dist < 10.0f)
        {
            *reachedOut = 0;
        }
        else
        {
            dx /= dist;
            dz /= dist;
            ((BaddieState*)state)->moveInputX = 50.0f * -dx;
            ((BaddieState*)state)->moveInputZ = 50.0f * dz;
            (obj)->anim.localPosX += dist * dx;
            (obj)->anim.localPosZ += dist * dz;
            (*gPlayerInterface)->update(obj, state, timeDelta, timeDelta, (void*)moveArg0, (void*)moveArg1);
        }
        if (*reachedOut == 0)
        {
            ((GroundBaddieState*)state)->subMode = 0;
            ((BaddieState*)state)->controlMode = controlMode;
            ((BaddieState*)state)->targetObj = 0;
            ((BaddieState*)state)->physicsActive = 0;
            mainSetBits(((GroundBaddieState*)state)->gameBitB, 0);
        }
        return 1;
    }
    return 0;
}

int dll_19_updateSequenceMovement(GameObject* obj, ObjSeqState* seq, char* st, void* moveHandlers, void* stateHandlers,
                  s16 controlMode)
{
    f32 dist;
    f32 nx;
    f32 nz;
    GameObject* t;

    ((BaddieState*)st)->heldButtons = 0;
    ((BaddieState*)st)->pressedButtons = 0;
    ((BaddieState*)st)->cameraYaw = 0;
    {
        f32 rest = 0.0f;
        ((BaddieState*)st)->moveInputX = rest;
        ((BaddieState*)st)->moveInputZ = rest;
    }
    if (seq->movementState != 1)
    {
        seq->posOffsetX = (obj)->anim.localPosX;
        seq->posOffsetY = (obj)->anim.localPosY;
        seq->posOffsetZ = (obj)->anim.localPosZ;
        gDll19SeqMinDist = 10000.0f;
        gDll19SeqStallCount = 0;
    }
    seq->flags = 0;
    seq->movementState = 1;
    {
        f32 ex = seq->posOffsetX - (obj)->anim.localPosX;
        f32 ez = seq->posOffsetZ - (obj)->anim.localPosZ;
        dist = sqrtf(ex * ex + ez * ez);
    }
    t = ((BaddieState*)st)->targetObj;
    if (t == NULL)
    {
        return 0;
    }
    nx = t->anim.localPosX - seq->posOffsetX;
    nz = t->anim.localPosZ - seq->posOffsetZ;
    {
        f32 total = sqrtf(nx * nx + nz * nz);
        f32 step = timeDelta * (total - dist);
        f32 td;
        step *= 0.25f;
        if (step > 50.0f)
        {
            step = 50.0f;
        }
        else if (step < 15.0f)
        {
            step = 15.0f;
        }
        if (dist <= gDll19SeqMinDist)
        {
            gDll19SeqStallCount = gDll19SeqStallCount + 1;
        }
        if (dist >= total || gDll19SeqStallCount > 9)
        {
            GameObject* t2 = ((BaddieState*)st)->targetObj;
            int delta = (obj)->anim.rotX - (u16)t2->anim.rotX;
            if (delta > 0x8000)
            {
                delta -= 0xffff;
            }
            if (delta < -0x8000)
            {
                delta += 0xffff;
            }
            if (delta > 0x2000)
            {
                delta = 0x2000;
            }
            if (delta < -0x2000)
            {
                delta = -0x2000;
            }
            (obj)->anim.rotX -= (delta * framesThisStep) >> 3;
            if (gDll19SeqStallCount > 10)
            {
                delta = 0;
            }
            if (delta < 0x100 && delta > -0x100)
            {
                seq->movementState = 0;
                seq->prevFrame = (s16)(seq->curFrame - 1);
            }
            else
            {
                td = timeDelta;
                (*gPlayerInterface)->update(obj, st, td, td, moveHandlers, stateHandlers);
            }
        }
        else
        {
            nx = nx / total;
            nz = nz / total;
            ((BaddieState*)st)->moveInputX = -nx * step;
            ((BaddieState*)st)->moveInputZ = nz * step;
            (obj)->anim.localPosX = dist * nx + seq->posOffsetX;
            (obj)->anim.localPosZ = dist * nz + seq->posOffsetZ;
            td = timeDelta;
            (*gPlayerInterface)->update(obj, st, td, td, moveHandlers, stateHandlers);
        }
    }
    gDll19SeqMinDist = dist;
    if (seq->movementState == 0)
    {
        ((GroundBaddieState*)st)->subMode = 0;
        ((BaddieState*)st)->controlMode = controlMode;
        ((BaddieState*)st)->targetObj = 0;
        seq->flags = -1;
        seq->flags = seq->flags & ~0x40;
        ((BaddieState*)st)->physicsActive = 0;
        mainSetBits(((GroundBaddieState*)st)->gameBitB, 0);
    }
    return 1;
}

f32 dll_19_func0B(GameObject* obj)
{
    return ((GroundBaddieState*)obj->extra)->pathRadius;
}

u16 dll_19_func0A(GameObject* obj)
{
    Dll19Placement* placement = (Dll19Placement*)(obj)->anim.placementData;
    if (placement != NULL)
        return placement->spawnCount;
    return 0xd2;
}

/* Steps the movement blend factors toward the current target and turns the
 * yaw by the buffered turn rate. */
void dll_19_updateMovementBlend(GameObject* obj, void* state, void* unusedState, f32 cap, f32 speed)
{
    BaddieState* st = state;

    if (st->inputMagnitude < 0.005f)
    {
        f32 rest;
        st->turnRateAbs = 0;
        st->turnRate = 0;
        rest = 0.0f;
        st->inputMagnitude = rest;
        st->animSpeedA = rest;
    }
    st->animSpeedB = 0.0f;
    obj->anim.rotX = 182.0f * ((f32)st->turnRate * timeDelta / speed) + (f32)obj->anim.rotX;
    st->animSpeedC += timeDelta * ((st->inputMagnitude - st->animSpeedC) / st->velSmoothTime);
    st->animSpeedA += timeDelta * ((st->inputMagnitude - st->animSpeedA) / st->velSmoothTime);
    if (st->animSpeedC > cap)
    {
        st->animSpeedC = cap;
    }
    if (st->animSpeedA > cap)
    {
        st->animSpeedA = cap;
    }
}

/* Constrains a follow point against the object's facing plane and returns
 * the lateral offset of the result. */
f32 dll_19_func05(GameObject* obj, f32 px, f32 pz, f32 range, GameObject* mover)
{
    f32 dist;
    f32 fz;
    f32 fx;
    f32 s;
    f32 c;
    f32 dx;
    f32 dz;

    dx = mover->anim.worldPosX - px;
    dz = mover->anim.worldPosZ - pz;
    dist = sqrtf(dx * dx + dz * dz);
    if (dist < range)
    {
        f32 base;
        f32 d1;
        f32 d2;
        s = mathSinf(3.1415927f * (f32)(obj)->anim.rotX / 32768.0f);
        c = mathCosf(3.1415927f * (f32)(obj)->anim.rotX / 32768.0f);
        base = -(s * (px - s) + c * (pz - c));
        d1 = base + (s * mover->anim.worldPosX + c * mover->anim.worldPosZ);
        d2 = base + (s * mover->anim.previousWorldPosX + c * mover->anim.previousWorldPosZ);
        if (d1 > 0.0f && d2 <= 1.0f)
        {
            mover->anim.worldPosX = mover->anim.worldPosX - s * d1;
            mover->anim.worldPosZ = mover->anim.worldPosZ - c * d1;
            Obj_TransformWorldPointToLocal(mover->anim.worldPosX, mover->anim.worldPosY, mover->anim.worldPosZ,
                                           &mover->anim.localPosX, &mover->anim.localPosY, &mover->anim.localPosZ,
                                           (GameObject*)mover->anim.parent);
        }
        else if (d2 > 1.0f)
        {
            dist = 2.0f * range;
        }
    }
    if (dist < range)
    {
        fx = mover->anim.worldPosX;
        fz = mover->anim.worldPosZ;
    }
    else
    {
        fx = px;
        fz = pz;
    }
    s = mathSinf(3.1415927f * (f32)((obj)->anim.rotX + 0x4000) / 32768.0f);
    c = mathCosf(3.1415927f * (f32)((obj)->anim.rotX + 0x4000) / 32768.0f);
    return -(-((obj)->anim.localPosX * s + (obj)->anim.localPosZ * c) + (s * fx + c * fz));
}

/* Computes the yaw step, wrapped yaw delta and distance from an object to its
 * target, updating the wide-turn flag. */
void dll_19_getTargetGeometry(GameObject* obj, GameObject* target, int div, u16* outYaw, u16* outDelta, u16* outDist)
{
    Dll19State* st = (obj)->extra;
    f32 d[3];
    f32* dp = d;
    s16* ovr;
    u16 ang;
    int cur;
    int delta;

    if ((void*)obj == NULL || target == NULL)
    {
        *outYaw = 0;
        *outDelta = 0;
        *outDist = 0;
    }
    else
    {
        dp[0] = target->anim.worldPosX - (obj)->anim.worldPosX;
        dp[1] = target->anim.worldPosY - (obj)->anim.worldPosY;
        dp[2] = target->anim.worldPosZ - (obj)->anim.worldPosZ;
        ang = getAngle(-dp[0], -dp[2]);
        ovr = (s16*)(obj)->anim.parent;
        if (ovr != NULL)
        {
            cur = (s16)((obj)->anim.rotX + *ovr);
        }
        else
        {
            cur = (obj)->anim.rotX;
        }
        delta = ang - (u16)(s16)cur;
        if (delta > 0x8000)
        {
            delta -= 0xffff;
        }
        if (delta < -0x8000)
        {
            delta += 0xffff;
        }
        *outDelta = delta;
        if ((u16)delta < 0x31c4 || (u16)delta > 0xce3b)
        {
            st->flags &= ~DLL19_FLAG_YAW_ALIGNED;
        }
        else
        {
            st->flags |= DLL19_FLAG_YAW_ALIGNED;
        }
        *outYaw = (u16)delta / (0x10000 / (u8)div);
        *outDist = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
    }
}

int dll_19_func09_ret_0(void)
{
    return 0x0;
}

/* Probes the four compass directions around the object for walkable space,
 * returning a bitmask of clear directions. */
u8 dll_19_getClearDirectionMask(GameObject* obj, void* state, f32 dist)
{
    u16 i;
    u8 mask;
    u8 hitFlag;
    int grid1[2];
    int grid0[2];
    f32 world[3];
    u8 bboxOut[0x54];
    int cur;
    s16* ovr;
    u8 ok;
    f32 angle;

    mask = 0;
    world[0] = obj->anim.localPosX;
    world[1] = 10.0f + obj->anim.localPosY;
    world[2] = obj->anim.localPosZ;
    voxmaps_worldToGrid(world, (s16*)grid0);
    ovr = (s16*)obj->anim.parent;
    if (ovr != NULL)
    {
        cur = (s16)(obj->anim.rotX + *ovr);
    }
    else
    {
        cur = obj->anim.rotX;
    }
    for (i = 0; i < 4; i++)
    {
        angle = 3.1415927f * (f32)((s16)cur + (i << 14)) / 32768.0f;
        world[0] = obj->anim.localPosX - dist * mathSinf(angle);
        world[1] = 10.0f + obj->anim.localPosY;
        world[2] = obj->anim.localPosZ - dist * mathCosf(angle);
        voxmaps_worldToGrid(world, (s16*)grid1);
        if (obj->anim.parent != NULL)
        {
            ok = 1;
        }
        else
        {
            ok = (u8)voxmaps_traceLine((VoxPos*)grid1, (VoxPos*)grid0, NULL, &hitFlag, 0);
            if (hitFlag == 1)
            {
                ok = 1;
            }
        }
        if (ok != 0)
        {
            if (trackGetLineIntersect(&obj->anim.localPosX, world, 1.0f, 0, (TrackBBoxHit*)bboxOut,
                                   obj, ((Dll19State*)state)->bboxTraceFlags, -1, 0, 0) != 0)
            {
                ok = 0;
            }
        }
        mask |= ok << i;
    }
    return mask;
}

void dll_19_func04_nop(void)
{
}

void dll_19_func03_nop(void)
{
}
typedef struct Dll19Interface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback slot03;
    ObjectDescriptorCallback slot04;
    ObjectDescriptorCallback slot05;
    ObjectDescriptorCallback updateMovementBlend;
    ObjectDescriptorCallback getTargetGeometry;
    ObjectDescriptorCallback getClearDirectionMask;
    ObjectDescriptorCallback slot09;
    ObjectDescriptorCallback slot0A;
    ObjectDescriptorCallback slot0B;
    ObjectDescriptorCallback startHitReaction;
    ObjectDescriptorCallback updateGravity;
    ObjectDescriptorCallback isObjectValid;
    ObjectDescriptorCallback updateSequenceMovement;
    ObjectDescriptorCallback slot10;
    ObjectDescriptorCallback pollCameraTarget;
    ObjectDescriptorCallback releaseState;
    ObjectDescriptorCallback shouldDropTarget;
    ObjectDescriptorCallback findAggroTarget;
    ObjectDescriptorCallback dropCollectable;
    ObjectDescriptorCallback updateHitReaction;
    ObjectDescriptorCallback processMessages;
    ObjectDescriptorCallback initGroundBaddie;
    ObjectDescriptorCallback changeWeapon;
    ObjectDescriptorCallback getHealthFraction;
    ObjectDescriptorCallback slot1B;
} Dll19Interface;

Dll19Interface dll_19 = {
    0,
    0,
    0,
    0x001a0000,
    (ObjectDescriptorCallback)dll_19_func03_nop,
    (ObjectDescriptorCallback)dll_19_func04_nop,
    0,
    (ObjectDescriptorCallback)dll_19_func03_nop,
    (ObjectDescriptorCallback)dll_19_func04_nop,
    (ObjectDescriptorCallback)dll_19_func05,
    (ObjectDescriptorCallback)dll_19_updateMovementBlend,
    (ObjectDescriptorCallback)dll_19_getTargetGeometry,
    (ObjectDescriptorCallback)dll_19_getClearDirectionMask,
    (ObjectDescriptorCallback)dll_19_func09_ret_0,
    (ObjectDescriptorCallback)dll_19_func0A,
    (ObjectDescriptorCallback)dll_19_func0B,
    (ObjectDescriptorCallback)dll_19_startHitReaction,
    (ObjectDescriptorCallback)dll_19_updateGravity,
    (ObjectDescriptorCallback)dll_19_isObjectValid,
    (ObjectDescriptorCallback)dll_19_updateSequenceMovement,
    (ObjectDescriptorCallback)dll_19_func10,
    (ObjectDescriptorCallback)dll_19_pollCameraTarget,
    (ObjectDescriptorCallback)dll_19_releaseState,
    (ObjectDescriptorCallback)dll_19_shouldDropTarget,
    (ObjectDescriptorCallback)dll_19_findAggroTarget,
    (ObjectDescriptorCallback)dll_19_dropCollectable,
    (ObjectDescriptorCallback)dll_19_updateHitReaction,
    (ObjectDescriptorCallback)dll_19_processMessages,
    (ObjectDescriptorCallback)dll_19_initGroundBaddie,
    (ObjectDescriptorCallback)dll_19_changeWeapon,
    (ObjectDescriptorCallback)dll_19_getHealthFraction,
    0,
};
