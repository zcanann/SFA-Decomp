/*
 * landedarwing (DLL 0x11B) - the grounded Arwing set-piece object.
 *
 * Its placement->mapId selects which Krazoa map sequence the object
 * drives: each sequence event (Landed_Arwing_SeqFn) loads/unlocks the
 * matching level, locks neighbours, toggles the block-load file flags,
 * and warps the player on completion. Per-frame the object spawns and
 * tends a child object (type 0x606), tracks an interaction trigger
 * through a three-state machine (sequenceState), and drives path-driven
 * particle effects (renderPathEffects, paths 5-8).
 *
 * The hit-reaction path (updateHitReaction / updateDamageTexture) reads a
 * damage game bit, swaps the damaged texture (textureId 0x100/0x200), and
 * on impact either spawns debris, damages a nearby sibling, or jitters
 * its own rotation depending on the placement reaction type (def+0x1e).
 * Hit state is packed into a one-byte flag word (LandedArwingHitFlagBits).
 */
#include "main/obj_placement.h"
#include "main/frame_timing.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/dll/player_api.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/object_descriptor.h"
#include "main/gamebits.h"
#include "main/mapEvent.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/objseq.h"
#include "main/obj_group.h"
#include "main/obj_link.h"
#include "main/obj_path.h"
#include "main/obj_trigger.h"
#include "main/objtexture.h"
#include "main/dll/CF/CFBaby.h"
#include "main/loaded_file_flags.h"
#include "main/map_load.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/tricky_api.h"
#include "main/dll/dll_011B_landedarwing.h"
#include "main/dll/ARW/dll_029D_arwarwinggu.h"

/* group owned by another DLL, queried here */
#define STAFFACTIVATED_OBJ_GROUP 0x41 /* DLL 0x11C staffactivated */

/* object group queried to find the nearby target */
#define LANDEDARWING_TARGET_OBJGROUP 0xf

#define LANDEDARWING_OBJFLAG_HITDETECT_DISABLED 0x2000

/* attached gadget-unit child (arwarwinggu_*); cached in state->childObject */
#define LANDEDARWING_CHILD_OBJ_GADGET_UNIT 0x606

/* debris spawned (x spawnCount) in landed_arwing_updateHitReaction reactionType
 * case 0 (docblock: "on impact either spawns debris, damages a nearby sibling,
 * or jitters its own rotation depending on the placement reaction type"). */
#define LANDEDARWING_CHILD_OBJ_DEBRIS 0x259

typedef struct LandedArwingPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 mapId;
    u16 unk18;
    s16 unk1A;
    s16 triggerGameBit;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} LandedArwingPlacement;

typedef struct LandedArwingUpdateHitReactionPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 mapId;
    u16 unk18;
    s16 unk1A;
    s16 triggerGameBit;
    u8 reactionType;
    u8 spawnCount;
    s16 unk20;
    s16 siblingGameBit;
    s16 reactionGameBit;
    u8 pad26[0x28 - 0x26];
} LandedArwingUpdateHitReactionPlacement;

typedef struct LandedArwingUpdateDamageTexturePlacement
{
    u8 pad0[0x14 - 0x0];
    s32 mapId;
    u16 unk18;
    s16 unk1A;
    s16 triggerGameBit;
    s16 unk1E;
    s16 unk20;
    s16 damagedGameBit;
    s16 damageStateGameBit;
    u8 pad26[0x28 - 0x26];
} LandedArwingUpdateDamageTexturePlacement;

typedef struct LandedArwingFxPoint
{
    f32 scale;
    u8 pathPoint;
    u8 mode;
    u8 mask;
    u8 pad;
} LandedArwingFxPoint;

typedef struct LandedArwingFxScratch
{
    u8 effectPos[12];
    f32 x;
    f32 y;
    f32 z;
} LandedArwingFxScratch;

typedef struct LandedArwingState
{
    f32 sequenceHitCooldown;
    f32 path7Fx;
    f32 path8Fx;
    f32 path6Fx;
    GameObject* childObject;
    s16 unk14;
    u8 sequenceState;
    u8 unk17;
    u8 unk18;
    u8 unk19;
    u8 enablePathFx;
    u8 unk1B;
    u8 hitStarted;
    u8 hitFlags;
    u8 unk1E;
    u8 spawnCount;
    f32 hitEffectCooldown;
} LandedArwingState;

extern LandedArwingFxPoint gLandedArwingPathFxTable[];
extern f32 lbl_803E3B98;
extern f32 lbl_803E3B9C;
#define objfx_spawnMaskedHitEffectLegacy(obj, scale, type, mode, mask, origin)                                    \
    ((void (*)(void*, f32, int, int, int, void*))objfx_spawnMaskedHitEffect)(                                    \
        (void*)(obj), (scale), (type), (mode), (mask), (origin))
#pragma dont_inline on
void landed_arwing_renderPathEffects(GameObject* obj)
{
    LandedArwingState* state;
    u8 i;
    LandedArwingFxScratch scratch;

    state = (obj)->extra;
    if (state->enablePathFx != 0)
    {
        i = 0;
        while (i < 5)
        {
            ObjPath_GetPointWorldPosition(obj, gLandedArwingPathFxTable[i].pathPoint, &scratch.x, &scratch.y,
                                          &scratch.z, 0);
            scratch.x -= (obj)->anim.localPosX;
            scratch.y -= (obj)->anim.localPosY;
            scratch.z -= (obj)->anim.localPosZ;
            objfx_spawnMaskedHitEffectLegacy(obj, (obj)->anim.rootMotionScale * gLandedArwingPathFxTable[i].scale,
                                             4, gLandedArwingPathFxTable[i].mode,
                                             gLandedArwingPathFxTable[i].mask, scratch.effectPos);
            i++;
        }
    }

    if (state->path6Fx != lbl_803E3B98)
    {
        ObjPath_GetPointWorldPosition(obj, 6, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= (obj)->anim.localPosX;
        scratch.y -= (obj)->anim.localPosY;
        scratch.z -= (obj)->anim.localPosZ;
        objfx_spawnLightPulseLegacy(obj, lbl_803E3B9C, 4, 0, 0, state->path6Fx, scratch.effectPos);
    }

    if (state->path8Fx != lbl_803E3B98)
    {
        ObjPath_GetPointWorldPosition(obj, 8, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= (obj)->anim.localPosX;
        scratch.y -= (obj)->anim.localPosY;
        scratch.z -= (obj)->anim.localPosZ;
        objfx_spawnLightPulseLegacy(obj, lbl_803E3B9C, 4, 0, 0, state->path8Fx, scratch.effectPos);
    }

    if (state->path7Fx != lbl_803E3B98)
    {
        ObjPath_GetPointWorldPosition(obj, 7, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= (obj)->anim.localPosX;
        scratch.y -= (obj)->anim.localPosY;
        scratch.z -= (obj)->anim.localPosZ;
        objfx_spawnLightPulseLegacy(obj, lbl_803E3B9C, 4, 0, 0, state->path7Fx, scratch.effectPos);
    }
}
#pragma dont_inline reset

int landed_arwing_getExtraSize(void)
{
    return 0x1c;
}

extern void objRenderModelAndHitVolumes(f32);
void landed_arwing_free(GameObject* obj)
{
    LandedArwingState* state = obj->extra;
    if (state->childObject != NULL)
    {
        Obj_FreeObject(state->childObject);
        ObjLink_DetachChild(obj, (int)state->childObject);
    }
}

extern f32 lbl_803E3BA4;

void landed_arwing_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        objRenderModelAndHitVolumes(lbl_803E3BA4);
        landed_arwing_renderPathEffects((GameObject*)obj);
    }
}

typedef struct LandedArwingHitFlagBits
{
    u8 damaged : 1;
    u8 impactHandled : 1;
    u8 gameBit24Set : 1;
    u8 reactionDone : 1;
    u8 rest : 4;
} LandedArwingHitFlagBits;

void landed_arwing_init(GameObject* obj, int param);
void landed_arwing_update(GameObject* obj);

LandedArwingFxPoint gLandedArwingPathFxTable[] = {
    {0.1f, 1, 7, 0x20, 0}, {0.1f, 2, 7, 0x20, 0}, {0.1f, 3, 8, 0x20, 0}, {0.1f, 4, 9, 0x20, 0}, {0.1f, 5, 6, 0x10, 0},
};

ObjectDescriptor gLanded_ArwingObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)landed_arwing_init,
    (ObjectDescriptorCallback)landed_arwing_update,
    0,
    (ObjectDescriptorCallback)landed_arwing_render,
    (ObjectDescriptorCallback)landed_arwing_free,
    0,
    landed_arwing_getExtraSize,
};

extern f32 lbl_803E3BA0;
extern f32 lbl_803E3BA8;
extern f32 lbl_803E3BAC;
extern f32 lbl_803E3BB0;
extern f32 lbl_803E3BB8;
extern f32 lbl_803E3BBC;
extern f32 lbl_803E3BC0;
extern f32 lbl_803E3BC4;

#define MAP_EVENT_STATUS(mapId)         (*gMapEventInterface)->getMapAct((mapId))
#define MAP_EVENT_SET(mapId, value)     (*gMapEventInterface)->setMapAct((mapId), (value))
#define MAP_EVENT_OP(mapId, arg, value) (*gMapEventInterface)->setObjGroupStatus((mapId), (arg), (value))

int Landed_Arwing_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    int def;
    LandedArwingState* state;
    int mapId;
    GameObject* child;

    def = *(int*)&obj->anim.placementData;
    state = obj->extra;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 2:
        case 0x65:
            mapId = *(int*)(def + 0x14);
            switch (mapId)
            {
            case 0x43775:
                loadMapAndParent(0x29);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x29), 0);
                break;
            case 0x451b9:
                if (MAP_EVENT_STATUS(0xd) == 2)
                {
                    loadMapAndParent(0xb);
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(0xb), 0);
                }
                else
                {
                    loadMapAndParent(0x29);
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(0x29), 0);
                }
                break;
            case 0x49f5a:
                loadMapAndParent(0x26);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x26), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                break;
            case 0x4cd65:
                loadMapAndParent(0x41);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x41), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                break;
            default:
                loadMapAndParent(0x29);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x29), 0);
                break;
            }
            break;
        case 3:
        case 0x64:
            mapId = ((LandedArwingPlacement*)def)->mapId;
            switch (mapId)
            {
            case 0x43775:
                unlockLevel(0, 0, 1);
                mapUnload(mapGetDirIdx(7), 0x3f3c);
                break;
            case 0x49f5a:
                MAP_EVENT_OP(0xb, 4, 0);
                break;
            case 0x451b9:
                if (MAP_EVENT_STATUS(0xd) == 2)
                {
                    unlockLevel(0, 0, 1);
                    mapUnload(mapGetDirIdx(0xd), 0x3f3f);
                    MAP_EVENT_OP(0xd, 0xa, 0);
                    MAP_EVENT_OP(0xd, 0xb, 0);
                    MAP_EVENT_OP(0xd, 0xe, 0);
                }
                break;
            case 0x4cd65:
                unlockLevel(0, 0, 1);
                mapUnload(mapGetDirIdx(0xb), 0x3f00);
                break;
            }
            break;
        case 5:
            mapId = ((LandedArwingPlacement*)def)->mapId;
            switch (mapId)
            {
            case 0x43775:
            case 0x49f5a:
                setLoadedFileFlags_blocks1();
                break;
            case 0x451b9:
                if (MAP_EVENT_STATUS(0xd) == 2)
                {
                    setLoadedFileFlags_blocks1();
                }
                break;
            }
            break;
        case 6:
            mapId = ((LandedArwingPlacement*)def)->mapId;
            switch (mapId)
            {
            case 0x43775:
            case 0x49f5a:
                clearLoadedFileFlags_blocks1();
                break;
            case 0x451b9:
                if (MAP_EVENT_STATUS(0xd) == 2)
                {
                    clearLoadedFileFlags_blocks1();
                }
                break;
            }
            break;
        case 7:
        case 0x66:
            mapId = ((LandedArwingPlacement*)def)->mapId;
            switch (mapId)
            {
            case 0x451b9:
                if (MAP_EVENT_STATUS(0xd) == 2)
                {
                    MAP_EVENT_SET(0xb, 5);
                    warpToMap(0x4e, 0);
                }
                break;
            case 0x49f5a:
                warpToMap(0x32, 0);
                break;
            case 0x4cd65:
                warpToMap(0x7f, 0);
                MAP_EVENT_SET(0x41, 2);
                break;
            }
            break;
        case 0xa:
            state->enablePathFx = 1;
            break;
        case 0xb:
            state->enablePathFx = 0;
            break;
        case 0xc:
            state->path7Fx = lbl_803E3B98;
            break;
        case 0xd:
            state->path7Fx = lbl_803E3BA8;
            break;
        case 0xe:
            state->path7Fx = lbl_803E3BAC;
            break;
        case 0xf:
            state->path7Fx = lbl_803E3BB0;
            break;
        case 0x10:
            state->path8Fx = lbl_803E3B98;
            break;
        case 0x11:
            state->path8Fx = lbl_803E3BA8;
            break;
        case 0x12:
            state->path8Fx = lbl_803E3BAC;
            break;
        case 0x13:
            state->path8Fx = lbl_803E3BB0;
            break;
        case 0x14:
            state->path6Fx = lbl_803E3B98;
            break;
        case 0x15:
            state->path6Fx = lbl_803E3BA8;
            break;
        case 0x16:
            state->path6Fx = lbl_803E3BAC;
            break;
        case 0x17:
            state->path6Fx = lbl_803E3BB0;
            break;
        case 0x18:
            child = state->childObject;
            if (child != NULL)
            {
                child->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            }
            break;
        case 0x19:
            child = state->childObject;
            if (child != NULL)
            {
                child->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
            break;
        }
    }
    return 0;
}

void landed_arwing_update(GameObject* obj)
{
    LandedArwingState* state;
    int player;
    GameObject* child;

    state = (obj)->extra;
    player = (int)Obj_GetPlayerObject();
    if (state->childObject == NULL)
    {
        if (Obj_IsLoadingLocked() != 0)
        {
            child = (GameObject*)Obj_SetupObject(Obj_AllocObjectSetup(0x24, LANDEDARWING_CHILD_OBJ_GADGET_UNIT), 4, -1, -1, 0);
            state->childObject = child;
            if (state->childObject != NULL)
            {
                ObjLink_AttachChild((int)obj, (int)state->childObject, 0);
                arwarwinggu_setTextureFrame(state->childObject, 0xaf);
                state->childObject->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }

    if (state->childObject != NULL)
    {
        arwarwinggu_applyTextureFrame(state->childObject);
    }

    if ((u32)player != 0 && playerGetFocusObject((GameObject*)player) != NULL)
    {
        *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    else
    {
        *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    }

    switch (state->sequenceState)
    {
    case 0:
        if (ObjTrigger_IsSet((int)obj) != 0)
        {
            int nearest;
            int def;
            def = *(int*)&(obj)->anim.placementData;
            nearest = ObjGroup_FindNearestObject(LANDEDARWING_TARGET_OBJGROUP, (int)obj, NULL);
            if ((obj)->anim.mapEventSlot == 0xd && mainGetBit(GAMEBIT_Tricky_SaidGoodBye) != 0)
            {
                ((GameObject*)nearest)->anim.localPosY += lbl_803E3BA0;
                (*gObjectTriggerInterface)->runSequence(2, (void*)nearest, -1);
            }
            else
            {
                (*gObjectTriggerInterface)->runSequence(1, (void*)nearest, -1);
            }
            mainSetBits(((LandedArwingUpdateDamageTexturePlacement*)def)->triggerGameBit, 0);
        }
        break;
    case 1:
        if (ObjTrigger_IsSet((int)obj) != 0)
        {
            state->sequenceState = 2;
            cutSceneFn_8011dd30();
        }
        ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f, &state->sequenceHitCooldown);
        break;
    case 2:
        if (fn_8012DDA4() != 0)
        {
            int def;
            int nearest;
            def = *(int*)&(obj)->anim.placementData;
            nearest = ObjGroup_FindNearestObject(LANDEDARWING_TARGET_OBJGROUP, (int)obj, NULL);
            if ((obj)->anim.mapEventSlot == 0xd && mainGetBit(GAMEBIT_Tricky_SaidGoodBye) != 0)
            {
                ((GameObject*)nearest)->anim.localPosY += lbl_803E3BA0;
                (*gObjectTriggerInterface)->runSequence(2, (void*)nearest, -1);
            }
            else
            {
                (*gObjectTriggerInterface)->runSequence(1, (void*)nearest, -1);
            }
            mainSetBits(((LandedArwingUpdateDamageTexturePlacement*)def)->triggerGameBit, 0);
        }
        else
        {
            state->sequenceState = 1;
        }
        break;
    }
}

void landed_arwing_init(GameObject* obj, int param)
{
    LandedArwingState* state = obj->extra;
    obj->objectFlags = obj->objectFlags | LANDEDARWING_OBJFLAG_HITDETECT_DISABLED;
    state->sequenceState = 1;
    if (mainGetBit(((LandedArwingPlacement*)param)->triggerGameBit) == 0)
    {
        unlockLevel(0, 0, 1);
    }
    obj->animEventCallback = Landed_Arwing_SeqFn;
}

void landed_arwing_updateHitReaction(GameObject* obj, LandedArwingState* state)
{
    int i;
    LandedArwingState* otherState;
    int def;
    ObjPlacement* setup;
    int other;
    f32 range;
    f32 yOffset;
    ObjAnimEventList events;

    def = *(int*)&(obj)->anim.placementData;
    if (!((LandedArwingHitFlagBits*)&state->hitFlags)->damaged ||
        (((LandedArwingHitFlagBits*)&state->hitFlags)->impactHandled && state->hitStarted == 0u))
    {
        return;
    }
    if (state->hitStarted != 0)
    {
        (obj)->anim.rotY = 0;
        (obj)->anim.rotZ = 0;
        if ((obj)->anim.currentMoveProgress >= lbl_803E3BBC &&
            !((LandedArwingHitFlagBits*)&state->hitFlags)->reactionDone)
        {
            if (((LandedArwingUpdateHitReactionPlacement*)def)->reactionGameBit > 0)
            {
                mainSetBits(((LandedArwingUpdateHitReactionPlacement*)def)->reactionGameBit, 1);
            }

            switch (((LandedArwingUpdateHitReactionPlacement*)def)->reactionType)
            {
            case 0:
                if (Obj_IsLoadingLocked() != 0)
                {
                    i = 0;
                    yOffset = lbl_803E3BB8;
                    while (i < ((LandedArwingUpdateHitReactionPlacement*)def)->spawnCount)
                    {
                        setup = Obj_AllocObjectSetup(0x24, LANDEDARWING_CHILD_OBJ_DEBRIS);
                        setup->posX = (obj)->anim.localPosX;
                        setup->posY = yOffset + (obj)->anim.localPosY;
                        setup->posZ = (obj)->anim.localPosZ;
                        setup->color[0] = 1;
                        Obj_SetupObject(setup, 5, (obj)->anim.mapEventSlot, -1, (obj)->anim.parent);
                        i++;
                    }
                }
                break;
            case 1:
                range = lbl_803E3BC0;
                other = ObjGroup_FindNearestObject(STAFFACTIVATED_OBJ_GROUP, (int)obj, &range);
                if ((void*)other != NULL)
                {
                    otherState = ((GameObject*)other)->extra;
                    if (((LandedArwingUpdateHitReactionPlacement*)*(int*)&((GameObject*)other)->anim.placementData)
                            ->siblingGameBit > 0)
                    {
                        mainSetBits(
                            ((LandedArwingUpdateHitReactionPlacement*)*(int*)&((GameObject*)other)->anim.placementData)
                                ->siblingGameBit,
                            1);
                    }
                    ((LandedArwingHitFlagBits*)&otherState->hitFlags)->damaged = 1;
                }
                break;
            case 2:
                break;
            }
            state->hitStarted = 0;
            ((LandedArwingHitFlagBits*)&state->hitFlags)->reactionDone = 1;
        }
        ((LandedArwingHitFlagBits*)&state->hitFlags)->impactHandled = 1;
        state->path8Fx = lbl_803E3BC4;
    }
    else
    {
        if (((LandedArwingUpdateHitReactionPlacement*)def)->reactionType == 2)
        {
            (obj)->anim.rotY = randomGetRange(-200, 200);
            (obj)->anim.rotZ = randomGetRange(-200, 200);
        }
        ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f, &state->hitEffectCooldown);
    }
    ObjAnim_AdvanceCurrentMove((int)obj, state->path8Fx, timeDelta, &events);
}

void landed_arwing_updateDamageTexture(GameObject* obj, LandedArwingState* state)
{
    int def;
    ObjTextureRuntimeSlot* texture;
    u32 bit;
    LandedArwingHitFlagBits* flags;

    def = *(int*)&obj->anim.placementData;
    flags = (LandedArwingHitFlagBits*)&state->hitFlags;
    if (((LandedArwingUpdateDamageTexturePlacement*)def)->damageStateGameBit != -1)
    {
        bit = mainGetBit(((LandedArwingUpdateDamageTexturePlacement*)def)->damageStateGameBit);
        flags->gameBit24Set = bit;
        bit = flags->gameBit24Set;
        if (bit != 0 && *(u8*)(def + 0x1c) == 5)
        {
            flags->impactHandled = 1;
        }
        else if (bit == 0)
        {
            flags->impactHandled = 0;
        }
    }

    if (flags->damaged == 0)
    {
        if (((LandedArwingUpdateDamageTexturePlacement*)def)->damagedGameBit != -1 &&
            mainGetBit(((LandedArwingUpdateDamageTexturePlacement*)def)->damagedGameBit) != 0)
        {
            flags->damaged = 1;
        }
    }
    else
    {
        if (((LandedArwingUpdateDamageTexturePlacement*)def)->damagedGameBit != -1 &&
            mainGetBit(((LandedArwingUpdateDamageTexturePlacement*)def)->damagedGameBit) == 0)
        {
            flags->damaged = 0;
        }
    }

    texture = objFindTexture((GameObject*)obj, 0, 0);
    if (texture != NULL)
    {
        if (flags->damaged != 0)
        {
            if (flags->gameBit24Set != 0)
            {
                texture->textureId = 0x200;
            }
            else
            {
                texture->textureId = 0x100;
            }
        }
        else
        {
            texture->textureId = 0;
        }
    }
}
