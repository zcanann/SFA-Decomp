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
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/mapEvent.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/dll/CF/CFBaby.h"
#include "main/objprint_dolphin.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/dll_011B_landedarwing.h"

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

extern int randomGetRange(int lo, int hi);
extern int ObjGroup_FindNearestObject(int group, u32 obj, float* maxDistance);
extern void ObjLink_DetachChild(int obj, int child);
extern void ObjLink_AttachChild(int parent, int child, u16 linkMode);
extern int ObjTrigger_IsSet(int obj);
extern void ObjPath_GetPointWorldPosition(int obj, int pointIndex, float* outX, float* outY, float* outZ, int useInputPosition);
extern void* Obj_GetPlayerObject(void);
extern int loadMapAndParent(int mapId);
extern int mapGetDirIdx(int idx);
extern int lockLevel(s32 val, int idx);
extern int mapUnload(int mapId, int flags);
extern void setLoadedFileFlags_blocks1(void);
extern void warpToMap(int idx, s8 transType);
extern int unlockLevel(s32 val, int idx, int flag);
extern void fn_8022F270(int obj, int arg);
extern void fn_8022F27C(int obj);
extern int fn_802972A8(int obj);




int landed_arwing_getExtraSize(void) { return 0x1c; }

extern f32 timeDelta;
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int type);
extern int Obj_SetupObject(int setup, int arg1, int arg2, int arg3, int arg4);
extern void objRenderFn_8003b8f4(f32);
extern void Obj_FreeObject(int obj);

#pragma scheduling off
#pragma peephole off
void landed_arwing_free(int obj)
{
    int o = obj;
    int* p = (int*)((GameObject*)o)->extra;
    if (*(void**)&p[0x10 / 4] != NULL)
    {
        Obj_FreeObject(p[0x10 / 4]);
        ObjLink_DetachChild(o, p[0x10 / 4]);
    }
}

extern f32 lbl_803E3BA4;

void landed_arwing_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
    {
        objRenderFn_8003b8f4(lbl_803E3BA4);
        landed_arwing_renderPathEffects(obj);
    }
}

typedef struct LandedArwingFxPoint
{
    f32 scale;
    u8 pathPoint;
    u8 arg5;
    u8 arg6;
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
    int childObject;
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

typedef struct LandedArwingHitFlagBits
{
    u8 damaged : 1;
    u8 impactHandled : 1;
    u8 gameBit24Set : 1;
    u8 reactionDone : 1;
    u8 rest : 4;
} LandedArwingHitFlagBits;

extern LandedArwingFxPoint gLandedArwingPathFxTable[];
extern f32 lbl_803E3B98;
extern f32 lbl_803E3B9C;
extern f32 lbl_803E3BA0;
extern f32 lbl_803E3BA8;
extern f32 lbl_803E3BAC;
extern f32 lbl_803E3BB0;
extern f32 lbl_803E3BB8;
extern f32 lbl_803E3BBC;
extern f32 lbl_803E3BC0;
extern f32 lbl_803E3BC4;
extern void objfx_spawnMaskedHitEffect(int obj, f32 scale, int arg4, int arg5, int arg6, void* pos);
extern void objfx_spawnLightPulse(int obj, f32 scale, int arg4, int arg5, int arg6, f32 value, void* pos);

void landed_arwing_renderPathEffects(int obj)
{
    LandedArwingState* state;
    u8 i;
    LandedArwingFxScratch scratch;

    state = ((GameObject*)obj)->extra;
    if (state->enablePathFx != 0)
    {
        i = 0;
        while (i < 5)
        {
            ObjPath_GetPointWorldPosition(obj, gLandedArwingPathFxTable[i].pathPoint, &scratch.x, &scratch.y, &scratch.z, 0);
            scratch.x -= ((GameObject*)obj)->anim.localPosX;
            scratch.y -= ((GameObject*)obj)->anim.localPosY;
            scratch.z -= ((GameObject*)obj)->anim.localPosZ;
            objfx_spawnMaskedHitEffect(obj, ((GameObject*)obj)->anim.rootMotionScale * gLandedArwingPathFxTable[i].scale, 4,
                                       gLandedArwingPathFxTable[i].arg5, gLandedArwingPathFxTable[i].arg6, scratch.effectPos);
            i++;
        }
    }

    if (state->path6Fx != lbl_803E3B98)
    {
        ObjPath_GetPointWorldPosition(obj, 6, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= ((GameObject*)obj)->anim.localPosX;
        scratch.y -= ((GameObject*)obj)->anim.localPosY;
        scratch.z -= ((GameObject*)obj)->anim.localPosZ;
        objfx_spawnLightPulse(obj, lbl_803E3B9C, 4, 0, 0, state->path6Fx, scratch.effectPos);
    }

    if (state->path8Fx != lbl_803E3B98)
    {
        ObjPath_GetPointWorldPosition(obj, 8, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= ((GameObject*)obj)->anim.localPosX;
        scratch.y -= ((GameObject*)obj)->anim.localPosY;
        scratch.z -= ((GameObject*)obj)->anim.localPosZ;
        objfx_spawnLightPulse(obj, lbl_803E3B9C, 4, 0, 0, state->path8Fx, scratch.effectPos);
    }

    if (state->path7Fx != lbl_803E3B98)
    {
        ObjPath_GetPointWorldPosition(obj, 7, &scratch.x, &scratch.y, &scratch.z, 0);
        scratch.x -= ((GameObject*)obj)->anim.localPosX;
        scratch.y -= ((GameObject*)obj)->anim.localPosY;
        scratch.z -= ((GameObject*)obj)->anim.localPosZ;
        objfx_spawnLightPulse(obj, lbl_803E3B9C, 4, 0, 0, state->path7Fx, scratch.effectPos);
    }
}

#define MAP_EVENT_STATUS(mapId) (*gMapEventInterface)->getMapAct((mapId))
#define MAP_EVENT_SET(mapId, value) (*gMapEventInterface)->setMapAct((mapId), (value))
#define MAP_EVENT_OP(mapId, arg, value) (*gMapEventInterface)->setObjGroupStatus((mapId), (arg), (value))

int Landed_Arwing_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    int def;
    LandedArwingState* state;
    int mapId;
    int child;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
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
            if ((void*)child != NULL)
            {
                ((GameObject*)child)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            }
            break;
        case 0x19:
            child = state->childObject;
            if ((void*)child != NULL)
            {
                ((GameObject*)child)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
            break;
        }
    }
    return 0;
}

void landed_arwing_update(int obj)
{
    LandedArwingState* state;
    int player;
    int child;

    state = ((GameObject*)obj)->extra;
    player = (int)Obj_GetPlayerObject();
    if ((u32)state->childObject == 0)
    {
        if (Obj_IsLoadingLocked() != 0)
        {
            child = Obj_SetupObject(Obj_AllocObjectSetup(0x24, 0x606), 4, -1, -1, 0);
            state->childObject = child;
            if ((u32)state->childObject != 0)
            {
                ObjLink_AttachChild(obj, state->childObject, 0);
                fn_8022F270(state->childObject, 0xaf);
                ((GameObject*)state->childObject)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }

    if ((u32)state->childObject != 0)
    {
        fn_8022F27C(state->childObject);
    }

    if ((u32)player != 0 && (u32)fn_802972A8(player) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    }

    switch (state->sequenceState)
    {
    case 0:
        if (ObjTrigger_IsSet(obj) != 0)
        {
            int nearest;
            int def;
            def = *(int*)&((GameObject*)obj)->anim.placementData;
            nearest = ObjGroup_FindNearestObject(0xf, obj, NULL);
            if (((GameObject*)obj)->anim.mapEventSlot == 0xd && GameBit_Get(0xc92) != 0)
            {
                *(f32*)(nearest + 0x10) += lbl_803E3BA0;
                (*gObjectTriggerInterface)->runSequence(2, (void*)nearest, -1);
            }
            else
            {
                (*gObjectTriggerInterface)->runSequence(1, (void*)nearest, -1);
            }
            GameBit_Set(((LandedArwingUpdateDamageTexturePlacement*)def)->triggerGameBit, 0);
        }
        break;
    case 1:
        if (ObjTrigger_IsSet(obj) != 0)
        {
            state->sequenceState = 2;
            cutSceneFn_8011dd30();
        }
        ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f,
                                                  &state->sequenceHitCooldown);
        break;
    case 2:
        if (fn_8012DDA4() != 0)
        {
            int def;
            int nearest;
            def = *(int*)&((GameObject*)obj)->anim.placementData;
            nearest = ObjGroup_FindNearestObject(0xf, obj, NULL);
            if (((GameObject*)obj)->anim.mapEventSlot == 0xd && GameBit_Get(0xc92) != 0)
            {
                *(f32*)(nearest + 0x10) += lbl_803E3BA0;
                (*gObjectTriggerInterface)->runSequence(2, (void*)nearest, -1);
            }
            else
            {
                (*gObjectTriggerInterface)->runSequence(1, (void*)nearest, -1);
            }
            GameBit_Set(((LandedArwingUpdateDamageTexturePlacement*)def)->triggerGameBit, 0);
        }
        else
        {
            state->sequenceState = 1;
        }
        break;
    }
}

void landed_arwing_init(int obj, int param)
{
    LandedArwingState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x2000;
    state->sequenceState = 1;
    if (GameBit_Get(((LandedArwingPlacement*)param)->triggerGameBit) == 0)
    {
        unlockLevel(0, 0, 1);
    }
    ((GameObject*)obj)->animEventCallback = Landed_Arwing_SeqFn;
}

void landed_arwing_updateHitReaction(int obj, LandedArwingState* state)
{
    int i;
    LandedArwingState* otherState;
    int def;
    int setup;
    int other;
    f32 range;
    f32 yOffset;
    ObjAnimEventList events;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (!((LandedArwingHitFlagBits*)&state->hitFlags)->damaged ||
        (((LandedArwingHitFlagBits*)&state->hitFlags)->impactHandled && state->hitStarted == 0u))
    {
        return;
    }
    if (state->hitStarted != 0)
    {
        ((GameObject*)obj)->anim.rotY = 0;
        ((GameObject*)obj)->anim.rotZ = 0;
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E3BBC && !((LandedArwingHitFlagBits*)&state->hitFlags)->reactionDone)
        {
            if (((LandedArwingUpdateHitReactionPlacement*)def)->reactionGameBit > 0)
            {
                GameBit_Set(((LandedArwingUpdateHitReactionPlacement*)def)->reactionGameBit, 1);
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
                        setup = Obj_AllocObjectSetup(0x24, 0x259);
                        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                        ((ObjPlacement*)setup)->posY = yOffset + ((GameObject*)obj)->anim.localPosY;
                        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                        ((ObjPlacement*)setup)->color[0] = 1;
                        Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                        *(int*)&((GameObject*)obj)->anim.parent);
                        i++;
                    }
                }
                break;
            case 1:
                range = lbl_803E3BC0;
                other = ObjGroup_FindNearestObject(0x41, obj, &range);
                if ((void*)other != NULL)
                {
                    otherState = ((GameObject*)other)->extra;
                    if (((LandedArwingUpdateHitReactionPlacement*)*(int*)&((GameObject*)other)->anim.placementData)->siblingGameBit > 0)
                    {
                        GameBit_Set(((LandedArwingUpdateHitReactionPlacement*)*(int*)&((GameObject*)other)->anim.placementData)->siblingGameBit, 1);
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
            ((GameObject*)obj)->anim.rotY = randomGetRange(-200, 200);
            ((GameObject*)obj)->anim.rotZ = randomGetRange(-200, 200);
        }
        ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xb4, 0xf0, 0xff, 0x6f,
                                                  &state->hitEffectCooldown);
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, state->path8Fx, timeDelta,
                                                                  &events);
}

void landed_arwing_updateDamageTexture(int obj, LandedArwingState* state)
{
    int def;
    ObjTextureRuntimeSlot* texture;
    u32 bit;
    LandedArwingHitFlagBits* flags;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    flags = (LandedArwingHitFlagBits*)&state->hitFlags;
    if (((LandedArwingUpdateDamageTexturePlacement*)def)->damageStateGameBit != -1)
    {
        bit = GameBit_Get(((LandedArwingUpdateDamageTexturePlacement*)def)->damageStateGameBit);
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
        if (((LandedArwingUpdateDamageTexturePlacement*)def)->damagedGameBit != -1 && GameBit_Get(
            ((LandedArwingUpdateDamageTexturePlacement*)def)->damagedGameBit) != 0)
        {
            flags->damaged = 1;
        }
    }
    else
    {
        if (((LandedArwingUpdateDamageTexturePlacement*)def)->damagedGameBit != -1 && GameBit_Get(
            ((LandedArwingUpdateDamageTexturePlacement*)def)->damagedGameBit) == 0)
        {
            flags->damaged = 0;
        }
    }

    texture = objFindTexture((void*)obj, 0, 0);
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
