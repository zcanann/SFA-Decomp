/*
 * shqueenearthwalker (DLL 0x1AC) - the Queen EarthWalker in ThornTail
 * Hollow, the giant matriarch dinosaur the player tends.
 *
 * update() is driven by the area's map-event act: it picks the queen's
 * trigger-sequence event table for the current act, walks her toward the
 * player and runs idle/attention sequences. The feed and open-portal
 * sub-handlers cover the berry-feeding interaction (Y-button item 0x66d)
 * and the spell-portal opening. stateIndex selects the locomotion move
 * (gQueenEarthWalkerMoveTable/E24 tables); the flags byte tracks the per-frame mode.
 */
#include "main/dll/SH/SHrocketmushroom.h"
#include "main/gamebit_ids.h"
#include "main/game_object.h"
#include "main/audio/sfx.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/SH/dll_01AC_shqueenearthwalker.h"
#include "main/mapEvent.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/vecmath.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx_trigger_ids.h"

#define SHQUEENEARTHWALKER_OBJFLAG_HIDDEN 0x4000
/* object group scanned for the nearest target (player group) */
#define SHQUEENEARTHWALKER_TARGET_OBJGROUP 0xf

/* QueenEarthWalkerState::flags bits (shared with dll_801d4198.c) */
#define QEW_FLAG_STARTED   0x1  /* first update ran; per-act logic engaged */
#define QEW_FLAG_TARGETING 0x2  /* targeting the player */
#define QEW_FLAG_LATCHED   0x4  /* player position captured */
#define QEW_FLAG_EYE_ANIMS 0x8  /* run characterDoEyeAnims vs the bite */
#define QEW_FLAG_ACTIVE    0x10 /* feed sequence completed; suppress idle attacks */
#define QEW_FLAG_INIT_DONE 0x20 /* per-frame anim-event handshake (cleared each update) */

extern u8 gQueenEarthWalkerEventTableAct1;
extern u8 gQueenEarthWalkerEventTableAct2;
extern u8 gQueenEarthWalkerEventTableFed;
extern u8 gQueenEarthWalkerEventTableFeed;
extern u8 gQueenEarthWalkerEventTablePortalDefault;
extern u8 gQueenEarthWalkerEventTablePortalReady;
extern u8 gQueenEarthWalkerEventTableSpell;
extern u8 gQueenEarthWalkerEventTableBerry;
extern u8 gQueenEarthWalkerEventTableDeparture;
extern u8 gQueenEarthWalkerEventTableComplete;
extern f32 lbl_803E53F8;
extern f32 gQueenEarthWalkerPortalSpellDistance;
extern f32 gQueenEarthWalkerTrickyFeedDistance;
extern f32 gQueenEarthWalkerAttackTimerMin;
extern f32 gQueenEarthWalkerAttackTimerMax;

extern int ObjTrigger_IsSetById();
extern f32 getXZDistance(f32* a, f32* b);
extern int fn_8003B500(GameObject* obj, void* p2, f32 f1);
extern int fn_8003B228(GameObject* obj, void* p2);
extern int characterDoEyeAnims(GameObject* obj, void* p2);
extern int getYButtonItem(s16* outTrigger);
extern void* getTrickyObject(void);
extern int playerHasSpell(GameObject* obj, int param);
extern void* ObjGroup_FindNearestObject(int group, void* obj, f32* distanceOut);
extern int ObjTrigger_IsSet(void* obj);

s16 gQueenEarthWalkerMoveTable[6] = {34, 34, 34, 5, 28, 0};
f32 gQueenEarthWalkerMoveSpeedTable[5] = {0.005f, 0.005f, 0.005f, 0.01f, 0.005f};

int sh_queenearthwalker_getExtraSize(void)
{
    return 0x40;
}

void sh_queenearthwalker_update(GameObject* obj)
{
    void* state;
    void* player;
    void* target;
    u8 action;
    s8 mapSlot;
    u8 stateFlags;
    u8 eventIndex;
    int currentMove;
    s16 targetMove;

    state = (obj)->extra;
    ((QueenEarthWalkerState*)state)->flags &= ~QEW_FLAG_INIT_DONE;
    mapSlot = (obj)->anim.mapEventSlot;
    action = (*gMapEventInterface)->getMapAct(mapSlot);

    if ((((QueenEarthWalkerState*)state)->flags & QEW_FLAG_STARTED) != 0)
    {
        switch (action)
        {
        case 0:
            queenFeedFn_801d44a4(obj, state);
            break;
        case 1:
            if (mainGetBit(GAMEBIT_ITEM_MoonPassKey_Got) != 0)
            {
                ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableComplete;
            }
            else
            {
                ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableFeed;
            }
            player = Obj_GetPlayerObject();
            ((QueenEarthWalkerState*)state)->eyeAnimEnabled = 1;
            ((QueenEarthWalkerState*)state)->targetX = ((GameObject*)player)->anim.localPosX;
            ((QueenEarthWalkerState*)state)->targetY = ((GameObject*)player)->anim.localPosY;
            ((QueenEarthWalkerState*)state)->targetZ = ((GameObject*)player)->anim.localPosZ;
            fn_8003B500(obj, (u8*)state + 0x8, lbl_803E53F8);
            break;
        case 2:
            openPortalFn_801d4364(obj, state);
            break;
        case 3:
            if (mainGetBit(GAMEBIT_ITEM_BigScarabBag_Got) != 0)
            {
                ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableComplete;
            }
            else
            {
                ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableSpell;
            }
            player = Obj_GetPlayerObject();
            ((QueenEarthWalkerState*)state)->eyeAnimEnabled = 1;
            ((QueenEarthWalkerState*)state)->targetX = ((GameObject*)player)->anim.localPosX;
            ((QueenEarthWalkerState*)state)->targetY = ((GameObject*)player)->anim.localPosY;
            ((QueenEarthWalkerState*)state)->targetZ = ((GameObject*)player)->anim.localPosZ;
            fn_8003B500(obj, (u8*)state + 0x8, lbl_803E53F8);
            break;
        case 4:
            if (mainGetBit(0x199) != 0)
            {
                ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableComplete;
            }
            else
            {
                ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableBerry;
            }
            player = Obj_GetPlayerObject();
            ((QueenEarthWalkerState*)state)->eyeAnimEnabled = 1;
            ((QueenEarthWalkerState*)state)->targetX = ((GameObject*)player)->anim.localPosX;
            ((QueenEarthWalkerState*)state)->targetY = ((GameObject*)player)->anim.localPosY;
            ((QueenEarthWalkerState*)state)->targetZ = ((GameObject*)player)->anim.localPosZ;
            fn_8003B500(obj, (u8*)state + 0x8, lbl_803E53F8);
            break;
        case 5:
            player = Obj_GetPlayerObject();
            ((QueenEarthWalkerState*)state)->eyeAnimEnabled = 1;
            ((QueenEarthWalkerState*)state)->targetX = ((GameObject*)player)->anim.localPosX;
            ((QueenEarthWalkerState*)state)->targetY = ((GameObject*)player)->anim.localPosY;
            ((QueenEarthWalkerState*)state)->targetZ = ((GameObject*)player)->anim.localPosZ;
            fn_8003B500(obj, (u8*)state + 0x8, lbl_803E53F8);
            break;
        case 6:
        case 7:
        case 8:
            break;
        default:
            break;
        }
    }
    else
    {
        switch (action)
        {
        case 1:
            target = ObjGroup_FindNearestObject(SHQUEENEARTHWALKER_TARGET_OBJGROUP, obj, NULL);
            (*gObjectTriggerInterface)->preempt((int)target, 0x1324);
            (*gObjectTriggerInterface)->runSequence(1, target, 0x10);
            ((QueenEarthWalkerState*)state)->flags |= (QEW_FLAG_LATCHED | QEW_FLAG_EYE_ANIMS);
            ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableAct1;
            break;
        case 2:
            if (mainGetBit(GAMEBIT_ITEM_WhiteGrubTub_Used) == 6)
            {
                (*gObjectTriggerInterface)->preempt((int)obj, 0x18f6);
                (*gObjectTriggerInterface)->runSequence(6, obj, 1);
                ((QueenEarthWalkerState*)state)->stateIndex = 3;
            }
            else
            {
                if (mainGetBit(GAMEBIT_SH_ReturnedToQueen) != 0)
                {
                    ((QueenEarthWalkerState*)state)->stateIndex = 1;
                }
                ((QueenEarthWalkerState*)state)->flags |= (QEW_FLAG_LATCHED | QEW_FLAG_EYE_ANIMS);
                ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableAct2;
            }
            break;
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
            (*gObjectTriggerInterface)->preempt((int)obj, 0x18f6);
            (*gObjectTriggerInterface)->runSequence(6, obj, 1);
            ((QueenEarthWalkerState*)state)->stateIndex = 3;
            break;
        case 8:
            target = ObjGroup_FindNearestObject(SHQUEENEARTHWALKER_TARGET_OBJGROUP, obj, NULL);
            (*gObjectTriggerInterface)->preempt((int)target, 0x6a4);
            (*gObjectTriggerInterface)->runSequence(7, target, 8);
            ((QueenEarthWalkerState*)state)->stateIndex = 4;
            ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableDeparture;
            break;
        default:
            break;
        }
        ((QueenEarthWalkerState*)state)->flags |= QEW_FLAG_STARTED;
        return;
    }

    if ((((QueenEarthWalkerState*)state)->flags & QEW_FLAG_EYE_ANIMS) != 0)
    {
        fn_8003B228(obj, (u8*)state + 0x8);
    }
    else
    {
        characterDoEyeAnims(obj, (u8*)state + 0x8);
    }

    currentMove = (obj)->anim.currentMove;
    targetMove = gQueenEarthWalkerMoveTable[((QueenEarthWalkerState*)state)->stateIndex];
    if (currentMove != targetMove)
    {
        ObjAnim_SetCurrentMove((int)obj, targetMove, lbl_803E53F8, 0);
    }
    ObjAnim_AdvanceCurrentMove(
        (int)obj, gQueenEarthWalkerMoveSpeedTable[((QueenEarthWalkerState*)state)->stateIndex], timeDelta, NULL);

    stateFlags = ((QueenEarthWalkerState*)state)->flags;
    if ((stateFlags & QEW_FLAG_ACTIVE) == 0)
    {
        ((QueenEarthWalkerState*)state)->flags &= ~QEW_FLAG_TARGETING;
        if (ObjTrigger_IsSet(obj) != 0 && *(u8*)(*(int*)((u8*)obj + 0x78) + 0x4) != 4)
        {
            eventIndex = randomGetRange(1, *((QueenEarthWalkerState*)state)->eventTable);
            ((QueenEarthWalkerState*)state)->flags |= QEW_FLAG_TARGETING;
            (*gObjectTriggerInterface)
                ->runSequence(((u8*)((QueenEarthWalkerState*)state)->eventTable)[eventIndex], obj, -1);
        }
    }

    if (RandomTimer_UpdateRangeTrigger(&((QueenEarthWalkerState*)state)->attackTimer, gQueenEarthWalkerAttackTimerMin,
                                       gQueenEarthWalkerAttackTimerMax) != 0)
    {
        Sfx_PlayFromObject((u32)obj, SFXTRIG_thorntail);
    }
}

void queenFeedFn_801d44a4(GameObject* obj, void* state)
{
    s16 triggerId;
    s32 total;
    void* tricky;
    void* player;

    switch (((QueenEarthWalkerState*)state)->stateIndex)
    {
    case 0:
        if (mainGetBit(GAMEBIT_SH_ReturnedToQueen) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            ((QueenEarthWalkerState*)state)->stateIndex = 1;
        }
        break;
    case 1:
        (obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        if (cMenuGetSelectedItemInt() == -1)
        {
            if (getYButtonItem(&triggerId) == 0 || triggerId != 0x66d)
            {
                tricky = getTrickyObject();
                if (tricky != NULL && getXZDistance((f32*)((u8*)tricky + 0x18), &(obj)->anim.worldPosX) <
                                          gQueenEarthWalkerTrickyFeedDistance)
                {
                    Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 2);
                }
                else
                {
                    (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                }
                break;
            }
        }
        Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 4);
        if (ObjTrigger_IsSetById(obj, 0x66d) != 0)
        {
            ((QueenEarthWalkerState*)state)->flags |= QEW_FLAG_ACTIVE;
            total = mainGetBit(GAMEBIT_ITEM_WhiteShroom_Count);
            total += mainGetBit(GAMEBIT_ITEM_WhiteGrubTub_Used);
            mainSetBits(GAMEBIT_ITEM_WhiteShroom_Count, 0);
            mainSetBits(GAMEBIT_ITEM_WhiteGrubTub_Used, total);
            if (total != 6)
            {
                ((QueenEarthWalkerState*)state)->flags |= QEW_FLAG_TARGETING;
                if (randomGetRange(0, 1) != 0)
                {
                    (*gObjectTriggerInterface)->runSequence(3, obj, -1);
                }
                else
                {
                    (*gObjectTriggerInterface)->runSequence(4, obj, -1);
                }
            }
            else
            {
                (*gObjectTriggerInterface)->runSequence(5, obj, -1);
                ((QueenEarthWalkerState*)state)->stateIndex = 2;
            }
        }
        break;
    case 2:
        (*gObjectTriggerInterface)->runSequence(6, obj, -1);
        mainSetBits(0x9e, 1);
        ((QueenEarthWalkerState*)state)->stateIndex = 3;
        break;
    case 3:
        Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 2);
        ((QueenEarthWalkerState*)state)->flags &= ~QEW_FLAG_LATCHED;
        ((QueenEarthWalkerState*)state)->flags &= ~QEW_FLAG_EYE_ANIMS;
        ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableFed;
        player = Obj_GetPlayerObject();
        ((u8*)state)[0x8] = 1;
        ((QueenEarthWalkerState*)state)->targetX = ((GameObject*)player)->anim.localPosX;
        ((QueenEarthWalkerState*)state)->targetY = ((GameObject*)player)->anim.localPosY;
        ((QueenEarthWalkerState*)state)->targetZ = ((GameObject*)player)->anim.localPosZ;
        fn_8003B500(obj, (void*)((int)state + 0x8), lbl_803E53F8);
        break;
    default:
        break;
    }
}

void openPortalFn_801d4364(GameObject* obj, void* state)
{
    void* player;

    player = Obj_GetPlayerObject();
    (obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    if (mainGetBit(0xc48) != 0)
    {
        ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableComplete;
    }
    else if (mainGetBit(GAMEBIT_SH_Related023C) != 0)
    {
        ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTablePortalReady;
    }
    else if (mainGetBit(GAMEBIT_STAFF_ABILITY_OPEN_PORTAL) != 0)
    {
        (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if (playerHasSpell((GameObject*)(player), 3) != 0 &&
            getXZDistance(&((GameObject*)player)->anim.worldPosX, &(obj)->anim.worldPosX) <
                gQueenEarthWalkerPortalSpellDistance)
        {
            mainSetBits(0x23b, 1);
        }
    }
    else if (mainGetBit(GAMEBIT_SH_RescuedEggs) != 0)
    {
        ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableComplete;
    }
    else
    {
        ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTablePortalDefault;
    }

    player = Obj_GetPlayerObject();
    ((u8*)state)[8] = 1;
    ((QueenEarthWalkerState*)state)->targetX = ((GameObject*)player)->anim.localPosX;
    ((QueenEarthWalkerState*)state)->targetY = ((GameObject*)player)->anim.localPosY;
    ((QueenEarthWalkerState*)state)->targetZ = ((GameObject*)player)->anim.localPosZ;
    fn_8003B500(obj, (void*)((int)state + 0x8), lbl_803E53F8);
}

void sh_queenearthwalker_init(GameObject* obj, QueenEarthWalkerMapData* mapData)
{
    obj->anim.rotX = (s16)(mapData->yawByte << 8);
    obj->animEventCallback = sh_queenearthwalker_processAnimEvents;
    obj->objectFlags |= SHQUEENEARTHWALKER_OBJFLAG_HIDDEN;
}
