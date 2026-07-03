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
#include "main/game_object.h"
#include "main/dll/SH/dll_01AC_shqueenearthwalker.h"
#include "main/mapEvent.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/vecmath.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx_trigger_ids.h"

#define SHQUEENEARTHWALKER_OBJFLAG_HIDDEN 0x4000

extern int ObjTrigger_IsSetById();

extern f32 getXZDistance(f32* a, f32* b);
extern int fn_8003B500(void* obj, void* p2, f32 f1);
extern int fn_8003B228(void* obj, void* p2);
extern int characterDoEyeAnims(void* obj, void* p2);
extern int cMenuGetSelectedItem(void);
extern int getYButtonItem(s16 * outTrigger);
extern void* getTrickyObject(void);
extern int playerHasSpell(void* obj, int param);
extern void* ObjGroup_FindNearestObject(int group, void* obj, f32* distanceOut);
extern int ObjTrigger_IsSet(void* obj);
extern void Sfx_PlayFromObject(void* obj, int sfxId);
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
s16 gQueenEarthWalkerMoveTable[6] = {34, 34, 34, 5, 28, 0};
f32 gQueenEarthWalkerMoveSpeedTable[5] = {0.005f, 0.005f, 0.005f, 0.01f, 0.005f};
extern f32 lbl_803E53F8;
extern f32 gQueenEarthWalkerPortalSpellDistance;
extern f32 gQueenEarthWalkerTrickyFeedDistance;
extern f32 gQueenEarthWalkerAttackTimerMin;
extern f32 gQueenEarthWalkerAttackTimerMax;

int sh_queenearthwalker_getExtraSize(void)
{
    return 0x40;
}

void sh_queenearthwalker_update(void* obj)
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

    state = ((GameObject*)obj)->extra;
    ((QueenEarthWalkerState*)state)->flags &= ~0x20;
    mapSlot = ((GameObject*)obj)->anim.mapEventSlot;
    action = (*gMapEventInterface)->getMapAct(mapSlot);

    if ((((QueenEarthWalkerState*)state)->flags & 0x1) != 0)
    {
        switch (action)
        {
        case 0:
            queenFeedFn_801d44a4(obj, state);
            break;
        case 1:
            if (GameBit_Get(0x193) != 0)
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
            if (GameBit_Get(0x13f) != 0)
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
            if (GameBit_Get(0x199) != 0)
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
            target = ObjGroup_FindNearestObject(0xf, obj, NULL);
            (*gObjectTriggerInterface)->preempt((int)target, 0x1324);
            (*gObjectTriggerInterface)->runSequence(1, target, 0x10);
            ((QueenEarthWalkerState*)state)->flags |= 0xc;
            ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableAct1;
            break;
        case 2:
            if (GameBit_Get(0xc2) == 6)
            {
                (*gObjectTriggerInterface)->preempt((int)obj, 0x18f6);
                (*gObjectTriggerInterface)->runSequence(6, obj, 1);
                ((QueenEarthWalkerState*)state)->stateIndex = 3;
            }
            else
            {
                if (GameBit_Get(0xbf) != 0)
                {
                    ((QueenEarthWalkerState*)state)->stateIndex = 1;
                }
                ((QueenEarthWalkerState*)state)->flags |= 0xc;
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
            target = ObjGroup_FindNearestObject(0xf, obj, NULL);
            (*gObjectTriggerInterface)->preempt((int)target, 0x6a4);
            (*gObjectTriggerInterface)->runSequence(7, target, 8);
            ((QueenEarthWalkerState*)state)->stateIndex = 4;
            ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableDeparture;
            break;
        default:
            break;
        }
        ((QueenEarthWalkerState*)state)->flags |= 0x1;
        return;
    }

    if ((((QueenEarthWalkerState*)state)->flags & 0x8) != 0)
    {
        fn_8003B228(obj, (u8*)state + 0x8);
    }
    else
    {
        characterDoEyeAnims(obj, (u8*)state + 0x8);
    }

    currentMove = ((GameObject*)obj)->anim.currentMove;
    targetMove = gQueenEarthWalkerMoveTable[((QueenEarthWalkerState*)state)->stateIndex];
    if (currentMove != targetMove)
    {
        ObjAnim_SetCurrentMove((int)obj, targetMove, lbl_803E53F8, 0);
    }
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(
        (int)obj, gQueenEarthWalkerMoveSpeedTable[((QueenEarthWalkerState*)state)->stateIndex], timeDelta, NULL);

    stateFlags = ((QueenEarthWalkerState*)state)->flags;
    if ((stateFlags & 0x10) == 0)
    {
        ((QueenEarthWalkerState*)state)->flags &= ~0x2;
        if (ObjTrigger_IsSet(obj) != 0 && *(u8*)(*(int*)((u8*)obj + 0x78) + 0x4) != 4)
        {
            eventIndex = randomGetRange(1, *((QueenEarthWalkerState*)state)->eventTable);
            ((QueenEarthWalkerState*)state)->flags |= 0x2;
            (*gObjectTriggerInterface)->runSequence(
                ((u8*)((QueenEarthWalkerState*)state)->eventTable)[eventIndex], obj, -1);
        }
    }

    if (RandomTimer_UpdateRangeTrigger(&((QueenEarthWalkerState*)state)->attackTimer, gQueenEarthWalkerAttackTimerMin,
                                       gQueenEarthWalkerAttackTimerMax) != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_thorntail);
    }
}

void queenFeedFn_801d44a4(void* obj, void* state)
{
    s16 triggerId;
    s32 total;
    void* tricky;
    void* player;

    switch (((QueenEarthWalkerState*)state)->stateIndex)
    {
    case 0:
        if (GameBit_Get(0xbf) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(1, obj, -1);
            ((QueenEarthWalkerState*)state)->stateIndex = 1;
        }
        break;
    case 1:
        ((GameObject*)obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        if (cMenuGetSelectedItem() == -1)
        {
            if (getYButtonItem(&triggerId) == 0 || triggerId != 0x66d)
            {
                tricky = getTrickyObject();
                if (tricky != NULL &&
                    getXZDistance((f32*)((u8*)tricky + 0x18), &((GameObject*)obj)->anim.worldPosX) <
                    gQueenEarthWalkerTrickyFeedDistance)
                {
                    Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 2);
                }
                else
                {
                    ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
                }
                break;
            }
        }
        Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 4);
        if (ObjTrigger_IsSetById(obj, 0x66d) != 0)
        {
            ((QueenEarthWalkerState*)state)->flags |= 0x10;
            total = GameBit_Get(0x66d);
            total += GameBit_Get(0xc2);
            GameBit_Set(0x66d, 0);
            GameBit_Set(0xc2, total);
            if (total != 6)
            {
                ((QueenEarthWalkerState*)state)->flags |= 0x2;
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
        GameBit_Set(0x9e, 1);
        ((QueenEarthWalkerState*)state)->stateIndex = 3;
        break;
    case 3:
        Obj_SetActiveHitVolumeBounds(obj, 0, 0, 0, 0, 2);
        ((QueenEarthWalkerState*)state)->flags &= ~0x4;
        ((QueenEarthWalkerState*)state)->flags &= ~0x8;
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

void openPortalFn_801d4364(void* obj, void* state)
{
    void* player;

    player = Obj_GetPlayerObject();
    ((GameObject*)obj)->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    if (GameBit_Get(0xc48) != 0)
    {
        ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTableComplete;
    }
    else if (GameBit_Get(0x23c) != 0)
    {
        ((QueenEarthWalkerState*)state)->eventTable = &gQueenEarthWalkerEventTablePortalReady;
    }
    else if (GameBit_Get(0x5bd) != 0)
    {
        ((GameObject*)obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        if (playerHasSpell(player, 3) != 0 &&
            getXZDistance(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX) < gQueenEarthWalkerPortalSpellDistance)
        {
            GameBit_Set(0x23b, 1);
        }
    }
    else if (GameBit_Get(0xa31) != 0)
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

void sh_queenearthwalker_init(void* obj, QueenEarthWalkerMapData* mapData)
{
    ((GameObject*)obj)->anim.rotX = (s16)(mapData->yawByte << 8);
    ((GameObject*)obj)->animEventCallback = sh_queenearthwalker_processAnimEvents;
    ((GameObject*)obj)->objectFlags |= SHQUEENEARTHWALKER_OBJFLAG_HIDDEN;
}
