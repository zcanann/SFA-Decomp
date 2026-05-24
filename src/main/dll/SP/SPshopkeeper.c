#include "ghidra_import.h"
#include "main/dll/SP/SPshopkeeper.h"

#define SHOPKEEPER_THORNTAIL_OBJECT_ID 0x442ff
#define SHOPKEEPER_OBJFLAG_REFRESH_MAP 0x2
#define SHOPKEEPER_OBJFLAG_THORNTAIL_TRIGGERED 0x40
#define SHOPKEEPER_OBJFLAG_EARLY_SCENE_STARTED 0x80
#define SHOPKEEPER_LOADING_FLAG 0x1000

typedef struct ShopkeeperObject {
    u8 unk0[0xac];
    s8 mapId;
    u8 unkAD[3];
    u16 flagsB0;
} ShopkeeperObject;

typedef void (*ObjectTriggerRefreshFn)(int triggerId, int obj, int arg);
typedef void (*ScreenTransitionStartFn)(int transitionId, int value);
typedef int (*ScreenTransitionFinishedFn)(void);
typedef void (*MapEventTriggerFn)(int mapId, int eventId, int value, int arg);
typedef int (*MapEventGetAnimFn)(int mapId, int eventId);
typedef void (*MapEventSetAnimFn)(int mapId, int eventId, int value);

extern u32 GameBit_Get(u32 id);
extern void GameBit_Set(u32 id, u32 value);
extern int Obj_GetPlayerObject(void);
extern int ObjList_FindObjectById(int objectId);
extern int isScreenTransitionActive(void);
extern void padClearAnalogInputX(int controller);
extern void padClearAnalogInputY(int controller);
extern void buttonDisable(int controller, int flags);
extern int playerHasSpell(int obj, int spell);

extern int *gObjectTriggerInterface;
extern int *gScreenTransitionInterface;
extern int *gMapEventInterface;

#define OBJECT_TRIGGER_REFRESH(triggerId, obj, arg) \
    ((ObjectTriggerRefreshFn)(*(u32 *)(*gObjectTriggerInterface + 0x48)))((triggerId), (obj), (arg))
#define SCREEN_TRANSITION_START(transitionId, value) \
    ((ScreenTransitionStartFn)(*(u32 *)(*gScreenTransitionInterface + 0x8)))((transitionId), (value))
#define SCREEN_TRANSITION_FINISHED() \
    ((ScreenTransitionFinishedFn)(*(u32 *)(*gScreenTransitionInterface + 0x14)))()
#define MAP_EVENT_TRIGGER(mapId, eventId, value, arg) \
    ((MapEventTriggerFn)(*(u32 *)(*gMapEventInterface + 0x1c)))((mapId), (eventId), (value), (arg))
#define MAP_EVENT_GET_ANIM(mapId, eventId) \
    ((MapEventGetAnimFn)(*(u32 *)(*gMapEventInterface + 0x4c)))((mapId), (eventId))
#define MAP_EVENT_SET_ANIM(mapId, eventId, value) \
    ((MapEventSetAnimFn)(*(u32 *)(*gMapEventInterface + 0x50)))((mapId), (eventId), (value))
#define SHOPKEEPER_APPLY_MAP_OVERRIDE(state, enabledBit)      \
    if (GameBit_Get((enabledBit)) != 0) {                     \
        if ((state)->mapOverride != 0xcc) {                   \
            (state)->mapOverride = 0xcc;                      \
            GameBit_Set(0xc0, 1);                             \
            (state)->flags &= ~SHOPKEEPER_OBJFLAG_REFRESH_MAP;\
        }                                                     \
    } else if ((state)->mapOverride == 0xcc) {                \
        (state)->mapOverride = -1;                            \
    }

/*
 * --INFO--
 *
 * Function: SH_LevelControl_doThornTailEvents
 * EN v1.0 Address: 0x801D87F8
 * EN v1.0 Size: 776b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void SH_LevelControl_doThornTailEvents(int obj, ShopkeeperLevelControlState *state)
{
    ShopkeeperObject *thornTailObj;
    ShopkeeperObject *playerObj;

    SHOPKEEPER_APPLY_MAP_OVERRIDE(state, 0x193);

    switch (state->thornTailState) {
    case 0:
        if (GameBit_Get(0xd39) != 0) {
            state->thornTailState = 7;
        } else {
            OBJECT_TRIGGER_REFRESH(5, obj, -1);
            state->thornTailState = 1;
        }
        break;
    case 1:
        thornTailObj = (ShopkeeperObject *)ObjList_FindObjectById(SHOPKEEPER_THORNTAIL_OBJECT_ID);
        if ((thornTailObj->flagsB0 & SHOPKEEPER_LOADING_FLAG) == 0) {
            playerObj = (ShopkeeperObject *)Obj_GetPlayerObject();
            if ((playerObj->flagsB0 & SHOPKEEPER_LOADING_FLAG) == 0) {
                OBJECT_TRIGGER_REFRESH(6, obj, -1);
                state->thornTailState = 7;
                GameBit_Set(0xd39, 1);
            }
        }
        break;
    case 7:
        break;
    }

    if ((state->flags & SHOPKEEPER_OBJFLAG_THORNTAIL_TRIGGERED) == 0 &&
        GameBit_Get(0x190) != 0 &&
        GameBit_Get(0x191) != 0 &&
        GameBit_Get(0x192) != 0) {
        if (GameBit_Get(0x193) == 0) {
            thornTailObj = (ShopkeeperObject *)ObjList_FindObjectById(SHOPKEEPER_THORNTAIL_OBJECT_ID);
            if (thornTailObj != 0) {
                playerObj = (ShopkeeperObject *)Obj_GetPlayerObject();
                if ((playerObj->flagsB0 & SHOPKEEPER_LOADING_FLAG) == 0) {
                    if (isScreenTransitionActive() != 0) {
                        GameBit_Set(0x193, 1);
                        OBJECT_TRIGGER_REFRESH(1, obj, -1);
                        state->flags |= SHOPKEEPER_OBJFLAG_THORNTAIL_TRIGGERED;
                    } else {
                        GameBit_Set(0x193, 1);
                        SCREEN_TRANSITION_START(0x14, 1);
                    }
                }
            }
        } else if (SCREEN_TRANSITION_FINISHED() != 0) {
            thornTailObj = (ShopkeeperObject *)ObjList_FindObjectById(SHOPKEEPER_THORNTAIL_OBJECT_ID);
            if (thornTailObj != 0) {
                playerObj = (ShopkeeperObject *)Obj_GetPlayerObject();
                if ((playerObj->flagsB0 & SHOPKEEPER_LOADING_FLAG) == 0) {
                    OBJECT_TRIGGER_REFRESH(1, obj, -1);
                    state->flags |= SHOPKEEPER_OBJFLAG_THORNTAIL_TRIGGERED;
                }
            }
        }
    }

    if (GameBit_Get(0xea9) == 0 && GameBit_Get(0x611) != 0) {
        GameBit_Set(0xea9, 1);
        MAP_EVENT_TRIGGER(0, 0, 1, 0);
    }
}

/*
 * --INFO--
 *
 * Function: SH_LevelControl_doEarlyScenes
 * EN v1.0 Address: 0x801D8B00
 * EN v1.0 Size: 544b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void SH_LevelControl_doEarlyScenes(int obj, ShopkeeperLevelControlState *state)
{
    ShopkeeperObject *playerObj;
    s32 mapId;
    u8 mapEventActive;

    SHOPKEEPER_APPLY_MAP_OVERRIDE(state, 0x1ab);

    if (state->earlySceneDelay < 2) {
        state->earlySceneDelay++;
    } else {
        if (GameBit_Get(0xb) == 0) {
            padClearAnalogInputX(0);
            padClearAnalogInputY(0);
            buttonDisable(0, 0x100);
            buttonDisable(0, 0x200);
            buttonDisable(0, 0x1000);
            playerObj = (ShopkeeperObject *)Obj_GetPlayerObject();
            if ((playerObj->flagsB0 & SHOPKEEPER_LOADING_FLAG) == 0) {
                OBJECT_TRIGGER_REFRESH(0, obj, -1);
                GameBit_Set(0xb, 1);
            }
        }

        if ((state->flags & SHOPKEEPER_OBJFLAG_EARLY_SCENE_STARTED) == 0) {
            GameBit_Set(0x2ba, 0);
            state->flags |= SHOPKEEPER_OBJFLAG_EARLY_SCENE_STARTED;
        }
    }

    if (GameBit_Get(0x2da) == 0 &&
        GameBit_Get(0x34a) != 0 &&
        GameBit_Get(0x36f) != 0 &&
        GameBit_Get(0x166) != 0 &&
        GameBit_Get(0x167) != 0) {
        playerObj = (ShopkeeperObject *)Obj_GetPlayerObject();
        if ((playerObj->flagsB0 & SHOPKEEPER_LOADING_FLAG) == 0) {
            GameBit_Set(0x2da, 1);
        }
    }

    mapId = ((ShopkeeperObject *)obj)->mapId;
    mapEventActive = MAP_EVENT_GET_ANIM(mapId, 6);
    if (mapEventActive == 0) {
        playerObj = (ShopkeeperObject *)Obj_GetPlayerObject();
        if (playerHasSpell((int)playerObj, 0) != 0) {
            MAP_EVENT_SET_ANIM(mapId, 6, 1);
        }
    }
}
