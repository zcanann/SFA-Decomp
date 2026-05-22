#include "ghidra_import.h"
#include "main/dll/CF/laser.h"

extern undefined4 Sfx_KeepAliveLoopedObjectSound(int obj,int sfxId);
extern undefined4 loadUiDll(int id);
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern undefined4 FUN_80017814();
extern undefined4 FUN_8003b818(int obj);
extern undefined4 defragMemory(int param_1);
extern undefined4 loadMapAndParent(int mapId);
extern undefined4 lockLevel(undefined4 mapDir,int flags);
extern undefined4 mapUnload(undefined4 mapDir,uint flags);
extern undefined4 mapGetDirIdx(int mapId);
extern undefined4 warpToMap(int mapId,int flags);
extern undefined4 FUN_800723a0();

extern LaserReleaseInterface **lbl_803DD6D4;
extern LaserEventInterface **lbl_803DD72C;

#define renderLoadedLaserModel FUN_8003b818

#define LASER_LOOP_SFX_ID 0x48B

#define LASER_MODE_0 0
#define LASER_MODE_1 1
#define LASER_MODE_2 2
#define LASER_MODE_3 3

#define LASER_ANIM_EVENT_OPEN_PATH 1
#define LASER_ANIM_EVENT_WARP 2
#define LASER_ANIM_EVENT_UNLOAD_NEIGHBOR_MAP 3

#define LASER_MAP_ID_7 7
#define LASER_MAP_ID_0B 0x0B
#define LASER_MAP_ID_17 0x17

#define LASER_WARP_ID_SHRINE 2
#define LASER_WARP_ID_MODE2_ROUTE_A 0x20
#define LASER_WARP_ID_MODE2_ROUTE_B 0x22
#define LASER_WARP_ID_MODE3 0x0F

#define LASER_MODE2_RESET_GAMEBIT 0x405
#define LASER_MODE2_ROUTE_A_GAMEBIT 0xBFD
#define LASER_MODE2_ROUTE_B_GAMEBIT 0x0FF
#define LASER_MODE2_ROUTE_C_GAMEBIT 0xC6E
#define LASER_LIGHTFOOT_UNLOCK_GAMEBIT 0x1ED

#define LASER_MAP_UNLOAD_FLAGS 0x20000000

/*
 * --INFO--
 *
 * Function: laser_update
 * EN v1.0 Address: 0x80209564
 * EN v1.0 Size: 1928b
 * EN v1.1 Address: 0x80209944
 * EN v1.1 Size: 1032b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
laser_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
             undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
             undefined4 param_10,ObjAnimUpdateState *animUpdate,int param_12,undefined4 param_13,
             undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  LaserObject *obj;
  LaserEventInterface *eventInterface;
  u8 eventId;
  u8 mode;
  undefined4 mapDir;
  int eventIndex;
  
  obj = (LaserObject *)param_9;
  eventInterface = *lbl_803DD72C;
  mode = eventInterface->getMode((int)obj->modeIndex);
  Sfx_KeepAliveLoopedObjectSound(0,LASER_LOOP_SFX_ID);
  for (eventIndex = 0; eventIndex < (int)(uint)animUpdate->eventCount; eventIndex = eventIndex + 1) {
    eventId = animUpdate->eventIds[eventIndex];
    if (eventId == LASER_ANIM_EVENT_OPEN_PATH) {
      defragMemory(0);
      if (mode == LASER_MODE_2) {
        loadMapAndParent(LASER_MAP_ID_0B);
        mapDir = mapGetDirIdx(LASER_MAP_ID_0B);
        lockLevel(mapDir,0);
      }
      else if (mode < LASER_MODE_2) {
        eventInterface->setAnimEvent(LASER_MAP_ID_7,0,0);
        eventInterface->setAnimEvent(LASER_MAP_ID_7,2,0);
        eventInterface->setAnimEvent(LASER_MAP_ID_7,3,0);
        eventInterface->setAnimEvent(LASER_MAP_ID_7,7,0);
        eventInterface->setAnimEvent(LASER_MAP_ID_7,10,0);
        eventInterface->setAnimEvent(10,7,0);
        GameBit_Set(LASER_LIGHTFOOT_UNLOCK_GAMEBIT,1);
        loadMapAndParent(LASER_MAP_ID_17);
        mapDir = mapGetDirIdx(LASER_MAP_ID_17);
        lockLevel(mapDir,0);
      }
      else if (mode < 4) {
        loadMapAndParent(LASER_MAP_ID_7);
        mapDir = mapGetDirIdx(LASER_MAP_ID_7);
        lockLevel(mapDir,0);
      }
    }
    else if (eventId == LASER_ANIM_EVENT_WARP) {
      if (mode == LASER_MODE_2) {
        GameBit_Set(LASER_MODE2_RESET_GAMEBIT,0);
        if (GameBit_Get(LASER_MODE2_ROUTE_B_GAMEBIT) == 0) {
          if (GameBit_Get(LASER_MODE2_ROUTE_A_GAMEBIT) == 0) {
            if (GameBit_Get(LASER_MODE2_ROUTE_C_GAMEBIT) != 0) {
              eventInterface->triggerEvent(LASER_MAP_ID_0B,4);
              eventInterface->setAnimEvent(LASER_MAP_ID_0B,8,1);
              eventInterface->setAnimEvent(LASER_MAP_ID_0B,9,1);
              warpToMap(LASER_WARP_ID_MODE2_ROUTE_B,0);
            }
          }
          else {
            eventInterface->triggerEvent(LASER_MAP_ID_0B,2);
            eventInterface->setAnimEvent(LASER_MAP_ID_0B,5,1);
            eventInterface->setAnimEvent(LASER_MAP_ID_0B,6,1);
            warpToMap(LASER_WARP_ID_MODE2_ROUTE_A,0);
          }
        }
        else {
          eventInterface->triggerEvent(LASER_MAP_ID_0B,3);
          eventInterface->setAnimEvent(LASER_MAP_ID_0B,8,1);
          eventInterface->setAnimEvent(LASER_MAP_ID_0B,9,1);
          warpToMap(LASER_WARP_ID_MODE2_ROUTE_B,0);
        }
      }
      else if (mode < LASER_MODE_2) {
        warpToMap(LASER_WARP_ID_SHRINE,0);
      }
      else if (mode < 4) {
        warpToMap(LASER_WARP_ID_MODE3,0);
      }
      loadUiDll(1);
    }
    else if (eventId == LASER_ANIM_EVENT_UNLOAD_NEIGHBOR_MAP) {
      if (mode == LASER_MODE_3) {
        mapDir = mapGetDirIdx(LASER_MAP_ID_0B);
        mapUnload(mapDir,LASER_MAP_UNLOAD_FLAGS);
      }
      else if (mode < LASER_MODE_3) {
        mapDir = mapGetDirIdx(LASER_MAP_ID_7);
        mapUnload(mapDir,LASER_MAP_UNLOAD_FLAGS);
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: laser_render
 * EN v1.0 Address: 0x80209CEC
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209D4C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void laser_render(int param_1)
{
  renderLoadedLaserModel(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: laser_release
 * EN v1.0 Address: 0x80209D0C
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80209D74
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void laser_release(undefined4 param_1)
{
  (*lbl_803DD6D4)->releaseObject(0,param_1,0xffffffff);
  return;
}

/*
 * --INFO--
 *
 * Function: laser_hitDetect
 * EN v1.0 Address: 0x80209D4C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80209DB0
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void laser_hitDetect(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                     undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                     int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80209d50
 * EN v1.0 Address: 0x80209D50
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209E58
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209d50(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80209d70
 * EN v1.0 Address: 0x80209D70
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209E8C
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209d70(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80209d90
 * EN v1.0 Address: 0x80209D90
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209EB8
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209d90(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80209db0
 * EN v1.0 Address: 0x80209DB0
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209F00
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209db0(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80209dd0
 * EN v1.0 Address: 0x80209DD0
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209F30
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209dd0(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80209df0
 * EN v1.0 Address: 0x80209DF0
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80209F5C
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209df0(void)
{
  FUN_800723a0();
  return;
}

/*
 * --INFO--
 *
 * Function: laser_free
 * EN v1.0 Address: 0x80209E10
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80209F98
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void laser_free(int param_1)
{
  LaserObject *obj;
  LaserState *state;
  uint sequenceIds;
  
  if (param_1 != 0) {
    obj = (LaserObject *)param_1;
    state = obj->state;
    sequenceIds = *(uint *)&state->primarySequenceId;
    if (sequenceIds != 0) {
      FUN_80017814(sequenceIds);
      *(uint *)&state->primarySequenceId = 0;
    }
  }
  return;
}
