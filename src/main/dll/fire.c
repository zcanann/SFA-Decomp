#include "ghidra_import.h"
#include "main/dll/fire.h"

extern undefined4 FUN_800178b8();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 fn_8000A380(int param_1,int param_2,int param_3);
extern undefined4 Sfx_KeepAliveLoopedObjectSound(int param_1,int param_2);
extern undefined4 loadUiDll(int param_1);
extern undefined4 fn_80041E3C(int param_1);
extern undefined4 fn_80042F78(int param_1);
extern undefined4 fn_80043560(undefined4 param_1,int param_2);
extern undefined4 mapUnload(undefined4 param_1,uint param_2);
extern undefined4 mapGetDirIdx(int param_1);
extern undefined4 warpToMap(int param_1,int param_2);
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern undefined4 fn_8003B8F4(double scale);
extern undefined4 unlockLevel(int param_1,int param_2,int param_3);
extern undefined4 fn_800887F8(int param_1);

typedef struct FireObjectInterface {
  u8 pad00[0x48];
  void (*refresh)(int param_1,FireObject *obj,int param_3);
} FireObjectInterface;

typedef struct FireEventInterface {
  u8 pad00[0x40];
  int (*getMode)(int mapId);
  void (*triggerEvent)(int eventId,int value);
  u8 pad48[0x50 - 0x48];
  void (*setAnimEvent)(int animId,int eventId,int value);
} FireEventInterface;

extern FireObjectInterface **lbl_803DCA54;
extern FireEventInterface **lbl_803DCAAC;
extern f32 lbl_803E64D8;

#define FIRE_LOOP_SFX_ID 0x48B

#define FIRE_MODE_0 0
#define FIRE_MODE_1 1
#define FIRE_MODE_2 2
#define FIRE_MODE_3 3

#define FIRE_ANIM_EVENT_OPEN_PATH 1
#define FIRE_ANIM_EVENT_WARP 2
#define FIRE_ANIM_EVENT_UNLOAD_NEIGHBOR_MAP 3

#define FIRE_MAP_ID_7 7
#define FIRE_MAP_ID_0B 0x0B
#define FIRE_MAP_ID_17 0x17

#define FIRE_WARP_ID_SHRINE 2
#define FIRE_WARP_ID_MODE2_ROUTE_A 0x20
#define FIRE_WARP_ID_MODE2_ROUTE_B 0x22
#define FIRE_WARP_ID_MODE3 0x0F

#define FIRE_MODE2_RESET_GAMEBIT 0x405
#define FIRE_MODE2_ROUTE_A_GAMEBIT 0xBFD
#define FIRE_MODE2_ROUTE_B_GAMEBIT 0x0FF
#define FIRE_MODE2_ROUTE_C_GAMEBIT 0xC6E
#define FIRE_LIGHTFOOT_UNLOCK_GAMEBIT 0x1ED

#define FIRE_INIT_GAMEBIT_0 0x90D
#define FIRE_INIT_GAMEBIT_1 0x90E
#define FIRE_INIT_GAMEBIT_2 0x90F
#define FIRE_INIT_COLLECTABLE_ID 0x2EE

/*
 * --INFO--
 *
 * Function: fire_updateState
 * EN v1.0 Address: 0x8020930C
 * EN v1.0 Size: 576b
 * EN v1.1 Address: 0x802093B4
 * EN v1.1 Size: 624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 fire_updateState(FireObject *obj,undefined4 param_2,ObjAnimUpdateState *animUpdate)
{
  u8 mode;
  int stateIndex;
  u8 eventId;
  undefined4 anim;

  mode = (u8)(*lbl_803DCAAC)->getMode((int)obj->mapId);
  Sfx_KeepAliveLoopedObjectSound(0,FIRE_LOOP_SFX_ID);
  for (stateIndex = 0; stateIndex < (int)(uint)animUpdate->eventCount; stateIndex++) {
    eventId = animUpdate->eventIds[stateIndex];
    if (eventId == FIRE_ANIM_EVENT_OPEN_PATH) {
      fn_80041E3C(0);
      switch (mode) {
      case FIRE_MODE_0:
      case FIRE_MODE_1:
        (*lbl_803DCAAC)->setAnimEvent(FIRE_MAP_ID_7,0,0);
        (*lbl_803DCAAC)->setAnimEvent(FIRE_MAP_ID_7,2,0);
        (*lbl_803DCAAC)->setAnimEvent(FIRE_MAP_ID_7,3,0);
        (*lbl_803DCAAC)->setAnimEvent(FIRE_MAP_ID_7,7,0);
        (*lbl_803DCAAC)->setAnimEvent(FIRE_MAP_ID_7,10,0);
        (*lbl_803DCAAC)->setAnimEvent(10,7,0);
        GameBit_Set(FIRE_LIGHTFOOT_UNLOCK_GAMEBIT,1);
        fn_80042F78(FIRE_MAP_ID_17);
        anim = mapGetDirIdx(FIRE_MAP_ID_17);
        fn_80043560(anim,0);
        break;
      case FIRE_MODE_2:
        fn_80042F78(FIRE_MAP_ID_0B);
        anim = mapGetDirIdx(FIRE_MAP_ID_0B);
        fn_80043560(anim,0);
        break;
      case FIRE_MODE_3:
        fn_80042F78(FIRE_MAP_ID_7);
        anim = mapGetDirIdx(FIRE_MAP_ID_7);
        fn_80043560(anim,0);
        break;
      }
    }
    else if (eventId == FIRE_ANIM_EVENT_WARP) {
      switch (mode) {
      case FIRE_MODE_0:
      case FIRE_MODE_1:
        warpToMap(FIRE_WARP_ID_SHRINE,0);
        break;
      case FIRE_MODE_2:
        GameBit_Set(FIRE_MODE2_RESET_GAMEBIT,0);
        if (GameBit_Get(FIRE_MODE2_ROUTE_B_GAMEBIT) != 0) {
          (*lbl_803DCAAC)->triggerEvent(FIRE_MAP_ID_0B,3);
          (*lbl_803DCAAC)->setAnimEvent(FIRE_MAP_ID_0B,8,1);
          (*lbl_803DCAAC)->setAnimEvent(FIRE_MAP_ID_0B,9,1);
          warpToMap(FIRE_WARP_ID_MODE2_ROUTE_B,0);
        }
        else if (GameBit_Get(FIRE_MODE2_ROUTE_A_GAMEBIT) != 0) {
          (*lbl_803DCAAC)->triggerEvent(FIRE_MAP_ID_0B,2);
          (*lbl_803DCAAC)->setAnimEvent(FIRE_MAP_ID_0B,5,1);
          (*lbl_803DCAAC)->setAnimEvent(FIRE_MAP_ID_0B,6,1);
          warpToMap(FIRE_WARP_ID_MODE2_ROUTE_A,0);
        }
        else if (GameBit_Get(FIRE_MODE2_ROUTE_C_GAMEBIT) != 0) {
          (*lbl_803DCAAC)->triggerEvent(FIRE_MAP_ID_0B,4);
          (*lbl_803DCAAC)->setAnimEvent(FIRE_MAP_ID_0B,8,1);
          (*lbl_803DCAAC)->setAnimEvent(FIRE_MAP_ID_0B,9,1);
          warpToMap(FIRE_WARP_ID_MODE2_ROUTE_B,0);
        }
        break;
      case FIRE_MODE_3:
        warpToMap(FIRE_WARP_ID_MODE3,0);
        break;
      }
      loadUiDll(1);
    }
    else if (eventId == FIRE_ANIM_EVENT_UNLOAD_NEIGHBOR_MAP) {
      switch (mode) {
      case FIRE_MODE_0:
      case FIRE_MODE_1:
      case FIRE_MODE_2:
        anim = mapGetDirIdx(FIRE_MAP_ID_7);
        mapUnload(anim,0x20000000);
        break;
      case FIRE_MODE_3:
        anim = mapGetDirIdx(FIRE_MAP_ID_0B);
        mapUnload(anim,0x20000000);
        break;
      }
    }
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

int fireObj_getExtraSize(void)
{
  return 4;
}

int fireObj_func08(void)
{
  return 0;
}

void fireObj_free(void)
{
}

void fireObj_render(void)
{
  fn_8003B8F4((double)lbl_803E64D8);
  return;
}

void fireObj_hitDetect(void)
{
}

#pragma scheduling off
#pragma peephole off
void fireObj_update(FireObject *obj)
{
  (*lbl_803DCA54)->refresh(0,obj,0xffffffff);
  return;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fireObj_init(FireObject *obj)
{
  u32 v;
  obj->stateCallback = fire_updateState;
  unlockLevel(0,0,1);
  v = obj->flags | 0x2000;
  obj->flags = (u16)v;
  fn_800887F8(0);
  GameBit_Set(FIRE_INIT_GAMEBIT_0,1);
  GameBit_Set(FIRE_INIT_GAMEBIT_1,1);
  GameBit_Set(FIRE_INIT_GAMEBIT_2,1);
  fn_8000A380(3,2,FIRE_INIT_COLLECTABLE_ID);
  return;
}
#pragma peephole reset
#pragma scheduling reset

void fireObj_release(void)
{
}

void fireObj_initialise(void)
{
}
