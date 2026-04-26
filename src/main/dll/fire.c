#include "ghidra_import.h"
#include "main/dll/fire.h"

extern undefined4 FUN_800178b8();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 fn_8000A380(int param_1,int param_2,int param_3);
extern undefined4 fn_8000DA58(int param_1,int param_2);
extern undefined4 fn_80014948(int param_1);
extern undefined4 fn_80041E3C(int param_1);
extern undefined4 fn_80042F78(int param_1);
extern undefined4 fn_80043560(undefined4 param_1,int param_2);
extern undefined4 fn_800437BC(undefined4 param_1,uint param_2);
extern undefined4 fn_800481B0(int param_1);
extern undefined4 fn_800552E8(int param_1,int param_2);
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern undefined4 fn_8003B8F4(double scale);
extern undefined4 fn_8004350C(int param_1,int param_2,int param_3);
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
undefined4 fire_updateState(FireObject *obj,undefined4 param_2,u8 *stateList)
{
  int stateIndex;
  int mode;
  u8 state;
  undefined4 anim;

  mode = (u8)(*lbl_803DCAAC)->getMode((int)obj->mapId);
  fn_8000DA58(0,0x48b);
  for (stateIndex = 0; stateIndex < (int)(uint)stateList[0x8b]; stateIndex++) {
    state = stateList[stateIndex + 0x81];
    if (state == 1) {
      fn_80041E3C(0);
      if (mode != 2) {
        if (mode < 2) {
          if (-1 < mode) {
            (*lbl_803DCAAC)->setAnimEvent(7,0,0);
            (*lbl_803DCAAC)->setAnimEvent(7,2,0);
            (*lbl_803DCAAC)->setAnimEvent(7,3,0);
            (*lbl_803DCAAC)->setAnimEvent(7,7,0);
            (*lbl_803DCAAC)->setAnimEvent(7,10,0);
            (*lbl_803DCAAC)->setAnimEvent(10,7,0);
            GameBit_Set(0x1ed,1);
            fn_80042F78(0x17);
            anim = fn_800481B0(0x17);
            fn_80043560(anim,0);
          }
        }
        else if (mode < 4) {
          fn_80042F78(7);
          anim = fn_800481B0(7);
          fn_80043560(anim,0);
        }
      }
      else {
        fn_80042F78(0xb);
        anim = fn_800481B0(0xb);
        fn_80043560(anim,0);
      }
    }
    else if (state == 2) {
      if (mode != 2) {
        if (mode < 2) {
          if (-1 < mode) {
            fn_800552E8(2,0);
          }
        }
        else if (mode < 4) {
          fn_800552E8(0xf,0);
        }
      }
      else {
        GameBit_Set(0x405,0);
        if (GameBit_Get(0xff) != 0) {
          (*lbl_803DCAAC)->triggerEvent(0xb,3);
          (*lbl_803DCAAC)->setAnimEvent(0xb,8,1);
          (*lbl_803DCAAC)->setAnimEvent(0xb,9,1);
          fn_800552E8(0x22,0);
        }
        else if (GameBit_Get(0xbfd) != 0) {
          (*lbl_803DCAAC)->triggerEvent(0xb,2);
          (*lbl_803DCAAC)->setAnimEvent(0xb,5,1);
          (*lbl_803DCAAC)->setAnimEvent(0xb,6,1);
          fn_800552E8(0x20,0);
        }
        else if (GameBit_Get(0xc6e) != 0) {
          (*lbl_803DCAAC)->triggerEvent(0xb,4);
          (*lbl_803DCAAC)->setAnimEvent(0xb,8,1);
          (*lbl_803DCAAC)->setAnimEvent(0xb,9,1);
          fn_800552E8(0x22,0);
        }
      }
      fn_80014948(1);
    }
    else if (state == 3) {
      if (mode != 3) {
        if (mode < 3) {
          if (-1 < mode) {
            anim = fn_800481B0(7);
            fn_800437BC(anim,0x20000000);
          }
        }
      }
      else {
        anim = fn_800481B0(0xb);
        fn_800437BC(anim,0x20000000);
      }
    }
  }
  return 0;
}

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
void fireObj_update(FireObject *obj)
{
  (*lbl_803DCA54)->refresh(0,obj,0xffffffff);
  return;
}
#pragma scheduling reset

#pragma scheduling off
void fireObj_init(FireObject *obj)
{
  obj->stateCallback = fire_updateState;
  fn_8004350C(0,0,1);
  obj->flags |= 0x2000;
  fn_800887F8(0);
  GameBit_Set(0x90d,1);
  GameBit_Set(0x90e,1);
  GameBit_Set(0x90f,1);
  fn_8000A380(3,2,0x2ee);
  return;
}
#pragma scheduling reset

void fireObj_release(void)
{
}

void fireObj_initialise(void)
{
}
