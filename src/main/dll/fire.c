#include "ghidra_import.h"
#include "main/dll/fire.h"

extern uint FUN_80017690();
extern undefined4 FUN_800178b8();
extern undefined4 FUN_8000a380();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 fn_8000DA58(int param_1,int param_2);
extern undefined4 fn_80014948(int param_1);
extern undefined4 fn_80041E3C(int param_1);
extern undefined4 fn_80042F78(int param_1);
extern undefined4 fn_80043560(undefined4 param_1,int param_2);
extern undefined4 fn_800437BC(undefined4 param_1,uint param_2);
extern undefined4 fn_800481B0(int param_1);
extern undefined4 fn_800552E8(int param_1,int param_2);
extern uint fn_8001FFB4(int eventId);
extern void fn_800200E8(int eventId,int value);
extern undefined4 fn_8003B8F4(double scale);
extern undefined4 fn_8004350C(int param_1,int param_2,int param_3);
extern undefined4 fn_800887F8(int param_1);

extern undefined4 *lbl_803DCA54;
extern undefined4 *lbl_803DCAAC;
extern undefined4 DAT_8032a7b8;
extern undefined4 DAT_8032a7bc;
extern undefined4 DAT_8032a7c0;
extern f32 lbl_803E64D8;
extern f32 FLOAT_803e7144;
extern f32 FLOAT_803e7164;
extern f32 FLOAT_803e7168;
extern f32 FLOAT_803e716c;

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
undefined4 fire_updateState(int obj,undefined4 param_2,u8 *stateList)
{
  int stateIndex;
  int mode;
  u8 state;
  undefined4 anim;

  mode = (u8)(*(code *)(*lbl_803DCAAC + 0x40))((int)*(s8 *)(obj + 0xac));
  fn_8000DA58(0,0x48b);
  for (stateIndex = 0; stateIndex < (int)(uint)stateList[0x8b]; stateIndex++) {
    state = stateList[stateIndex + 0x81];
    if (state == 1) {
      fn_80041E3C(0);
      if (mode != 2) {
        if (mode < 2) {
          if (-1 < mode) {
            (*(code *)(*lbl_803DCAAC + 0x50))(7,0,0);
            (*(code *)(*lbl_803DCAAC + 0x50))(7,2,0);
            (*(code *)(*lbl_803DCAAC + 0x50))(7,3,0);
            (*(code *)(*lbl_803DCAAC + 0x50))(7,7,0);
            (*(code *)(*lbl_803DCAAC + 0x50))(7,10,0);
            (*(code *)(*lbl_803DCAAC + 0x50))(10,7,0);
            fn_800200E8(0x1ed,1);
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
        fn_800200E8(0x405,0);
        if (fn_8001FFB4(0xff) != 0) {
          (*(code *)(*lbl_803DCAAC + 0x44))(0xb,3);
          (*(code *)(*lbl_803DCAAC + 0x50))(0xb,8,1);
          (*(code *)(*lbl_803DCAAC + 0x50))(0xb,9,1);
          fn_800552E8(0x22,0);
        }
        else if (fn_8001FFB4(0xbfd) != 0) {
          (*(code *)(*lbl_803DCAAC + 0x44))(0xb,2);
          (*(code *)(*lbl_803DCAAC + 0x50))(0xb,5,1);
          (*(code *)(*lbl_803DCAAC + 0x50))(0xb,6,1);
          fn_800552E8(0x20,0);
        }
        else if (fn_8001FFB4(0xc6e) != 0) {
          (*(code *)(*lbl_803DCAAC + 0x44))(0xb,4);
          (*(code *)(*lbl_803DCAAC + 0x50))(0xb,8,1);
          (*(code *)(*lbl_803DCAAC + 0x50))(0xb,9,1);
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

void fireObj_update(int obj)
{
  ((void (*)(int,int,int))*(void **)(*lbl_803DCA54 + 0x48))(0,obj,0xffffffff);
  return;
}

void fireObj_init(int obj)
{
  *(undefined4 (**)(int,undefined4,u8 *))(obj + 0xbc) = fire_updateState;
  fn_8004350C(0,0,1);
  *(u16 *)(obj + 0xb0) |= 0x2000;
  fn_800887F8(0);
  fn_800200E8(0x90d,1);
  fn_800200E8(0x90e,1);
  fn_800200E8(0x90f,1);
  FUN_8000a380(3,2,0x2ee);
  return;
}

void fireObj_release(void)
{
}

void fireObj_initialise(void)
{
}
