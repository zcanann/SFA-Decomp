#include "ghidra_import.h"
#include "main/dll/brokecannon.h"

extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined8 FUN_80043938();

extern undefined4* DAT_803dd72c;

/*
 * --INFO--
 *
 * Function: FUN_801d8284
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D8284
 * EN v1.1 Size: 576b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d8284(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  uint uVar1;
  undefined8 uVar2;
  
  uVar1 = FUN_80020078(0xbf8);
  if (uVar1 != 0) {
    *(undefined *)(param_10 + 7) = 5;
    FUN_800201ac(0xbf8,0);
  }
  if (*(char *)(param_10 + 7) != '\0') {
    if (*(char *)(param_10 + 7) == '\x05') {
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),1,0);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),4,0);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),6,0);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),7,0);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),8,0);
      uVar2 = (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),9,0);
      uVar2 = FUN_80043938(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      uVar2 = FUN_80043938(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      uVar2 = FUN_80043938(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_80043938(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    if (*(char *)(param_10 + 7) == '\x01') {
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0,1);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),2,1);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),3,1);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),5,1);
      (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),10,1);
    }
    *(char *)(param_10 + 7) = *(char *)(param_10 + 7) + -1;
  }
  return;
}
