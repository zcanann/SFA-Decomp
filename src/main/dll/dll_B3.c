#include "ghidra_import.h"
#include "main/dll/dll_B3.h"

extern int FUN_8001792c();
extern undefined4 FUN_80051d64();
extern undefined4 FUN_800528d0();
extern undefined4 FUN_80052904();
extern uint FUN_80053078();
extern undefined4 FUN_8006f8a4();
extern undefined4 FUN_8006f8fc();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025cce8();

extern undefined4 gCamcontrolState;

/*
 * --INFO--
 *
 * Function: FUN_80100dcc
 * EN v1.0 Address: 0x80100DCC
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80100F2C
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80100dcc(int param_1,int *param_2,int param_3)
{
  int iVar1;
  uint uVar2;
  char acStack_18 [3];
  byte local_15;
  
  iVar1 = FUN_8001792c(*param_2,param_3);
  FUN_80052904();
  if (*(char *)(iVar1 + 0x29) == '\x01') {
    if ((*(byte *)(gCamcontrolState + 0x141) & 0x20) == 0) {
      local_15 = 0;
    }
    else {
      local_15 = *(byte *)(param_1 + 0x36);
    }
  }
  else {
    local_15 = *(byte *)(param_1 + 0x36);
  }
  if (*(char *)(gCamcontrolState + 0x138) == '\b') {
    local_15 = 0;
  }
  uVar2 = FUN_80053078(*(uint *)(iVar1 + 0x24));
  FUN_80051d64(uVar2,(float *)0x0,0,acStack_18);
  FUN_800528d0();
  if (local_15 < 0xff) {
    FUN_8025cce8(1,4,5,5);
    FUN_8006f8fc(1,3,0);
  }
  else {
    FUN_8025cce8(0,1,0,5);
    FUN_8006f8fc(1,3,1);
  }
  FUN_8006f8a4(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80259288(2);
  return 1;
}
