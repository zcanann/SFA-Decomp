#include "ghidra_import.h"
#include "main/dll/dll_B4.h"

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
extern f32 FLOAT_803e22b0;
extern f32 FLOAT_803e22b4;
extern f32 FLOAT_803e22b8;
extern f32 FLOAT_803e22bc;

/*
 * --INFO--
 *
 * Function: FUN_80100fa0
 * EN v1.0 Address: 0x80100FA0
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x80101068
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80100fa0(int param_1,int *param_2,int param_3)
{
  float fVar1;
  int iVar2;
  uint uVar3;
  byte bVar4;
  char local_18 [12];
  
  iVar2 = FUN_8001792c(*param_2,param_3);
  fVar1 = *(float *)(gCamcontrolState + 0x134);
  if (FLOAT_803e22b0 < fVar1) {
    if (FLOAT_803e22b4 < fVar1) {
      if (FLOAT_803e22b8 < fVar1) {
        if (FLOAT_803e22bc < fVar1) {
          bVar4 = 0;
        }
        else {
          bVar4 = 1;
        }
      }
      else {
        bVar4 = 2;
      }
    }
    else {
      bVar4 = 3;
    }
  }
  else {
    bVar4 = 4;
  }
  FUN_80052904();
  if (bVar4 < *(byte *)(iVar2 + 0x29)) {
    local_18[0] = -1;
    local_18[1] = 0xff;
    local_18[2] = 0xff;
    local_18[3] = *(undefined *)(param_1 + 0x36);
    uVar3 = FUN_80053078(*(uint *)(iVar2 + 0x24));
    FUN_80051d64(uVar3,(float *)0x0,0,local_18);
  }
  else {
    local_18[0] = '\0';
    local_18[1] = 0;
    local_18[2] = 0;
    local_18[3] = (char)((*(byte *)(param_1 + 0x36) + 1) * 0x60 >> 8);
    uVar3 = FUN_80053078(*(uint *)(iVar2 + 0x24));
    FUN_80051d64(uVar3,(float *)0x0,0,local_18);
  }
  FUN_800528d0();
  if ((*(char *)(param_1 + 0x36) == -1) && (bVar4 < *(byte *)(iVar2 + 0x29))) {
    FUN_8025cce8(0,1,0,5);
    FUN_8006f8fc(1,3,1);
  }
  else {
    FUN_8025cce8(1,4,5,5);
    FUN_8006f8fc(1,3,0);
  }
  FUN_8006f8a4(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80259288(2);
  return 1;
}
