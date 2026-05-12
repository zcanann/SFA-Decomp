#include "ghidra_import.h"
#include "main/dll/SP/SPdrape.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern int FUN_80017a98();
extern int FUN_80017af8();
extern uint FUN_800d7824();

extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd72c;

/*
 * --INFO--
 *
 * Function: FUN_801d8d20
 * EN v1.0 Address: 0x801D8D20
 * EN v1.0 Size: 768b
 * EN v1.1 Address: 0x801D8DE8
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d8d20(undefined4 param_1,uint *param_2)
{
  uint uVar1;
  int iVar2;
  
  uVar1 = GameBit_Get(0x193);
  if (uVar1 == 0) {
    if (*(short *)((int)param_2 + 0x12) == 0xcc) {
      *(undefined2 *)((int)param_2 + 0x12) = 0xffff;
    }
  }
  else if (*(short *)((int)param_2 + 0x12) != 0xcc) {
    *(undefined2 *)((int)param_2 + 0x12) = 0xcc;
    GameBit_Set(0xc0,1);
    *param_2 = *param_2 & 0xfffffffd;
  }
  if (*(char *)((int)param_2 + 6) == '\x01') {
    iVar2 = FUN_80017af8(0x442ff);
    if (((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0) &&
       (iVar2 = FUN_80017a98(), (*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(6,param_1,0xffffffff);
      *(undefined *)((int)param_2 + 6) = 7;
      GameBit_Set(0xd39,1);
    }
  }
  else if (*(char *)((int)param_2 + 6) == '\0') {
    uVar1 = GameBit_Get(0xd39);
    if (uVar1 == 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(5,param_1,0xffffffff);
      *(undefined *)((int)param_2 + 6) = 1;
    }
    else {
      *(undefined *)((int)param_2 + 6) = 7;
    }
  }
  if (((((*param_2 & 0x40) == 0) && (uVar1 = GameBit_Get(400), uVar1 != 0)) &&
      (uVar1 = GameBit_Get(0x191), uVar1 != 0)) && (uVar1 = GameBit_Get(0x192), uVar1 != 0)) {
    uVar1 = GameBit_Get(0x193);
    if (uVar1 == 0) {
      iVar2 = FUN_80017af8(0x442ff);
      if ((iVar2 != 0) && (iVar2 = FUN_80017a98(), (*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)) {
        uVar1 = FUN_800d7824();
        if (uVar1 == 0) {
          GameBit_Set(0x193,1);
          (**(code **)(*DAT_803dd6cc + 8))(0x14,1);
        }
        else {
          GameBit_Set(0x193,1);
          (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
          *param_2 = *param_2 | 0x40;
        }
      }
    }
    else {
      iVar2 = (**(code **)(*DAT_803dd6cc + 0x14))();
      if (((iVar2 != 0) && (iVar2 = FUN_80017af8(0x442ff), iVar2 != 0)) &&
         (iVar2 = FUN_80017a98(), (*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
        *param_2 = *param_2 | 0x40;
      }
    }
  }
  uVar1 = GameBit_Get(0xea9);
  if ((uVar1 == 0) && (uVar1 = GameBit_Get(0x611), uVar1 != 0)) {
    GameBit_Set(0xea9,1);
    (**(code **)(*DAT_803dd72c + 0x1c))(0,0,1,0);
  }
  return;
}
