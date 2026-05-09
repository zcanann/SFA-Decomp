#include "ghidra_import.h"
#include "main/dll/ped.h"

extern undefined4 FUN_80006b14();
extern uint FUN_80017690();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003b818();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd708;
extern f64 DOUBLE_803e5e88;
extern f32 lbl_803E5E78;
extern f32 lbl_803E5E7C;
extern f32 lbl_803E5E80;
extern f32 lbl_803E5E94;

/*
 * --INFO--
 *
 * Function: treebird_init
 * EN v1.0 Address: 0x801CDBEC
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x801CDC2C
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void treebird_init(undefined2 *param_1,int param_2)
{
  int *piVar1;
  int *piVar2;
  undefined auStack_38 [16];
  float local_28;
  undefined4 local_20;
  uint uStack_1c;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  *param_1 = (short)(((int)*(char *)(param_2 + 0x18) & 0x3fU) << 10);
  if (*(short *)(param_2 + 0x1a) < 1) {
    *(float *)(param_1 + 4) = lbl_803E5E80;
  }
  else {
    uStack_1c = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5e88) / lbl_803E5E7C;
  }
  *(undefined *)((int)piVar2 + 0xb) = *(undefined *)(param_2 + 0x19);
  *(undefined *)(piVar2 + 3) = 0;
  *(undefined *)((int)piVar2 + 0xf) = 0;
  *piVar2 = (int)*(short *)(param_2 + 0x1e);
  local_28 = lbl_803E5E78;
  if (*(char *)((int)piVar2 + 0xb) == '\x01') {
    *(char *)((int)piVar2 + 0xf) = (char)*(undefined2 *)(param_2 + 0x1c);
    *(undefined *)((int)piVar2 + 0xd) = 0;
    *(ushort *)(piVar2 + 2) = (ushort)*(byte *)((int)piVar2 + 0xf) * 0x28 + 0x398;
    *(undefined *)((int)piVar2 + 0xe) = 0;
  }
  else if (*(char *)((int)piVar2 + 0xb) == '\0') {
    *(undefined *)(piVar2 + 3) = 1;
    piVar1 = (int *)FUN_80006b14(0x69);
    if (*(short *)(param_2 + 0x1c) == 0) {
      (**(code **)(*piVar1 + 4))(param_1,0,auStack_38,0x10004,0xffffffff,0);
    }
  }
  *(undefined2 *)(piVar2 + 1) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cdd1c
 * EN v1.0 Address: 0x801CDD1C
 * EN v1.0 Size: 616b
 * EN v1.1 Address: 0x801CDD90
 * EN v1.1 Size: 628b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cdd1c(undefined4 param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  short sVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar3 = FUN_80286840();
  iVar6 = *(int *)(iVar3 + 0xb8);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar5 = iVar5 + 1) {
    bVar1 = *(byte *)(param_3 + iVar5 + 0x81);
    if (bVar1 == 2) {
      iVar4 = 100;
      if (*(short *)(iVar3 + 0x46) == 0x5d) {
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar3,0xd3,0,1,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
      else {
        sVar2 = *(short *)(iVar6 + 2);
        if (sVar2 == 0) {
          do {
            (**(code **)(*DAT_803dd708 + 8))(iVar3,0xcd,0,1,0xffffffff,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
        else if (sVar2 == 1) {
          do {
            (**(code **)(*DAT_803dd708 + 8))(iVar3,0xcf,0,1,0xffffffff,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 != 0) {
        iVar4 = 200;
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar3,0xcc,0,1,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    else if (bVar1 < 4) {
      iVar4 = 5;
      if (*(short *)(iVar3 + 0x46) == 0x5d) {
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar3,0xd4,0,1,0xffffffff,0);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
      else {
        sVar2 = *(short *)(iVar6 + 2);
        if (sVar2 == 0) {
          do {
            (**(code **)(*DAT_803dd708 + 8))(iVar3,0xce,0,1,0xffffffff,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
        else if (sVar2 == 1) {
          do {
            (**(code **)(*DAT_803dd708 + 8))(iVar3,0xd0,0,1,0xffffffff,0);
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cdf84
 * EN v1.0 Address: 0x801CDF84
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x801CE004
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cdf84(int param_1)
{
  int iVar1;
  float local_18;
  undefined4 local_14;
  float local_10 [2];
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8003b818(param_1);
  if (*(int *)(iVar1 + 8) != 0) {
    ObjPath_GetPointWorldPosition(param_1,0,local_10,&local_14,&local_18,0);
    *(float *)(*(int *)(iVar1 + 8) + 0xc) = local_10[0];
    *(undefined4 *)(*(int *)(iVar1 + 8) + 0x10) = local_14;
    *(float *)(*(int *)(iVar1 + 8) + 0x14) = local_18;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ce008
 * EN v1.0 Address: 0x801CE008
 * EN v1.0 Size: 288b
 * EN v1.1 Address: 0x801CE08C
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ce008(int param_1)
{
  undefined4 uVar1;
  uint uVar2;
  short *psVar3;
  float local_18 [4];
  
  psVar3 = *(short **)(param_1 + 0xb8);
  local_18[0] = lbl_803E5E94;
  if (*(char *)((int)psVar3 + 7) == '\0') {
    if (*(char *)(psVar3 + 3) == '\0') {
      if (psVar3[2] == 0) {
        uVar2 = FUN_80017690((int)*psVar3);
        if (uVar2 != 0) {
          (**(code **)(*DAT_803dd6d4 + 0x48))((int)psVar3[1],param_1,0xffffffff);
          *(undefined *)(psVar3 + 3) = 1;
        }
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x54))();
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)psVar3[1],param_1,1);
        *(undefined *)(psVar3 + 3) = 1;
      }
    }
  }
  else {
    uVar1 = ObjGroup_FindNearestObject(4,param_1,local_18);
    *(undefined4 *)(psVar3 + 4) = uVar1;
    if (*(int *)(psVar3 + 4) == 0) {
      *(char *)((int)psVar3 + 7) = *(char *)((int)psVar3 + 7) + -1;
    }
    else {
      *(undefined *)((int)psVar3 + 7) = 0;
    }
  }
  return;
}

extern void NW_geyser_SeqFn(void);

/*
 * --INFO--
 *
 * Function: nw_geyser_init
 * EN v1.0 Address: 0x801CDE50
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void nw_geyser_init(int obj)
{
  *(ushort *)(obj + 0xb0) = (ushort)(*(ushort *)(obj + 0xb0) | 0x6000);
  *(void **)(obj + 0xbc) = NW_geyser_SeqFn;
}
#pragma peephole reset
#pragma scheduling reset
