#include "ghidra_import.h"
#include "main/dll/SC/SCtotemlogpuz.h"

extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern uint FUN_80017690();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_800305f8();
extern int ObjGroup_FindNearestObject();
extern undefined8 ObjLink_DetachChild();
extern int Obj_GetYawDeltaToObject();
extern undefined4 FUN_80038f38();
extern undefined4 FUN_80039468();
extern undefined4 FUN_8003964c();
extern undefined4 FUN_8003add8();
extern undefined4 FUN_8003b280();
extern uint FUN_8007f66c();
extern int FUN_801d7034();
extern uint countLeadingZeros();

extern undefined4 DAT_803dcca0;
extern undefined4 DAT_803dcca4;
extern undefined4 DAT_803dcca8;
extern undefined4 DAT_803dccac;
extern undefined4 DAT_803dccb0;
extern undefined4 DAT_803dccb4;
extern undefined4 DAT_803de870;
extern undefined4 DAT_803de872;
extern f64 DOUBLE_803e6128;
extern f32 FLOAT_803e60f8;
extern f32 FLOAT_803e6104;
extern f32 FLOAT_803e6140;
extern f32 FLOAT_803e6144;

/*
 * --INFO--
 *
 * Function: FUN_801d7c14
 * EN v1.0 Address: 0x801D7C14
 * EN v1.0 Size: 1628b
 * EN v1.1 Address: 0x801D7C64
 * EN v1.1 Size: 1164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d7c14(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  short *psVar5;
  uint uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar9;
  undefined8 uVar10;
  double dVar11;
  
  piVar9 = *(int **)(param_9 + 0x5c);
  if (*piVar9 != 0) {
    uVar10 = ObjLink_DetachChild((int)param_9,*piVar9);
    FUN_80017ac8(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar9);
    *piVar9 = 0;
  }
  iVar2 = FUN_801d7034();
  if (param_9[0x50] == 0) {
    uVar3 = FUN_8007f66c(100);
    if (uVar3 != 0) {
      FUN_80039468(param_9,piVar9 + 5,0xab,-0x100,0xffffffff,0);
    }
    uVar3 = FUN_8007f66c(500);
    if (uVar3 != 0) {
      FUN_80039468(param_9,piVar9 + 5,0x417,-0x500,0xffffffff,0);
    }
  }
  uVar3 = FUN_80017690(0xc7d);
  if (uVar3 != 0) {
    uVar3 = FUN_8007f66c(DAT_803dcca0);
    if (uVar3 != 0) {
      uVar3 = countLeadingZeros(*(byte *)((int)piVar9 + 0xd5) >> 6 & 1);
      *(byte *)((int)piVar9 + 0xd5) =
           (byte)((uVar3 >> 5 & 0xff) << 6) & 0x40 | *(byte *)((int)piVar9 + 0xd5) & 0xbf;
    }
    if ((*(byte *)((int)piVar9 + 0xd5) >> 6 & 1) == 0) {
      uVar3 = FUN_80017690(0xa45);
      *(byte *)((int)piVar9 + 0xd5) =
           (byte)((uVar3 & 0xff) << 6) & 0x40 | *(byte *)((int)piVar9 + 0xd5) & 0xbf;
    }
  }
  if ((*(byte *)((int)piVar9 + 0xd5) >> 6 & 1) == 0) {
    iVar4 = ObjGroup_FindNearestObject(8,param_9,(float *)0x0);
  }
  else {
    iVar4 = FUN_80017a98();
  }
  *(float *)(param_9 + 8) =
       *(float *)(param_9 + 8) +
       (float)((double)CONCAT44(0x43300000,DAT_803dcca8 ^ 0x80000000) - DOUBLE_803e6128);
  uVar7 = 0x23;
  uVar8 = 1;
  uVar3 = DAT_803dcca4;
  FUN_8003add8(param_9,iVar4,(int)(piVar9 + 0x1d),0x23,1,DAT_803dcca4);
  psVar5 = (short *)FUN_8003964c((int)param_9,0);
  dVar11 = (double)*(float *)(param_9 + 8);
  *(float *)(param_9 + 8) =
       (float)(dVar11 - (double)(float)((double)CONCAT44(0x43300000,DAT_803dcca8 ^ 0x80000000) -
                                       DOUBLE_803e6128));
  if (psVar5 != (short *)0x0) {
    psVar5[1] = psVar5[1] + DAT_803de872;
    *psVar5 = 0;
    *psVar5 = *psVar5 + DAT_803dccac;
  }
  if (iVar2 != 0) {
    *(byte *)((int)piVar9 + 0xd5) = *(byte *)((int)piVar9 + 0xd5) & 0xef;
    iVar2 = Obj_GetYawDeltaToObject(param_9,iVar4,(float *)0x0);
    iVar4 = (int)(short)((short)iVar2 - DAT_803de870);
    iVar2 = iVar4 + -0x8000;
    if (iVar2 < 0) {
      iVar2 = -iVar2;
    }
    if (iVar2 < 0x18e4) {
      if (param_9[0x50] == 0) {
        uVar6 = FUN_8007f66c(DAT_803dccb0);
        if (uVar6 == 0) {
          uVar6 = FUN_8007f66c(DAT_803dccb4);
          if (uVar6 != 0) {
            FUN_80006824((uint)param_9,0x2f1);
            FUN_800305f8((double)FLOAT_803e60f8,dVar11,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,0x1a,0,uVar7,uVar8,uVar3,in_r9,in_r10);
          }
        }
        else {
          FUN_80006824((uint)param_9,0x416);
          FUN_800305f8((double)FLOAT_803e60f8,dVar11,param_3,param_4,param_5,param_6,param_7,param_8
                       ,param_9,0x1b,0,uVar7,uVar8,uVar3,in_r9,in_r10);
        }
      }
      else {
        FUN_800305f8((double)FLOAT_803e60f8,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0,0,uVar7,uVar8,uVar3,in_r9,in_r10);
        FUN_80006810((int)param_9,0x2f1);
      }
    }
    else {
      if (iVar4 < 1) {
        if (iVar4 < -0xe38) {
          iVar2 = 0x19;
        }
        else {
          iVar2 = 0x18;
        }
      }
      else if (iVar4 < 0xe39) {
        iVar2 = 0x16;
      }
      else {
        iVar2 = 0x17;
      }
      if ((short)param_9[0x50] != iVar2) {
        FUN_800305f8((double)FLOAT_803e60f8,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,iVar2,0,uVar7,uVar8,uVar3,in_r9,in_r10);
      }
    }
  }
  FUN_80038f38((int)param_9,(char *)(piVar9 + 5));
  FUN_8003b280((int)param_9,(int)(piVar9 + 0x11));
  uVar3 = FUN_80017690(0x887);
  if (uVar3 == 0) {
    *(undefined *)(piVar9 + 3) = 0;
  }
  if ((*(byte *)((int)piVar9 + 0xd5) >> 4 & 1) != 0) {
    return;
  }
  uVar1 = param_9[0x50];
  if (uVar1 != 0x19) {
    if (0x18 < (short)uVar1) {
      if (uVar1 == 0x1b) {
        if (*(float *)(param_9 + 0x4c) <= FLOAT_803e6144) {
          return;
        }
        FUN_80006824((uint)param_9,0x2f4);
        *(byte *)((int)piVar9 + 0xd5) = *(byte *)((int)piVar9 + 0xd5) & 0xef | 0x10;
        return;
      }
      if (0x1a < (short)uVar1) {
        return;
      }
      if (*(float *)(param_9 + 0x4c) <= FLOAT_803e6140) {
        return;
      }
      FUN_80006824((uint)param_9,0x417);
      *(byte *)((int)piVar9 + 0xd5) = *(byte *)((int)piVar9 + 0xd5) & 0xef | 0x10;
      return;
    }
    if (uVar1 != 0x17) {
      if (((short)uVar1 < 0x17) && ((short)uVar1 < 0x16)) {
        return;
      }
      if (*(float *)(param_9 + 0x4c) <= FLOAT_803e6104) {
        return;
      }
      FUN_80006824((uint)param_9,700);
      *(byte *)((int)piVar9 + 0xd5) = *(byte *)((int)piVar9 + 0xd5) & 0xef | 0x10;
      return;
    }
  }
  if (FLOAT_803e6104 < *(float *)(param_9 + 0x4c)) {
    FUN_80006824((uint)param_9,0x2f1);
    *(byte *)((int)piVar9 + 0xd5) = *(byte *)((int)piVar9 + 0xd5) & 0xef | 0x10;
  }
  return;
}
