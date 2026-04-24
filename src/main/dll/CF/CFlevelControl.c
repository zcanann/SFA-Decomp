#include "ghidra_import.h"
#include "main/dll/CF/CFlevelControl.h"

extern undefined4 FUN_800066e0();
extern undefined4 FUN_8000bb38();
extern void* FUN_8000facc();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern uint FUN_80022264();
extern int FUN_8002bac4();
extern undefined4 FUN_8002cc9c();
extern undefined4 FUN_8002fb40();
extern undefined8 FUN_80035eec();
extern int FUN_80036974();
extern undefined4 FUN_800395a4();
extern double FUN_80293900();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6d4;
extern f64 DOUBLE_803e4a78;
extern f64 DOUBLE_803e4ab0;
extern f64 DOUBLE_803e4ac0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e4a80;
extern f32 FLOAT_803e4a84;
extern f32 FLOAT_803e4a88;
extern f32 FLOAT_803e4a8c;
extern f32 FLOAT_803e4a90;
extern f32 FLOAT_803e4a94;
extern f32 FLOAT_803e4a98;
extern f32 FLOAT_803e4a9c;
extern f32 FLOAT_803e4aa0;
extern f32 FLOAT_803e4aa4;
extern f32 FLOAT_803e4aa8;
extern f32 FLOAT_803e4aac;
extern f32 FLOAT_803e4ab8;

/*
 * --INFO--
 *
 * Function: FUN_8018de58
 * EN v1.0 Address: 0x8018D8DC
 * EN v1.0 Size: 2236b
 * EN v1.1 Address: 0x8018DE58
 * EN v1.1 Size: 1992b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018de58(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  short sVar1;
  float fVar2;
  undefined2 *puVar3;
  int *piVar4;
  int iVar5;
  uint uVar6;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  int iVar8;
  undefined8 uVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  undefined8 local_28;
  undefined8 local_20;
  
  FUN_8002bac4();
  iVar8 = *(int *)(param_9 + 0x5c);
  puVar3 = FUN_8000facc();
  iVar7 = *(int *)(param_9 + 0x26);
  sVar1 = param_9[0x23];
  if (sVar1 == 0x6b4) {
    FUN_8002fb40((double)FLOAT_803e4a90,(double)FLOAT_803dc074);
  }
  else if (sVar1 < 0x6b4) {
    if (sVar1 == 0x409) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
    }
    else if (sVar1 < 0x409) {
      if (sVar1 == 0x10d) {
        *(ushort *)(iVar8 + 0x3c) = *(short *)(iVar8 + 0x3c) - (ushort)DAT_803dc070;
        if (*(short *)(iVar8 + 0x3c) < 0) {
          uVar6 = FUN_80022264(0,*(byte *)(iVar8 + 0x40) - 1);
          FUN_8000bb38((uint)param_9,*(ushort *)(*(int *)(iVar8 + 0x44) + uVar6 * 2));
          *(undefined2 *)(iVar8 + 0x3c) = *(undefined2 *)(iVar8 + 0x48);
          uVar6 = FUN_80022264(0,(uint)*(ushort *)(iVar8 + 0x48));
          *(short *)(iVar8 + 0x3c) = *(short *)(iVar8 + 0x3c) + (short)uVar6;
        }
      }
      else if (sVar1 < 0x10d) {
        if (sVar1 == 0x8e) {
          *(float *)(iVar8 + 0x14) =
               FLOAT_803e4a9c * *(float *)(iVar8 + 0x1c) + *(float *)(iVar8 + 0x14);
          if ((FLOAT_803e4aa0 < *(float *)(iVar8 + 0x14)) ||
             (*(float *)(iVar8 + 0x14) < FLOAT_803e4aa4)) {
            *(float *)(iVar8 + 0x1c) = -*(float *)(iVar8 + 0x1c);
          }
          if ((FLOAT_803e4aa8 < *(float *)(iVar8 + 0x18)) ||
             (*(float *)(iVar8 + 0x18) < FLOAT_803e4aac)) {
            *(float *)(iVar8 + 0x24) = -*(float *)(iVar8 + 0x24);
          }
          *(float *)(iVar8 + 0x18) =
               FLOAT_803e4a9c * *(float *)(iVar8 + 0x24) + *(float *)(iVar8 + 0x18);
        }
      }
      else if (sVar1 == 0x125) {
        local_20 = (double)CONCAT44(0x43300000,-(int)(short)puVar3[2] ^ 0x80000000);
        param_9[2] = (short)(int)(DOUBLE_803e4ab0 * (local_20 - DOUBLE_803e4ac0));
        iVar7 = FUN_8002bac4();
        dVar11 = (double)(*(float *)(iVar7 + 0x18) - *(float *)(param_9 + 0xc));
        dVar12 = (double)(*(float *)(iVar7 + 0x20) - *(float *)(param_9 + 0x10));
        fVar2 = *(float *)(iVar7 + 0x1c) - *(float *)(param_9 + 0xe);
        dVar10 = FUN_80293900((double)(fVar2 * fVar2 +
                                      (float)(dVar11 * dVar11 + (double)(float)(dVar12 * dVar12))));
        if (((double)FLOAT_803e4ab8 <= dVar10) || (*(char *)(iVar8 + 0x3f) != '\x01')) {
          if (((double)FLOAT_803e4ab8 < dVar10) && (*(char *)(iVar8 + 0x3f) == '\0')) {
            *(undefined *)(iVar8 + 0x3f) = 1;
            FUN_800066e0(dVar10,dVar11,dVar12,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_9,0x5d,0,0,0,in_r9,in_r10);
          }
        }
        else {
          *(undefined *)(iVar8 + 0x3f) = 0;
          FUN_800066e0(dVar10,dVar11,dVar12,param_4,param_5,param_6,param_7,param_8,param_9,param_9,
                       0x5c,0,0,0,in_r9,in_r10);
        }
      }
    }
    else if (sVar1 == 0x622) {
      piVar4 = (int *)FUN_800395a4((int)param_9,0);
      if (((piVar4 != (int *)0x0) &&
          (uVar6 = FUN_80020078((int)*(short *)(iVar8 + 0x38)), uVar6 != 0)) && (*piVar4 == 0)) {
        FUN_8000bb38((uint)param_9,0x3c4);
        *piVar4 = 0x100;
      }
    }
    else if (sVar1 < 0x622) {
      if (((sVar1 == 0x4bf) && (*(float *)(param_9 + 8) < FLOAT_803e4a94 + *(float *)(iVar7 + 0xc)))
         && (uVar6 = FUN_80020078((int)*(short *)(iVar8 + 0x38)), uVar6 != 0)) {
        *(float *)(param_9 + 8) = *(float *)(param_9 + 8) + FLOAT_803dc074;
      }
    }
    else if (sVar1 == 0x65d) {
      FUN_8002fb40((double)FLOAT_803e4a90,(double)FLOAT_803dc074);
    }
  }
  else if (sVar1 == 0x71b) {
    *(ushort *)(iVar8 + 0x36) = *(short *)(iVar8 + 0x36) - (ushort)DAT_803dc070;
    uVar9 = FUN_80035eec((int)param_9,0x13,1,0);
    if (*(short *)(iVar8 + 0x36) < 1) {
      FUN_8002cc9c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
    else {
      *(float *)(param_9 + 8) =
           (float)-(DOUBLE_803e4a78 * (double)FLOAT_803dc074 - (double)*(float *)(param_9 + 8));
    }
  }
  else if (sVar1 < 0x71b) {
    if (sVar1 == 0x6fd) {
      uVar6 = FUN_80020078((int)*(short *)(iVar8 + 0x38));
      if (uVar6 == 0) {
        *param_9 = *param_9 + (short)(int)(FLOAT_803e4a88 * FLOAT_803dc074);
        param_9[2] = param_9[2] + (short)(int)(FLOAT_803e4a8c * FLOAT_803dc074);
      }
      else {
        *param_9 = *param_9 + (short)(int)(FLOAT_803e4a88 * FLOAT_803dc074);
        param_9[2] = param_9[2] + (short)(int)(FLOAT_803e4a8c * FLOAT_803dc074);
      }
    }
    else if (sVar1 < 0x6fd) {
      if (sVar1 == 0x6be) {
        uVar6 = FUN_80020078((int)*(short *)(iVar8 + 0x3a));
        if ((uVar6 != 0) && (*(char *)(iVar8 + 0x3e) == '\0')) {
          *(undefined *)(iVar8 + 0x3e) = 1;
          (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
        }
      }
      else if ((((0x6bd < sVar1) && (0x6fb < sVar1)) &&
               (uVar6 = FUN_80020078((int)*(short *)(iVar8 + 0x38)), fVar2 = FLOAT_803e4a80,
               uVar6 != 0)) &&
              ((*(float *)(param_9 + 8) <= FLOAT_803e4a80 + *(float *)(iVar7 + 0xc) &&
               (*(float *)(param_9 + 8) = FLOAT_803e4a84 * FLOAT_803dc074 + *(float *)(param_9 + 8),
               fVar2 + *(float *)(iVar7 + 0xc) <= *(float *)(param_9 + 8))))) {
        FUN_800201ac((int)*(short *)(iVar8 + 0x38),0);
      }
    }
    else if (sVar1 == 0x708) {
      iVar5 = FUN_80036974((int)param_9,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if (iVar5 != 0) {
        FUN_800201ac((int)*(short *)(iVar8 + 0x38),1);
      }
      uVar6 = FUN_80020078((int)*(short *)(iVar8 + 0x38));
      if (uVar6 == 0) {
        *param_9 = *param_9 + (short)*(char *)(iVar7 + 0x18) * (ushort)DAT_803dc070;
      }
    }
    else if ((sVar1 < 0x708) && (sVar1 < 0x6ff)) {
      uVar6 = FUN_80020078((int)*(short *)(iVar8 + 0x38));
      if (uVar6 == 0) {
        param_9[1] = param_9[1] + (short)(int)(FLOAT_803e4a88 * FLOAT_803dc074);
        param_9[2] = param_9[2] + (short)(int)(FLOAT_803e4a8c * FLOAT_803dc074);
      }
      else {
        param_9[1] = param_9[1] + (short)(int)(FLOAT_803e4a88 * FLOAT_803dc074);
        param_9[2] = param_9[2] + (short)(int)(FLOAT_803e4a8c * FLOAT_803dc074);
      }
    }
  }
  else if (sVar1 == 0x7de) {
    uVar6 = FUN_80020078((int)*(short *)(iVar8 + 0x38));
    if (uVar6 == 0) {
      local_20 = (double)CONCAT44(0x43300000,(int)param_9[2] ^ 0x80000000);
      param_9[2] = (short)(int)(FLOAT_803dc074 * *(float *)(iVar8 + 0x24) +
                               (float)(local_20 - DOUBLE_803e4ac0));
    }
    else {
      local_28 = (double)CONCAT44(0x43300000,(int)param_9[2] ^ 0x80000000);
      param_9[2] = (short)(int)-(FLOAT_803dc074 * *(float *)(iVar8 + 0x24) -
                                (float)(local_28 - DOUBLE_803e4ac0));
    }
  }
  else if (sVar1 < 0x7de) {
    if ((sVar1 == 0x729) && (uVar6 = FUN_80020078((int)*(short *)(iVar8 + 0x38)), uVar6 == 0)) {
      param_9[1] = param_9[1] + (ushort)DAT_803dc070 * 100;
    }
  }
  else if (((sVar1 == 0x828) && (uVar6 = FUN_80020078((int)*(short *)(iVar8 + 0x3a)), uVar6 != 0))
          && (*(char *)(iVar8 + 0x3e) == '\0')) {
    iVar7 = (int)param_9[2] + (int)(FLOAT_803e4a98 * FLOAT_803dc074);
    if (iVar7 < 0x8000) {
      param_9[2] = (short)iVar7;
    }
    else {
      *(undefined *)(iVar8 + 0x3e) = 1;
      param_9[2] = 0x7fff;
    }
  }
  return;
}
