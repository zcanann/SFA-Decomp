#include "ghidra_import.h"
#include "main/dll/DIM/DIMlevcontrol.h"

extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006ba8();
extern char FUN_80006bd0();
extern uint FUN_80006bf8();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017708();
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_80037180();
extern undefined4 FUN_800388b4();
extern int FUN_8003964c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8011e800();
extern undefined4 FUN_8011e844();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_801b2260();
extern undefined4 FUN_801b2640();
extern undefined8 FUN_801b2644();
extern undefined4 FUN_80286838();
extern undefined4 FUN_80286884();
extern int FUN_80294d38();
extern undefined4 FUN_80294d40();
extern int FUN_80294dbc();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcb68;
extern undefined4 DAT_803dcb6a;
extern undefined4 DAT_803dcb6c;
extern undefined4 DAT_803dcb74;
extern undefined4 DAT_803dcb78;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern void* DAT_803de7d0;
extern f64 DOUBLE_803e5558;
extern f64 DOUBLE_803e5578;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dcb5c;
extern f32 FLOAT_803dcb60;
extern f32 FLOAT_803dcb64;
extern f32 FLOAT_803dcb70;
extern f32 FLOAT_803e5584;
extern f32 FLOAT_803e5588;

/*
 * --INFO--
 *
 * Function: FUN_801b2550
 * EN v1.0 Address: 0x801B2550
 * EN v1.0 Size: 1672b
 * EN v1.1 Address: 0x801B2B04
 * EN v1.1 Size: 1560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b2550(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
  short sVar1;
  short sVar3;
  int iVar2;
  short *psVar4;
  int iVar5;
  uint uVar6;
  char cVar7;
  bool bVar8;
  bool bVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  double dVar14;
  double dVar15;
  short *local_38 [2];
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  
  psVar4 = (short *)FUN_80286838();
  iVar13 = *(int *)(psVar4 + 0x26);
  bVar9 = false;
  *(undefined *)(param_11 + 0x56) = 0;
  *(ushort *)(param_11 + 0x6e) = *(ushort *)(param_11 + 0x6e) & 0xf9f7;
  iVar12 = *(int *)(psVar4 + 0x5c);
  if (*(char *)(iVar12 + 0xac) == '\x03') {
    iVar13 = FUN_80017a98();
    FUN_8011e868(0x16);
    FUN_8011e844(0x17);
    FUN_8011e800(1);
    iVar5 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if ((iVar5 != 0x51) && (iVar5 != 0x4c)) {
      local_38[0] = psVar4;
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x51,1,0,4,local_38,0x32,0xff);
    }
    if (iVar5 == 0x51) {
      iVar5 = FUN_8003964c((int)psVar4,0);
      if (*(char *)(iVar12 + 0xb0) < '\x01') {
        uVar6 = FUN_80017690(0xdb);
        if (uVar6 == 0) {
          (**(code **)(*DAT_803dd6e8 + 0x38))(0x4b9,0x14,0x8c,1);
          FUN_80017698(0xdb,1);
        }
        cVar7 = FUN_80006bd0(0);
        uStack_2c = (int)cVar7 ^ 0x80000000;
        local_30 = 0x43300000;
        iVar11 = (int)(-FLOAT_803dcb70 *
                      (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e5558));
        local_28 = (double)(longlong)iVar11;
        if (iVar11 == 0) {
          if (*(int *)(iVar12 + 0xa8) != 0) {
            FUN_80006824((uint)psVar4,0x1fe);
          }
        }
        else {
          sVar1 = *(short *)(iVar5 + 2);
          sVar3 = sVar1;
          if (sVar1 < 0) {
            sVar3 = -sVar1;
          }
          if ((int)DAT_803dcb6a - (int)DAT_803dcb6c < (int)sVar3) {
            if (iVar11 < 0) {
              iVar10 = -1;
            }
            else if (iVar11 < 1) {
              iVar10 = 0;
            }
            else {
              iVar10 = 1;
            }
            if (sVar1 < 0) {
              iVar2 = -1;
            }
            else if (sVar1 < 1) {
              iVar2 = 0;
            }
            else {
              iVar2 = 1;
            }
            if (iVar2 == iVar10) {
              iVar11 = (iVar11 * ((int)DAT_803dcb6a - (int)sVar3)) / (int)DAT_803dcb6c;
            }
          }
          *(short *)(iVar5 + 2) = *(short *)(iVar5 + 2) + (short)iVar11;
          FUN_800068c4((uint)psVar4,0x1ff);
        }
        *(int *)(iVar12 + 0xa8) = iVar11;
        if (0 < *(short *)(iVar12 + 0xa4)) {
          *(ushort *)(iVar12 + 0xa4) = *(short *)(iVar12 + 0xa4) - (ushort)DAT_803dc070;
        }
        if (0 < *(short *)(iVar12 + 0xa6)) {
          *(ushort *)(iVar12 + 0xa6) = *(short *)(iVar12 + 0xa6) - (ushort)DAT_803dc070;
        }
        uVar6 = FUN_80006c10(0);
        if (((uVar6 & 0x100) == 0) || (0 < *(short *)(iVar12 + 0xa4))) {
          FUN_8000680c((int)psVar4,2);
        }
        else {
          FUN_80006ba8(0,0x100);
          iVar5 = FUN_80294d38(iVar13);
          if (iVar5 < 1) {
            FUN_80006824((uint)psVar4,0x40c);
          }
          else {
            *(byte *)(iVar12 + 0xae) = *(char *)(iVar12 + 0xae) + DAT_803dc070;
            bVar8 = FUN_800067f0((int)psVar4,2);
            if (!bVar8) {
              FUN_80006824((uint)psVar4,0x201);
              FUN_80006824((uint)psVar4,0x202);
            }
          }
        }
        if (DAT_803dcb68 < *(byte *)(iVar12 + 0xae)) {
          *(byte *)(iVar12 + 0xae) = DAT_803dcb68;
        }
        (**(code **)(*DAT_803dd6e8 + 0x5c))(*(undefined *)(iVar12 + 0xae));
        local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar12 + 0xae));
        dVar15 = (double)(float)(local_28 - DOUBLE_803e5578);
        dVar14 = (double)FLOAT_803dcb64;
        *(float *)(iVar12 + 0x98) = (float)(dVar15 * dVar14 + (double)FLOAT_803dcb60);
        uVar6 = FUN_80006bf8(0);
        if (((((uVar6 & 0x100) != 0) || (*(byte *)(iVar12 + 0xae) == DAT_803dcb68)) &&
            (*(short *)(iVar12 + 0xa4) < 1)) && (iVar5 = FUN_80294d38(iVar13), 0 < iVar5)) {
          FUN_80006ba8(0,0x100);
          dVar14 = (double)FUN_80294d40(iVar13,-1);
          *(undefined *)(iVar12 + 0xad) = 1;
          *(undefined *)(iVar12 + 0xae) = 0;
        }
        FUN_801b2640(dVar14,dVar15,param_3,param_4,param_5,param_6,param_7,param_8);
        if (((*(char *)(psVar4 + 0x56) == '\x13') && (*(char *)(iVar12 + 0xb2) == '\0')) &&
           ((uVar6 = FUN_80017690(0xc17), uVar6 != 0 && (uVar6 = FUN_80017690(0xa21), uVar6 != 0))))
        {
          *(undefined *)(iVar12 + 0xb2) = 1;
          *(undefined *)(iVar12 + 0xb1) = 1;
        }
        if ((*(char *)(iVar12 + 0xb1) != '\0') &&
           (*(byte *)(iVar12 + 0xb1) = *(char *)(iVar12 + 0xb1) + DAT_803dc070,
           0x3c < *(byte *)(iVar12 + 0xb1))) {
          bVar9 = true;
        }
        if ((bVar9) || (uVar6 = FUN_80006c00(0), (uVar6 & 0x200) != 0)) {
          FUN_80006ba8(0,0x200);
          FUN_8011e800(0);
          (**(code **)(*DAT_803dd6e8 + 0x60))();
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x42,0,1,0,0,0,0xff);
          *(undefined *)(iVar12 + 0xac) = 5;
          *(undefined *)(iVar12 + 0xb0) = 0x3c;
          *(byte *)(param_11 + 0x90) = *(byte *)(param_11 + 0x90) | 4;
          *(byte *)((int)psVar4 + 0xaf) = *(byte *)((int)psVar4 + 0xaf) & 0xf7;
          bVar9 = FUN_800067f0((int)psVar4,8);
          if (bVar9) {
            FUN_800067f0((int)psVar4,0);
          }
          FUN_8000680c((int)psVar4,2);
        }
        FUN_8002fc3c((double)FLOAT_803dcb5c,(double)FLOAT_803dc074);
      }
      else {
        *(byte *)(iVar12 + 0xb0) = *(char *)(iVar12 + 0xb0) - DAT_803dc070;
        if (*(char *)(iVar12 + 0xb0) < '\x01') {
          (**(code **)(*DAT_803dd6e8 + 0x58))(DAT_803dcb68,0x5d5);
        }
      }
    }
  }
  else {
    psVar4[3] = psVar4[3] & 0xbfff;
    iVar5 = FUN_8003964c((int)psVar4,0);
    *(short *)(iVar5 + 2) = *psVar4 - (short)((int)*(char *)(iVar13 + 0x28) << 8);
    *psVar4 = (short)((int)*(char *)(iVar13 + 0x28) << 8);
    *(undefined *)(iVar12 + 0xac) = 4;
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b2bd8
 * EN v1.0 Address: 0x801B2BD8
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801B311C
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b2bd8(int param_1)
{
  if (*(short *)(param_1 + 0x46) != 0x1d6) {
    (**(code **)(*DAT_803dd6e8 + 0x60))();
    FUN_80006b0c(DAT_803de7d0);
    DAT_803de7d0 = (void*)0x0;
  }
  FUN_80037180(param_1,3);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b2c40
 * EN v1.0 Address: 0x801B2C40
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x801B3180
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b2c40(undefined2 *param_1)
{
  undefined2 uVar1;
  int iVar2;
  
  if (param_1[0x23] == 0x1d6) {
    FUN_8003b818((int)param_1);
  }
  else {
    iVar2 = *(int *)(param_1 + 0x5c);
    uVar1 = *param_1;
    *param_1 = (short)((int)*(char *)(*(int *)(param_1 + 0x26) + 0x28) << 8);
    FUN_8003b818((int)param_1);
    *param_1 = uVar1;
    FUN_800388b4(param_1,0,(float *)(iVar2 + 0x8c),(undefined4 *)(iVar2 + 0x90),
                 (float *)(iVar2 + 0x94),0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801b2ccc
 * EN v1.0 Address: 0x801B2CCC
 * EN v1.0 Size: 1324b
 * EN v1.1 Address: 0x801B321C
 * EN v1.1 Size: 1120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b2ccc(double param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  byte bVar4;
  int iVar5;
  int *piVar6;
  double dVar7;
  undefined8 uVar8;
  double dVar9;
  double dVar10;
  short *local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar5 = *(int *)(param_9 + 0x26);
  if (param_9[0x23] == 0x1d6) {
    FUN_801b2260(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  else {
    if (((*(byte *)((int)param_9 + 0xaf) & 8) != 0) &&
       (uVar1 = FUN_80017690((int)*(short *)(iVar5 + 0x1a)), uVar1 != 0)) {
      *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    }
    piVar6 = *(int **)(param_9 + 0x5c);
    iVar2 = FUN_80017a98();
    iVar3 = FUN_80294dbc(iVar2);
    if (iVar3 == 0) {
      *piVar6 = iVar2;
    }
    else {
      *piVar6 = 0;
    }
    param_9[3] = param_9[3] & 0xbfff;
    bVar4 = *(byte *)(piVar6 + 0x2b);
    if (bVar4 == 4) {
      FUN_801b2644();
      uVar1 = FUN_80017690((int)*(short *)(iVar5 + 0x1a));
      if (uVar1 == 0) {
        if ((*piVar6 != 0) && (uVar1 = FUN_80017690((int)*(short *)(iVar5 + 0x1e)), uVar1 == 0)) {
          dVar7 = FUN_80017708((float *)(param_9 + 0xc),(float *)(*piVar6 + 0x18));
          uStack_1c = *(short *)(iVar5 + 0x26) * DAT_803dcb78 ^ 0x80000000;
          local_20 = 0x43300000;
          if (dVar7 < (double)((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5558) /
                              FLOAT_803e5584)) {
            *(undefined *)(piVar6 + 0x2b) = 1;
          }
        }
      }
      else {
        *(undefined *)(piVar6 + 0x2b) = 5;
      }
      *(undefined *)((int)piVar6 + 0xad) = 0;
      *(undefined2 *)(piVar6 + 0x29) = 0;
      *(undefined2 *)((int)piVar6 + 0xa6) = 0;
    }
    else if (bVar4 < 4) {
      if (bVar4 == 1) {
        uVar1 = FUN_80017690((int)*(short *)(iVar5 + 0x1a));
        if (uVar1 == 0) {
          uVar1 = FUN_80017690((int)*(short *)(iVar5 + 0x1e));
          if (uVar1 == 0) {
            if (*piVar6 == 0) {
              *(undefined *)(piVar6 + 0x2b) = 4;
            }
            else {
              *(byte *)((int)piVar6 + 0xaf) = *(char *)((int)piVar6 + 0xaf) + DAT_803dc070;
              if (10 < *(byte *)((int)piVar6 + 0xaf)) {
                *(undefined *)((int)piVar6 + 0xaf) = 0;
                for (bVar4 = 0; bVar4 < 9; bVar4 = bVar4 + 1) {
                  uVar1 = (uint)bVar4;
                  piVar6[uVar1 + 5] = piVar6[uVar1 + 6];
                  piVar6[uVar1 + 0xf] = piVar6[uVar1 + 0x10];
                  piVar6[uVar1 + 0x19] = piVar6[uVar1 + 0x1a];
                  if ((uVar1 == 0) || ((float)piVar6[2] < (float)piVar6[uVar1 + 0xf])) {
                    piVar6[2] = piVar6[uVar1 + 0xf];
                  }
                }
                piVar6[0xe] = *(int *)(*piVar6 + 0xc);
                piVar6[0x18] = *(int *)(*piVar6 + 0x10);
                piVar6[0x22] = *(int *)(*piVar6 + 0x14);
                piVar6[1] = piVar6[5];
                piVar6[3] = piVar6[0x19];
              }
              if (0 < *(short *)(piVar6 + 0x29)) {
                *(ushort *)(piVar6 + 0x29) = *(short *)(piVar6 + 0x29) - (ushort)DAT_803dc070;
              }
              if (0 < *(short *)((int)piVar6 + 0xa6)) {
                *(ushort *)((int)piVar6 + 0xa6) =
                     *(short *)((int)piVar6 + 0xa6) - (ushort)DAT_803dc070;
              }
              dVar7 = FUN_80017708((float *)(param_9 + 0xc),(float *)(*piVar6 + 0x18));
              piVar6[4] = (int)(float)dVar7;
              dVar7 = (double)(float)piVar6[2];
              dVar9 = (double)(float)piVar6[3];
              dVar10 = (double)(float)piVar6[4];
              uVar8 = FUN_801b2644();
              FUN_801b2640(uVar8,dVar7,dVar9,dVar10,param_5,param_6,param_7,param_8);
              uStack_1c = *(short *)(iVar5 + 0x26) * DAT_803dcb74 ^ 0x80000000;
              local_20 = 0x43300000;
              if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e5558) / FLOAT_803e5584
                  < (float)piVar6[4]) {
                *(undefined *)(piVar6 + 0x2b) = 4;
              }
            }
          }
          else {
            *(undefined *)(piVar6 + 0x2b) = 4;
          }
        }
        else {
          *(undefined *)(piVar6 + 0x2b) = 5;
        }
      }
      else if ((bVar4 == 0) && (uVar1 = FUN_80017690((int)*(short *)(iVar5 + 0x1c)), uVar1 != 0)) {
        *(undefined *)(piVar6 + 0x2b) = 4;
      }
    }
    else if (bVar4 < 6) {
      if (*(char *)(piVar6 + 0x2c) < '\x01') {
        if ((*(byte *)((int)param_9 + 0xaf) & 1) != 0) {
          *(undefined *)((int)piVar6 + 0xae) = 0;
          *(undefined *)((int)piVar6 + 0xb1) = 0;
          local_28[0] = param_9;
          (**(code **)(*DAT_803dd6d0 + 0x1c))(0x51,1,0,4,local_28,0x32,0xff);
          FUN_80006ba8(0,0x100);
          *(undefined *)(piVar6 + 0x2b) = 3;
          (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
          *(undefined *)(piVar6 + 0x2c) = 0x3c;
          *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
        }
      }
      else {
        *(byte *)(piVar6 + 0x2c) = *(char *)(piVar6 + 0x2c) - DAT_803dc070;
      }
      *(undefined *)((int)piVar6 + 0xad) = 0;
      *(undefined2 *)(piVar6 + 0x29) = 0;
      *(undefined2 *)((int)piVar6 + 0xa6) = 0;
    }
    FLOAT_803dcb5c = FLOAT_803e5588;
    FUN_8002fc3c((double)FLOAT_803e5588,(double)FLOAT_803dc074);
  }
  return;
}
