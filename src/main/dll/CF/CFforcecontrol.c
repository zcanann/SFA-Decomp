#include "ghidra_import.h"
#include "main/dll/CF/CFforcecontrol.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000dbb0();
extern undefined4 FUN_8000dcdc();
extern undefined4 FUN_8001fe5c();
extern undefined4 FUN_80020000();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern int FUN_80020800();
extern double FUN_80021730();
extern undefined4 FUN_80021754();
extern double FUN_80021794();
extern undefined4 FUN_800217c8();
extern uint FUN_80022264();
extern int FUN_800284e8();
extern undefined4 FUN_800285f0();
extern int FUN_8002867c();
extern int FUN_8002b660();
extern undefined4 FUN_8002b738();
extern undefined4 FUN_8002b95c();
extern int FUN_8002ba84();
extern int FUN_8002bac4();
extern undefined4 FUN_80036548();
extern void* FUN_80037048();
extern undefined4 FUN_8003709c();
extern undefined4 FUN_800372f8();
extern int FUN_800375e4();
extern undefined4 FUN_800379bc();
extern undefined4 FUN_80037a5c();
extern int FUN_8003811c();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80041110();
extern undefined4 FUN_8004c380();
extern undefined4 FUN_8004c38c();
extern undefined4 FUN_8005d0e4();
extern undefined4 FUN_80070434();
extern undefined4 FUN_8007048c();
extern undefined4 FUN_8008fb90();
extern undefined4 FUN_8008fdac();
extern undefined4 FUN_8008ff08();
extern undefined4 FUN_80097568();
extern undefined4 FUN_800d7cfc();
extern undefined4 FUN_8012f288();
extern char FUN_80133868();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025cce8();
extern int FUN_80286830();
extern undefined4 FUN_8028687c();
extern byte FUN_80296434();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6e8;
extern f64 DOUBLE_803e4910;
extern f64 DOUBLE_803e4950;
extern f64 DOUBLE_803e4998;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e48e4;
extern f32 FLOAT_803e4918;
extern f32 FLOAT_803e491c;
extern f32 FLOAT_803e4920;
extern f32 FLOAT_803e4924;
extern f32 FLOAT_803e4928;
extern f32 FLOAT_803e492c;
extern f32 FLOAT_803e4930;
extern f32 FLOAT_803e4934;
extern f32 FLOAT_803e4938;
extern f32 FLOAT_803e493c;
extern f32 FLOAT_803e4940;
extern f32 FLOAT_803e4944;
extern f32 FLOAT_803e4948;
extern f32 FLOAT_803e494c;
extern f32 FLOAT_803e4960;
extern f32 FLOAT_803e4964;
extern f32 FLOAT_803e4968;
extern f32 FLOAT_803e496c;
extern f32 FLOAT_803e4970;
extern f32 FLOAT_803e4974;
extern f32 FLOAT_803e4978;
extern f32 FLOAT_803e497c;
extern f32 FLOAT_803e4980;
extern f32 FLOAT_803e4984;
extern f32 FLOAT_803e4988;
extern f32 FLOAT_803e498c;
extern f32 FLOAT_803e4990;
extern f32 FLOAT_803e49a0;
extern f32 FLOAT_803e49a4;
extern f32 FLOAT_803e49a8;

/*
 * --INFO--
 *
 * Function: FUN_8018bc64
 * EN v1.0 Address: 0x8018BC64
 * EN v1.0 Size: 208b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018bc64(short *param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  param_1[0x58] = param_1[0x58] | 0x6000;
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1c));
  if (uVar1 != 0) {
    *(float *)(iVar3 + 4) = FLOAT_803e48e4;
  }
  *param_1 = (ushort)*(byte *)(param_2 + 0x23) << 8;
  iVar2 = FUN_8002b660((int)param_1);
  iVar2 = FUN_8002867c(iVar2,0);
  if (0 < *(short *)(param_2 + 0x24)) {
    uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x24));
    if (uVar1 == 0) {
      *(undefined *)(iVar2 + 8) = 0x16;
    }
    else {
      *(byte *)(iVar3 + 1) = *(byte *)(iVar3 + 1) | 0xc;
      *(undefined *)(iVar2 + 8) = 0x17;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018bd34
 * EN v1.0 Address: 0x8018BD34
 * EN v1.0 Size: 40b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018bd34(int param_1)
{
  FUN_8003709c(param_1,0x1e);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018bd5c
 * EN v1.0 Address: 0x8018BD5C
 * EN v1.0 Size: 432b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018bd5c(int param_1)
{
  int iVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  double dVar5;
  
  piVar4 = *(int **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_8002ba84();
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *(byte *)(piVar4 + 1) = *(byte *)(piVar4 + 1) & 0x7f;
  if ((iVar1 != 0) && (cVar2 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x44))(), cVar2 != '\0')) {
    dVar5 = (double)FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18));
    if (dVar5 < (double)(float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(iVar3 + 0x1a) ^ 0x80000000) -
                               DOUBLE_803e4910)) {
      *piVar4 = *piVar4 - (uint)DAT_803dc070;
      *(byte *)(piVar4 + 1) = *(byte *)(piVar4 + 1) & 0x7f | 0x80;
    }
  }
  if (*piVar4 == 0) {
    if (iVar1 != 0) {
      (**(code **)(**(int **)(iVar1 + 0x68) + 0x3c))(iVar1);
      *piVar4 = (uint)*(byte *)(iVar3 + 0x19) * 0x3c;
    }
  }
  else if ((iVar1 != 0) &&
          (cVar2 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x44))(iVar1), cVar2 == '\0')) {
    if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
      (**(code **)(**(int **)(iVar1 + 0x68) + 0x28))(iVar1,param_1,1,3);
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    FUN_80041110();
  }
  FUN_800201ac((int)*(short *)(iVar3 + 0x1e),(uint)(*(byte *)(piVar4 + 1) >> 7));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018bf0c
 * EN v1.0 Address: 0x8018BF0C
 * EN v1.0 Size: 104b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018bf0c(short *param_1,int param_2)
{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0x5c);
  FUN_800372f8((int)param_1,0x1e);
  *piVar1 = (uint)*(byte *)(param_2 + 0x19) * 0x3c;
  *param_1 = (short)*(char *)(param_2 + 0x18);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018bf74
 * EN v1.0 Address: 0x8018BF74
 * EN v1.0 Size: 196b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018bf74(int param_1)
{
  int iVar1;
  char cVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  iVar1 = FUN_8003811c(param_1);
  if ((iVar1 != 0) && (cVar2 = FUN_80133868(), cVar2 == '\0')) {
    *pfVar3 = FLOAT_803e4918;
  }
  if (FLOAT_803e491c < *pfVar3) {
    if ((*(byte *)(param_1 + 0xaf) & 4) == 0) {
      *pfVar3 = FLOAT_803e491c;
    }
    else {
      *pfVar3 = *pfVar3 - FLOAT_803dc074;
      FUN_8012f288(*(undefined2 *)
                    (*(int *)(param_1 + 0x50) + (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x19) * 2
                    + 0x7c));
    }
  }
  if ((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) {
    FUN_80041110();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c038
 * EN v1.0 Address: 0x8018C038
 * EN v1.0 Size: 76b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c038(short *param_1,int param_2)
{
  param_1[0x58] = param_1[0x58] | 0x6000;
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  FUN_8002b738((int)param_1,(ushort)*(byte *)(param_2 + 0x19));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c084
 * EN v1.0 Address: 0x8018C084
 * EN v1.0 Size: 328b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c084(int param_1)
{
  int iVar1;
  byte bVar2;
  char cVar3;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  iVar1 = FUN_8002bac4();
  if (*(char *)(pfVar4 + 1) == '\0') {
    bVar2 = FUN_80296434(iVar1);
    if (bVar2 != 0) {
      *(undefined *)(pfVar4 + 1) = 1;
    }
  }
  else {
    bVar2 = FUN_80296434(iVar1);
    if (bVar2 == 0) {
      *(undefined *)(pfVar4 + 1) = 0;
    }
  }
  FUN_8002b738(param_1,(ushort)*(byte *)(pfVar4 + 1));
  FUN_8002b95c(param_1,(uint)*(byte *)(pfVar4 + 1));
  iVar1 = FUN_8003811c(param_1);
  if ((iVar1 != 0) && (cVar3 = FUN_80133868(), cVar3 == '\0')) {
    *pfVar4 = FLOAT_803e4920;
  }
  if (FLOAT_803e4924 < *pfVar4) {
    if ((*(byte *)(param_1 + 0xaf) & 4) == 0) {
      *pfVar4 = FLOAT_803e4924;
    }
    else {
      *pfVar4 = *pfVar4 - FLOAT_803dc074;
      FUN_8012f288(*(undefined2 *)
                    (*(int *)(param_1 + 0x50) + (uint)*(byte *)(pfVar4 + 1) * 2 + 0x7c));
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c1cc
 * EN v1.0 Address: 0x8018C1CC
 * EN v1.0 Size: 108b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c1cc(int param_1)
{
  byte bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  bVar1 = *(byte *)(iVar2 + 0xc);
  if (((char)bVar1 < '\0') && ((bVar1 >> 5 & 1) == 0)) {
    FUN_8004c380();
  }
  if ((*(byte *)(iVar2 + 0xc) >> 6 & 1) != 0) {
    (**(code **)(*DAT_803dd6e8 + 0x60))();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c238
 * EN v1.0 Address: 0x8018C238
 * EN v1.0 Size: 876b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c238(int param_1)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  byte bVar4;
  float *pfVar5;
  int iVar6;
  double dVar7;
  undefined8 local_18;
  
  iVar6 = *(int *)(param_1 + 0x4c);
  pfVar5 = *(float **)(param_1 + 0xb8);
  if ((int)*(short *)(iVar6 + 0x1a) == 0xffffffff) {
    uVar2 = 1;
  }
  else {
    uVar2 = FUN_80020078((int)*(short *)(iVar6 + 0x1a));
    uVar2 = uVar2 & 0xff;
  }
  if (uVar2 != 0) {
    if (-1 < (char)*(byte *)(pfVar5 + 3)) {
      if ((*(byte *)(pfVar5 + 3) >> 5 & 1) == 0) {
        FUN_8004c38c((double)(FLOAT_803e4928 + *(float *)(param_1 + 0x1c)),
                     (double)(*(float *)(param_1 + 0x1c) - FLOAT_803e492c),(double)FLOAT_803e4930,
                     (double)FLOAT_803e4934,(double)FLOAT_803e4938,0);
      }
      *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0x7f | 0x80;
    }
    iVar3 = FUN_8002bac4();
    bVar4 = FUN_80296434(iVar3);
    if (((bVar4 != 0) || (FLOAT_803e493c + *(float *)(param_1 + 0x1c) < *(float *)(iVar3 + 0x1c)))
       || (dVar7 = (double)FUN_800217c8((float *)(iVar3 + 0x18),(float *)(param_1 + 0x18)),
          (double)pfVar5[2] < dVar7)) {
      if ((*(byte *)(pfVar5 + 3) >> 6 & 1) != 0) {
        local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x19));
        *pfVar5 = *pfVar5 + (FLOAT_803dc074 * (float)(local_18 - DOUBLE_803e4950)) / FLOAT_803e4944;
        if (FLOAT_803e4940 < *pfVar5) {
          (**(code **)(*DAT_803dd6e8 + 100))();
          *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0xbf;
        }
      }
    }
    else {
      if ((*(byte *)(pfVar5 + 3) >> 6 & 1) == 0) {
        (**(code **)(*DAT_803dd6e8 + 0x58))(6000,0x603);
        *pfVar5 = FLOAT_803e4940;
        *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0xbf | 0x40;
      }
      local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x18));
      *pfVar5 = *pfVar5 - (FLOAT_803dc074 * (float)(local_18 - DOUBLE_803e4950)) / FLOAT_803e4944;
      fVar1 = FLOAT_803e4948;
      if (*pfVar5 <= FLOAT_803e4948) {
        *pfVar5 = FLOAT_803e4948;
        pfVar5[1] = pfVar5[1] - FLOAT_803dc074;
        if (pfVar5[1] < fVar1) {
          pfVar5[1] = pfVar5[1] + FLOAT_803e494c;
          FUN_80036548(iVar3,param_1,'\x16',1,0);
        }
      }
    }
    if ((*(byte *)(pfVar5 + 3) >> 6 & 1) != 0) {
      (**(code **)(*DAT_803dd6e8 + 0x5c))((int)*pfVar5);
    }
    return;
  }
  if ((char)*(byte *)(pfVar5 + 3) < '\0') {
    if ((*(byte *)(pfVar5 + 3) >> 5 & 1) == 0) {
      FUN_8004c380();
    }
    *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0x7f;
  }
  if ((*(byte *)(pfVar5 + 3) >> 6 & 1) == 0) {
    return;
  }
  (**(code **)(*DAT_803dd6e8 + 0x60))();
  *(byte *)(pfVar5 + 3) = *(byte *)(pfVar5 + 3) & 0xbf;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c5a4
 * EN v1.0 Address: 0x8018C5A4
 * EN v1.0 Size: 140b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c5a4(int param_1)
{
  if (*(char *)(param_1 + 0x37) == -1) {
    FUN_8025cce8(0,1,0,5);
  }
  else {
    FUN_8025cce8(1,4,1,5);
  }
  FUN_8007048c(1,3,0);
  FUN_80070434(1);
  FUN_8025c754(7,0,0,7,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c630
 * EN v1.0 Address: 0x8018C630
 * EN v1.0 Size: 140b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c630(int param_1)
{
  uint uVar1;
  byte bVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  for (bVar2 = 0; bVar2 < 10; bVar2 = bVar2 + 1) {
    uVar1 = *(uint *)(iVar3 + (uint)bVar2 * 4 + 8);
    if (uVar1 != 0) {
      FUN_8008ff08(uVar1);
    }
  }
  if (*(char *)(iVar3 + 0x5c) < '\0') {
    FUN_8003709c(param_1,0x4f);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018c6bc
 * EN v1.0 Address: 0x8018C6BC
 * EN v1.0 Size: 1040b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018c6bc(void)
{
  float fVar1;
  bool bVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  undefined4 *puVar8;
  undefined4 uVar9;
  uint uVar10;
  uint uVar11;
  byte bVar12;
  undefined uVar13;
  int iVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps30_1;
  double in_ps31_1;
  int local_98;
  float local_94;
  float local_90;
  float local_8c;
  int local_88 [10];
  undefined8 local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  iVar3 = FUN_80286830();
  iVar14 = *(int *)(iVar3 + 0xb8);
  dVar16 = (double)FLOAT_803e4960;
  local_98 = 0;
  uVar13 = 0x40;
  uVar10 = 0;
  bVar2 = false;
  if ((char)*(byte *)(iVar14 + 0x5c) < '\0') {
    if ((*(byte *)(iVar14 + 0x5c) >> 5 & 1) == 0) {
      FUN_80097568((double)FLOAT_803e4964,(double)FLOAT_803e496c,iVar3,5,1,1,0x14,0,0);
    }
    else {
      FUN_80097568((double)FLOAT_803e4964,(double)FLOAT_803e4968,iVar3,5,1,1,0x14,0,0);
    }
    piVar4 = (int *)FUN_8002b660(iVar3);
    iVar5 = FUN_800284e8(*piVar4,0);
    *(undefined *)(iVar5 + 0x43) = 0x7f;
    FUN_8003b9ec(iVar3);
    for (bVar12 = 0; bVar12 < 10; bVar12 = bVar12 + 1) {
      iVar5 = iVar14 + (uint)bVar12 * 4;
      if (*(float **)(iVar5 + 8) == (float *)0x0) {
        if ((!bVar2) && (iVar6 = FUN_80020800(), iVar6 == 0)) {
          uVar7 = FUN_80022264(0,9);
          if ((uVar7 == 0) && ((*(byte *)(iVar14 + 0x5c) >> 5 & 1) == 0)) {
            puVar8 = FUN_80037048(0x4f,&local_98);
            for (uVar7 = 0; (int)(uVar7 & 0xff) < local_98; uVar7 = uVar7 + 1) {
              iVar6 = puVar8[uVar7 & 0xff];
              uVar11 = uVar10;
              if (iVar6 != iVar3) {
                if ((*(int *)(iVar6 + 0xb8) == 0) ||
                   ((*(byte *)(*(int *)(iVar6 + 0xb8) + 0x5c) >> 5 & 1) == 0)) {
                  bVar2 = true;
                }
                else {
                  bVar2 = false;
                }
                if ((bVar2) &&
                   (dVar15 = FUN_80021794((float *)(iVar6 + 0x18),(float *)(iVar3 + 0x18)),
                   dVar15 < (double)FLOAT_803e4974)) {
                  uVar11 = uVar10 + 1;
                  local_88[uVar10 & 0xff] = puVar8[uVar7 & 0xff];
                }
              }
              uVar10 = uVar11;
            }
          }
          if ((uVar10 & 0xff) == 0) {
            local_88[0] = iVar3;
          }
          else {
            uVar10 = FUN_80022264(0,uVar10 - 1 & 0xff);
            uVar10 = uVar10 & 0xff;
            dVar16 = (double)FUN_800217c8((float *)(local_88[uVar10] + 0x18),(float *)(iVar3 + 0x18)
                                         );
            dVar16 = -(double)(FLOAT_803e4980 * (float)(dVar16 / (double)FLOAT_803e4978) -
                              FLOAT_803e497c);
            uVar13 = 0xff;
          }
          iVar6 = local_88[uVar10 & 0xff];
          local_94 = *(float *)(iVar6 + 0xc);
          local_90 = *(float *)(iVar6 + 0x10);
          local_8c = *(float *)(iVar6 + 0x14);
          if (iVar6 == iVar3) {
            fVar1 = FLOAT_803e4988;
            if ((*(byte *)(iVar14 + 0x5c) >> 5 & 1) != 0) {
              fVar1 = FLOAT_803e4984;
            }
            dVar15 = (double)fVar1;
            uVar7 = FUN_80022264(0,2000);
            local_60 = (double)CONCAT44(0x43300000,uVar7 - 1000 ^ 0x80000000);
            local_94 = (float)(dVar15 * (double)(float)(local_60 - DOUBLE_803e4998) +
                              (double)local_94);
            uVar7 = FUN_80022264(0,2000);
            uStack_54 = uVar7 - 1000 ^ 0x80000000;
            local_58 = 0x43300000;
            local_90 = (float)(dVar15 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) -
                                                       DOUBLE_803e4998) + (double)local_90);
            uVar7 = FUN_80022264(0,2000);
            uStack_4c = uVar7 - 1000 ^ 0x80000000;
            local_50 = 0x43300000;
            local_8c = (float)(dVar15 * (double)(float)((double)CONCAT44(0x43300000,uStack_4c) -
                                                       DOUBLE_803e4998) + (double)local_8c);
          }
          uVar9 = FUN_8008fdac(dVar16,(double)FLOAT_803e498c,iVar3 + 0xc,&local_94,0x14,uVar13,0);
          *(undefined4 *)(iVar5 + 8) = uVar9;
          *(float *)(iVar5 + 0x34) = FLOAT_803e4990;
          bVar2 = true;
        }
      }
      else {
        FUN_8008fb90(*(float **)(iVar5 + 8));
        iVar6 = FUN_80020800();
        if (iVar6 == 0) {
          *(float *)(iVar5 + 0x34) = *(float *)(iVar5 + 0x34) + FLOAT_803dc074;
          iVar6 = (int)(FLOAT_803e4970 + *(float *)(iVar5 + 0x34));
          local_60 = (double)(longlong)iVar6;
          *(short *)(*(int *)(iVar5 + 8) + 0x20) = (short)iVar6;
          if (0x14 < *(ushort *)(*(uint *)(iVar5 + 8) + 0x20)) {
            FUN_8008ff08(*(uint *)(iVar5 + 8));
            *(undefined4 *)(iVar5 + 8) = 0;
          }
        }
      }
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018cacc
 * EN v1.0 Address: 0x8018CACC
 * EN v1.0 Size: 568b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018cacc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  float fVar1;
  int iVar2;
  uint uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  undefined2 *puVar5;
  double dVar6;
  uint uStack_18;
  uint local_14;
  
  iVar4 = *(int *)(param_9 + 0x4c);
  puVar5 = *(undefined2 **)(param_9 + 0xb8);
  iVar2 = FUN_8002bac4();
  if ((*(byte *)(puVar5 + 0x2e) >> 6 & 1) == 0) {
    if (((int)*(short *)(iVar4 + 0x1e) == 0xffffffff) ||
       (uVar3 = FUN_80020078((int)*(short *)(iVar4 + 0x1e)), uVar3 != 0)) {
      if ((char)*(byte *)(puVar5 + 0x2e) < '\0') {
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0x7f;
        FUN_8000dbb0();
        FUN_8003709c(param_9,0x4f);
      }
    }
    else if (((int)*(short *)(iVar4 + 0x20) == 0xffffffff) ||
            (uVar3 = FUN_80020078((int)*(short *)(iVar4 + 0x20)), uVar3 != 0)) {
      if ((char)*(byte *)(puVar5 + 0x2e) < '\0') {
        if ((*(byte *)(puVar5 + 0x2e) >> 4 & 1) != 0) {
          *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(iVar4 + 8);
          *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
          *(undefined4 *)(param_9 + 0x14) = *(undefined4 *)(iVar4 + 0x10);
          *(undefined *)(param_9 + 0x36) = 0xff;
          *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0xef;
        }
      }
      else {
        FUN_8000dcdc(param_9,0x403);
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0x7f | 0x80;
        FUN_800372f8(param_9,0x4f);
      }
      fVar1 = *(float *)(param_9 + 0x10) - *(float *)(iVar2 + 0x10);
      if ((((FLOAT_803e49a0 < fVar1) && (fVar1 < FLOAT_803e49a4)) &&
          (uVar3 = FUN_80020078(0xe97), uVar3 == 0)) &&
         (dVar6 = FUN_80021730((float *)(param_9 + 0x18),(float *)(iVar2 + 0x18)),
         dVar6 < (double)FLOAT_803e49a8)) {
        *puVar5 = 0xcbe;
        FUN_800379bc(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,0x7000a,
                     param_9,(uint)puVar5,in_r7,in_r8,in_r9,in_r10);
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0xbf | 0x40;
        FUN_800201ac(0xe97,1);
        FUN_8000bb38(param_9,0x49);
      }
    }
  }
  else {
    while (iVar2 = FUN_800375e4(param_9,&local_14,&uStack_18,(uint *)0x0), iVar2 != 0) {
      if (local_14 == 0x7000b) {
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0xbf;
        FUN_800201ac((int)*(short *)(iVar4 + 0x1e),1);
        FUN_80020000(0x3f5);
        FUN_800201ac(0xe97,0);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018cd04
 * EN v1.0 Address: 0x8018CD04
 * EN v1.0 Size: 96b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018cd04(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8018cd64
 * EN v1.0 Address: 0x8018CD64
 * EN v1.0 Size: 72b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018cd64(int param_1)
{
  FUN_800d7cfc(0);
  FUN_8005d0e4(0);
  FUN_8001fe5c(param_1);
  return;
}
