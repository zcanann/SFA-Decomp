// Function: FUN_80177cc4
// Entry: 80177cc4
// Size: 1024 bytes

/* WARNING: Removing unreachable block (ram,0x801780a4) */
/* WARNING: Removing unreachable block (ram,0x8017809c) */
/* WARNING: Removing unreachable block (ram,0x80178094) */
/* WARNING: Removing unreachable block (ram,0x80177ce4) */
/* WARNING: Removing unreachable block (ram,0x80177cdc) */
/* WARNING: Removing unreachable block (ram,0x80177cd4) */

void FUN_80177cc4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  char cVar5;
  int iVar6;
  float *pfVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined8 extraout_f1;
  undefined8 uVar11;
  double dVar12;
  double in_f29;
  double dVar13;
  double in_f30;
  double dVar14;
  double in_f31;
  double dVar15;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_58 [2];
  undefined4 local_50;
  uint uStack_4c;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  iVar4 = FUN_80286840();
  pfVar7 = *(float **)(iVar4 + 0xb8);
  *(undefined4 *)(iVar4 + 0x80) = *(undefined4 *)(iVar4 + 0xc);
  *(undefined4 *)(iVar4 + 0x84) = *(undefined4 *)(iVar4 + 0x10);
  *(undefined4 *)(iVar4 + 0x88) = *(undefined4 *)(iVar4 + 0x14);
  switch(*(undefined *)(pfVar7 + 2)) {
  case 0:
    iVar10 = FUN_8002bac4();
    dVar12 = DOUBLE_803e4290;
    while (iVar10 != 0) {
      fVar2 = *(float *)(iVar4 + 0xc) - *(float *)(iVar10 + 0xc);
      fVar1 = *(float *)(iVar4 + 0x10) - *(float *)(iVar10 + 0x10);
      fVar3 = *(float *)(iVar4 + 0x14) - *(float *)(iVar10 + 0x14);
      dVar13 = FUN_80293900((double)(fVar3 * fVar3 + fVar2 * fVar2 + fVar1 * fVar1));
      uStack_4c = *(uint *)(iVar4 + 0xf8) ^ 0x80000000;
      local_50 = 0x43300000;
      if (dVar13 < (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - dVar12)) {
        iVar6 = *(int *)(iVar10 + 0x54);
        *(char *)(iVar6 + 0x71) = *(char *)(iVar6 + 0x71) + '\x01';
        *(ushort *)(iVar6 + 0x60) = *(ushort *)(iVar6 + 0x60) & 0xfffe;
        *(char *)(*(int *)(iVar4 + 0x54) + 0x71) = *(char *)(*(int *)(iVar4 + 0x54) + 0x71) + '\x01'
        ;
      }
      if (*(short *)(iVar10 + 0x44) == 1) {
        iVar10 = FUN_8002ba84();
      }
      else {
        iVar10 = 0;
      }
    }
    break;
  case 1:
    FUN_80038300(*(int *)(iVar4 + 0xf4));
    break;
  case 3:
    iVar10 = FUN_8002bac4();
    if (iVar10 != 0) {
      DAT_803ad3e0 = *(undefined4 *)(iVar4 + 0x18);
      DAT_803ad3e4 = *(undefined4 *)(iVar4 + 0x1c);
      DAT_803ad3e8 = *(undefined4 *)(iVar4 + 0x20);
    }
    break;
  case 4:
    *(uint *)(iVar4 + 0xf8) = *(int *)(iVar4 + 0xf8) - (uint)DAT_803dc070;
    if (*(int *)(*(int *)(iVar4 + 0x54) + 0x50) != 0) {
      *(undefined2 *)(*(int *)(iVar4 + 0x54) + 0x60) = 0;
    }
    iVar10 = *(int *)(iVar4 + 0xf4);
    if (iVar10 != 0) {
      iVar6 = FUN_80038300(iVar10);
      fVar2 = FLOAT_803e4284;
      if (iVar6 == 0) break;
      fVar1 = *(float *)(iVar10 + 0x14);
      *(float *)(iVar4 + 0xc) =
           ((*(float *)(iVar10 + 0xc) - *(float *)(iVar4 + 0xc)) / FLOAT_803e4284) * FLOAT_803dc074
           + *(float *)(iVar4 + 0xc);
      *(float *)(iVar4 + 0x14) =
           ((fVar1 - *(float *)(iVar4 + 0x14)) / fVar2) * FLOAT_803dc074 + *(float *)(iVar4 + 0x14);
      fVar2 = *(float *)(iVar10 + 0xc) - *pfVar7;
      fVar1 = *(float *)(iVar10 + 0x14) - pfVar7[1];
      dVar12 = FUN_80293900((double)(fVar2 * fVar2 + fVar1 * fVar1));
      dVar13 = (double)(float)((double)FLOAT_803e4288 + dVar12);
      dVar15 = (double)(*(float *)(iVar4 + 0xc) - *pfVar7);
      dVar14 = (double)(*(float *)(iVar4 + 0x14) - pfVar7[1]);
      dVar12 = FUN_80293900((double)(float)(dVar15 * dVar15 + (double)(float)(dVar14 * dVar14)));
      if (dVar13 < dVar12) {
        *(float *)(iVar4 + 0xc) = *pfVar7 + (float)(dVar15 * (double)(float)(dVar13 / dVar12));
        *(float *)(iVar4 + 0x14) = pfVar7[1] + (float)(dVar14 * (double)(float)(dVar13 / dVar12));
      }
      (**(code **)(*DAT_803dd708 + 8))(iVar4,0x25,0,0,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(iVar4,0x56,0,0,0xffffffff,0);
    }
    cVar5 = FUN_80065fcc((double)*(float *)(iVar4 + 0xc),(double)*(float *)(iVar4 + 0x10),
                         (double)*(float *)(iVar4 + 0x14),iVar4,local_58,0,0);
    fVar2 = FLOAT_803e428c;
    for (iVar10 = 0; iVar10 < cVar5; iVar10 = iVar10 + 1) {
      fVar1 = **(float **)(local_58[0] + iVar10 * 4);
      if ((fVar1 < fVar2 + *(float *)(iVar4 + 0x10)) && (*(float *)(iVar4 + 0x10) - fVar2 < fVar1))
      {
        *(float *)(iVar4 + 0x10) = fVar1;
        iVar10 = (int)cVar5;
      }
    }
    break;
  case 5:
    iVar10 = FUN_8002bac4();
    iVar6 = FUN_80296878(iVar10);
    if ((iVar10 != 0) && (iVar6 != 0)) {
      DAT_803ad3e0 = *(undefined4 *)(iVar4 + 0x18);
      DAT_803ad3e4 = *(undefined4 *)(iVar4 + 0x1c);
      DAT_803ad3e8 = *(undefined4 *)(iVar4 + 0x20);
    }
    break;
  case 7:
    iVar9 = *(int *)(iVar4 + 0x54);
    iVar8 = *(int *)(*(int *)(iVar4 + 0xf4) + 0x54);
    iVar10 = iVar8;
    uVar11 = extraout_f1;
    for (iVar6 = 0; iVar6 < *(char *)(iVar8 + 0x71); iVar6 = iVar6 + 1) {
      if (*(int *)(iVar10 + 0x7c) == iVar4) {
        *(ushort *)(iVar9 + 0x60) = *(ushort *)(iVar9 + 0x60) & 0xfffe;
        uVar11 = FUN_8002cc9c(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
      }
      iVar10 = iVar10 + 4;
    }
  }
  FUN_8028688c();
  return;
}

