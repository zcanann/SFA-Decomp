// Function: FUN_80107718
// Entry: 80107718
// Size: 1640 bytes

/* WARNING: Removing unreachable block (ram,0x80107d60) */
/* WARNING: Removing unreachable block (ram,0x80107d58) */
/* WARNING: Removing unreachable block (ram,0x80107d50) */
/* WARNING: Removing unreachable block (ram,0x80107d48) */
/* WARNING: Removing unreachable block (ram,0x80107d40) */
/* WARNING: Removing unreachable block (ram,0x80107748) */
/* WARNING: Removing unreachable block (ram,0x80107740) */
/* WARNING: Removing unreachable block (ram,0x80107738) */
/* WARNING: Removing unreachable block (ram,0x80107730) */
/* WARNING: Removing unreachable block (ram,0x80107728) */

void FUN_80107718(undefined4 param_1,undefined4 param_2,short *param_3)

{
  float fVar1;
  float fVar2;
  short sVar3;
  short sVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined4 *puVar10;
  undefined4 in_r9;
  undefined4 in_r10;
  short *psVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  undefined8 uVar17;
  double dVar18;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_a8;
  float local_a4;
  float local_a0;
  float local_9c [2];
  uint uStack_94;
  undefined4 local_90;
  uint uStack_8c;
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined8 local_78;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
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
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  iVar5 = FUN_80286840();
  *(undefined *)((int)param_3 + 3) = 1;
  psVar11 = *(short **)(iVar5 + 0xa4);
  if (DAT_803de1b0 == (undefined4 *)0x0) {
    DAT_803de1b0 = (undefined4 *)FUN_80023d8c(0x1c0,0xf);
  }
  FUN_800033a8((int)DAT_803de1b0,0,0x1c0);
  iVar6 = (**(code **)(*DAT_803dd6d0 + 0x18))();
  puVar10 = DAT_803de1b0 + 4;
  iVar6 = **(int **)(iVar6 + 4);
  (**(code **)(iVar6 + 0x20))(DAT_803de1b0 + 1,DAT_803de1b0 + 2,DAT_803de1b0 + 3,0);
  *(undefined *)(DAT_803de1b0 + 0x6f) = 0;
  *DAT_803de1b0 = *(undefined4 *)(iVar5 + 0x30);
  uStack_94 = (int)*psVar11 ^ 0x80000000;
  local_9c[1] = 176.0;
  dVar12 = (double)FUN_802945e0();
  uStack_8c = (int)*psVar11 ^ 0x80000000;
  local_90 = 0x43300000;
  dVar13 = (double)FUN_80294964();
  if ((short *)*DAT_803de1b0 == (short *)0x0) {
    uStack_84 = (uint)*psVar11;
  }
  else {
    uStack_84 = (int)*psVar11 - (int)*(short *)*DAT_803de1b0;
  }
  uStack_84 = uStack_84 ^ 0x80000000;
  local_88 = 0x43300000;
  dVar14 = (double)FUN_802945e0();
  dVar15 = (double)FUN_80294964();
  iVar7 = FUN_80021884();
  sVar3 = *psVar11 - (short)iVar7;
  if (0x8000 < sVar3) {
    sVar3 = sVar3 + 1;
  }
  if (sVar3 < -0x8000) {
    sVar3 = sVar3 + -1;
  }
  if (sVar3 < 0) {
    sVar3 = -sVar3;
  }
  uStack_7c = (int)*param_3 ^ 0x80000000;
  local_80 = 0x43300000;
  iVar7 = (int)(FLOAT_803e23e8 * (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e23d0));
  local_78 = (longlong)iVar7;
  if (sVar3 < (short)iVar7) {
    *(undefined *)(DAT_803de1b0 + 0x6f) = 1;
  }
  else {
    dVar16 = (double)((float)DAT_803de1b0[1] * (float)DAT_803de1b0[1] -
                     (float)DAT_803de1b0[3] * (float)DAT_803de1b0[3]);
    if (dVar16 < (double)FLOAT_803e23ec) {
      dVar16 = (double)FLOAT_803e23ec;
    }
    dVar16 = FUN_80293900(dVar16);
    local_a4 = (float)(dVar12 * dVar16 + (double)*(float *)(psVar11 + 0xc));
    local_a0 = (float)DAT_803de1b0[3] + *(float *)(psVar11 + 0xe) + (float)DAT_803de1b0[4];
    local_9c[0] = (float)(dVar13 * dVar16 + (double)*(float *)(psVar11 + 0x10));
    if (*(char *)((int)param_3 + 3) != '\0') {
      FUN_801039a4(iVar5,psVar11,&local_a4,(short *)0x0);
    }
    iVar7 = *(int *)(iVar5 + 0x30);
    FUN_8000e054((double)local_a4,(double)local_a0,(double)local_9c[0],&local_a4,&local_a0,local_9c,
                 iVar7);
    for (local_a8 = 0; local_a8 < 3; local_a8 = local_a8 + 1) {
      DAT_803de1b0[local_a8 + 7] = *(undefined4 *)(iVar5 + 0xc);
      DAT_803de1b0[local_a8 + 0x1b] = *(undefined4 *)(iVar5 + 0x10);
      DAT_803de1b0[local_a8 + 0x2f] = *(undefined4 *)(iVar5 + 0x14);
    }
    fVar1 = *(float *)(iVar5 + 0xc) - local_a4;
    fVar2 = *(float *)(iVar5 + 0x14) - local_9c[0];
    dVar12 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
    dVar12 = (double)(float)((double)FLOAT_803e23f0 * dVar12);
    iVar8 = FUN_80021884();
    iVar9 = FUN_80021884();
    sVar3 = (short)iVar8 - (short)iVar9;
    if (0x8000 < sVar3) {
      sVar3 = sVar3 + 1;
    }
    if (sVar3 < -0x8000) {
      sVar3 = sVar3 + -1;
    }
    sVar4 = sVar3;
    if (sVar3 < 0) {
      sVar4 = -sVar3;
    }
    if (sVar4 < 0x4001) {
      sVar4 = 0x4000 - sVar4;
    }
    else {
      sVar4 = 0;
    }
    if (sVar3 < 0) {
      sVar3 = -(short)((int)sVar4 << 1);
    }
    else {
      sVar3 = (short)((int)sVar4 << 1);
    }
    fVar1 = FLOAT_803e23c0;
    if ((int)sVar4 != 0) {
      local_78 = CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000);
      dVar13 = (double)FUN_802945e0();
      fVar1 = (float)(dVar12 / dVar13);
    }
    dVar12 = -(double)(float)(dVar15 * (double)fVar1 - (double)local_9c[0]);
    DAT_803de1b0[0x69] = DAT_803de1b0 + 7;
    DAT_803de1b0[0x6a] = DAT_803de1b0 + 0x1b;
    DAT_803de1b0[0x6b] = DAT_803de1b0 + 0x2f;
    DAT_803de1b0[0x6d] = FUN_80010f00;
    DAT_803de1b0[0x6e] = &LAB_80010e4c;
    dVar13 = (double)*(float *)(iVar5 + 0xc);
    dVar15 = (double)*(float *)(iVar5 + 0x10);
    dVar16 = (double)*(float *)(iVar5 + 0x14);
    dVar18 = (double)local_a0;
    uVar17 = FUN_80107020(-(double)(float)(dVar14 * (double)fVar1 - (double)local_a4),dVar12,dVar13,
                          dVar15,dVar16,dVar18,(int)sVar3,0x1555,&local_a8);
    iVar5 = local_a8 << 2;
    for (iVar8 = local_a8; iVar8 < local_a8 + 3; iVar8 = iVar8 + 1) {
      *(float *)((int)DAT_803de1b0 + iVar5 + 0x1c) = local_a4;
      *(float *)((int)DAT_803de1b0 + iVar5 + 0x6c) = local_a0;
      *(float *)((int)DAT_803de1b0 + iVar5 + 0xbc) = local_9c[0];
      iVar5 = iVar5 + 4;
    }
    DAT_803de1b0[0x6c] = iVar8;
    DAT_803de1b0[0x68] = 0;
    FUN_80010a8c(uVar17,dVar12,dVar13,dVar15,dVar16,dVar18,in_f7,in_f8,
                 (float *)(DAT_803de1b0 + 0x48),iVar5,iVar8,iVar7,puVar10,iVar6,in_r9,in_r10);
    if (sVar3 < 0) {
      sVar3 = -sVar3;
    }
    if ((0x2000 < sVar3) && (*(char *)(param_3 + 1) != '\0')) {
      FUN_8000bb38(0,0x286);
    }
    (**(code **)(*DAT_803dd6d0 + 0x34))
              ((double)(float)DAT_803de1b0[0x4b],(double)FLOAT_803e23f4,(double)FLOAT_803e23f0,
               (double)FLOAT_803e23c4,(double)FLOAT_803e23f8,DAT_803de1b0 + 0x43);
    DAT_803de1b0[5] = FLOAT_803e23d8;
    DAT_803de1b0[6] = FLOAT_803e23dc;
  }
  FUN_8028688c();
  return;
}

