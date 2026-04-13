// Function: FUN_80181328
// Entry: 80181328
// Size: 1672 bytes

/* WARNING: Removing unreachable block (ram,0x80181990) */
/* WARNING: Removing unreachable block (ram,0x80181988) */
/* WARNING: Removing unreachable block (ram,0x80181980) */
/* WARNING: Removing unreachable block (ram,0x801813a0) */
/* WARNING: Removing unreachable block (ram,0x80181348) */
/* WARNING: Removing unreachable block (ram,0x80181340) */
/* WARNING: Removing unreachable block (ram,0x80181338) */

void FUN_80181328(void)

{
  ushort *puVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  bool bVar7;
  int iVar6;
  byte bVar8;
  undefined4 uVar9;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar10;
  int iVar11;
  float *pfVar12;
  undefined8 extraout_f1;
  double dVar13;
  undefined8 extraout_f1_00;
  double dVar14;
  double dVar15;
  double in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f29;
  double dVar16;
  double in_f30;
  double in_f31;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 local_68 [2];
  undefined8 local_60;
  undefined4 local_58;
  uint uStack_54;
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
  puVar1 = (ushort *)FUN_80286838();
  pfVar12 = *(float **)(puVar1 + 0x5c);
  iVar11 = *(int *)(puVar1 + 0x26);
  iVar2 = FUN_8002bac4();
  iVar10 = *(int *)(puVar1 + 0x26);
  local_68[0] = DAT_803e4580;
  pfVar12[0x47] = pfVar12[0x47] + FLOAT_803dc074;
  bVar8 = *(byte *)(pfVar12 + 0x42);
  if (bVar8 == 2) {
LAB_801814d8:
    if (pfVar12[0x47] <= FLOAT_803e4584) {
      iVar2 = (int)(FLOAT_803e458c * (pfVar12[0x47] / FLOAT_803e4584));
      local_60 = (double)(longlong)iVar2;
      *(char *)(puVar1 + 0x1b) = (char)iVar2;
      goto LAB_80181980;
    }
    *(undefined *)(puVar1 + 0x1b) = 0xff;
    *(undefined *)(pfVar12 + 0x42) = 3;
  }
  else {
    if (bVar8 < 2) {
      if (bVar8 == 0) {
        local_60 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar11 + 0x20));
        fVar3 = FLOAT_803e4584 * (float)(local_60 - DOUBLE_803e45b0);
        if (pfVar12[0x47] < fVar3) goto LAB_80181980;
        pfVar12[0x47] = pfVar12[0x47] - fVar3;
        *(undefined *)(pfVar12 + 0x42) = 1;
      }
      *(undefined4 *)(puVar1 + 6) = *(undefined4 *)(iVar10 + 8);
      *(undefined4 *)(puVar1 + 8) = *(undefined4 *)(iVar10 + 0xc);
      *(undefined4 *)(puVar1 + 10) = *(undefined4 *)(iVar10 + 0x10);
      dVar14 = (double)*(float *)(puVar1 + 8);
      dVar15 = (double)*(float *)(puVar1 + 10);
      (**(code **)(*DAT_803dd71c + 0x14))((double)*(float *)(puVar1 + 6),local_68,1,0xffffffff);
      fVar3 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      (**(code **)(*DAT_803dd71c + 0x54))(fVar3,0);
      fVar4 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      (**(code **)(*DAT_803dd71c + 0x54))(fVar4,0);
      fVar5 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      bVar7 = FUN_800dac0c(extraout_f1,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,pfVar12,fVar3,
                           fVar4,fVar5,in_r7,in_r8,in_r9,in_r10);
      if (bVar7) goto LAB_80181980;
      *(undefined *)(pfVar12 + 0x42) = 2;
      pfVar12[0x45] = FLOAT_803e4588;
      goto LAB_801814d8;
    }
    if (3 < bVar8) goto LAB_80181980;
  }
  uVar9 = 0;
  iVar6 = FUN_80036974((int)puVar1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
  if (iVar6 == 0) {
    bVar8 = FUN_80296ba8(iVar2);
    if (bVar8 != 0) {
      dVar14 = FUN_80021730((float *)(iVar2 + 0xc),(float *)(puVar1 + 6));
      in_f4 = DOUBLE_803e45b0;
      fVar3 = FLOAT_803e4590;
      uStack_54 = (uint)*(byte *)(iVar11 + 0x23);
      local_60 = (double)CONCAT44(0x43300000,uStack_54);
      local_58 = 0x43300000;
      if (dVar14 < (double)((float)(local_60 - DOUBLE_803e45b0) *
                           (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e45b0))) {
        uStack_54 = (uint)*(byte *)(iVar10 + 0x19);
        local_58 = 0x43300000;
        pfVar12[0x45] =
             pfVar12[0x45] +
             (FLOAT_803e4590 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e45b0) *
             FLOAT_803dc074) / FLOAT_803e4594;
        if (fVar3 * pfVar12[0x44] < pfVar12[0x45]) {
          pfVar12[0x45] = fVar3 * pfVar12[0x44];
        }
        goto LAB_80181668;
      }
    }
    uStack_54 = FUN_80022264(-(uint)*(byte *)(iVar10 + 0x19),(uint)*(byte *)(iVar10 + 0x19) << 1);
    uStack_54 = uStack_54 ^ 0x80000000;
    local_58 = 0x43300000;
    pfVar12[0x45] =
         pfVar12[0x45] +
         ((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e45b8) * FLOAT_803dc074) /
         FLOAT_803e4594;
    if (FLOAT_803e4588 <= pfVar12[0x45]) {
      if (pfVar12[0x44] < pfVar12[0x45]) {
        pfVar12[0x45] = pfVar12[0x44];
      }
    }
    else {
      pfVar12[0x45] = FLOAT_803e4588;
    }
  }
  else {
    pfVar12[0x45] = FLOAT_803e4590 * pfVar12[0x44];
  }
LAB_80181668:
  dVar15 = (double)pfVar12[0x45];
  dVar14 = (double)pfVar12[0x44];
  if ((double)(float)(dVar14 * (double)FLOAT_803e4598) <= dVar15) {
    if (dVar15 <= (double)(float)((double)(float)((double)FLOAT_803e45a4 * dVar14) *
                                 (double)FLOAT_803e4598)) {
      if ((puVar1[0x50] == 1) && (FLOAT_803e45a8 < pfVar12[0x43])) {
        FUN_8003042c((double)FLOAT_803e4588,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,puVar1,0,0,
                     uVar9,in_r7,in_r8,in_r9,in_r10);
        FUN_8002f66c((int)puVar1,0x3c);
        pfVar12[0x43] = FLOAT_803e4588;
      }
      pfVar12[0x46] = (FLOAT_803e45ac * pfVar12[0x45]) / pfVar12[0x44];
    }
    else {
      if ((puVar1[0x50] == 0) && (FLOAT_803e45a8 < pfVar12[0x43])) {
        FUN_8003042c((double)FLOAT_803e4588,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,puVar1,1,0,
                     uVar9,in_r7,in_r8,in_r9,in_r10);
        FUN_8002f66c((int)puVar1,0x3c);
        pfVar12[0x43] = FLOAT_803e4588;
      }
      pfVar12[0x46] = FLOAT_803e45ac;
    }
  }
  else {
    if ((puVar1[0x50] == 0) && (FLOAT_803e459c < pfVar12[0x43])) {
      FUN_8003042c((double)FLOAT_803e4588,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,puVar1,1,0,
                   uVar9,in_r7,in_r8,in_r9,in_r10);
      FUN_8002f66c((int)puVar1,0x3c);
      pfVar12[0x43] = FLOAT_803e4588;
    }
    pfVar12[0x46] = FLOAT_803e45a0;
  }
  if (FLOAT_803e4588 != pfVar12[0x45]) {
    fVar3 = pfVar12[0x45] * FLOAT_803dc074;
    dVar16 = (double)(fVar3 * fVar3);
    dVar13 = FUN_80021730(pfVar12 + 0x1a,(float *)(puVar1 + 6));
    for (iVar2 = 0; (dVar13 < dVar16 && (iVar2 < 5)); iVar2 = iVar2 + 1) {
      FUN_80010340((double)FLOAT_803e4590,pfVar12);
      dVar13 = FUN_80021730(pfVar12 + 0x1a,(float *)(puVar1 + 6));
    }
    if (pfVar12[4] != 0.0) {
      iVar2 = *DAT_803dd71c;
      (**(code **)(iVar2 + 0x54))(pfVar12[0x29],0);
      fVar3 = (float)(**(code **)(*DAT_803dd71c + 0x1c))();
      iVar2 = FUN_800da4c8(extraout_f1_00,dVar14,dVar15,in_f4,in_f5,in_f6,in_f7,in_f8,pfVar12,fVar3,
                           iVar2,uVar9,in_r7,in_r8,in_r9,in_r10);
      if (iVar2 != 0) {
        *(undefined *)(pfVar12 + 0x42) = 0;
        pfVar12[0x47] = FLOAT_803e4588;
        *(undefined *)(puVar1 + 0x1b) = 0;
        goto LAB_80181980;
      }
    }
    dVar16 = (double)(pfVar12[0x1a] - *(float *)(puVar1 + 6));
    uStack_54 = (uint)*(byte *)(iVar11 + 0x22);
    local_58 = 0x43300000;
    dVar13 = (double)((pfVar12[0x1b] +
                      (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e45b0)) -
                     *(float *)(puVar1 + 8));
    dVar15 = (double)(pfVar12[0x1c] - *(float *)(puVar1 + 10));
    dVar14 = FUN_80293900((double)(float)(dVar15 * dVar15 +
                                         (double)(float)(dVar16 * dVar16 +
                                                        (double)(float)(dVar13 * dVar13))));
    *(float *)(puVar1 + 6) = (float)(dVar16 / dVar14) * pfVar12[0x45] + *(float *)(puVar1 + 6);
    *(float *)(puVar1 + 8) = (float)(dVar13 / dVar14) * pfVar12[0x45] + *(float *)(puVar1 + 8);
    *(float *)(puVar1 + 10) = (float)(dVar15 / dVar14) * pfVar12[0x45] + *(float *)(puVar1 + 10);
    iVar2 = FUN_80021884();
    iVar10 = (int)(short)(ushort)iVar2 - (uint)*puVar1;
    if (0x8000 < iVar10) {
      iVar10 = iVar10 + -0xffff;
    }
    if (iVar10 < -0x8000) {
      iVar10 = iVar10 + 0xffff;
    }
    if (iVar10 < 0x181) {
      if (iVar10 < -0x180) {
        *puVar1 = *puVar1 - 0x180;
      }
      else {
        *puVar1 = (ushort)iVar2;
      }
    }
    else {
      *puVar1 = *puVar1 + 0x180;
    }
  }
  FUN_8002fb40((double)pfVar12[0x46],(double)FLOAT_803dc074);
  pfVar12[0x43] = pfVar12[0x43] + FLOAT_803dc074;
LAB_80181980:
  FUN_80286884();
  return;
}

