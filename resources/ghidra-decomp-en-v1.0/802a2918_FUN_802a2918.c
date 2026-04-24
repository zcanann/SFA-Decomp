// Function: FUN_802a2918
// Entry: 802a2918
// Size: 1396 bytes

/* WARNING: Removing unreachable block (ram,0x802a2e6c) */

void FUN_802a2918(void)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined2 *puVar5;
  int iVar6;
  uint uVar7;
  undefined2 uVar8;
  uint *puVar9;
  int iVar10;
  int iVar11;
  short *psVar12;
  undefined4 uVar13;
  undefined8 extraout_f1;
  undefined8 in_f31;
  undefined8 uVar14;
  undefined4 local_68;
  undefined4 local_64;
  undefined auStack96 [8];
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  undefined auStack72 [4];
  float local_44;
  undefined4 local_38;
  uint uStack52;
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar14 = FUN_802860d4();
  iVar6 = (int)((ulonglong)uVar14 >> 0x20);
  puVar9 = (uint *)uVar14;
  iVar10 = *(int *)(iVar6 + 0xb8);
  *(uint *)(iVar10 + 0x360) = *(uint *)(iVar10 + 0x360) & 0xfffffffd;
  *(uint *)(iVar10 + 0x360) = *(uint *)(iVar10 + 0x360) | 0x2000;
  puVar9[1] = puVar9[1] | 0x100000;
  fVar1 = FLOAT_803e7ea4;
  puVar9[0xa0] = (uint)FLOAT_803e7ea4;
  puVar9[0xa1] = (uint)fVar1;
  *puVar9 = *puVar9 | 0x200000;
  *(float *)(iVar6 + 0x24) = fVar1;
  *(float *)(iVar6 + 0x2c) = fVar1;
  puVar9[1] = puVar9[1] | 0x8000000;
  *(float *)(iVar6 + 0x28) = fVar1;
  uVar3 = 1U - (int)*(char *)(iVar10 + 0x4e4) | (int)*(char *)(iVar10 + 0x4e4) - 1U;
  if ((int)uVar3 < 0) {
    puVar9[0xa8] = (uint)FLOAT_803e7ef8;
  }
  else {
    puVar9[0xa8] = (uint)FLOAT_803e8024;
  }
  uVar14 = extraout_f1;
  if ((puVar9[0xc5] & 0x80) != 0) {
    if (*(short *)(iVar10 + 0x81a) == 0) {
      uVar4 = 0x398;
    }
    else {
      uVar4 = 0x1d;
    }
    FUN_8000bb18(iVar6,uVar4);
  }
  if ((puVar9[0xc5] & 1) != 0) {
    if (*(char *)(iVar10 + 0x546) == '\x04') {
      FUN_8000bb18(iVar6,0x33a);
    }
    else {
      FUN_8000bb18(iVar6,0x11);
    }
  }
  if (*(char *)((int)puVar9 + 0x27a) == '\0') {
    if (FLOAT_803e7ff4 < *(float *)(iVar6 + 0x98)) {
      FUN_8002edc0((double)(float)puVar9[0xa8],uVar14,iVar6,0);
      puVar9[0xc2] = (uint)FUN_8029ffd0;
      uVar4 = 0x10;
      goto LAB_802a2e6c;
    }
  }
  else {
    FUN_80035e8c(iVar6);
    if ((DAT_803de44c != 0) && ((*(byte *)(iVar10 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar10 + 0x8b4) = 1;
      *(byte *)(iVar10 + 0x3f4) = *(byte *)(iVar10 + 0x3f4) & 0xf7 | 8;
    }
    local_54 = FLOAT_803e7ea4;
    puVar9[0xa0] = (uint)FLOAT_803e7ea4;
    puVar9[0xa1] = (uint)local_54;
    *(undefined2 *)(puVar9 + 0x9e) = 0xe;
    *(code **)(iVar10 + 0x898) = FUN_8029ffd0;
    if ((int)uVar3 < 0) {
      local_58 = -*(float *)(iVar10 + 0x50c);
      local_50 = -*(float *)(iVar10 + 0x514);
      local_4c = -*(float *)(iVar10 + 0x518);
    }
    else {
      local_58 = *(float *)(iVar10 + 0x50c);
      local_50 = *(float *)(iVar10 + 0x514);
      local_4c = *(float *)(iVar10 + 0x518);
    }
    uVar7 = FUN_800217c0((double)local_58,(double)local_50);
    iVar11 = (uVar7 & 0xffff) - (int)*(short *)(iVar10 + 0x478);
    if (0x8000 < iVar11) {
      iVar11 = iVar11 + -0xffff;
    }
    if (iVar11 < -0x8000) {
      iVar11 = iVar11 + 0xffff;
    }
    *(short *)(iVar10 + 0x478) = *(short *)(iVar10 + 0x478) + (short)iVar11;
    *(undefined2 *)(iVar10 + 0x484) = *(undefined2 *)(iVar10 + 0x478);
    *(undefined4 *)(iVar10 + 0x504) = *(undefined4 *)(iVar6 + 0xc);
    *(undefined4 *)(iVar10 + 0x508) = *(undefined4 *)(iVar6 + 0x14);
    *(undefined4 *)(iVar6 + 0xc) = *(undefined4 *)(iVar10 + 0x52c);
    *(undefined4 *)(iVar6 + 0x14) = *(undefined4 *)(iVar10 + 0x534);
    if (*(float *)(iVar10 + 0x4fc) < FLOAT_803e7ea4) {
      iVar11 = 4;
    }
    else {
      iVar11 = 0;
    }
    if ((int)uVar3 < 0) {
      puVar5 = &DAT_80332f88;
    }
    else {
      puVar5 = &DAT_80332f78;
    }
    psVar12 = puVar5 + iVar11;
    uVar8 = FUN_802a71e0((double)FLOAT_803e7ea4,(double)(float)puVar9[0xa8],iVar6,(int)*psVar12,
                         (int)psVar12[2],iVar10 + 0x538,&local_58,2,9);
    *(undefined2 *)(iVar10 + 0x544) = uVar8;
    uVar4 = 0x34;
    if ((int)uVar3 < 0) {
      uVar4 = 0x74;
    }
    FUN_802a71e0((double)FLOAT_803e7ea4,(double)(float)puVar9[0xa8],iVar6,(int)*psVar12,
                 (int)(short)puVar5[iVar11 + 1],iVar10 + 0x538,iVar10 + 0x51c,0,uVar4);
    FUN_802a71e0((double)FLOAT_803e7ea4,(double)(float)puVar9[0xa8],iVar6,(int)psVar12[2],
                 (int)(short)puVar5[iVar11 + 3],iVar10 + 0x538,iVar10 + 0x51c,0,0x1a);
    uStack52 = (int)*(char *)(iVar10 + 0x4e4) ^ 0x80000000;
    local_38 = 0x43300000;
    *(float *)(iVar10 + 0x4f4) =
         *(float *)(iVar10 + 0x4f0) *
         (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e7ec0) +
         *(float *)(iVar10 + 0x4ec);
    *(undefined4 *)(iVar10 + 0x4f8) = *(undefined4 *)(iVar6 + 0x10);
    FUN_80027e00((double)FLOAT_803e7ee0,(double)*(float *)(iVar6 + 8),
                 *(undefined4 *)(*(int *)(iVar6 + 0x7c) + *(char *)(iVar6 + 0xad) * 4),0,0,auStack72
                 ,auStack96);
    FLOAT_803de438 = *(float *)(iVar6 + 0x10) + local_44;
    FLOAT_803de43c = *(float *)(iVar10 + 0x4f4) + DAT_803daf8c;
    local_68 = *(undefined4 *)(iVar10 + 0x4e8);
    local_64 = *(undefined4 *)(iVar10 + 0x4ec);
    if ((*(char *)(iVar10 + 0x8c8) != 'H') && (*(char *)(iVar10 + 0x8c8) != 'G')) {
      (**(code **)(*DAT_803dca50 + 0x1c))(0x4b,1,1,8,&local_68,0,0);
    }
  }
  if (FLOAT_803e7f18 <= *(float *)(iVar6 + 0x98)) {
    fVar1 = FLOAT_803e8028 * (FLOAT_803e802c * *(float *)(iVar6 + 0x98) - FLOAT_803e7f18);
    fVar2 = FLOAT_803e7ea4;
    if ((FLOAT_803e7ea4 <= fVar1) && (fVar2 = fVar1, FLOAT_803e7ee0 < fVar1)) {
      fVar2 = FLOAT_803e7ee0;
    }
    *(float *)(iVar6 + 0x10) =
         fVar2 * (FLOAT_803de43c - FLOAT_803de438) + *(float *)(iVar10 + 0x4f8);
  }
  FUN_8002f52c(iVar6,0,2,0);
  FUN_8002f52c(iVar6,1,2,0);
  FUN_8002f52c(iVar6,1,0,(int)*(short *)(iVar10 + 0x544));
  FUN_8002edc0((double)(float)puVar9[0xa8],uVar14,iVar6,0);
  (**(code **)(*DAT_803dca50 + 0x2c))
            ((double)*(float *)(iVar6 + 0xc),
             (double)(*(float *)(iVar6 + 0x98) *
                      (*(float *)(iVar10 + 0x4f4) - *(float *)(iVar6 + 0x10)) +
                     *(float *)(iVar6 + 0x10)),(double)*(float *)(iVar6 + 0x14));
  FUN_802ab5a4(iVar6,iVar10,5);
  uVar4 = 0;
LAB_802a2e6c:
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  FUN_80286120(uVar4);
  return;
}

