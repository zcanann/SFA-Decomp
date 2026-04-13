// Function: FUN_802a3078
// Entry: 802a3078
// Size: 1396 bytes

/* WARNING: Removing unreachable block (ram,0x802a35cc) */
/* WARNING: Removing unreachable block (ram,0x802a3088) */

void FUN_802a3078(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  ushort uVar5;
  undefined2 *puVar4;
  uint uVar6;
  uint uVar7;
  undefined2 uVar8;
  uint *puVar9;
  int iVar10;
  int iVar11;
  undefined4 in_r10;
  short *psVar12;
  double extraout_f1;
  double in_f31;
  double dVar13;
  double in_ps31_1;
  undefined8 uVar14;
  undefined4 local_68;
  undefined4 local_64;
  short asStack_60 [4];
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float fStack_48;
  float local_44;
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar14 = FUN_80286838();
  uVar6 = (uint)((ulonglong)uVar14 >> 0x20);
  puVar9 = (uint *)uVar14;
  iVar10 = *(int *)(uVar6 + 0xb8);
  *(uint *)(iVar10 + 0x360) = *(uint *)(iVar10 + 0x360) & 0xfffffffd;
  *(uint *)(iVar10 + 0x360) = *(uint *)(iVar10 + 0x360) | 0x2000;
  puVar9[1] = puVar9[1] | 0x100000;
  fVar1 = FLOAT_803e8b3c;
  puVar9[0xa0] = (uint)FLOAT_803e8b3c;
  puVar9[0xa1] = (uint)fVar1;
  *puVar9 = *puVar9 | 0x200000;
  *(float *)(uVar6 + 0x24) = fVar1;
  *(float *)(uVar6 + 0x2c) = fVar1;
  puVar9[1] = puVar9[1] | 0x8000000;
  *(float *)(uVar6 + 0x28) = fVar1;
  uVar3 = 1U - (int)*(char *)(iVar10 + 0x4e4) | (int)*(char *)(iVar10 + 0x4e4) - 1U;
  if ((int)uVar3 < 0) {
    puVar9[0xa8] = (uint)FLOAT_803e8b90;
  }
  else {
    puVar9[0xa8] = (uint)FLOAT_803e8cbc;
  }
  dVar13 = extraout_f1;
  if ((puVar9[0xc5] & 0x80) != 0) {
    if (*(short *)(iVar10 + 0x81a) == 0) {
      uVar5 = 0x398;
    }
    else {
      uVar5 = 0x1d;
    }
    FUN_8000bb38(uVar6,uVar5);
  }
  if ((puVar9[0xc5] & 1) != 0) {
    if (*(char *)(iVar10 + 0x546) == '\x04') {
      FUN_8000bb38(uVar6,0x33a);
    }
    else {
      FUN_8000bb38(uVar6,0x11);
    }
  }
  if (*(char *)((int)puVar9 + 0x27a) == '\0') {
    if (FLOAT_803e8c8c < *(float *)(uVar6 + 0x98)) {
      FUN_8002eeb8((double)(float)puVar9[0xa8],dVar13,uVar6,0);
      puVar9[0xc2] = (uint)FUN_802a0730;
      goto LAB_802a35cc;
    }
  }
  else {
    FUN_80035f84(uVar6);
    if ((DAT_803df0cc != 0) && ((*(byte *)(iVar10 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar10 + 0x8b4) = 1;
      *(byte *)(iVar10 + 0x3f4) = *(byte *)(iVar10 + 0x3f4) & 0xf7 | 8;
    }
    local_54 = FLOAT_803e8b3c;
    puVar9[0xa0] = (uint)FLOAT_803e8b3c;
    puVar9[0xa1] = (uint)local_54;
    *(undefined2 *)(puVar9 + 0x9e) = 0xe;
    *(code **)(iVar10 + 0x898) = FUN_802a0730;
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
    uVar7 = FUN_80021884();
    iVar11 = (uVar7 & 0xffff) - (int)*(short *)(iVar10 + 0x478);
    if (0x8000 < iVar11) {
      iVar11 = iVar11 + -0xffff;
    }
    if (iVar11 < -0x8000) {
      iVar11 = iVar11 + 0xffff;
    }
    *(short *)(iVar10 + 0x478) = *(short *)(iVar10 + 0x478) + (short)iVar11;
    *(undefined2 *)(iVar10 + 0x484) = *(undefined2 *)(iVar10 + 0x478);
    *(undefined4 *)(iVar10 + 0x504) = *(undefined4 *)(uVar6 + 0xc);
    *(undefined4 *)(iVar10 + 0x508) = *(undefined4 *)(uVar6 + 0x14);
    *(undefined4 *)(uVar6 + 0xc) = *(undefined4 *)(iVar10 + 0x52c);
    *(undefined4 *)(uVar6 + 0x14) = *(undefined4 *)(iVar10 + 0x534);
    if (*(float *)(iVar10 + 0x4fc) < FLOAT_803e8b3c) {
      iVar11 = 4;
    }
    else {
      iVar11 = 0;
    }
    if ((int)uVar3 < 0) {
      puVar4 = &DAT_80333be8;
    }
    else {
      puVar4 = &DAT_80333bd8;
    }
    psVar12 = puVar4 + iVar11;
    uVar8 = FUN_802a7940((double)FLOAT_803e8b3c,(double)(float)puVar9[0xa8],param_3,param_4,param_5,
                         param_6,param_7,param_8,uVar6,(int)*psVar12,(int)psVar12[2],
                         (float *)(iVar10 + 0x538),&local_58,2,9,in_r10);
    *(undefined2 *)(iVar10 + 0x544) = uVar8;
    uVar7 = 0x34;
    if ((int)uVar3 < 0) {
      uVar7 = 0x74;
    }
    FUN_802a7940((double)FLOAT_803e8b3c,(double)(float)puVar9[0xa8],param_3,param_4,param_5,param_6,
                 param_7,param_8,uVar6,(int)*psVar12,(int)(short)puVar4[iVar11 + 1],
                 (float *)(iVar10 + 0x538),(float *)(iVar10 + 0x51c),0,uVar7,in_r10);
    FUN_802a7940((double)FLOAT_803e8b3c,(double)(float)puVar9[0xa8],param_3,param_4,param_5,param_6,
                 param_7,param_8,uVar6,(int)psVar12[2],(int)(short)puVar4[iVar11 + 3],
                 (float *)(iVar10 + 0x538),(float *)(iVar10 + 0x51c),0,0x1a,in_r10);
    uStack_34 = (int)*(char *)(iVar10 + 0x4e4) ^ 0x80000000;
    local_38 = 0x43300000;
    *(float *)(iVar10 + 0x4f4) =
         *(float *)(iVar10 + 0x4f0) *
         (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e8b58) +
         *(float *)(iVar10 + 0x4ec);
    *(undefined4 *)(iVar10 + 0x4f8) = *(undefined4 *)(uVar6 + 0x10);
    FUN_80027ec4((double)FLOAT_803e8b78,(double)*(float *)(uVar6 + 8),
                 *(int **)(*(int *)(uVar6 + 0x7c) + *(char *)(uVar6 + 0xad) * 4),0,0,&fStack_48,
                 asStack_60);
    FLOAT_803df0b8 = *(float *)(uVar6 + 0x10) + local_44;
    FLOAT_803df0bc = *(float *)(iVar10 + 0x4f4) + DAT_803dbbec;
    local_68 = *(undefined4 *)(iVar10 + 0x4e8);
    local_64 = *(undefined4 *)(iVar10 + 0x4ec);
    if ((*(char *)(iVar10 + 0x8c8) != 'H') && (*(char *)(iVar10 + 0x8c8) != 'G')) {
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x4b,1,1,8,&local_68,0,0);
    }
  }
  if (FLOAT_803e8bb0 <= *(float *)(uVar6 + 0x98)) {
    fVar1 = FLOAT_803e8cc0 * (FLOAT_803e8cc4 * *(float *)(uVar6 + 0x98) - FLOAT_803e8bb0);
    fVar2 = FLOAT_803e8b3c;
    if ((FLOAT_803e8b3c <= fVar1) && (fVar2 = fVar1, FLOAT_803e8b78 < fVar1)) {
      fVar2 = FLOAT_803e8b78;
    }
    *(float *)(uVar6 + 0x10) =
         fVar2 * (FLOAT_803df0bc - FLOAT_803df0b8) + *(float *)(iVar10 + 0x4f8);
  }
  FUN_8002f624(uVar6,0,2,0);
  FUN_8002f624(uVar6,1,2,0);
  FUN_8002f624(uVar6,1,0,*(undefined2 *)(iVar10 + 0x544));
  FUN_8002eeb8((double)(float)puVar9[0xa8],dVar13,uVar6,0);
  (**(code **)(*DAT_803dd6d0 + 0x2c))
            ((double)*(float *)(uVar6 + 0xc),
             (double)(*(float *)(uVar6 + 0x98) *
                      (*(float *)(iVar10 + 0x4f4) - *(float *)(uVar6 + 0x10)) +
                     *(float *)(uVar6 + 0x10)),(double)*(float *)(uVar6 + 0x14));
  FUN_802abd04(uVar6,iVar10,5);
LAB_802a35cc:
  FUN_80286884();
  return;
}

