// Function: FUN_8014a304
// Entry: 8014a304
// Size: 760 bytes

/* WARNING: Removing unreachable block (ram,0x8014a5d4) */
/* WARNING: Removing unreachable block (ram,0x8014a5c4) */
/* WARNING: Removing unreachable block (ram,0x8014a5b4) */
/* WARNING: Removing unreachable block (ram,0x8014a5bc) */
/* WARNING: Removing unreachable block (ram,0x8014a5cc) */
/* WARNING: Removing unreachable block (ram,0x8014a5dc) */

void FUN_8014a304(void)

{
  short sVar1;
  short sVar2;
  short *psVar3;
  char cVar5;
  int iVar4;
  int iVar6;
  ushort uVar7;
  undefined4 uVar8;
  double extraout_f1;
  double dVar9;
  undefined8 in_f26;
  double dVar10;
  undefined8 in_f27;
  double dVar11;
  undefined8 in_f28;
  double dVar12;
  undefined8 in_f29;
  double dVar13;
  undefined8 in_f30;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  undefined8 uVar16;
  char local_110 [4];
  undefined auStack268 [8];
  undefined auStack260 [8];
  undefined auStack252 [12];
  uint local_f0 [4];
  float local_e0;
  float local_dc;
  float local_d8;
  undefined auStack212 [84];
  undefined4 local_80;
  uint uStack124;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  uVar16 = FUN_802860d8();
  psVar3 = (short *)((ulonglong)uVar16 >> 0x20);
  iVar6 = (int)uVar16;
  local_f0[0] = DAT_802c21f0;
  local_f0[1] = DAT_802c21f4;
  local_f0[2] = DAT_802c21f8;
  local_f0[3] = DAT_802c21fc;
  local_e0 = *(float *)(psVar3 + 6);
  local_dc = FLOAT_803e25a0 + *(float *)(psVar3 + 8);
  local_d8 = *(float *)(psVar3 + 10);
  dVar15 = extraout_f1;
  FUN_80012d00(&local_e0,auStack268);
  if (*(short **)(psVar3 + 0x18) == (short *)0x0) {
    sVar2 = *psVar3;
  }
  else {
    sVar2 = *psVar3 + **(short **)(psVar3 + 0x18);
  }
  dVar11 = (double)FLOAT_803e25b4;
  dVar13 = (double)FLOAT_803e25b8;
  dVar14 = (double)FLOAT_803e25b0;
  dVar12 = DOUBLE_803e2580;
  for (uVar7 = 0; uVar7 < 4; uVar7 = uVar7 + 1) {
    uStack124 = (int)sVar2 + (uint)uVar7 * 0x4000 ^ 0x80000000;
    local_80 = 0x43300000;
    dVar10 = (double)(float)((double)(float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000,
                                                                                       uStack124) -
                                                                     dVar12)) / dVar13);
    dVar9 = (double)FUN_80293e80(dVar10);
    local_e0 = -(float)(dVar15 * dVar9 - (double)*(float *)(psVar3 + 0xc));
    local_dc = *(float *)(psVar3 + 0xe);
    dVar9 = (double)FUN_80294204(dVar10);
    local_d8 = -(float)(dVar15 * dVar9 - (double)*(float *)(psVar3 + 0x10));
    sVar1 = psVar3[0x23];
    if (((((sVar1 != 0x613) && (sVar1 != 0x642)) && (sVar1 != 0x3fe)) &&
        ((sVar1 != 0x7c6 && (sVar1 != 0x7c8)))) && ((sVar1 != 0x251 && (sVar1 != 0x851)))) {
      local_dc = local_dc + FLOAT_803e25a0;
    }
    FUN_80012d00(&local_e0,auStack260);
    FUN_80247754(psVar3 + 0xc,&local_e0,auStack252);
    dVar9 = (double)FUN_802477f0(auStack252);
    if (dVar14 <= dVar9) {
      cVar5 = '\0';
    }
    else if (*(int *)(psVar3 + 0x18) == 0) {
      cVar5 = FUN_800128dc(auStack260,auStack268,0,local_110,0);
      if (local_110[0] == '\x01') {
        cVar5 = '\x01';
      }
    }
    else {
      cVar5 = '\x01';
    }
    if ((cVar5 != '\0') && ((*(uint *)(iVar6 + 0x2e4) & 8) != 0)) {
      iVar4 = FUN_800640cc((double)FLOAT_803e256c,psVar3 + 0xc,&local_e0,0,auStack212,psVar3,
                           *(undefined *)(iVar6 + 0x261),0xffffffff,0,0);
      if (iVar4 != 0) {
        cVar5 = '\0';
      }
    }
    if (cVar5 == '\0') {
      *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) & ~local_f0[uVar7];
    }
    else {
      *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) | local_f0[uVar7];
    }
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  __psq_l0(auStack72,uVar8);
  __psq_l1(auStack72,uVar8);
  __psq_l0(auStack88,uVar8);
  __psq_l1(auStack88,uVar8);
  FUN_80286124();
  return;
}

