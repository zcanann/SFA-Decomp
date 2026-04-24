// Function: FUN_80059cb0
// Entry: 80059cb0
// Size: 560 bytes

/* WARNING: Removing unreachable block (ram,0x80059eb8) */
/* WARNING: Removing unreachable block (ram,0x80059ec0) */

void FUN_80059cb0(void)

{
  bool bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  short *psVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar3 = FUN_802860dc();
  bVar1 = false;
  while (iVar4 = FUN_800430a4(), iVar4 != 0) {
    FUN_80014f40();
    FUN_800202cc();
    if (bVar1) {
      FUN_8004a868();
    }
    FUN_800481d4();
    FUN_80015624();
    if (bVar1) {
      FUN_800234ec(0);
      FUN_80019c24();
      FUN_8004a43c(1,0);
    }
    if (DAT_803dc950 != '\0') {
      bVar1 = true;
    }
  }
  iVar4 = 0;
  for (piVar5 = &DAT_8038224c; (iVar4 < DAT_803dcdec && (*piVar5 != 0)); piVar5 = piVar5 + 2) {
    iVar4 = iVar4 + 1;
  }
  if (iVar4 == DAT_803dcdec) {
    DAT_803dcdec = DAT_803dcdec + '\x01';
  }
  iVar6 = FUN_80059ee0(iVar3,0);
  (&DAT_8038224c)[iVar4 * 2] = iVar6;
  (&DAT_80386468)[iVar3] = iVar6;
  (&DAT_80382250)[iVar4 * 4] = (short)iVar3;
  DAT_803dcea0 = (&DAT_8038224c)[iVar4 * 2];
  psVar8 = (short *)(DAT_8038223c + iVar3 * 10);
  *(undefined *)(DAT_803dcea0 + 0x19) = *(undefined *)(DAT_80382244 + iVar3);
  dVar12 = DOUBLE_803debc0;
  fVar2 = FLOAT_803debb4;
  *(float *)(DAT_803dcea0 + 0x24) =
       FLOAT_803debb4 *
       (float)((double)CONCAT44(0x43300000,
                                (int)*psVar8 + (int)*(short *)(DAT_803dcea0 + 4) ^ 0x80000000) -
              DOUBLE_803debc0);
  *(float *)(DAT_803dcea0 + 0x28) =
       fVar2 * (float)((double)CONCAT44(0x43300000,
                                        (int)psVar8[2] + (int)*(short *)(DAT_803dcea0 + 6) ^
                                        0x80000000) - dVar12);
  iVar6 = DAT_803dcea0;
  dVar12 = (double)*(float *)(DAT_803dcea0 + 0x28);
  dVar13 = (double)*(float *)(DAT_803dcea0 + 0x24);
  if (DAT_803dcea0 != 0) {
    iVar9 = *(int *)(DAT_803dcea0 + 0x20);
    for (iVar10 = 0; iVar10 < (int)(uint)*(ushort *)(iVar6 + 8); iVar10 = iVar10 + iVar7) {
      iVar7 = FUN_800e8100(iVar9);
      if (iVar7 == 0) {
        *(float *)(iVar9 + 8) = (float)((double)*(float *)(iVar9 + 8) + dVar13);
        *(float *)(iVar9 + 0x10) = (float)((double)*(float *)(iVar9 + 0x10) + dVar12);
      }
      iVar7 = (uint)*(byte *)(iVar9 + 2) * 4;
      iVar9 = iVar9 + iVar7;
    }
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  DAT_803db620 = iVar3;
  FUN_80286128(iVar4);
  return;
}

