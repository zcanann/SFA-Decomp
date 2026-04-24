// Function: FUN_802ab1d0
// Entry: 802ab1d0
// Size: 444 bytes

/* WARNING: Removing unreachable block (ram,0x802ab364) */
/* WARNING: Removing unreachable block (ram,0x802ab35c) */
/* WARNING: Removing unreachable block (ram,0x802ab36c) */

void FUN_802ab1d0(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  short sVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  undefined8 in_f29;
  double dVar12;
  undefined8 in_f30;
  double dVar13;
  undefined8 in_f31;
  double dVar14;
  int local_58 [2];
  undefined4 local_50;
  uint uStack76;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar4 = FUN_802860dc();
  if ((*(ushort *)(iVar4 + 0xb0) & 0x1000) == 0) {
    iVar5 = *(int *)(*(int *)(iVar4 + 0xb8) + 0x2d0);
    if (iVar5 == 0) {
      iVar6 = FUN_80036f50(8,local_58);
      iVar9 = 0;
      iVar5 = 0;
      dVar13 = (double)FLOAT_803e7ea4;
      while (iVar9 < local_58[0]) {
        iVar8 = iVar9 + 1;
        iVar10 = *(int *)(iVar6 + iVar9 * 4);
        iVar9 = iVar8;
        if ((((*(short *)(iVar10 + 0x44) == 0x1c) || (*(short *)(iVar10 + 0x44) == 0x2a)) &&
            (*(char *)(iVar10 + 0x36) == -1)) &&
           (fVar1 = *(float *)(iVar10 + 0x18) - *(float *)(iVar4 + 0x18),
           fVar2 = *(float *)(iVar10 + 0x1c) - *(float *)(iVar4 + 0x1c),
           fVar3 = *(float *)(iVar10 + 0x20) - *(float *)(iVar4 + 0x20),
           dVar14 = (double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2),
           dVar14 < (double)FLOAT_803e80e8)) {
          if (dVar14 <= (double)FLOAT_803e7ea4) {
            uStack76 = (int)*(char *)(*(int *)(iVar10 + 0x50) + 0x56) ^ 0x80000000;
            local_50 = 0x43300000;
            dVar12 = (double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e7ec0);
            if (dVar12 <= (double)FLOAT_803e7ea4) {
              dVar12 = (double)FLOAT_803e7ee0;
            }
            dVar14 = (double)FUN_802931a0(dVar14);
            dVar14 = (double)(float)(dVar14 / dVar12);
          }
          sVar7 = FUN_800385e8(iVar4,iVar10,0);
          if (((sVar7 < 0x5555) && (-0x5555 < sVar7)) &&
             ((dVar14 < dVar13 || ((double)FLOAT_803e7ea4 == dVar13)))) {
            iVar5 = iVar10;
            dVar13 = dVar14;
          }
        }
      }
    }
  }
  else {
    iVar5 = 0;
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  __psq_l0(auStack40,uVar11);
  __psq_l1(auStack40,uVar11);
  FUN_80286128(iVar5);
  return;
}

