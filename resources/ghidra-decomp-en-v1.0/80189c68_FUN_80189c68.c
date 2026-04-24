// Function: FUN_80189c68
// Entry: 80189c68
// Size: 732 bytes

/* WARNING: Removing unreachable block (ram,0x80189f1c) */
/* WARNING: Removing unreachable block (ram,0x80189f0c) */
/* WARNING: Removing unreachable block (ram,0x80189f04) */
/* WARNING: Removing unreachable block (ram,0x80189f14) */
/* WARNING: Removing unreachable block (ram,0x80189f24) */

void FUN_80189c68(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  char cVar7;
  short *psVar5;
  uint uVar6;
  undefined4 *puVar8;
  int iVar9;
  undefined4 uVar10;
  double dVar11;
  undefined8 in_f27;
  double dVar12;
  undefined8 in_f28;
  double dVar13;
  undefined8 in_f29;
  double dVar14;
  undefined8 in_f30;
  double dVar15;
  undefined8 in_f31;
  double dVar16;
  undefined2 local_98;
  undefined2 local_96;
  undefined2 local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
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
  iVar1 = FUN_802860d0();
  iVar9 = *(int *)(iVar1 + 0x4c);
  iVar2 = FUN_8002b9ec();
  iVar3 = FUN_8002b9ac();
  puVar8 = *(undefined4 **)(iVar1 + 0xb8);
  iVar4 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(iVar9 + 0x14));
  if ((iVar4 != 0) && (cVar7 = FUN_8002e04c(), cVar7 != '\0')) {
    uStack124 = (uint)*(byte *)(iVar9 + 0x20);
    local_80 = 0x43300000;
    (**(code **)(*DAT_803dcaac + 100))
              ((double)(FLOAT_803e3bd8 *
                       (float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e3be8)),
               *(undefined4 *)(iVar9 + 0x14));
    if (iVar3 != 0) {
      FUN_80138ef8(iVar3);
    }
    dVar16 = (double)FLOAT_803e3bdc;
    dVar13 = (double)FLOAT_803e3bc4;
    dVar14 = (double)FLOAT_803e3bbc;
    dVar15 = (double)FLOAT_803e3be0;
    dVar12 = DOUBLE_803e3bd0;
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(iVar9 + 0x1f); iVar3 = iVar3 + 1) {
      iVar4 = FUN_8002bdf4(0x24,(int)*(short *)(&DAT_803dbde0 + (uint)*(byte *)(iVar9 + 0x1e) * 2));
      *(undefined4 *)(iVar4 + 8) = *puVar8;
      *(undefined4 *)(iVar4 + 0xc) = *(undefined4 *)(iVar1 + 0x10);
      *(undefined4 *)(iVar4 + 0x10) = puVar8[1];
      *(undefined2 *)(iVar4 + 0x1a) = 400;
      psVar5 = (short *)FUN_8002df90(iVar4,5,(int)*(char *)(iVar1 + 0xac),0xffffffff,
                                     *(undefined4 *)(iVar1 + 0x30));
      *(float *)(psVar5 + 0x12) = *(float *)(iVar1 + 0xc) - *(float *)(iVar2 + 0xc);
      *(float *)(psVar5 + 0x16) = *(float *)(iVar1 + 0x14) - *(float *)(iVar2 + 0x14);
      if ((double)(*(float *)(psVar5 + 0x12) * *(float *)(psVar5 + 0x12) +
                  *(float *)(psVar5 + 0x16) * *(float *)(psVar5 + 0x16)) != dVar16) {
        dVar11 = (double)FUN_802931a0();
        *(float *)(psVar5 + 0x12) = (float)((double)*(float *)(psVar5 + 0x12) / dVar11);
        *(float *)(psVar5 + 0x16) = (float)((double)*(float *)(psVar5 + 0x16) / dVar11);
      }
      uStack124 = FUN_800221a0(0,0x19);
      uStack124 = uStack124 ^ 0x80000000;
      local_80 = 0x43300000;
      *(float *)(psVar5 + 0x12) =
           *(float *)(psVar5 + 0x12) *
           -(float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uStack124) - dVar12) -
                   dVar14);
      uStack116 = FUN_800221a0(0,0x19);
      uStack116 = uStack116 ^ 0x80000000;
      local_78 = 0x43300000;
      *(float *)(psVar5 + 0x16) =
           *(float *)(psVar5 + 0x16) *
           -(float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uStack116) - dVar12) -
                   dVar14);
      *(float *)(psVar5 + 0x14) = (float)dVar15;
      local_8c = (float)dVar16;
      local_88 = (float)dVar16;
      local_84 = (float)dVar16;
      local_90 = (float)dVar14;
      local_94 = 0;
      local_96 = 0;
      local_98 = FUN_800221a0(0xffffd8f0,10000);
      FUN_80021ac8(&local_98,psVar5 + 0x12);
      uVar6 = FUN_800217c0((double)*(float *)(psVar5 + 0x12),-(double)*(float *)(psVar5 + 0x16));
      iVar4 = (int)*psVar5 - (uVar6 & 0xffff);
      if (0x8000 < iVar4) {
        iVar4 = iVar4 + -0xffff;
      }
      if (iVar4 < -0x8000) {
        iVar4 = iVar4 + 0xffff;
      }
      *psVar5 = (short)iVar4;
    }
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  __psq_l0(auStack56,uVar10);
  __psq_l1(auStack56,uVar10);
  __psq_l0(auStack72,uVar10);
  __psq_l1(auStack72,uVar10);
  FUN_8028611c();
  return;
}

