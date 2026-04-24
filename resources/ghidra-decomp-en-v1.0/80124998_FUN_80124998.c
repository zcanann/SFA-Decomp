// Function: FUN_80124998
// Entry: 80124998
// Size: 1000 bytes

/* WARNING: Removing unreachable block (ram,0x80124d58) */
/* WARNING: Removing unreachable block (ram,0x80124d50) */
/* WARNING: Removing unreachable block (ram,0x80124d60) */

void FUN_80124998(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  short **ppsVar6;
  char *pcVar7;
  float *pfVar8;
  undefined4 uVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f29;
  double dVar12;
  undefined8 in_f30;
  double dVar13;
  undefined8 in_f31;
  undefined8 uVar14;
  char acStack137 [5];
  float local_84 [4];
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar14 = FUN_802860c8();
  uVar1 = (undefined4)((ulonglong)uVar14 >> 0x20);
  uVar3 = (undefined4)uVar14;
  FUN_8000faac();
  iVar4 = 0;
  if (DAT_803dd7d4 == '\x03') {
    iVar4 = 1;
  }
  else if (DAT_803dd7d4 < '\x03') {
    if ('\x01' < DAT_803dd7d4) {
      iVar4 = 0;
    }
  }
  else if (DAT_803dd7d4 < '\x05') {
    iVar4 = 2;
  }
  uStack116 = -(int)DAT_803dd796 * (uint)DAT_803dba30 ^ 0x80000000;
  local_84[3] = 176.0;
  *(float *)((&DAT_803a93e0)[iVar4] + 0x10) =
       FLOAT_803e1e40 +
       (float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e1e78) / FLOAT_803e201c;
  dVar13 = (double)FLOAT_803dbac8;
  dVar12 = (double)FLOAT_803dbac4;
  dVar10 = (double)FUN_8000fc34();
  FLOAT_803dbaa4 = (float)dVar10;
  FUN_8000fc3c((double)FLOAT_803e2020);
  FUN_8000f458(1);
  DAT_803dd7e0 = FUN_8000fac4();
  FUN_8000facc();
  dVar10 = (double)FLOAT_803e1e3c;
  FUN_8000f510(dVar10,dVar10,dVar10);
  FUN_8000f4e0(0x8000,0,0);
  FUN_8000f564();
  FUN_8000fb00();
  uStack108 = (uint)*(ushort *)(DAT_803dccf0 + 4);
  local_70 = 0x43300000;
  uStack100 = (uint)*(ushort *)(DAT_803dccf0 + 8);
  local_68 = 0x43300000;
  FUN_8025d300((double)(float)(dVar12 - (double)FLOAT_803e1f34),
               (double)(float)(dVar13 - (double)FLOAT_803e2024),
               (double)(float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e1e88),
               (double)(float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e1e88),
               (double)FLOAT_803e1e3c,(double)FLOAT_803e1e68);
  iVar4 = 0;
  pcVar7 = acStack137;
  ppsVar6 = (short **)&DAT_803a93ec;
  pfVar8 = local_84;
  dVar12 = (double)FLOAT_803e1ec8;
  dVar13 = (double)FLOAT_803e1e94;
  dVar10 = DOUBLE_803e1e78;
  do {
    pcVar7 = pcVar7 + 1;
    *pcVar7 = '\0';
    uStack100 = (int)**ppsVar6 ^ 0x80000000;
    local_68 = 0x43300000;
    dVar11 = (double)FUN_80294204((double)(float)((double)(float)(dVar12 * (double)(float)((double)
                                                  CONCAT44(0x43300000,uStack100) - dVar10)) / dVar13
                                                 ));
    *pfVar8 = (float)dVar11;
    ppsVar6 = ppsVar6 + 1;
    pfVar8 = pfVar8 + 1;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 3);
  iVar4 = 0;
  dVar10 = (double)FLOAT_803e1e3c;
  do {
    dVar12 = (double)FLOAT_803e1ec4;
    iVar5 = -1;
    if ((acStack137[1] == '\0') && ((double)local_84[0] < dVar12)) {
      iVar5 = 0;
      dVar12 = (double)local_84[0];
    }
    if ((acStack137[2] == '\0') && ((double)local_84[1] < dVar12)) {
      iVar5 = 1;
      dVar12 = (double)local_84[1];
    }
    if ((acStack137[3] == '\0') && ((double)local_84[2] < dVar12)) {
      iVar5 = 2;
      dVar12 = (double)local_84[2];
    }
    if (iVar5 == -1) break;
    iVar2 = FUN_8002b588((&DAT_803a93ec)[iVar5]);
    *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
    *(char *)((&DAT_803a93ec)[iVar5] + 0x37) = (char)DAT_803dd798;
    iVar2 = FUN_8002b588((&DAT_803a93e0)[iVar5]);
    *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
    iVar2 = (int)((int)DAT_803dd798 * (uint)DAT_803dd8d4) / 0xff +
            ((int)((int)DAT_803dd798 * (uint)DAT_803dd8d4) >> 0x1f);
    *(char *)((&DAT_803a93e0)[iVar5] + 0x37) = (char)iVar2 - (char)(iVar2 >> 0x1f);
    if (dVar12 <= dVar10) {
      FUN_8003b958(uVar1,uVar3,param_3,0,(&DAT_803a93ec)[iVar5],1);
    }
    else {
      FUN_8003b958(uVar1,uVar3,param_3,0,(&DAT_803a93ec)[iVar5],1);
      FUN_8025d324(0,0x79,0x280,0x95);
      FUN_8003b958(uVar1,uVar3,param_3,0,(&DAT_803a93e0)[iVar5],1);
      FUN_8025d324(0,0,0x280,0x1e0);
    }
    acStack137[iVar5 + 1] = '\x01';
    iVar4 = iVar4 + 1;
  } while (iVar4 < 3);
  FUN_8000f458(0);
  if (DAT_803dd7e0 != 0) {
    FUN_8000fad8();
  }
  FUN_8000f564();
  FUN_8000fc3c((double)FLOAT_803dbaa4);
  FUN_8000fb00();
  FUN_8000f780();
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  FUN_80286114();
  return;
}

