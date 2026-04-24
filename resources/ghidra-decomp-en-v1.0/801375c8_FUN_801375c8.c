// Function: FUN_801375c8
// Entry: 801375c8
// Size: 736 bytes

/* WARNING: Removing unreachable block (ram,0x80137888) */

void FUN_801375c8(void)

{
  undefined *puVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  undefined4 uVar12;
  undefined8 in_f31;
  double dVar13;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  int iStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  int iStack52;
  undefined auStack8 [8];
  
  uVar12 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar3 = FUN_802860dc();
  uVar4 = FUN_8006fed4();
  DAT_803dd9f4 = (ushort)(uVar4 >> 0x10);
  DAT_803dd9f6 = (ushort)(uVar4 & 0xffff);
  FUN_8025d324(0,0,uVar4 & 0xffff,uVar4 >> 0x10);
  uVar4 = (uint)DAT_803dd9f6;
  if (uVar4 < 0x141) {
    DAT_803dda08 = 0x10;
    DAT_803dda04 = uVar4 - 0x10;
  }
  else {
    DAT_803dda08 = 0x20;
    DAT_803dda04 = uVar4 - 0x20;
  }
  uVar4 = (uint)DAT_803dd9f4;
  if (uVar4 < 0xf1) {
    DAT_803dda00 = 0x10;
    DAT_803dd9fc = uVar4 - 0x10;
  }
  else {
    DAT_803dda00 = 0x20;
    DAT_803dd9fc = uVar4 - 0x20;
  }
  FUN_80078c1c();
  DAT_803dda16 = (ushort)DAT_803dda08;
  DAT_803dda14 = (ushort)DAT_803dda00;
  DAT_803dd9f8 = 0xffffffff;
  DAT_803dda10 = 0;
  DAT_803dda18 = DAT_803dda14;
  DAT_803dda1a = DAT_803dda16;
  for (puVar1 = &DAT_803aa018; puVar1 != DAT_803dbc14; puVar1 = puVar1 + iVar10) {
    DAT_803dda0c = 0;
    iVar10 = FUN_80136e00(uVar3,puVar1);
  }
  iVar10 = DAT_803dda18 + 10;
  uVar9 = (uint)DAT_803dda14;
  uVar11 = (uint)DAT_803dda16;
  uVar4 = countLeadingZeros(DAT_803dda1a - uVar11);
  uVar2 = countLeadingZeros(iVar10 - uVar9);
  if ((uVar4 | uVar2) >> 5 == 0) {
    if (1 < uVar11) {
      uVar11 = uVar11 - 2;
    }
    iStack76 = DAT_803dda1a + 2;
    local_60 = 0x43300000;
    uStack84 = (uint)DAT_803dd9e0;
    local_58 = 0x43300000;
    dVar13 = (double)(FLOAT_803dd9d8 +
                     (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e23a8));
    uStack92 = uVar11;
    uVar5 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar11) -
                                                        DOUBLE_803e23a8) * dVar13));
    local_50 = 0x43300000;
    uVar6 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,iStack76) -
                                                        DOUBLE_803e23a8) * dVar13));
    local_48 = 0x43300000;
    uStack60 = (uint)DAT_803dd9e1;
    local_40 = 0x43300000;
    dVar13 = (double)(FLOAT_803dd9dc +
                     (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e23a8));
    uStack68 = uVar9;
    uVar7 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar9) -
                                                        DOUBLE_803e23a8) * dVar13));
    local_38 = 0x43300000;
    iStack52 = iVar10;
    uVar8 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,iVar10) -
                                                        DOUBLE_803e23a8) * dVar13));
    local_68 = CONCAT31(CONCAT21(CONCAT11(DAT_803dd9f3,DAT_803dd9f2),DAT_803dd9f1),DAT_803dd9f0);
    local_64 = local_68;
    FUN_800753b8(uVar5,uVar7,uVar6,uVar8,&local_64);
  }
  DAT_803dda1a = (ushort)DAT_803dda08;
  DAT_803dda18 = (ushort)DAT_803dda00;
  DAT_803dd9f8 = 0xffffffff;
  DAT_803dda10 = 0;
  for (puVar1 = &DAT_803aa018; puVar1 != DAT_803dbc14; puVar1 = puVar1 + iVar10) {
    DAT_803dda0c = 1;
    iVar10 = FUN_80136e00(uVar3,puVar1);
  }
  DAT_803dbc14 = &DAT_803aa018;
  DAT_803dd9e4 = 0;
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  FUN_80286128();
  return;
}

