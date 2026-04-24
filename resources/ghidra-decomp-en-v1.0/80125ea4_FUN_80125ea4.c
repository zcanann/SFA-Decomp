// Function: FUN_80125ea4
// Entry: 80125ea4
// Size: 1064 bytes

/* WARNING: Removing unreachable block (ram,0x801262ac) */

void FUN_80125ea4(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined4 uVar9;
  uint uVar10;
  byte bVar11;
  undefined4 uVar12;
  undefined8 in_f31;
  double dVar13;
  double dVar14;
  undefined4 local_58;
  undefined local_54;
  double local_50;
  undefined4 local_48;
  uint uStack68;
  double local_40;
  undefined auStack8 [8];
  
  uVar12 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FUN_802860c8();
  iVar3 = FUN_8022d768();
  local_58 = DAT_803e1e08;
  local_54 = DAT_803e1e0c;
  if (iVar3 != 0) {
    if (DAT_803dd7cc == '\0') {
      local_40 = (double)CONCAT44(0x43300000,(uint)DAT_803db410);
      uStack68 = (int)(short)DAT_803dd838 ^ 0x80000000;
      iVar7 = (int)-(FLOAT_803e1fa0 * (float)(local_40 - DOUBLE_803e1e88) -
                    (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e1e78));
      local_50 = (double)(longlong)iVar7;
      DAT_803dd838 = (ushort)iVar7;
      if ((short)DAT_803dd838 < 0) {
        DAT_803dd838 = 0;
      }
    }
    else {
      local_50 = (double)CONCAT44(0x43300000,(uint)DAT_803db410);
      uStack68 = (int)(short)DAT_803dd838 ^ 0x80000000;
      iVar7 = (int)(FLOAT_803e1fa0 * (float)(local_50 - DOUBLE_803e1e88) +
                   (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e1e78));
      local_40 = (double)(longlong)iVar7;
      DAT_803dd838 = (ushort)iVar7;
      if (0xff < (short)DAT_803dd838) {
        DAT_803dd838 = 0xff;
      }
    }
    local_48 = 0x43300000;
    uVar4 = FUN_8022d590(iVar3);
    iVar5 = FUN_8022d580(iVar3);
    iVar6 = FUN_8022d574(iVar3);
    iVar7 = FUN_8022d514(iVar3);
    iVar8 = FUN_8022d508(iVar3);
    if (iVar8 < iVar7) {
      iVar7 = iVar8;
    }
    dVar13 = DOUBLE_803e1e78;
    for (uVar10 = 0; uVar1 = uVar10 & 0xff, (int)uVar1 < iVar5 >> 2; uVar10 = uVar10 + 1) {
      if ((int)uVar1 < (int)uVar4 >> 2) {
        iVar2 = 0x16;
      }
      else {
        iVar2 = (uVar4 & 3) + 0x12;
        if ((int)uVar4 >> 2 < (int)uVar1) {
          iVar2 = 0x12;
        }
      }
      local_40 = (double)CONCAT44(0x43300000,uVar1 * 0x21 + 0x1e ^ 0x80000000);
      FUN_8007719c((double)(float)(local_40 - dVar13),(double)FLOAT_803e1fac,(&DAT_803a89b0)[iVar2],
                   DAT_803dd838 & 0xff,0x100);
    }
    dVar13 = DOUBLE_803e1e78;
    for (bVar11 = 0; bVar11 < 3; bVar11 = bVar11 + 1) {
      iVar5 = (uint)bVar11 * 0x1c;
      local_40 = (double)CONCAT44(0x43300000,iVar5 + 0x1eU ^ 0x80000000);
      FUN_8007719c((double)(float)(local_40 - dVar13),(double)FLOAT_803e2060,DAT_803a8a90,
                   DAT_803dd838 & 0xff,0x100);
      if ((int)(uint)bVar11 < iVar6) {
        local_40 = (double)CONCAT44(0x43300000,iVar5 + 0x23U ^ 0x80000000);
        FUN_8007719c((double)(float)(local_40 - DOUBLE_803e1e78),(double)FLOAT_803e2064,DAT_803a8a94
                     ,DAT_803dd838 & 0xff,0x100);
      }
    }
    if (*(char *)(iVar3 + 0xac) != '&') {
      FUN_8007719c((double)FLOAT_803e2068,(double)FLOAT_803e1fac,DAT_803a8aa4,DAT_803dd838 & 0xff,
                   0x100);
      dVar13 = DOUBLE_803e1e78;
      for (uVar4 = 0; dVar14 = DOUBLE_803e1e78, (int)(uVar4 & 0xff) < iVar7; uVar4 = uVar4 + 1) {
        local_40 = (double)CONCAT44(0x43300000,(uVar4 & 0xff) * -0x14 + 0x244 ^ 0x80000000);
        FUN_8007719c((double)(float)(local_40 - dVar13),(double)FLOAT_803e1f9c,DAT_803a8aa0,
                     DAT_803dd838 & 0xff,0x100);
      }
      for (; uVar10 = uVar4 & 0xff, (int)uVar10 < iVar8; uVar4 = uVar4 + 1) {
        local_40 = (double)CONCAT44(0x43300000,uVar10 * -0x14 + 0x244 ^ 0x80000000);
        FUN_8007719c((double)(float)(local_40 - dVar14),(double)FLOAT_803e1f9c,DAT_803a8a9c,
                     DAT_803dd838 & 0xff,0x100);
      }
      local_40 = (double)CONCAT44(0x43300000,uVar10 * -0x14 + 0x23c ^ 0x80000000);
      FUN_8007719c((double)(float)(local_40 - DOUBLE_803e1e78),(double)FLOAT_803e1fac,DAT_803a8a98,
                   DAT_803dd838 & 0xff,0x100);
      uVar9 = FUN_8022d550(iVar3);
      FUN_8028f688(&local_58,&DAT_803dbb60,uVar9);
    }
    FUN_80019908(0xff,0xff,0xff,DAT_803dd838 & 0xff);
    FUN_80015dc8(&local_58,0x93,0x23a,0x41);
    FUN_80125424();
  }
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  FUN_80286114();
  return;
}

