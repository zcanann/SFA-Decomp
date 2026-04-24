// Function: FUN_80015e84
// Entry: 80015e84
// Size: 776 bytes

/* WARNING: Removing unreachable block (ram,0x80016164) */
/* WARNING: Removing unreachable block (ram,0x8001616c) */

void FUN_80015e84(void)

{
  int iVar1;
  int iVar2;
  bool bVar3;
  undefined uVar4;
  undefined uVar5;
  undefined uVar6;
  undefined4 uVar7;
  undefined4 *puVar8;
  int iVar9;
  undefined *puVar10;
  undefined4 uVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  undefined8 uVar14;
  float local_68;
  uint local_64;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  double local_50;
  longlong local_48;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar14 = FUN_802860d0();
  uVar7 = (undefined4)((ulonglong)uVar14 >> 0x20);
  iVar2 = (int)uVar14 * 0x20;
  puVar10 = &DAT_802c7400 + iVar2;
  bVar3 = false;
  if ((DAT_803dc9c0 != 1) && ((&DAT_802c7412)[iVar2] = (&DAT_802c7410)[iVar2], DAT_803dc9bc == 0)) {
    FUN_8001be90(0,uVar7,puVar10);
  }
  uStack92 = (uint)*(ushort *)(&DAT_802c7408 + iVar2);
  local_60 = 0x43300000;
  puVar8 = (undefined4 *)
           FUN_80016c9c((double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803de6f0),
                        (double)*(float *)(&DAT_802c740c + iVar2),uVar7,&local_64,&local_68);
  if (puVar8 == (undefined4 *)0x0) {
    uStack92 = local_64 ^ 0x80000000;
    local_60 = 0x43300000;
    uStack84 = (int)*(short *)(&DAT_802c741a + iVar2) ^ 0x80000000;
    local_58 = 0x43300000;
    iVar9 = (int)(local_68 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803de6f8) +
                 (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803de6f8));
    local_50 = (double)(longlong)iVar9;
    *(short *)(&DAT_802c741a + iVar2) = (short)iVar9;
  }
  else {
    if (DAT_803dc96c == 0) {
      if (DAT_803dc9bc == 0) {
        FUN_800550d0(0,0,(int)*(short *)(&DAT_802c7414 + iVar2),
                     (int)*(short *)(&DAT_802c7416 + iVar2),
                     (int)*(short *)(&DAT_802c7414 + iVar2) +
                     (uint)*(ushort *)(&DAT_802c7408 + iVar2),
                     (int)*(short *)(&DAT_802c7416 + iVar2) +
                     (uint)*(ushort *)(&DAT_802c740a + iVar2));
      }
    }
    else {
      FUN_800550d0(0,0,0,0,0x280,0x1e0);
    }
    FLOAT_803dc9a0 = *(float *)(&DAT_802c740c + iVar2);
    dVar13 = DOUBLE_803de6f8;
    for (iVar9 = 0; iVar9 < (int)local_64; iVar9 = iVar9 + 1) {
      if ((iVar9 == local_64 - 1) && ((&DAT_802c7412)[iVar2] == '\x03')) {
        (&DAT_802c7412)[iVar2] = 0;
        bVar3 = true;
      }
      uVar6 = DAT_803dc9a7;
      uVar5 = DAT_803dc9a6;
      uVar4 = DAT_803dc9a5;
      if ((DAT_803dc984 == 1) && (DAT_803dc9bc == 0)) {
        dVar12 = (double)FLOAT_803dc9a0;
        DAT_803dc9a7 = DAT_803dc992;
        DAT_803dc9a6 = DAT_803dc991;
        DAT_803dc9a5 = DAT_803dc990;
        local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_802c7418 + iVar2) ^ 0x80000000);
        uStack84 = (int)*(short *)(&DAT_802c741a + iVar2) ^ 0x80000000;
        local_58 = 0x43300000;
        FUN_800174d0((double)(float)(local_50 - DOUBLE_803de6f8),
                     (double)(float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803de6f8),
                     (double)local_68,*puVar8,puVar10,1);
        FLOAT_803dc9a0 = (float)dVar12;
      }
      local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_802c7418 + iVar2) ^ 0x80000000);
      uStack84 = (int)*(short *)(&DAT_802c741a + iVar2) ^ 0x80000000;
      local_58 = 0x43300000;
      DAT_803dc9a5 = uVar4;
      DAT_803dc9a6 = uVar5;
      DAT_803dc9a7 = uVar6;
      FUN_800174d0((double)(float)(local_50 - dVar13),
                   (double)(float)((double)CONCAT44(0x43300000,uStack84) - dVar13),(double)local_68,
                   *puVar8,puVar10,0);
      uStack92 = (int)*(short *)(&DAT_802c741a + iVar2) ^ 0x80000000;
      local_60 = 0x43300000;
      iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack92) - dVar13) + local_68);
      local_48 = (longlong)iVar1;
      *(short *)(&DAT_802c741a + iVar2) = (short)iVar1;
      if (bVar3) {
        (&DAT_802c7412)[iVar2] = 3;
      }
      puVar8 = puVar8 + 1;
    }
    if (DAT_803dc9bc == 0) {
      FUN_8000f0b8(0);
    }
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  FUN_8028611c();
  return;
}

