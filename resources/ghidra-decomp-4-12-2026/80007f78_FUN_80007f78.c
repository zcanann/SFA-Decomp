// Function: FUN_80007f78
// Entry: 80007f78
// Size: 2212 bytes

/* WARNING: Removing unreachable block (ram,0x800087fc) */

void FUN_80007f78(undefined4 param_1,undefined4 param_2,short *param_3)

{
  uint uVar1;
  ushort uVar2;
  byte bVar3;
  ushort uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  short sVar12;
  ushort *puVar13;
  ushort *puVar14;
  uint uVar15;
  uint uVar16;
  short sVar17;
  short *psVar18;
  uint uVar19;
  uint uVar20;
  bool bVar21;
  int iVar22;
  uint unaff_GQR0;
  double dVar23;
  double in_f31;
  double dVar24;
  double in_ps31_1;
  undefined8 uVar25;
  undefined8 uVar26;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  longlong local_80;
  int local_78;
  short *local_6c;
  int local_68;
  undefined4 local_60;
  undefined4 local_8;
  float fStack_4;
  
  bVar3 = (byte)unaff_GQR0 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar23 = 1.0;
  }
  else {
    dVar23 = (double)ldexpf((byte)(unaff_GQR0 >> 8) & 0x3f);
  }
  if (bVar3 == 4 || bVar3 == 6) {
    local_8 = (float)CONCAT13((char)(dVar23 * in_f31),
                              CONCAT12((char)(dVar23 * in_ps31_1),local_8._2_2_));
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    local_8 = (float)CONCAT22((short)(dVar23 * in_f31),(short)(dVar23 * in_ps31_1));
  }
  else {
    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
  }
  uVar25 = FUN_80286810();
  iVar22 = (int)((ulonglong)uVar25 >> 0x20);
  psVar18 = (short *)uVar25;
  dVar24 = (double)*(float *)(iVar22 + 4);
  local_68 = 0;
  uVar15 = *(uint *)(iVar22 + 0x2c);
  iVar5 = *(int *)(iVar22 + 0x34);
  uVar11 = uVar15 + *(ushort *)(iVar22 + 0x4c);
  local_6c = psVar18 + 3;
  dVar23 = FUN_80294e84(dVar24);
  uVar1 = (uint)((float)(dVar24 - dVar23) * FLOAT_803df1c4);
  local_80 = (longlong)(int)uVar1;
  local_78 = (int)uVar1 >> 0x1f;
  FUN_800089ac((uint *)&local_88,uVar15);
  FUN_8000881c((uint *)&local_88,uVar15 + 7);
  FUN_800089ac((uint *)&local_90,uVar11);
  FUN_8000881c((uint *)&local_90,uVar11 + 7);
  uVar19 = 0;
  uVar20 = 0;
  local_60 = 0xfff0;
  puVar13 = (ushort *)(iVar5 + 4);
  do {
    sVar12 = 0;
    uVar2 = *puVar13;
    uVar16 = uVar2 & 0xf;
    uVar4 = (ushort)local_60;
    if ((uVar2 & 0xf) != 0) {
      bVar21 = CARRY4(uVar19,uVar16);
      uVar19 = uVar19 + uVar16;
      uVar20 = uVar20 + bVar21;
      if (0x80000000 < (uint)(0x40 < uVar19) + (uVar20 ^ 0x80000000)) {
        uVar20 = uVar20 - (uVar19 < uVar16);
        local_88._4_4_ = uVar20 * 0x20000000 | uVar19 - uVar16 >> 3;
        local_88._0_4_ = uVar20 >> 3;
        uVar15 = uVar15 + local_88._4_4_;
        uVar11 = local_88._4_4_ + uVar11;
        uVar20 = uVar19 - uVar16 & 7;
        FUN_800089ac((uint *)&local_88,uVar15);
        FUN_8000881c((uint *)&local_88,uVar15 + 7);
        FUN_800089ac((uint *)&local_90,uVar11);
        FUN_8000881c((uint *)&local_90,uVar11 + 7);
        local_88 = FUN_80286bac(local_88._0_4_,local_88._4_4_,uVar20);
        local_90 = FUN_80286bac(local_90._0_4_,local_90._4_4_,uVar20);
        uVar19 = uVar20 + uVar16;
        uVar20 = (uint)CARRY4(uVar20,uVar16);
      }
      uVar25 = FUN_80286bd0(local_88._0_4_,local_88._4_4_,0x40 - uVar16);
      uVar26 = FUN_80286bd0(local_90._0_4_,local_90._4_4_,0x40 - uVar16);
      local_98._0_4_ = ((int)uVar26 - (int)uVar25) * 0x40000;
      local_98._4_4_ = 0;
      iVar22 = 10;
      do {
        uVar8 = local_98._0_4_ << 0x1f | local_98._4_4_ >> 1;
        uVar6 = local_98._4_4_ & 1 | local_98._0_4_ & 0xfffffffe;
        uVar7 = (uint)((int)uVar6 < 0 && (local_98._4_4_ & 1) != 0);
        uVar9 = uVar8 + uVar7;
        uVar7 = ((int)uVar6 >> 1) + (uint)CARRY4(uVar8,uVar7);
        uVar8 = uVar7 * -0x80000000 | uVar9 >> 1;
        uVar9 = uVar9 & 1;
        uVar6 = uVar9 | uVar7 & 0xfffffffe;
        uVar7 = (uint)((int)uVar6 < 0 && uVar9 != 0);
        uVar9 = uVar8 + uVar7;
        uVar7 = ((int)uVar6 >> 1) + (uint)CARRY4(uVar8,uVar7);
        uVar8 = uVar7 * -0x80000000 | uVar9 >> 1;
        uVar9 = uVar9 & 1;
        uVar6 = uVar9 | uVar7 & 0xfffffffe;
        uVar7 = (uint)((int)uVar6 < 0 && uVar9 != 0);
        uVar9 = uVar8 + uVar7;
        uVar7 = ((int)uVar6 >> 1) + (uint)CARRY4(uVar8,uVar7);
        uVar8 = uVar7 * -0x80000000 | uVar9 >> 1;
        uVar9 = uVar9 & 1;
        uVar6 = uVar9 | uVar7 & 0xfffffffe;
        uVar7 = (uint)((int)uVar6 < 0 && uVar9 != 0);
        uVar9 = uVar8 + uVar7;
        uVar7 = ((int)uVar6 >> 1) + (uint)CARRY4(uVar8,uVar7);
        uVar8 = uVar7 * -0x80000000 | uVar9 >> 1;
        uVar9 = uVar9 & 1;
        uVar6 = uVar9 | uVar7 & 0xfffffffe;
        uVar7 = (uint)((int)uVar6 < 0 && uVar9 != 0);
        local_98._4_4_ = uVar8 + uVar7;
        local_98._0_4_ = ((int)uVar6 >> 1) + (uint)CARRY4(uVar8,uVar7);
        iVar22 = iVar22 + -1;
      } while (iVar22 != 0);
      local_98 = CONCAT44((int)((ulonglong)local_98._4_4_ * (ulonglong)uVar1 >> 0x20) +
                          local_98._0_4_ * uVar1 + local_98._4_4_ * local_78,local_98._4_4_ * uVar1)
      ;
      iVar22 = 7;
      do {
        uVar6 = local_98._0_4_ << 0x1f | local_98._4_4_ >> 1;
        uVar8 = local_98._4_4_ & 1 | local_98._0_4_ & 0xfffffffe;
        uVar7 = (uint)((int)uVar8 < 0 && (local_98 & 1) != 0);
        uVar9 = uVar6 + uVar7;
        uVar7 = ((int)uVar8 >> 1) + (uint)CARRY4(uVar6,uVar7);
        uVar6 = uVar7 * -0x80000000 | uVar9 >> 1;
        uVar9 = uVar9 & 1;
        uVar8 = uVar9 | uVar7 & 0xfffffffe;
        uVar7 = (uint)((int)uVar8 < 0 && uVar9 != 0);
        iVar5 = uVar6 + uVar7;
        local_98 = CONCAT44(((int)uVar8 >> 1) + (uint)CARRY4(uVar6,uVar7),iVar5);
        iVar22 = iVar22 + -1;
      } while (iVar22 != 0);
      sVar12 = (uVar2 & uVar4) + (short)((int)uVar25 + iVar5) * 4;
      local_88 = FUN_80286bac(local_88._0_4_,local_88._4_4_,uVar16);
      local_90 = FUN_80286bac(local_90._0_4_,local_90._4_4_,uVar16);
    }
    sVar17 = 0;
    puVar14 = puVar13 + 1;
    *param_3 = sVar12;
    bVar21 = (short *)0xfffffffd < param_3;
    param_3 = param_3 + 1;
    local_68 = local_68 + (uint)bVar21;
    if ((uVar2 & 0x10) != 0) {
      uVar2 = *puVar14;
      uVar16 = (uint)uVar2;
      if ((uVar2 & 0x10) != 0) {
        uVar16 = uVar16 & 0xf;
        if ((uVar2 & 0xf) != 0) {
          bVar21 = CARRY4(uVar19,uVar16);
          uVar19 = uVar19 + uVar16;
          uVar20 = uVar20 + bVar21;
          if (0x80000000 < (uint)(0x40 < uVar19) + (uVar20 ^ 0x80000000)) {
            uVar20 = uVar20 - (uVar19 < uVar16);
            local_88._4_4_ = uVar20 * 0x20000000 | uVar19 - uVar16 >> 3;
            local_88._0_4_ = uVar20 >> 3;
            uVar15 = uVar15 + local_88._4_4_;
            uVar11 = local_88._4_4_ + uVar11;
            uVar20 = uVar19 - uVar16 & 7;
            FUN_800089ac((uint *)&local_88,uVar15);
            FUN_8000881c((uint *)&local_88,uVar15 + 7);
            FUN_800089ac((uint *)&local_90,uVar11);
            FUN_8000881c((uint *)&local_90,uVar11 + 7);
            local_88 = FUN_80286bac(local_88._0_4_,local_88._4_4_,uVar20);
            local_90 = FUN_80286bac(local_90._0_4_,local_90._4_4_,uVar20);
            uVar19 = uVar20 + uVar16;
            uVar20 = (uint)CARRY4(uVar20,uVar16);
          }
          local_88 = FUN_80286bac(local_88._0_4_,local_88._4_4_,uVar16);
          local_90 = FUN_80286bac(local_90._0_4_,local_90._4_4_,uVar16);
        }
        sVar17 = 0;
        puVar14 = puVar13 + 2;
        if ((uVar2 & 0x20) == 0) goto LAB_800087d4;
        uVar16 = (uint)*puVar14;
      }
      sVar17 = 0;
      uVar7 = uVar16 & 0xf;
      if (uVar7 != 0) {
        bVar21 = CARRY4(uVar19,uVar7);
        uVar19 = uVar19 + uVar7;
        uVar20 = uVar20 + bVar21;
        if (0x80000000 < (uint)(0x40 < uVar19) + (uVar20 ^ 0x80000000)) {
          uVar20 = uVar20 - (uVar19 < uVar7);
          local_88._4_4_ = uVar20 * 0x20000000 | uVar19 - uVar7 >> 3;
          local_88._0_4_ = uVar20 >> 3;
          uVar15 = uVar15 + local_88._4_4_;
          uVar11 = local_88._4_4_ + uVar11;
          uVar20 = uVar19 - uVar7 & 7;
          FUN_800089ac((uint *)&local_88,uVar15);
          FUN_8000881c((uint *)&local_88,uVar15 + 7);
          FUN_800089ac((uint *)&local_90,uVar11);
          FUN_8000881c((uint *)&local_90,uVar11 + 7);
          local_88 = FUN_80286bac(local_88._0_4_,local_88._4_4_,uVar20);
          local_90 = FUN_80286bac(local_90._0_4_,local_90._4_4_,uVar20);
          uVar19 = uVar20 + uVar7;
          uVar20 = (uint)CARRY4(uVar20,uVar7);
        }
        uVar25 = FUN_80286bd0(local_88._0_4_,local_88._4_4_,0x40 - uVar7);
        uVar26 = FUN_80286bd0(local_90._0_4_,local_90._4_4_,0x40 - uVar7);
        uVar9 = (uint)uVar26 - (uint)uVar25;
        local_98 = CONCAT44((int)((ulonglong)uVar9 * (ulonglong)uVar1 >> 0x20) +
                            ((int)((ulonglong)uVar26 >> 0x20) -
                            ((uint)((uint)uVar26 < (uint)uVar25) + (int)((ulonglong)uVar25 >> 0x20))
                            ) * uVar1 + uVar9 * local_78,uVar9 * uVar1);
        iVar22 = 7;
        do {
          uVar8 = local_98._0_4_ << 0x1f | local_98._4_4_ >> 1;
          uVar10 = local_98._4_4_ & 1 | local_98._0_4_ & 0xfffffffe;
          uVar9 = (uint)((int)uVar10 < 0 && (local_98 & 1) != 0);
          uVar6 = uVar8 + uVar9;
          uVar9 = ((int)uVar10 >> 1) + (uint)CARRY4(uVar8,uVar9);
          uVar8 = uVar9 * -0x80000000 | uVar6 >> 1;
          uVar6 = uVar6 & 1;
          uVar10 = uVar6 | uVar9 & 0xfffffffe;
          uVar9 = (uint)((int)uVar10 < 0 && uVar6 != 0);
          iVar5 = uVar8 + uVar9;
          local_98 = CONCAT44(((int)uVar10 >> 1) + (uint)CARRY4(uVar8,uVar9),iVar5);
          iVar22 = iVar22 + -1;
        } while (iVar22 != 0);
        sVar17 = ((ushort)uVar16 & 0xfff0) + (short)uVar25 + (short)iVar5;
        local_88 = FUN_80286bac(local_88._0_4_,local_88._4_4_,uVar7);
        local_90 = FUN_80286bac(local_90._0_4_,local_90._4_4_,uVar7);
      }
      puVar14 = puVar14 + 1;
    }
LAB_800087d4:
    *psVar18 = sVar17;
    psVar18 = psVar18 + 1;
    puVar13 = puVar14;
    if (psVar18 == local_6c) {
      if ((unaff_GQR0 & 0x3f000000) != 0) {
        ldexpf(-((byte)(unaff_GQR0 >> 0x18) & 0x3f));
      }
      FUN_8028685c();
      return;
    }
  } while( true );
}

