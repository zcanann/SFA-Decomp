// Function: FUN_80007f78
// Entry: 80007f78
// Size: 2212 bytes

/* WARNING: Removing unreachable block (ram,0x800087fc) */
/* WARNING: Could not reconcile some variable overlaps */

void FUN_80007f78(undefined4 param_1,undefined4 param_2,short *param_3)

{
  uint uVar1;
  ushort uVar2;
  ulonglong uVar3;
  ushort uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int extraout_r4;
  int extraout_r4_00;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  int iVar11;
  short sVar12;
  ushort *puVar13;
  ushort *puVar14;
  int iVar15;
  uint uVar16;
  short sVar17;
  short *psVar18;
  uint uVar19;
  uint uVar20;
  bool bVar21;
  undefined4 uVar22;
  double dVar23;
  undefined8 in_f31;
  double dVar24;
  undefined8 uVar25;
  undefined8 uVar26;
  uint local_98;
  uint local_94;
  undefined8 local_90;
  undefined8 local_88;
  longlong local_80;
  int local_78;
  short *local_6c;
  int local_68;
  undefined4 local_60;
  undefined auStack8 [8];
  
  uVar22 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar25 = FUN_802860ac();
  iVar11 = (int)((ulonglong)uVar25 >> 0x20);
  psVar18 = (short *)uVar25;
  dVar24 = (double)*(float *)(iVar11 + 4);
  local_68 = 0;
  iVar15 = *(int *)(iVar11 + 0x2c);
  iVar5 = *(int *)(iVar11 + 0x34);
  iVar11 = iVar15 + (uint)*(ushort *)(iVar11 + 0x4c);
  local_6c = psVar18 + 3;
  dVar23 = (double)FUN_80294724(dVar24);
  uVar1 = (uint)((float)(dVar24 - dVar23) * FLOAT_803de544);
  local_80 = (longlong)(int)uVar1;
  local_78 = (int)uVar1 >> 0x1f;
  FUN_800089ac(&local_88,iVar15);
  FUN_8000881c(&local_88,iVar15 + 7);
  FUN_800089ac(&local_90,iVar11);
  FUN_8000881c(&local_90,iVar11 + 7);
  uVar25 = CONCAT44(local_90._0_4_,local_90._4_4_);
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
        iVar15 = iVar15 + local_88._4_4_;
        iVar11 = local_88._4_4_ + iVar11;
        uVar20 = uVar19 - uVar16 & 7;
        local_90 = uVar25;
        FUN_800089ac(&local_88,iVar15);
        FUN_8000881c(&local_88,iVar15 + 7);
        FUN_800089ac(&local_90,iVar11);
        FUN_8000881c(&local_90,iVar11 + 7);
        local_88 = FUN_80286448(local_88._0_4_,local_88._4_4_,uVar20);
        uVar25 = FUN_80286448(local_90._0_4_,local_90._4_4_,uVar20);
        uVar19 = uVar20 + uVar16;
        uVar20 = (uint)CARRY4(uVar20,uVar16);
      }
      local_88._0_4_ = (uint)((ulonglong)local_88 >> 0x20);
      local_90 = uVar25;
      FUN_8028646c(local_88._0_4_,local_88._4_4_,0x40 - uVar16);
      FUN_8028646c(local_90._0_4_,local_90._4_4_,0x40 - uVar16);
      local_98 = (extraout_r4_00 - extraout_r4) * 0x40000;
      local_94 = 0;
      iVar5 = 10;
      do {
        uVar8 = local_98 << 0x1f | local_94 >> 1;
        uVar6 = local_94 & 1 | local_98 & 0xfffffffe;
        uVar7 = (uint)((int)uVar6 < 0 && (local_94 & 1) != 0);
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
        local_94 = uVar8 + uVar7;
        local_98 = ((int)uVar6 >> 1) + (uint)CARRY4(uVar8,uVar7);
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
      uVar3 = (ulonglong)local_94;
      iVar5 = local_94 * local_78;
      local_94 = local_94 * uVar1;
      local_98 = (int)(uVar3 * uVar1 >> 0x20) + local_98 * uVar1 + iVar5;
      iVar5 = 7;
      do {
        uVar6 = local_98 << 0x1f | local_94 >> 1;
        uVar8 = local_94 & 1 | local_98 & 0xfffffffe;
        uVar7 = (uint)((int)uVar8 < 0 && (local_94 & 1) != 0);
        uVar9 = uVar6 + uVar7;
        uVar7 = ((int)uVar8 >> 1) + (uint)CARRY4(uVar6,uVar7);
        uVar6 = uVar7 * -0x80000000 | uVar9 >> 1;
        uVar9 = uVar9 & 1;
        uVar8 = uVar9 | uVar7 & 0xfffffffe;
        uVar7 = (uint)((int)uVar8 < 0 && uVar9 != 0);
        local_94 = uVar6 + uVar7;
        local_98 = ((int)uVar8 >> 1) + (uint)CARRY4(uVar6,uVar7);
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
      sVar12 = (uVar2 & uVar4) + ((short)extraout_r4 + (short)local_94) * 4;
      uVar25 = FUN_80286448(local_88._0_4_,local_88._4_4_,uVar16);
      local_88 = uVar25;
      uVar25 = FUN_80286448(local_90._0_4_,local_90._4_4_,uVar16);
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
            iVar15 = iVar15 + local_88._4_4_;
            iVar11 = local_88._4_4_ + iVar11;
            uVar20 = uVar19 - uVar16 & 7;
            local_90 = uVar25;
            FUN_800089ac(&local_88,iVar15);
            FUN_8000881c(&local_88,iVar15 + 7);
            FUN_800089ac(&local_90,iVar11);
            FUN_8000881c(&local_90,iVar11 + 7);
            local_88 = FUN_80286448(local_88._0_4_,local_88._4_4_,uVar20);
            uVar25 = FUN_80286448(local_90._0_4_,local_90._4_4_,uVar20);
            uVar19 = uVar20 + uVar16;
            uVar20 = (uint)CARRY4(uVar20,uVar16);
          }
          local_88._0_4_ = (uint)((ulonglong)local_88 >> 0x20);
          local_90 = uVar25;
          uVar25 = FUN_80286448(local_88._0_4_,local_88._4_4_,uVar16);
          local_88 = uVar25;
          uVar25 = FUN_80286448(local_90._0_4_,local_90._4_4_,uVar16);
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
          iVar15 = iVar15 + local_88._4_4_;
          iVar11 = local_88._4_4_ + iVar11;
          uVar20 = uVar19 - uVar7 & 7;
          local_90 = uVar25;
          FUN_800089ac(&local_88,iVar15);
          FUN_8000881c(&local_88,iVar15 + 7);
          FUN_800089ac(&local_90,iVar11);
          FUN_8000881c(&local_90,iVar11 + 7);
          local_88 = FUN_80286448(local_88._0_4_,local_88._4_4_,uVar20);
          uVar25 = FUN_80286448(local_90._0_4_,local_90._4_4_,uVar20);
          uVar19 = uVar20 + uVar7;
          uVar20 = (uint)CARRY4(uVar20,uVar7);
        }
        local_88._0_4_ = (uint)((ulonglong)local_88 >> 0x20);
        local_90 = uVar25;
        uVar25 = FUN_8028646c(local_88._0_4_,local_88._4_4_,0x40 - uVar7);
        uVar26 = FUN_8028646c(local_90._0_4_,local_90._4_4_,0x40 - uVar7);
        uVar9 = (uint)uVar26 - (uint)uVar25;
        local_94 = uVar9 * uVar1;
        local_98 = (int)((ulonglong)uVar9 * (ulonglong)uVar1 >> 0x20) +
                   ((int)((ulonglong)uVar26 >> 0x20) -
                   ((uint)((uint)uVar26 < (uint)uVar25) + (int)((ulonglong)uVar25 >> 0x20))) * uVar1
                   + uVar9 * local_78;
        iVar5 = 7;
        do {
          uVar8 = local_98 << 0x1f | local_94 >> 1;
          uVar10 = local_94 & 1 | local_98 & 0xfffffffe;
          uVar9 = (uint)((int)uVar10 < 0 && (local_94 & 1) != 0);
          uVar6 = uVar8 + uVar9;
          uVar9 = ((int)uVar10 >> 1) + (uint)CARRY4(uVar8,uVar9);
          uVar8 = uVar9 * -0x80000000 | uVar6 >> 1;
          uVar6 = uVar6 & 1;
          uVar10 = uVar6 | uVar9 & 0xfffffffe;
          uVar9 = (uint)((int)uVar10 < 0 && uVar6 != 0);
          local_94 = uVar8 + uVar9;
          local_98 = ((int)uVar10 >> 1) + (uint)CARRY4(uVar8,uVar9);
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
        sVar17 = ((ushort)uVar16 & 0xfff0) + (short)uVar25 + (short)local_94;
        uVar25 = FUN_80286448(local_88._0_4_,local_88._4_4_,uVar7);
        local_88 = uVar25;
        uVar25 = FUN_80286448(local_90._0_4_,local_90._4_4_,uVar7);
      }
      puVar14 = puVar14 + 1;
    }
LAB_800087d4:
    *psVar18 = sVar17;
    psVar18 = psVar18 + 1;
    puVar13 = puVar14;
    if (psVar18 == local_6c) {
      __psq_l0(auStack8,uVar22);
      __psq_l1(auStack8,uVar22);
      local_90 = uVar25;
      FUN_802860f8();
      return;
    }
  } while( true );
}

