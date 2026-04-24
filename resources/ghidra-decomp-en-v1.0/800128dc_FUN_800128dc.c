// Function: FUN_800128dc
// Entry: 800128dc
// Size: 1060 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_800128dc(undefined4 param_1,undefined4 param_2,uint *param_3,undefined *param_4,
                 uint param_5)

{
  bool bVar1;
  int iVar2;
  bool bVar3;
  int iVar4;
  ushort uVar5;
  uint *puVar6;
  undefined4 uVar7;
  uint *puVar8;
  int iVar9;
  int iVar10;
  int unaff_r18;
  int iVar11;
  int iVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  int unaff_r22;
  uint uVar16;
  int iVar17;
  int iVar18;
  int iVar19;
  int iVar20;
  short sVar21;
  undefined8 uVar22;
  undefined4 local_6c;
  short local_68;
  undefined4 local_64;
  short local_60;
  int local_5c;
  undefined4 local_58;
  undefined4 local_54;
  uint local_50;
  
  uVar22 = FUN_802860a8();
  puVar6 = (uint *)((ulonglong)uVar22 >> 0x20);
  puVar8 = (uint *)uVar22;
  local_64 = *puVar6;
  local_60 = *(short *)(puVar6 + 1);
  local_54 = 1;
  local_64._0_2_ = (short)(local_64 >> 0x10);
  iVar9 = (int)*(short *)puVar8 - (int)local_64._0_2_;
  if (iVar9 < 0) {
    local_54 = 0xffffffff;
    iVar9 = -iVar9;
  }
  local_58 = 1;
  iVar10 = (int)*(short *)((int)puVar8 + 2) - (int)local_64._2_2_;
  if (iVar10 < 0) {
    local_58 = 0xffffffff;
    iVar10 = -iVar10;
  }
  sVar21 = 1;
  iVar4 = (int)*(short *)(puVar8 + 1) - (int)local_60;
  if (iVar4 < 0) {
    sVar21 = -1;
    iVar4 = -iVar4;
  }
  iVar20 = iVar10 - iVar9;
  iVar2 = iVar10 * 2;
  iVar19 = iVar4 - iVar9;
  iVar18 = iVar10 - iVar4;
  iVar17 = iVar9 + iVar10 + iVar4;
  FUN_80012fb8(&local_64);
  uVar16 = local_64._0_2_ - DAT_803387f0 & 0x3f;
  uVar15 = local_60 - DAT_803387f4 & 0x3f;
  local_6c = local_64;
  local_68 = local_60;
  iVar10 = 0;
  bVar3 = true;
  local_50 = param_5 & 0xff;
  iVar12 = (int)uVar15 >> 2;
  uVar14 = (int)uVar16 >> 2;
  do {
    bVar1 = iVar17 == 0;
    iVar17 = iVar17 + -1;
    if (bVar1) {
      if (param_3 != (uint *)0x0) {
        *param_3 = *puVar8;
        *(short *)(param_3 + 1) = *(short *)(puVar8 + 1);
      }
      uVar7 = 1;
LAB_80012ce8:
      FUN_802860f4(uVar7);
      return;
    }
    if ((local_50 == 0) || (!bVar3)) {
      if (DAT_803387f8 != 0) {
        if ((DAT_803387f8 != iVar10) || (local_64._2_2_ != local_6c._2_2_)) {
          iVar11 = (int)local_64._2_2_;
          iVar10 = *(int *)(DAT_803387f8 + 4);
          if (iVar11 < iVar10) {
            unaff_r22 = 0;
          }
          else if (iVar11 < *(int *)(DAT_803387f8 + 0xc)) {
            unaff_r22 = iVar11 - iVar10;
          }
          else {
            unaff_r22 = (*(int *)(DAT_803387f8 + 0xc) + -1) - iVar10;
          }
          unaff_r18 = 1;
          local_6c = local_6c & 0xffff0000 | local_64 & 0xffff;
          iVar10 = DAT_803387f8;
        }
        if (((int)(uint)*(byte *)(*(int *)(DAT_803387f8 + 0x24) +
                                 (unaff_r22 << 5 | iVar12 * 2 + ((int)uVar14 >> 3))) >> (uVar14 & 7)
            & 1U) != 0) {
          if (unaff_r18 != 0) {
            local_5c = FUN_80012ec0(*(undefined4 *)(DAT_803387f8 + 0x1c),
                                    *(undefined4 *)(DAT_803387f8 + 0x14),
                                    *(int *)(DAT_803387f8 + 0x24),uVar14,unaff_r22,iVar12);
            unaff_r18 = 0;
          }
          uVar13 = (int)(uint)*(byte *)(local_5c + (uVar15 & 3)) >> ((uVar16 & 3) << 1) & 3;
          if (uVar13 != 0) {
            if (param_4 != (undefined *)0x0) {
              *param_4 = (char)uVar13;
            }
            if (param_3 != (uint *)0x0) {
              *param_3 = local_6c;
              *(short *)(param_3 + 1) = local_68;
            }
            uVar7 = 0;
            goto LAB_80012ce8;
          }
        }
      }
    }
    else {
      bVar3 = false;
    }
    if (iVar20 < 0) {
      if (iVar19 < 0) {
        local_6c = local_64 & 0xffff0000 | local_6c & 0xffff;
        uVar5 = local_64._0_2_ + (short)local_54;
        local_64 = local_64 & 0xffff | (uint)uVar5 << 0x10;
        iVar20 = iVar20 + iVar2;
        iVar19 = iVar19 + iVar4 * 2;
        if ((short)uVar5 - DAT_803387f0 >> 6 != 0) {
          FUN_80012fb8(&local_64);
          iVar10 = 0;
        }
        uVar16 = local_64._0_2_ - DAT_803387f0 & 0x3f;
        uVar13 = (int)uVar16 >> 2;
        bVar1 = uVar13 != uVar14;
        uVar14 = uVar13;
        if (bVar1) {
          unaff_r18 = 1;
        }
      }
      else {
        local_68 = local_60;
        local_60 = local_60 + sVar21;
        iVar19 = iVar19 + iVar9 * -2;
        iVar18 = iVar18 + iVar2;
        if (local_60 - DAT_803387f4 >> 6 != 0) {
          FUN_80012fb8(&local_64);
          iVar10 = 0;
        }
        uVar15 = local_60 - DAT_803387f4 & 0x3f;
        iVar11 = (int)uVar15 >> 2;
        bVar1 = iVar11 != iVar12;
        iVar12 = iVar11;
        if (bVar1) {
          unaff_r18 = 1;
        }
      }
    }
    else if (iVar18 < 0) {
      local_68 = local_60;
      local_60 = local_60 + sVar21;
      iVar19 = iVar19 + iVar9 * -2;
      iVar18 = iVar18 + iVar2;
      if (local_60 - DAT_803387f4 >> 6 != 0) {
        FUN_80012fb8(&local_64);
        iVar10 = 0;
      }
      uVar15 = local_60 - DAT_803387f4 & 0x3f;
      iVar11 = (int)uVar15 >> 2;
      bVar1 = iVar11 != iVar12;
      iVar12 = iVar11;
      if (bVar1) {
        unaff_r18 = 1;
      }
    }
    else {
      local_6c = local_6c & 0xffff0000 | local_64 & 0xffff;
      local_64 = local_64 & 0xffff0000 | (uint)(ushort)(local_64._2_2_ + (short)local_58);
      iVar20 = iVar20 + iVar9 * -2;
      iVar18 = iVar18 + iVar4 * -2;
    }
  } while( true );
}

