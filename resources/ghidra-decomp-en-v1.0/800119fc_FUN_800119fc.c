// Function: FUN_800119fc
// Entry: 800119fc
// Size: 1204 bytes

/* WARNING: Could not reconcile some variable overlaps */

void FUN_800119fc(undefined4 param_1,undefined4 param_2,uint *param_3)

{
  bool bVar1;
  ushort uVar2;
  uint *puVar3;
  int iVar4;
  undefined4 uVar5;
  uint *puVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  uint uVar12;
  short sVar13;
  int iVar14;
  uint uVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  int unaff_r23;
  int unaff_r24;
  byte *pbVar19;
  int iVar20;
  int iVar21;
  undefined8 uVar22;
  uint local_70;
  short local_6c;
  undefined4 local_68;
  short local_64;
  byte local_60 [12];
  uint local_54;
  uint local_50;
  undefined4 local_4c;
  
  uVar22 = FUN_802860a8();
  puVar3 = (uint *)((ulonglong)uVar22 >> 0x20);
  puVar6 = (uint *)uVar22;
  local_68 = *puVar3;
  local_64 = *(short *)(puVar3 + 1);
  local_4c = 2;
  local_68._0_2_ = (short)(local_68 >> 0x10);
  uVar11 = (int)*(short *)puVar6 - (int)local_68._0_2_;
  if ((int)uVar11 < 0) {
    local_4c = 0xfffffffe;
    uVar11 = -uVar11;
  }
  sVar13 = 2;
  uVar7 = (int)*(short *)(puVar6 + 1) - (int)local_64;
  if ((int)uVar7 < 0) {
    sVar13 = -2;
    uVar7 = -uVar7;
  }
  local_50 = uVar11 & 0xfffffffe;
  local_54 = uVar7 & 0xfffffffe;
  iVar17 = ((int)uVar7 >> 1) - ((int)uVar11 >> 1);
  iVar16 = ((int)uVar11 >> 1) + ((int)uVar7 >> 1);
  FUN_80012fb8(&local_68);
  uVar15 = (int)(local_68._0_2_ - DAT_803387f0 & 0x3fU) >> 2;
  uVar11 = local_64 - DAT_803387f4 & 0x3f;
  iVar14 = (int)uVar11 >> 2;
  uVar7 = uVar15 & 7;
  iVar21 = (local_68._0_2_ - DAT_803387f0 & 3U) * 2;
  iVar20 = iVar21 + 2;
  local_70 = local_68;
  local_6c = local_64;
  do {
    iVar10 = DAT_803387f8;
    bVar1 = iVar16 == 0;
    iVar16 = iVar16 + -1;
    if (bVar1) {
      if (param_3 != (uint *)0x0) {
        *param_3 = *puVar6;
        *(short *)(param_3 + 1) = *(short *)(puVar6 + 1);
      }
      uVar5 = 1;
LAB_80011e98:
      FUN_802860f4(uVar5);
      return;
    }
    if (DAT_803387f8 != 0) {
      iVar18 = 0;
      pbVar19 = local_60;
      do {
        iVar4 = iVar18 + local_68._2_2_ + -1;
        iVar8 = *(int *)(iVar10 + 4);
        if (iVar4 < iVar8) {
          iVar8 = 0;
        }
        else if (iVar4 < *(int *)(iVar10 + 0xc)) {
          iVar8 = iVar4 - iVar8;
        }
        else {
          iVar8 = (*(int *)(iVar10 + 0xc) + -1) - iVar8;
        }
        if (((int)(uint)*(byte *)(*(int *)(iVar10 + 0x24) +
                                 (iVar8 << 5 | iVar14 * 2 + ((int)uVar15 >> 3))) >> uVar7 & 1U) == 0
           ) {
          *pbVar19 = 0;
          pbVar19[1] = 0;
          pbVar19[2] = 0;
          pbVar19[3] = 0;
        }
        else {
          iVar4 = FUN_80012ec0(*(undefined4 *)(iVar10 + 0x1c),*(undefined4 *)(iVar10 + 0x14),
                               *(int *)(iVar10 + 0x24),uVar15,iVar8,iVar14);
          uVar9 = (uint)*(byte *)((uVar11 & 3) + iVar4);
          *pbVar19 = (byte)((int)uVar9 >> iVar21) & 3;
          pbVar19[1] = (byte)((int)uVar9 >> iVar20) & 3;
          uVar9 = (uint)*(byte *)((uVar11 & 3) + 1 + iVar4);
          pbVar19[2] = (byte)((int)uVar9 >> iVar21) & 3;
          pbVar19[3] = (byte)((int)uVar9 >> iVar20) & 3;
        }
        pbVar19 = pbVar19 + 4;
        iVar18 = iVar18 + 1;
      } while (iVar18 < 3);
      for (iVar10 = 1; -1 < iVar10; iVar10 = iVar10 + -1) {
        iVar4 = iVar10 + 1;
        unaff_r24 = 0;
        iVar18 = iVar10 * 4;
        if (((((local_60[iVar18] & 2) != 0) || ((local_60[iVar18 + 1] & 2) != 0)) ||
            ((local_60[iVar18 + 2] & 2) != 0)) || ((local_60[iVar18 + 3] & 2) != 0)) {
          unaff_r24 = 1;
        }
        if ((unaff_r24 == 0) &&
           (((iVar8 = iVar4 * 4, (local_60[iVar8] & 2) != 0 || ((local_60[iVar8 + 1] & 2) != 0)) ||
            (((local_60[iVar8 + 2] & 2) != 0 || ((local_60[iVar8 + 3] & 2) != 0)))))) {
          unaff_r24 = 1;
        }
        unaff_r23 = iVar10;
        if (unaff_r24 == 0) {
          iVar8 = iVar4 * 4;
          uVar12 = (uint)local_60[iVar18] + (uint)local_60[iVar18 + 1] + (uint)local_60[iVar18 + 2]
                   + (uint)local_60[iVar18 + 3];
          uVar9 = (uint)local_60[iVar8] + (uint)local_60[iVar8 + 1] + (uint)local_60[iVar8 + 2] +
                  (uint)local_60[iVar8 + 3];
          if ((iVar4 == 2) && (uVar9 == 0)) {
            unaff_r24 = 1;
          }
          else {
            if (iVar4 == 1) {
              if (uVar9 <= uVar12) {
                uVar9 = uVar12;
                unaff_r23 = iVar10 + -1;
              }
            }
            else if (uVar9 < uVar12) {
              uVar9 = uVar12;
              unaff_r23 = iVar10 + -1;
            }
            if (uVar9 < 2) {
              unaff_r24 = 1;
            }
            else {
              iVar10 = 0;
            }
          }
        }
      }
      if (unaff_r24 != 0) {
        if (param_3 != (uint *)0x0) {
          *param_3 = local_70;
          *(short *)(param_3 + 1) = local_6c;
        }
        uVar5 = 0;
        goto LAB_80011e98;
      }
      uVar2 = local_68._2_2_ + (short)unaff_r23;
      local_68 = local_68 & 0xffff0000 | (uint)uVar2;
      local_70 = local_70 & 0xffff0000 | (uint)uVar2;
    }
    if (iVar17 < 0) {
      local_70 = local_68 & 0xffff0000 | local_70 & 0xffff;
      uVar2 = local_68._0_2_ + (short)local_4c;
      local_68 = local_68 & 0xffff | (uint)uVar2 << 0x10;
      iVar17 = iVar17 + local_54;
      if ((short)uVar2 - DAT_803387f0 >> 6 != 0) {
        FUN_80012fb8(&local_68);
      }
      uVar15 = (int)(local_68._0_2_ - DAT_803387f4 & 0x3fU) >> 2;
      uVar7 = uVar15 & 7;
      iVar21 = (local_68._0_2_ - DAT_803387f4 & 3U) * 2;
      iVar20 = iVar21 + 2;
    }
    else {
      local_6c = local_64;
      local_64 = local_64 + sVar13;
      iVar17 = iVar17 - local_50;
      if (local_64 - DAT_803387f4 >> 6 != 0) {
        FUN_80012fb8(&local_68);
      }
      uVar11 = local_64 - DAT_803387f4 & 0x3f;
      iVar14 = (int)uVar11 >> 2;
    }
  } while( true );
}

