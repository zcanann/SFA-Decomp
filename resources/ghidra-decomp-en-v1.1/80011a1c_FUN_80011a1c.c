// Function: FUN_80011a1c
// Entry: 80011a1c
// Size: 1204 bytes

void FUN_80011a1c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 *param_11)

{
  bool bVar1;
  short sVar2;
  undefined4 *puVar3;
  int iVar4;
  short *psVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  short sVar12;
  int iVar13;
  uint uVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int unaff_r23;
  int unaff_r24;
  byte *pbVar18;
  int iVar19;
  int iVar20;
  undefined8 extraout_f1;
  undefined8 uVar21;
  undefined4 local_70;
  short local_6c;
  undefined4 local_68;
  short local_64;
  byte local_60 [12];
  uint local_54;
  uint local_50;
  undefined4 local_4c;
  
  uVar21 = FUN_8028680c();
  puVar3 = (undefined4 *)((ulonglong)uVar21 >> 0x20);
  psVar5 = (short *)uVar21;
  local_70 = *puVar3;
  local_6c = *(short *)(puVar3 + 1);
  local_4c = 2;
  local_68._0_2_ = (short)((uint)local_70 >> 0x10);
  uVar10 = (int)*psVar5 - (int)local_68._0_2_;
  if ((int)uVar10 < 0) {
    local_4c = 0xfffffffe;
    uVar10 = -uVar10;
  }
  sVar12 = 2;
  uVar6 = (int)psVar5[2] - (int)local_6c;
  if ((int)uVar6 < 0) {
    sVar12 = -2;
    uVar6 = -uVar6;
  }
  local_50 = uVar10 & 0xfffffffe;
  local_54 = uVar6 & 0xfffffffe;
  iVar16 = ((int)uVar6 >> 1) - ((int)uVar10 >> 1);
  iVar15 = ((int)uVar10 >> 1) + ((int)uVar6 >> 1);
  uVar21 = FUN_80012fd8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar14 = (int)(local_68._0_2_ - DAT_80339450 & 0x3fU) >> 2;
  uVar10 = local_6c - DAT_80339454 & 0x3f;
  iVar13 = (int)uVar10 >> 2;
  uVar6 = uVar14 & 7;
  iVar20 = (local_68._0_2_ - DAT_80339450 & 3U) * 2;
  iVar19 = iVar20 + 2;
  local_68 = local_70;
  local_64 = local_6c;
  do {
    iVar9 = DAT_80339458;
    bVar1 = iVar15 == 0;
    iVar15 = iVar15 + -1;
    if (bVar1) {
      if (param_11 != (undefined4 *)0x0) {
        *param_11 = *(undefined4 *)psVar5;
        *(short *)(param_11 + 1) = psVar5[2];
      }
LAB_80011eb8:
      FUN_80286858();
      return;
    }
    if (DAT_80339458 != 0) {
      iVar17 = 0;
      pbVar18 = local_60;
      do {
        iVar4 = iVar17 + local_68._2_2_ + -1;
        iVar7 = *(int *)(iVar9 + 4);
        if (iVar4 < iVar7) {
          iVar7 = 0;
        }
        else if (iVar4 < *(int *)(iVar9 + 0xc)) {
          iVar7 = iVar4 - iVar7;
        }
        else {
          iVar7 = (*(int *)(iVar9 + 0xc) + -1) - iVar7;
        }
        if (((int)(uint)*(byte *)(*(int *)(iVar9 + 0x24) +
                                 (iVar7 << 5 | iVar13 * 2 + ((int)uVar14 >> 3))) >> uVar6 & 1U) == 0
           ) {
          *pbVar18 = 0;
          pbVar18[1] = 0;
          pbVar18[2] = 0;
          pbVar18[3] = 0;
        }
        else {
          iVar4 = FUN_80012ee0(*(int *)(iVar9 + 0x1c),*(int *)(iVar9 + 0x14),*(int *)(iVar9 + 0x24),
                               uVar14,iVar7,iVar13);
          uVar8 = (uint)*(byte *)((uVar10 & 3) + iVar4);
          *pbVar18 = (byte)((int)uVar8 >> iVar20) & 3;
          pbVar18[1] = (byte)((int)uVar8 >> iVar19) & 3;
          uVar8 = (uint)*(byte *)((uVar10 & 3) + 1 + iVar4);
          pbVar18[2] = (byte)((int)uVar8 >> iVar20) & 3;
          pbVar18[3] = (byte)((int)uVar8 >> iVar19) & 3;
        }
        pbVar18 = pbVar18 + 4;
        iVar17 = iVar17 + 1;
      } while (iVar17 < 3);
      for (iVar9 = 1; -1 < iVar9; iVar9 = iVar9 + -1) {
        iVar4 = iVar9 + 1;
        unaff_r24 = 0;
        iVar17 = iVar9 * 4;
        if (((((local_60[iVar17] & 2) != 0) || ((local_60[iVar17 + 1] & 2) != 0)) ||
            ((local_60[iVar17 + 2] & 2) != 0)) || ((local_60[iVar17 + 3] & 2) != 0)) {
          unaff_r24 = 1;
        }
        if ((unaff_r24 == 0) &&
           (((iVar7 = iVar4 * 4, (local_60[iVar7] & 2) != 0 || ((local_60[iVar7 + 1] & 2) != 0)) ||
            (((local_60[iVar7 + 2] & 2) != 0 || ((local_60[iVar7 + 3] & 2) != 0)))))) {
          unaff_r24 = 1;
        }
        unaff_r23 = iVar9;
        if (unaff_r24 == 0) {
          iVar7 = iVar4 * 4;
          uVar11 = (uint)local_60[iVar17] + (uint)local_60[iVar17 + 1] + (uint)local_60[iVar17 + 2]
                   + (uint)local_60[iVar17 + 3];
          uVar8 = (uint)local_60[iVar7] + (uint)local_60[iVar7 + 1] + (uint)local_60[iVar7 + 2] +
                  (uint)local_60[iVar7 + 3];
          if ((iVar4 == 2) && (uVar8 == 0)) {
            unaff_r24 = 1;
          }
          else {
            if (iVar4 == 1) {
              if (uVar8 <= uVar11) {
                uVar8 = uVar11;
                unaff_r23 = iVar9 + -1;
              }
            }
            else if (uVar8 < uVar11) {
              uVar8 = uVar11;
              unaff_r23 = iVar9 + -1;
            }
            if (uVar8 < 2) {
              unaff_r24 = 1;
            }
            else {
              iVar9 = 0;
            }
          }
        }
      }
      if (unaff_r24 != 0) {
        if (param_11 != (undefined4 *)0x0) {
          *param_11 = local_70;
          *(short *)(param_11 + 1) = local_6c;
        }
        goto LAB_80011eb8;
      }
      sVar2 = local_68._2_2_ + (short)unaff_r23;
      local_68 = CONCAT22(local_68._0_2_,sVar2);
      local_70 = CONCAT22(local_70._0_2_,sVar2);
    }
    if (iVar16 < 0) {
      local_70 = CONCAT22(local_68._0_2_,local_70._2_2_);
      sVar2 = local_68._0_2_ + (short)local_4c;
      local_68 = CONCAT22(sVar2,local_68._2_2_);
      iVar16 = iVar16 + local_54;
      if (sVar2 - DAT_80339450 >> 6 != 0) {
        uVar21 = FUN_80012fd8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      uVar14 = (int)(sVar2 - DAT_80339454 & 0x3fU) >> 2;
      uVar6 = uVar14 & 7;
      iVar20 = (sVar2 - DAT_80339454 & 3U) * 2;
      iVar19 = iVar20 + 2;
    }
    else {
      local_6c = local_64;
      local_64 = local_64 + sVar12;
      iVar16 = iVar16 - local_50;
      if (local_64 - DAT_80339454 >> 6 != 0) {
        uVar21 = FUN_80012fd8(uVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      uVar10 = local_64 - DAT_80339454 & 0x3f;
      iVar13 = (int)uVar10 >> 2;
    }
  } while( true );
}

