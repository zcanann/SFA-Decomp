// Function: FUN_800128fc
// Entry: 800128fc
// Size: 1060 bytes

void FUN_800128fc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 *param_11,undefined *param_12,
                 uint param_13)

{
  bool bVar1;
  int iVar2;
  bool bVar3;
  int iVar4;
  undefined4 *puVar5;
  short *psVar6;
  int iVar7;
  int iVar8;
  int unaff_r18;
  int iVar9;
  int iVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  int unaff_r22;
  uint uVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  short sVar19;
  undefined8 extraout_f1;
  undefined8 uVar20;
  undefined4 local_6c;
  short local_68;
  undefined4 local_64;
  short local_60;
  int local_5c;
  short sStack_56;
  short sStack_52;
  
  uVar20 = FUN_8028680c();
  puVar5 = (undefined4 *)((ulonglong)uVar20 >> 0x20);
  psVar6 = (short *)uVar20;
  local_6c = *puVar5;
  local_68 = *(short *)(puVar5 + 1);
  sStack_52 = 1;
  local_64._0_2_ = (short)((uint)local_6c >> 0x10);
  iVar7 = (int)*psVar6 - (int)local_64._0_2_;
  if (iVar7 < 0) {
    sStack_52 = -1;
    iVar7 = -iVar7;
  }
  sStack_56 = 1;
  local_64._2_2_ = (short)local_6c;
  iVar8 = (int)psVar6[1] - (int)local_64._2_2_;
  if (iVar8 < 0) {
    sStack_56 = -1;
    iVar8 = -iVar8;
  }
  sVar19 = 1;
  iVar4 = (int)psVar6[2] - (int)local_68;
  if (iVar4 < 0) {
    sVar19 = -1;
    iVar4 = -iVar4;
  }
  iVar18 = iVar8 - iVar7;
  iVar2 = iVar8 * 2;
  iVar17 = iVar4 - iVar7;
  iVar16 = iVar8 - iVar4;
  iVar15 = iVar7 + iVar8 + iVar4;
  uVar20 = FUN_80012fd8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar14 = local_64._0_2_ - DAT_80339450 & 0x3f;
  uVar13 = local_68 - DAT_80339454 & 0x3f;
  iVar8 = 0;
  bVar3 = true;
  iVar10 = (int)uVar13 >> 2;
  uVar12 = (int)uVar14 >> 2;
  local_64 = local_6c;
  local_60 = local_68;
  do {
    bVar1 = iVar15 == 0;
    iVar15 = iVar15 + -1;
    if (bVar1) {
      if (param_11 != (undefined4 *)0x0) {
        *param_11 = *(undefined4 *)psVar6;
        *(short *)(param_11 + 1) = psVar6[2];
      }
LAB_80012d08:
      FUN_80286858();
      return;
    }
    if (((param_13 & 0xff) == 0) || (!bVar3)) {
      if (DAT_80339458 != 0) {
        if ((DAT_80339458 != iVar8) || (local_64._2_2_ != local_6c._2_2_)) {
          iVar9 = (int)local_64._2_2_;
          iVar8 = *(int *)(DAT_80339458 + 4);
          if (iVar9 < iVar8) {
            unaff_r22 = 0;
          }
          else if (iVar9 < *(int *)(DAT_80339458 + 0xc)) {
            unaff_r22 = iVar9 - iVar8;
          }
          else {
            unaff_r22 = (*(int *)(DAT_80339458 + 0xc) + -1) - iVar8;
          }
          unaff_r18 = 1;
          local_6c = CONCAT22(local_6c._0_2_,local_64._2_2_);
          iVar8 = DAT_80339458;
        }
        if (((int)(uint)*(byte *)(*(int *)(DAT_80339458 + 0x24) +
                                 (unaff_r22 << 5 | iVar10 * 2 + ((int)uVar12 >> 3))) >> (uVar12 & 7)
            & 1U) != 0) {
          if (unaff_r18 != 0) {
            local_5c = FUN_80012ee0(*(int *)(DAT_80339458 + 0x1c),*(int *)(DAT_80339458 + 0x14),
                                    *(int *)(DAT_80339458 + 0x24),uVar12,unaff_r22,iVar10);
            unaff_r18 = 0;
          }
          uVar11 = (int)(uint)*(byte *)(local_5c + (uVar13 & 3)) >> ((uVar14 & 3) << 1) & 3;
          if (uVar11 != 0) {
            if (param_12 != (undefined *)0x0) {
              *param_12 = (char)uVar11;
            }
            if (param_11 != (undefined4 *)0x0) {
              *param_11 = local_6c;
              *(short *)(param_11 + 1) = local_68;
            }
            goto LAB_80012d08;
          }
        }
      }
    }
    else {
      bVar3 = false;
    }
    if (iVar18 < 0) {
      if (iVar17 < 0) {
        local_6c = CONCAT22(local_64._0_2_,local_6c._2_2_);
        local_64._0_2_ = local_64._0_2_ + sStack_52;
        iVar18 = iVar18 + iVar2;
        iVar17 = iVar17 + iVar4 * 2;
        if (local_64._0_2_ - DAT_80339450 >> 6 != 0) {
          uVar20 = FUN_80012fd8(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          iVar8 = 0;
        }
        uVar14 = local_64._0_2_ - DAT_80339450 & 0x3f;
        uVar11 = (int)uVar14 >> 2;
        bVar1 = uVar11 != uVar12;
        uVar12 = uVar11;
        if (bVar1) {
          unaff_r18 = 1;
        }
      }
      else {
        local_68 = local_60;
        local_60 = local_60 + sVar19;
        iVar17 = iVar17 + iVar7 * -2;
        iVar16 = iVar16 + iVar2;
        if (local_60 - DAT_80339454 >> 6 != 0) {
          uVar20 = FUN_80012fd8(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          iVar8 = 0;
        }
        uVar13 = local_60 - DAT_80339454 & 0x3f;
        iVar9 = (int)uVar13 >> 2;
        bVar1 = iVar9 != iVar10;
        iVar10 = iVar9;
        if (bVar1) {
          unaff_r18 = 1;
        }
      }
    }
    else if (iVar16 < 0) {
      local_68 = local_60;
      local_60 = local_60 + sVar19;
      iVar17 = iVar17 + iVar7 * -2;
      iVar16 = iVar16 + iVar2;
      if (local_60 - DAT_80339454 >> 6 != 0) {
        uVar20 = FUN_80012fd8(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        iVar8 = 0;
      }
      uVar13 = local_60 - DAT_80339454 & 0x3f;
      iVar9 = (int)uVar13 >> 2;
      bVar1 = iVar9 != iVar10;
      iVar10 = iVar9;
      if (bVar1) {
        unaff_r18 = 1;
      }
    }
    else {
      local_6c = CONCAT22(local_6c._0_2_,local_64._2_2_);
      local_64 = CONCAT22(local_64._0_2_,local_64._2_2_ + sStack_56);
      iVar18 = iVar18 + iVar7 * -2;
      iVar16 = iVar16 + iVar4 * -2;
    }
  } while( true );
}

