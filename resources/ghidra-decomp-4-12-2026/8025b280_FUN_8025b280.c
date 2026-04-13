// Function: FUN_8025b280
// Entry: 8025b280
// Size: 580 bytes

void FUN_8025b280(int param_1,uint *param_2)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint unaff_r27;
  uint unaff_r28;
  uint uVar14;
  uint uVar15;
  uint local_58;
  uint local_54 [3];
  
  uVar13 = 0;
  uVar1 = *(uint *)(param_1 + 8);
  uVar4 = (uint)*(ushort *)(param_1 + 0x1c);
  uVar8 = *param_2 & 0x7fff;
  uVar9 = *(uint *)(param_1 + 0xc) & 0x1fffff;
  uVar7 = param_2[1] & 0x7fff;
  uVar3 = countLeadingZeros(6 - (uVar1 >> 0x14 & 0xf));
  uVar12 = uVar9 | 0x60000000;
  uVar11 = uVar8 | 0x61000000;
  uVar10 = uVar7 | 0x62000000;
  uVar14 = uVar4 & 0xfffe7fff | 0x63000000 | (uint)*(byte *)(param_1 + 0x1e) << 0xf;
  if ((*(byte *)(param_1 + 0x1f) & 1) == 1) {
    unaff_r28 = (uVar1 & 0x3ff) + 1;
    unaff_r27 = (uVar1 >> 10 & 0x3ff) + 1;
    if (unaff_r27 < unaff_r28) {
      iVar2 = countLeadingZeros(unaff_r28);
      uVar13 = 0x1fU - iVar2 & 0xffff;
    }
    else {
      iVar2 = countLeadingZeros(unaff_r27);
      uVar13 = 0x1fU - iVar2 & 0xffff;
    }
  }
  FUN_8025bfdc();
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = uVar12;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = uVar11;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = uVar10;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = uVar14;
  if (uVar13 != 0) {
    for (uVar1 = 0; uVar1 < uVar13; uVar1 = uVar1 + 1) {
      if ((uVar3 >> 5 & 0xff) == 0) {
        uVar9 = uVar9 + uVar4;
        if ((uVar1 & 1) == 0) {
          uVar8 = uVar8 + uVar4;
        }
        else {
          uVar7 = uVar7 + uVar4;
        }
      }
      else {
        uVar9 = uVar9 + uVar4 * 2;
        uVar8 = uVar8 + uVar4;
        uVar7 = uVar7 + uVar4;
      }
      uVar15 = uVar8;
      uVar4 = uVar7;
      if ((uVar1 & 1) != 0) {
        uVar15 = uVar7;
        uVar4 = uVar8;
      }
      uVar6 = unaff_r28 >> uVar1 + 1 & 0xffff;
      uVar5 = unaff_r27 >> uVar1 + 1 & 0xffff;
      FUN_8025a7ec(*(undefined4 *)(param_1 + 0x14),&local_58,local_54);
      if (uVar6 == 0) {
        uVar6 = 1;
      }
      if (uVar5 == 0) {
        uVar5 = 1;
      }
      DAT_cc008000._0_1_ = 0x61;
      uVar12 = uVar12 & 0xffe00000 | uVar9;
      DAT_cc008000 = uVar12;
      DAT_cc008000._0_1_ = 0x61;
      uVar11 = uVar11 & 0xffff8000 | uVar4;
      DAT_cc008000 = uVar11;
      DAT_cc008000._0_1_ = 0x61;
      uVar10 = uVar10 & 0xffff8000 | uVar15;
      DAT_cc008000 = uVar10;
      DAT_cc008000._0_1_ = 0x61;
      uVar4 = ((int)(uVar6 + (1 << local_58) + -1) >> (local_58 & 0x3f)) *
              ((int)(uVar5 + (1 << local_54[0]) + -1) >> (local_54[0] & 0x3f));
      uVar14 = uVar14 & 0xffff8000 | uVar4;
      DAT_cc008000 = uVar14;
    }
  }
  FUN_8025bfdc();
  return;
}

