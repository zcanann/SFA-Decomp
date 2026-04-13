// Function: FUN_80259858
// Entry: 80259858
// Size: 552 bytes

void FUN_80259858(char param_1,byte *param_2,char param_3,byte *param_4)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  
  if (param_1 == '\0') {
    uVar2 = 0x1666666;
    uVar1 = 0x2666666;
    uVar3 = 0x3666666;
    uVar4 = 0x4666666;
  }
  else {
    uVar2 = *param_2 & 0xf | (param_2[1] & 0xf) << 4 | (param_2[2] & 0xf) << 8 |
            (param_2[3] & 0xf) << 0xc | (param_2[4] & 0xf) << 0x10 | (param_2[5] & 0xf) << 0x14 |
            0x1000000;
    uVar1 = param_2[6] & 0xf | (param_2[7] & 0xf) << 4 | (param_2[8] & 0xf) << 8 |
            (param_2[9] & 0xf) << 0xc | (param_2[10] & 0xf) << 0x10 | (param_2[0xb] & 0xf) << 0x14 |
            0x2000000;
    uVar3 = param_2[0xc] & 0xf | (param_2[0xd] & 0xf) << 4 | (param_2[0xe] & 0xf) << 8 |
            (param_2[0xf] & 0xf) << 0xc | (param_2[0x10] & 0xf) << 0x10 |
            (param_2[0x11] & 0xf) << 0x14 | 0x3000000;
    uVar4 = param_2[0x12] & 0xf | (param_2[0x13] & 0xf) << 4 | (param_2[0x14] & 0xf) << 8 |
            (param_2[0x15] & 0xf) << 0xc | (param_2[0x16] & 0xf) << 0x10 |
            (param_2[0x17] & 0xf) << 0x14 | 0x4000000;
  }
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = uVar2;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = uVar1;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = uVar3;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = uVar4;
  if (param_3 == '\0') {
    uVar1 = 0x53595000;
    uVar2 = 0x54000015;
  }
  else {
    uVar1 = *param_4 & 0xfffff03f | 0x53000000 | (param_4[1] & 0x3fff03f) << 6 |
            (param_4[2] & 0xff03f) << 0xc | (uint)param_4[3] << 0x12;
    uVar2 = param_4[4] & 0xfffff03f | 0x54000000 | (param_4[5] & 0x3fff03f) << 6 |
            (uint)param_4[6] << 0xc;
  }
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = uVar1;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = uVar2;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

