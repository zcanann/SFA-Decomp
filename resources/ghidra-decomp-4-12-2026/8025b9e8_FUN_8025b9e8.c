// Function: FUN_8025b9e8
// Entry: 8025b9e8
// Size: 352 bytes

void FUN_8025b9e8(int param_1,float *param_2,char param_3)

{
  int iVar1;
  uint uVar2;
  
  if (param_1 != 8) {
    if (param_1 < 8) {
      if (param_1 != 4) {
        if (3 < param_1) {
          iVar1 = param_1 + -5;
          goto LAB_8025ba38;
        }
        if (0 < param_1) {
          iVar1 = param_1 + -1;
          goto LAB_8025ba38;
        }
      }
    }
    else if (param_1 < 0xc) {
      iVar1 = param_1 + -9;
      goto LAB_8025ba38;
    }
  }
  iVar1 = 0;
LAB_8025ba38:
  iVar1 = iVar1 * 3;
  uVar2 = (uint)(char)(param_3 + '\x11');
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = (uVar2 & 3) << 0x16 |
                 (int)(FLOAT_803e8390 * *param_2) & 0x7ffU |
                 ((int)(FLOAT_803e8390 * param_2[3]) & 0x7ffU) << 0xb | (iVar1 + 6) * 0x1000000;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = (iVar1 + 7) * 0x1000000 |
                 (uVar2 & 0xc) << 0x14 |
                 (int)(FLOAT_803e8390 * param_2[1]) & 0x7ffU |
                 ((int)(FLOAT_803e8390 * param_2[4]) & 0x7ffU) << 0xb;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = (iVar1 + 8) * 0x1000000 |
                 (uVar2 & 0x30) << 0x12 |
                 (int)(FLOAT_803e8390 * param_2[2]) & 0x7ffU |
                 ((int)(FLOAT_803e8390 * param_2[5]) & 0x7ffU) << 0xb;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

