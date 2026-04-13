// Function: FUN_8025a1a4
// Entry: 8025a1a4
// Size: 328 bytes

void FUN_8025a1a4(int param_1,int param_2)

{
  int iVar1;
  
  if (param_2 == 0x10) {
    iVar1 = 4;
    goto LAB_8025a248;
  }
  if (param_2 < 0x10) {
    if (param_2 == 4) {
      iVar1 = 2;
      goto LAB_8025a248;
    }
    if (param_2 < 4) {
      if (param_2 == 2) {
        iVar1 = 1;
        goto LAB_8025a248;
      }
      if ((param_2 < 2) && (0 < param_2)) {
        iVar1 = 0;
        goto LAB_8025a248;
      }
    }
    else if (param_2 == 8) {
      iVar1 = 3;
      goto LAB_8025a248;
    }
  }
  else {
    if (param_2 == 0x40) {
      iVar1 = 6;
      goto LAB_8025a248;
    }
    if (param_2 < 0x40) {
      if (param_2 == 0x20) {
        iVar1 = 5;
        goto LAB_8025a248;
      }
    }
    else if (param_2 == 0x80) {
      iVar1 = 7;
      goto LAB_8025a248;
    }
  }
  iVar1 = 0;
LAB_8025a248:
  DAT_cc008000._0_1_ = 0x10;
  DAT_cc008000 = iVar1 * 0x10 + 0x600U | 0xf0000;
  DAT_cc008000 = 0;
  DAT_cc008000 = 0;
  DAT_cc008000 = 0;
  DAT_cc008000 = *(undefined4 *)(param_1 + 0xc);
  DAT_cc008000 = *(undefined4 *)(param_1 + 0x10);
  DAT_cc008000 = *(undefined4 *)(param_1 + 0x14);
  DAT_cc008000 = *(undefined4 *)(param_1 + 0x18);
  DAT_cc008000 = *(undefined4 *)(param_1 + 0x1c);
  DAT_cc008000 = *(undefined4 *)(param_1 + 0x20);
  DAT_cc008000 = *(undefined4 *)(param_1 + 0x24);
  DAT_cc008000 = *(undefined4 *)(param_1 + 0x28);
  DAT_cc008000 = *(undefined4 *)(param_1 + 0x2c);
  DAT_cc008000 = *(undefined4 *)(param_1 + 0x30);
  DAT_cc008000 = *(undefined4 *)(param_1 + 0x34);
  DAT_cc008000 = *(undefined4 *)(param_1 + 0x38);
  DAT_cc008000 = *(undefined4 *)(param_1 + 0x3c);
  *(undefined2 *)(DAT_803dd210 + 2) = 1;
  return;
}

