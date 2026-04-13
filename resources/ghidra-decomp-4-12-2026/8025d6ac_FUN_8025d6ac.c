// Function: FUN_8025d6ac
// Entry: 8025d6ac
// Size: 212 bytes

void FUN_8025d6ac(undefined4 *param_1,int param_2)

{
  *(int *)(DAT_803dd210 + 0x420) = param_2;
  *(undefined4 *)(DAT_803dd210 + 0x424) = *param_1;
  *(undefined4 *)(DAT_803dd210 + 0x42c) = param_1[5];
  *(undefined4 *)(DAT_803dd210 + 0x434) = param_1[10];
  *(undefined4 *)(DAT_803dd210 + 0x438) = param_1[0xb];
  if (param_2 == 1) {
    *(undefined4 *)(DAT_803dd210 + 0x428) = param_1[3];
    *(undefined4 *)(DAT_803dd210 + 0x430) = param_1[7];
  }
  else {
    *(undefined4 *)(DAT_803dd210 + 0x428) = param_1[2];
    *(undefined4 *)(DAT_803dd210 + 0x430) = param_1[6];
  }
  DAT_cc008000._0_1_ = 0x10;
  DAT_cc008000 = 0x61020;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x424);
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x428);
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x42c);
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x430);
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x434);
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x438);
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x420);
  *(undefined2 *)(DAT_803dd210 + 2) = 1;
  return;
}

