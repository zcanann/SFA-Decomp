// Function: FUN_8025aeac
// Entry: 8025aeac
// Size: 424 bytes

void FUN_8025aeac(uint *param_1,uint *param_2,int param_3)

{
  int iVar1;
  
  *param_1 = *param_1 & 0xffffff | (uint)(byte)(&DAT_803dd228)[param_3] << 0x18;
  param_1[1] = param_1[1] & 0xffffff | (uint)(byte)(&DAT_803dd230)[param_3] << 0x18;
  param_1[2] = param_1[2] & 0xffffff | (uint)(byte)(&DAT_803dd238)[param_3] << 0x18;
  *param_2 = *param_2 & 0xffffff | (uint)(byte)(&DAT_803dd240)[param_3] << 0x18;
  param_2[1] = param_2[1] & 0xffffff | (uint)(byte)(&DAT_803dd248)[param_3] << 0x18;
  param_1[3] = param_1[3] & 0xffffff | (uint)(byte)(&DAT_803dd250)[param_3] << 0x18;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *param_1;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = param_1[1];
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = param_1[2];
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *param_2;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = param_2[1];
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = param_1[3];
  if ((*(byte *)((int)param_1 + 0x1f) & 2) == 0) {
    iVar1 = (**(code **)(DAT_803dd210 + 0x414))(param_1[6]);
    *(uint *)(iVar1 + 4) =
         *(uint *)(iVar1 + 4) & 0xffffff | (uint)(byte)(&DAT_803dd258)[param_3] << 0x18;
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = *(undefined4 *)(iVar1 + 4);
  }
  *(uint *)(DAT_803dd210 + param_3 * 4 + 0x45c) = param_1[2];
  *(uint *)(DAT_803dd210 + param_3 * 4 + 0x47c) = *param_1;
  *(uint *)(DAT_803dd210 + 0x4f4) = *(uint *)(DAT_803dd210 + 0x4f4) | 1;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

