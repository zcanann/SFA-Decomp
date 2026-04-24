// Function: FUN_80259c0c
// Entry: 80259c0c
// Size: 400 bytes

void FUN_80259c0c(uint param_1,byte param_2)

{
  bool bVar1;
  uint uVar2;
  
  if (param_2 != 0) {
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = *(uint *)(DAT_803dd210 + 0x1d8) & 0xfffffff0 | 0xf;
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = *(uint *)(DAT_803dd210 + 0x1d0) & 0xfffffffc;
  }
  bVar1 = false;
  uVar2 = *(uint *)(DAT_803dd210 + 0x1dc);
  if (*(char *)(DAT_803dd210 + 0x200) != '\0') {
    if ((uVar2 & 7) != 3) {
      uVar2 = uVar2 & 0xfffffff8 | 3;
      bVar1 = true;
    }
  }
  if (param_2 == 0) {
    if ((uVar2 & 7) != 3) goto LAB_80259ca4;
  }
  if ((uVar2 >> 6 & 1) == 1) {
    bVar1 = true;
    uVar2 = uVar2 & 0xffffffbf;
  }
LAB_80259ca4:
  if (bVar1) {
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = uVar2;
  }
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x1f0);
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 500);
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x1f8);
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = param_1 >> 5 & 0xffffff | 0x4b000000;
  *(uint *)(DAT_803dd210 + 0x1fc) =
       *(uint *)(DAT_803dd210 + 0x1fc) & 0xfffff7ff | (uint)param_2 << 0xb;
  *(uint *)(DAT_803dd210 + 0x1fc) = *(uint *)(DAT_803dd210 + 0x1fc) & 0xffffbfff;
  *(uint *)(DAT_803dd210 + 0x1fc) = *(uint *)(DAT_803dd210 + 0x1fc) & 0xffffff | 0x52000000;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x1fc);
  if (param_2 != 0) {
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x1d8);
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x1d0);
  }
  if (bVar1) {
    DAT_cc008000._0_1_ = 0x61;
    DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x1dc);
  }
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

