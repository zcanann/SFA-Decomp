// Function: FUN_80259224
// Entry: 80259224
// Size: 100 bytes

void FUN_80259224(int param_1,uint param_2,uint param_3)

{
  int iVar1;
  
  iVar1 = param_1 * 4;
  *(uint *)(DAT_803dd210 + iVar1 + 0xb8) =
       *(uint *)(DAT_803dd210 + iVar1 + 0xb8) & 0xfffbffff | (param_2 & 0xff) << 0x12;
  *(uint *)(DAT_803dd210 + iVar1 + 0xb8) =
       *(uint *)(DAT_803dd210 + iVar1 + 0xb8) & 0xfff7ffff | (param_3 & 0xff) << 0x13;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + iVar1 + 0xb8);
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

