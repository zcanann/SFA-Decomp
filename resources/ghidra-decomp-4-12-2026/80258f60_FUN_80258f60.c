// Function: FUN_80258f60
// Entry: 80258f60
// Size: 160 bytes

void FUN_80258f60(undefined4 param_1,undefined4 param_2,uint param_3)

{
  undefined4 extraout_r4;
  
  if ((*(uint *)(DAT_803dd210 + 0x4f4) & 1) != 0) {
    FUN_8025b590();
    param_2 = extraout_r4;
  }
  if ((*(uint *)(DAT_803dd210 + 0x4f4) & 2) != 0) {
    FUN_8025bf10(DAT_803dd210,param_2,param_3);
  }
  if ((*(uint *)(DAT_803dd210 + 0x4f4) & 4) != 0) {
    FUN_8025931c();
  }
  if ((*(uint *)(DAT_803dd210 + 0x4f4) & 8) != 0) {
    FUN_802577c0();
  }
  if ((*(uint *)(DAT_803dd210 + 0x4f4) & 0x10) != 0) {
    FUN_80258280();
  }
  if ((*(uint *)(DAT_803dd210 + 0x4f4) & 0x18) != 0) {
    FUN_80257814();
  }
  *(undefined4 *)(DAT_803dd210 + 0x4f4) = 0;
  return;
}

