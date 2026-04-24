// Function: FUN_80258b60
// Entry: 80258b60
// Size: 184 bytes

void FUN_80258b60(uint param_1)

{
  ulonglong uVar1;
  
  uVar1 = FUN_80243e74();
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = param_1 & 0xffff | 0x48000000;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = param_1 & 0xffff | 0x47000000;
  if (*(int *)(DAT_803dd210 + 0x4f4) != 0) {
    FUN_80258f60((int)(uVar1 >> 0x20),DAT_803dd210,0xcc010000);
  }
  DAT_cc008000 = 0;
  DAT_cc008000 = 0;
  DAT_cc008000 = 0;
  DAT_cc008000 = 0;
  DAT_cc008000 = 0;
  DAT_cc008000 = 0;
  DAT_cc008000 = 0;
  DAT_cc008000 = 0;
  FUN_80240a74();
  FUN_80243e9c();
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

