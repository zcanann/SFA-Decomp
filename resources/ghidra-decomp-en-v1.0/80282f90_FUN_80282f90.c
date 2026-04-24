// Function: FUN_80282f90
// Entry: 80282f90
// Size: 72 bytes

void FUN_80282f90(uint *param_1,undefined4 param_2)

{
  uint uVar1;
  
  uVar1 = FUN_8026f584(param_2);
  *param_1 = ((*param_1 << 0x10) / uVar1) * 1000 >> 5;
  return;
}

