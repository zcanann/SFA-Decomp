// Function: FUN_80179678
// Entry: 80179678
// Size: 68 bytes

void FUN_80179678(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar1 + 0x26c) = FLOAT_803e369c;
  *(undefined *)(iVar1 + 0x274) = 0;
  FUN_80035f00();
  *(undefined *)(iVar1 + 0x25b) = 0;
  return;
}

