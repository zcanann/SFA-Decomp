// Function: FUN_80179b40
// Entry: 80179b40
// Size: 68 bytes

void FUN_80179b40(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar1 + 0x26c) = FLOAT_803e4334;
  *(undefined *)(iVar1 + 0x274) = 0;
  FUN_80035ff8(param_1);
  *(undefined *)(iVar1 + 0x25b) = 0;
  return;
}

