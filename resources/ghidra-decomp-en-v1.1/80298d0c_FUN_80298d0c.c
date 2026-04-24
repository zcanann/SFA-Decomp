// Function: FUN_80298d0c
// Entry: 80298d0c
// Size: 80 bytes

void FUN_80298d0c(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar1 + 0x3f4) = *(byte *)(iVar1 + 0x3f4) & 0xdf;
  *(float *)(iVar1 + 0x414) = FLOAT_803e8b3c;
  *(byte *)(iVar1 + 0x3f3) = *(byte *)(iVar1 + 0x3f3) & 0xef;
  *(undefined2 *)(iVar1 + 0x80a) = 0xffff;
  FUN_80035f9c(param_1);
  return;
}

