// Function: FUN_80217a48
// Entry: 80217a48
// Size: 116 bytes

void FUN_80217a48(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
    FUN_80038524(param_1,0,(float *)(iVar1 + 0x10),(undefined4 *)(iVar1 + 0x14),
                 (float *)(iVar1 + 0x18),0);
    *(float *)(iVar1 + 0x14) = *(float *)(iVar1 + 0x14) - FLOAT_803e7584;
  }
  return;
}

