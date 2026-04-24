// Function: FUN_802173d0
// Entry: 802173d0
// Size: 116 bytes

void FUN_802173d0(int param_1)

{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e68e8);
    FUN_8003842c(param_1,0,iVar1 + 0x10,iVar1 + 0x14,iVar1 + 0x18,0);
    *(float *)(iVar1 + 0x14) = *(float *)(iVar1 + 0x14) - FLOAT_803e68ec;
  }
  return;
}

