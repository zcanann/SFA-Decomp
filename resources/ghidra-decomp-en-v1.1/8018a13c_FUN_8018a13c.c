// Function: FUN_8018a13c
// Entry: 8018a13c
// Size: 116 bytes

void FUN_8018a13c(int param_1,char param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == '\0') {
    FUN_800201ac((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x24),0);
    *(byte *)(iVar1 + 0x1d) = *(byte *)(iVar1 + 0x1d) & 0xdf;
  }
  else {
    FUN_800201ac((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x24),1);
    *(byte *)(iVar1 + 0x1d) = *(byte *)(iVar1 + 0x1d) & 0xdf | 0x20;
  }
  return;
}

