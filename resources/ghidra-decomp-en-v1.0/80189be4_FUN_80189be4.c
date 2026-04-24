// Function: FUN_80189be4
// Entry: 80189be4
// Size: 116 bytes

void FUN_80189be4(int param_1,char param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 == '\0') {
    FUN_800200e8((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x24),0);
    *(byte *)(iVar1 + 0x1d) = *(byte *)(iVar1 + 0x1d) & 0xdf;
  }
  else {
    FUN_800200e8((int)*(short *)(*(int *)(param_1 + 0x4c) + 0x24),1);
    *(byte *)(iVar1 + 0x1d) = *(byte *)(iVar1 + 0x1d) & 0xdf | 0x20;
  }
  return;
}

