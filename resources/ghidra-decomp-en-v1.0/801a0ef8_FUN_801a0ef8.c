// Function: FUN_801a0ef8
// Entry: 801a0ef8
// Size: 96 bytes

void FUN_801a0ef8(int param_1,float *param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar1 + 0x15) != '\0') {
    return;
  }
  if (*(char *)(iVar1 + 0x17) != '\0') {
    return;
  }
  *(float *)(iVar1 + 0x24) = *(float *)(iVar1 + 0x24) + param_2[1];
  *(float *)(iVar1 + 0x20) = *(float *)(iVar1 + 0x20) + *param_2;
  *(float *)(iVar1 + 0x28) = *(float *)(iVar1 + 0x28) + param_2[2];
  *(byte *)(iVar1 + 0x49) = *(byte *)(iVar1 + 0x49) | 1;
  return;
}

