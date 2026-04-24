// Function: FUN_802227fc
// Entry: 802227fc
// Size: 72 bytes

void FUN_802227fc(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar1 + 8) != 0) {
    FUN_801a0b90();
    *(byte *)(iVar1 + 0x12a) = *(byte *)(iVar1 + 0x12a) & 0x7f;
  }
  return;
}

