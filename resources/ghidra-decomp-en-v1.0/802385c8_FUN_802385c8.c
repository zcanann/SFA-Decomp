// Function: FUN_802385c8
// Entry: 802385c8
// Size: 36 bytes

void FUN_802385c8(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar1 + 0xd) = *(byte *)(iVar1 + 0xd) & 0xbf;
  *(byte *)(iVar1 + 0xd) = *(byte *)(iVar1 + 0xd) & 0x7f;
  return;
}

