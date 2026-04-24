// Function: FUN_802bb0e4
// Entry: 802bb0e4
// Size: 96 bytes

bool FUN_802bb0e4(int param_1)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  bVar1 = (*(byte *)(iVar2 + 0xa8e) & 2) != 0;
  if (bVar1) {
    FUN_800200e8(0x3e3,0);
    *(byte *)(iVar2 + 0xa8e) = *(byte *)(iVar2 + 0xa8e) & 0xfd;
  }
  return bVar1;
}

