// Function: FUN_802bb844
// Entry: 802bb844
// Size: 96 bytes

bool FUN_802bb844(int param_1)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  bVar1 = (*(byte *)(iVar2 + 0xa8e) & 2) != 0;
  if (bVar1) {
    FUN_800201ac(0x3e3,0);
    *(byte *)(iVar2 + 0xa8e) = *(byte *)(iVar2 + 0xa8e) & 0xfd;
  }
  return bVar1;
}

