// Function: FUN_802304d4
// Entry: 802304d4
// Size: 64 bytes

void FUN_802304d4(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = *(uint *)(iVar2 + 0x20);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
    *(undefined4 *)(iVar2 + 0x20) = 0;
  }
  return;
}

