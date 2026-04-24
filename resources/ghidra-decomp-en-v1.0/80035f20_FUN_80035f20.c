// Function: FUN_80035f20
// Entry: 80035f20
// Size: 92 bytes

void FUN_80035f20(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x54);
  if (iVar1 == 0) {
    return;
  }
  if ((*(ushort *)(iVar1 + 0x60) & 1) != 0) {
    return;
  }
  *(ushort *)(iVar1 + 0x60) = *(ushort *)(iVar1 + 0x60) | 1;
  *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(iVar1 + 0x1c) = *(undefined4 *)(param_1 + 0x18);
  *(undefined4 *)(iVar1 + 0x20) = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)(iVar1 + 0x24) = *(undefined4 *)(param_1 + 0x20);
  return;
}

