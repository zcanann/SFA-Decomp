// Function: FUN_8002b754
// Entry: 8002b754
// Size: 92 bytes

void FUN_8002b754(int param_1)

{
  undefined *puVar1;
  int iVar2;
  
  if (param_1 == 0) {
    return;
  }
  if (*(int *)(param_1 + 0x78) == 0) {
    return;
  }
  iVar2 = *(int *)(*(int *)(param_1 + 0x50) + 0x40) + (uint)*(byte *)(param_1 + 0xe4) * 0x18;
  puVar1 = (undefined *)(*(int *)(param_1 + 0x78) + (uint)*(byte *)(param_1 + 0xe4) * 5);
  *puVar1 = *(undefined *)(iVar2 + 0xc);
  puVar1[1] = *(undefined *)(iVar2 + 0xd);
  puVar1[2] = *(undefined *)(iVar2 + 0xe);
  puVar1[3] = *(undefined *)(iVar2 + 0xf);
  puVar1[4] = *(undefined *)(iVar2 + 0x10);
  return;
}

