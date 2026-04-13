// Function: FUN_80172254
// Entry: 80172254
// Size: 80 bytes

undefined4 FUN_80172254(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(int *)(iVar2 + 0x18) == -2) {
    uVar1 = FUN_800387b4();
    *(uint *)(iVar2 + 0x18) = uVar1 & 0xffff;
  }
  return *(undefined4 *)(iVar2 + 0x18);
}

