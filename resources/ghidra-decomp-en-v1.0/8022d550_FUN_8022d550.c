// Function: FUN_8022d550
// Entry: 8022d550
// Size: 36 bytes

undefined2 FUN_8022d550(int param_1)

{
  ushort uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = *(ushort *)(iVar2 + 0x47c);
  if (9999 < uVar1) {
    uVar1 = 9999;
  }
  *(ushort *)(iVar2 + 0x47c) = uVar1;
  return *(undefined2 *)(iVar2 + 0x47c);
}

