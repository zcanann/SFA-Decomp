// Function: FUN_8022d520
// Entry: 8022d520
// Size: 48 bytes

void FUN_8022d520(int param_1,ushort param_2)

{
  ushort uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(ushort *)(iVar2 + 0x47c) = *(short *)(iVar2 + 0x47c) + (param_2 & 0xff);
  uVar1 = *(ushort *)(iVar2 + 0x47c);
  if (9999 < uVar1) {
    uVar1 = 9999;
  }
  *(ushort *)(iVar2 + 0x47c) = uVar1;
  return;
}

