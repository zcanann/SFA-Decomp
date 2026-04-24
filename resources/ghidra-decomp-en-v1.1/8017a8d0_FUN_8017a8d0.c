// Function: FUN_8017a8d0
// Entry: 8017a8d0
// Size: 140 bytes

void FUN_8017a8d0(void)

{
  int iVar1;
  int iVar2;
  char in_r8;
  
  iVar1 = FUN_80286840();
  iVar2 = *(int *)(iVar1 + 0x4c);
  if (in_r8 != '\0') {
    if ((*(byte *)(iVar2 + 0x23) & 1) != 0) {
      FUN_8003b700((ushort)*(byte *)(iVar2 + 0x20),(ushort)*(byte *)(iVar2 + 0x21),
                   (ushort)*(byte *)(iVar2 + 0x22));
    }
    FUN_8003b9ec(iVar1);
  }
  FUN_8028688c();
  return;
}

