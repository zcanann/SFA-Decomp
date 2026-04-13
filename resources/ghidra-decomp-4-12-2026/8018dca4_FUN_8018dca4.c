// Function: FUN_8018dca4
// Entry: 8018dca4
// Size: 156 bytes

void FUN_8018dca4(void)

{
  int iVar1;
  uint uVar2;
  char in_r8;
  
  iVar1 = FUN_80286840();
  if (((in_r8 != '\0') && (*(short *)(iVar1 + 0x46) != 0x1b8)) &&
     (((in_r8 != '\0' && (*(short *)(iVar1 + 0x46) != 0x6bf)) ||
      (uVar2 = FUN_80020078((int)*(short *)(*(int *)(iVar1 + 0xb8) + 0x3a)), uVar2 != 0)))) {
    FUN_8003b9ec(iVar1);
  }
  FUN_8028688c();
  return;
}

