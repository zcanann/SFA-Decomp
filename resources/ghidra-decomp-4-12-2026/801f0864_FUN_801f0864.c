// Function: FUN_801f0864
// Entry: 801f0864
// Size: 192 bytes

void FUN_801f0864(void)

{
  int iVar1;
  uint uVar2;
  char in_r8;
  
  iVar1 = FUN_8028683c();
  uVar2 = FUN_80020078(0x78);
  if (((uVar2 == 0) && (in_r8 != '\0')) &&
     ((*(short *)(iVar1 + 0x46) != 0x188 || (*(int *)(*(int *)(iVar1 + 0x30) + 0xf4) < 7)))) {
    FUN_8003b9ec(iVar1);
    if (DAT_803de8f0 != '\0') {
      (**(code **)(*DAT_803dd710 + 4))(1);
    }
  }
  FUN_80286888();
  return;
}

