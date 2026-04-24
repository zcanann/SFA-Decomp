// Function: FUN_801f31d8
// Entry: 801f31d8
// Size: 192 bytes

void FUN_801f31d8(void)

{
  int iVar1;
  char cVar3;
  uint uVar2;
  char in_r8;
  
  iVar1 = FUN_80286840();
  if (in_r8 != '\0') {
    cVar3 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(iVar1 + 0xac));
    if (cVar3 == '\x04') {
      uVar2 = FUN_80020078(0x2bd);
      if (uVar2 != 0) {
        FUN_8003b9ec(iVar1);
      }
    }
    else {
      FUN_8003b9ec(iVar1);
    }
  }
  FUN_8028688c();
  return;
}

