// Function: FUN_8024bad0
// Entry: 8024bad0
// Size: 172 bytes

int FUN_8024bad0(void)

{
  undefined *puVar1;
  int iVar2;
  
  FUN_80243e74();
  puVar1 = DAT_803deb88;
  if (DAT_803deba0 == 0) {
    if (DAT_803deb98 == 0) {
      if (DAT_803deb88 == (undefined *)0x0) {
        iVar2 = 0;
      }
      else if (DAT_803deb88 == &DAT_803aebe0) {
        iVar2 = 0;
      }
      else {
        FUN_80243e74();
        iVar2 = *(int *)(puVar1 + 0xc);
        if (iVar2 == 3) {
          iVar2 = 1;
        }
        FUN_80243e9c();
      }
    }
    else {
      iVar2 = 8;
    }
  }
  else {
    iVar2 = -1;
  }
  FUN_80243e9c();
  return iVar2;
}

