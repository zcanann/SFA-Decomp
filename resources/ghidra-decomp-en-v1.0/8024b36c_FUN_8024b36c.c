// Function: FUN_8024b36c
// Entry: 8024b36c
// Size: 172 bytes

int FUN_8024b36c(void)

{
  undefined *puVar1;
  undefined4 uVar2;
  int iVar3;
  
  uVar2 = FUN_8024377c();
  puVar1 = DAT_803ddf08;
  if (DAT_803ddf20 == 0) {
    if (DAT_803ddf18 == 0) {
      if (DAT_803ddf08 == (undefined *)0x0) {
        iVar3 = 0;
      }
      else if (DAT_803ddf08 == &DAT_803adf80) {
        iVar3 = 0;
      }
      else {
        FUN_8024377c();
        iVar3 = *(int *)(puVar1 + 0xc);
        if (iVar3 == 3) {
          iVar3 = 1;
        }
        FUN_802437a4();
      }
    }
    else {
      iVar3 = 8;
    }
  }
  else {
    iVar3 = -1;
  }
  FUN_802437a4(uVar2);
  return iVar3;
}

