// Function: FUN_8028685c
// Entry: 8028685c
// Size: 248 bytes

/* WARNING: Removing unreachable block (ram,0x802868ac) */

void FUN_8028685c(void)

{
  bool bVar1;
  bool bVar2;
  int iVar3;
  byte local_18 [8];
  undefined4 local_10;
  
  bVar2 = false;
  bVar1 = false;
  while (!bVar2) {
    iVar3 = FUN_80286a70(local_18);
    if (iVar3 == 0) {
      if ((bVar1) && (*DAT_803d82d0 == '\0')) {
        iVar3 = FUN_8028b6c0();
        if (iVar3 == 0) {
          FUN_8028d318();
        }
        bVar1 = false;
      }
      else {
        bVar1 = true;
        FUN_80287980();
      }
    }
    else {
      bVar1 = false;
      if (local_18[0] == 2) {
        FUN_8028779c(local_10);
        FUN_80287d5c();
      }
      else if (local_18[0] < 2) {
        if (local_18[0] != 0) {
          bVar2 = true;
        }
      }
      else if (local_18[0] == 5) {
        FUN_8028b70c();
      }
      else if (local_18[0] < 5) {
        FUN_8028bbd4(local_18);
      }
      FUN_80286954(local_18);
    }
  }
  return;
}

