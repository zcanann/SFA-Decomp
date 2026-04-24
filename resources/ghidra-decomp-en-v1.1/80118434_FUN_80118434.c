// Function: FUN_80118434
// Entry: 80118434
// Size: 108 bytes

void FUN_80118434(void)

{
  int iVar1;
  int iVar2;
  int local_18 [5];
  
  if (DAT_803de2e0 != 0) {
    while( true ) {
      iVar1 = FUN_80244820((int *)&DAT_803a692c,local_18,0);
      iVar2 = local_18[0];
      if (iVar1 != 1) {
        iVar2 = 0;
      }
      if (iVar2 == 0) break;
      FUN_80119a10(iVar2);
    }
  }
  return;
}

