// Function: FUN_8007d99c
// Entry: 8007d99c
// Size: 392 bytes

undefined4 FUN_8007d99c(void)

{
  bool bVar1;
  int iVar2;
  
  DAT_803dd058 = '\0';
  while( true ) {
    iVar2 = FUN_8007de0c(0);
    if (iVar2 == 0) {
      bVar1 = false;
    }
    else {
      DAT_803dd040 = FUN_80023cc8(0xa000,0xffffffff,0);
      if (DAT_803dd040 == 0) {
        DAT_803db700 = 8;
        bVar1 = false;
      }
      else {
        bVar1 = true;
      }
    }
    if (!bVar1) break;
    DAT_803db700 = 0;
    iVar2 = FUN_802623ac(0,DAT_803dd040,&LAB_8007fdf8);
    if ((iVar2 == 0) || (iVar2 == -6)) {
      iVar2 = FUN_80261a28(0);
    }
    if (iVar2 == 0) {
      iVar2 = FUN_80263ec0(0,DAT_803db704);
    }
    FUN_80262490(0);
    FUN_80023800(DAT_803dd040);
    DAT_803dd040 = 0;
    switch(iVar2) {
    case 0:
      DAT_803db700 = 0xd;
      DAT_803dd040 = 0;
      return 1;
    case -0xd:
      DAT_803db700 = 6;
      break;
    case -5:
      DAT_803db700 = 4;
      break;
    case -3:
      if (DAT_803db700 != 3) {
        DAT_803db700 = 2;
      }
      break;
    case -2:
      DAT_803db700 = 1;
    }
    FUN_8007e1ac(0);
    if (DAT_803dd058 == '\0') {
      return 0;
    }
  }
  return 0;
}

