// Function: FUN_8007d72c
// Entry: 8007d72c
// Size: 564 bytes

undefined4 FUN_8007d72c(void)

{
  bool bVar1;
  int iVar2;
  uint local_18;
  uint local_14;
  
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
  if (bVar1) {
    DAT_803db700 = 0;
    iVar2 = FUN_802623ac(0,DAT_803dd040,&LAB_8007fdf8);
    bVar1 = iVar2 != -0xd;
    if (iVar2 == -6) {
      iVar2 = FUN_80261a28(0);
      if (iVar2 == -6) {
        iVar2 = FUN_80262cd8(0);
      }
    }
    else if (((iVar2 == -0xd) || (iVar2 == 0)) && (iVar2 = FUN_802643e8(0,&local_18), iVar2 == 0)) {
      if (((DAT_803dd04c | DAT_803dd048) == 0) ||
         ((DAT_803dd04c ^ local_14 | DAT_803dd048 ^ local_18) != 0)) {
        iVar2 = -0x55;
        DAT_803db700 = 0xb;
      }
      else {
        if (bVar1) {
          FUN_80262490(0);
          FUN_80023800(DAT_803dd040);
          DAT_803db700 = 0xd;
          DAT_803dd040 = 0;
          return 1;
        }
        iVar2 = FUN_80262cd8(0);
      }
    }
    FUN_80262490(0);
    FUN_80023800(DAT_803dd040);
    DAT_803dd040 = 0;
    if (iVar2 == -2) {
      DAT_803db700 = 1;
    }
    else if (iVar2 < -2) {
      if (iVar2 != -4) {
        if (iVar2 < -4) {
          if (-6 < iVar2) {
            DAT_803db700 = 4;
          }
        }
        else if (DAT_803db700 != 3) {
          DAT_803db700 = 2;
        }
      }
    }
    else if (iVar2 == 0) {
      DAT_803db700 = 0xd;
      DAT_803dd040 = 0;
      DAT_803dd048 = 0;
      DAT_803dd04c = 0;
      DAT_803dd050 = 0;
      DAT_803dd054 = 0;
      return 1;
    }
  }
  return 0;
}

