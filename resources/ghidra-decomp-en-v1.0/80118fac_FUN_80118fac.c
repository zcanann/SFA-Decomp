// Function: FUN_80118fac
// Entry: 80118fac
// Size: 84 bytes

undefined4 FUN_80118fac(void)

{
  undefined4 uVar1;
  
  if ((DAT_803a5df8 == 0) || (DAT_803a5dfc != '\0')) {
    uVar1 = 0;
  }
  else {
    DAT_803a5df8 = 0;
    FUN_80248c64();
    uVar1 = 1;
  }
  return uVar1;
}

