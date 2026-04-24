// Function: FUN_80119254
// Entry: 80119254
// Size: 84 bytes

undefined4 FUN_80119254(void)

{
  undefined4 uVar1;
  
  if ((DAT_803a6a58 == 0) || (DAT_803a6a5c != '\0')) {
    uVar1 = 0;
  }
  else {
    DAT_803a6a58 = 0;
    FUN_802493c8((int *)&DAT_803a69c0);
    uVar1 = 1;
  }
  return uVar1;
}

