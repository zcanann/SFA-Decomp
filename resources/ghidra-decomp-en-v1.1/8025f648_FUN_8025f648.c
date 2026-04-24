// Function: FUN_8025f648
// Entry: 8025f648
// Size: 152 bytes

int FUN_8025f648(int param_1)

{
  int iVar1;
  
  FUN_80243e74();
  while( true ) {
    if ((param_1 < 0) || (1 < param_1)) {
      iVar1 = -0x80;
    }
    else {
      iVar1 = (&DAT_803afe44)[param_1 * 0x44];
    }
    if (iVar1 != -1) break;
    FUN_802471c4((int *)(&DAT_803afecc + param_1 * 0x110));
  }
  FUN_80243e9c();
  return iVar1;
}

