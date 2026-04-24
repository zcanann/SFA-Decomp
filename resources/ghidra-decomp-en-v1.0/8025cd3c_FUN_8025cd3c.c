// Function: FUN_8025cd3c
// Entry: 8025cd3c
// Size: 200 bytes

void FUN_8025cd3c(int param_1,int param_2)

{
  undefined4 uVar1;
  
  uVar1 = FUN_80256810();
  if (*(int *)(DAT_803dc5a8 + 0x4f4) != 0) {
    FUN_802587fc();
  }
  if (*(char *)(DAT_803dc5a8 + 0x4f1) != '\0') {
    FUN_80003494(&DAT_803aece4,DAT_803dc5a8,0x4f8);
  }
  DAT_803aecc4 = param_1 + param_2 + -4;
  DAT_803aecdc = 0;
  DAT_803aecc0 = param_1;
  DAT_803aecc8 = param_2;
  DAT_803aecd4 = param_1;
  DAT_803aecd8 = param_1;
  *(undefined *)(DAT_803dc5a8 + 0x4f0) = 1;
  FUN_80256268(uVar1);
  DAT_803de0f0 = uVar1;
  FUN_80255fe0(&DAT_803aecc0);
  return;
}

