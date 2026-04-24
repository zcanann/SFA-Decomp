// Function: FUN_8011dd88
// Entry: 8011dd88
// Size: 152 bytes

void FUN_8011dd88(void)

{
  int iVar1;
  
  iVar1 = (**(code **)(*DAT_803dcaac + 0x8c))();
  FUN_8012c558();
  if (*(char *)(iVar1 + 9) == '\0') {
    if (DAT_803db424 == '\0') {
      DAT_803dd780 = 10;
    }
    else {
      DAT_803dd780 = 9;
    }
  }
  else {
    DAT_803dd780 = 8;
  }
  DAT_803dd8dc = FUN_80019bf0();
  FUN_80019970(0xb);
  FLOAT_803dd764 = FLOAT_803e1e60;
  DAT_803dd7d8 = 1;
  return;
}

