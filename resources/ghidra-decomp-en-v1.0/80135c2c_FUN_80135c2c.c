// Function: FUN_80135c2c
// Entry: 80135c2c
// Size: 152 bytes

void FUN_80135c2c(void)

{
  char in_r8;
  
  if ((((in_r8 != '\0') && (DAT_803dd9ab != '\0')) &&
      (FUN_8003b8f4((double)FLOAT_803e2318), DAT_803dd993 != '\0')) && (DAT_803dd9aa == '\0')) {
    FUN_800200e8(0xdf6,1);
    DAT_803dd9aa = '\x01';
    (**(code **)(*DAT_803dca54 + 0x50))(0x57,0,0,0);
    FUN_8011611c();
    DAT_803dd9a4 = 0;
  }
  return;
}

