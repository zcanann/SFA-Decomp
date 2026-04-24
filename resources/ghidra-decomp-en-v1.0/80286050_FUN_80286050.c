// Function: FUN_80286050
// Entry: 80286050
// Size: 12 bytes

void FUN_80286050(void)

{
  int in_r11;
  undefined8 in_f30;
  undefined8 in_f31;
  
  *(undefined8 *)(in_r11 + -0x10) = in_f30;
  *(undefined8 *)(in_r11 + -8) = in_f31;
  return;
}

