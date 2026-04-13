// Function: FUN_80242220
// Entry: 80242220
// Size: 20 bytes

uint FUN_80242220(void)

{
  uint in_HID0;
  
  instructionSynchronize();
  return in_HID0 | 0x8000;
}

