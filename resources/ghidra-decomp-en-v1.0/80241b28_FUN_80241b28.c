// Function: FUN_80241b28
// Entry: 80241b28
// Size: 20 bytes

uint FUN_80241b28(void)

{
  uint in_HID0;
  
  instructionSynchronize();
  return in_HID0 | 0x8000;
}

