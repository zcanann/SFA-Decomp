// Function: FUN_80243e88
// Entry: 80243e88
// Size: 20 bytes

ulonglong FUN_80243e88(void)

{
  uint in_MSR;
  
  return CONCAT44(in_MSR >> 0xf,in_MSR) & 0x1ffffffff | 0x8000;
}

