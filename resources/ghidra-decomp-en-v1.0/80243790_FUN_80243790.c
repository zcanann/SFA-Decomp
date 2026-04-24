// Function: FUN_80243790
// Entry: 80243790
// Size: 20 bytes

ulonglong FUN_80243790(void)

{
  uint in_MSR;
  
  return CONCAT44(in_MSR >> 0xf,in_MSR) & 0x1ffffffff | 0x8000;
}

