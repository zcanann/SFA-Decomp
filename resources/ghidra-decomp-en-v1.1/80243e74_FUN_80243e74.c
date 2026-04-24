// Function: FUN_80243e74
// Entry: 80243e74
// Size: 20 bytes

ulonglong FUN_80243e74(void)

{
  uint in_MSR;
  
  return CONCAT44(in_MSR >> 0xf,in_MSR) & 0x1ffff7fff;
}

