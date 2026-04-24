// Function: FUN_8024377c
// Entry: 8024377c
// Size: 20 bytes

ulonglong FUN_8024377c(void)

{
  uint in_MSR;
  
  return CONCAT44(in_MSR >> 0xf,in_MSR) & 0x1ffff7fff;
}

