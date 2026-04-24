// Function: FUN_8001469c
// Entry: 8001469c
// Size: 32 bytes

void FUN_8001469c(void)

{
  if ((DAT_803dc8f8 & 1) == 0) {
    return;
  }
  DAT_803dc8f8 = DAT_803dc8f8 & 0xfe;
  return;
}

