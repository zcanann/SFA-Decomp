// Function: FUN_8000f0d8
// Entry: 8000f0d8
// Size: 68 bytes

void FUN_8000f0d8(void)

{
  uint uVar1;
  
  uVar1 = FUN_80070050();
  FUN_8005524c(0,0,0,DAT_803dd504 + 6,uVar1 & 0xffff,(uVar1 >> 0x10) - (DAT_803dd504 + 6));
  return;
}

