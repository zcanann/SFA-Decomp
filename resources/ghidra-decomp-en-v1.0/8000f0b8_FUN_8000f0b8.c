// Function: FUN_8000f0b8
// Entry: 8000f0b8
// Size: 68 bytes

void FUN_8000f0b8(void)

{
  uint uVar1;
  
  uVar1 = FUN_8006fed4();
  FUN_800550d0(0,0,0,DAT_803dc884 + 6,uVar1 & 0xffff,(uVar1 >> 0x10) - (DAT_803dc884 + 6));
  return;
}

