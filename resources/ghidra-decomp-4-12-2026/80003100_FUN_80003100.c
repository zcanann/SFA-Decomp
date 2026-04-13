// Function: FUN_80003100
// Entry: 80003100
// Size: 64 bytes

uint FUN_80003100(void)

{
  uint uVar1;
  bool bVar2;
  
  uVar1 = 0x80000000;
  if ((DAT_800030e4 & 0xeef) == 0xeef) {
    bVar2 = FUN_80244fa0(0,0,0);
    uVar1 = (uint)bVar2;
  }
  return uVar1;
}

