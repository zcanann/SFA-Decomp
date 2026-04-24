// Function: FUN_80146158
// Entry: 80146158
// Size: 124 bytes

uint FUN_80146158(void)

{
  int iVar1;
  uint uVar2;
  
  uVar2 = 0;
  iVar1 = FUN_8001ffb4(0x4e4);
  if (iVar1 != 0) {
    uVar2 = 10;
    iVar1 = FUN_8001ffb4(0xdd);
    if (iVar1 != 0) {
      uVar2 = 0xb;
    }
    iVar1 = FUN_8001ffb4(0x25);
    if (iVar1 != 0) {
      uVar2 = uVar2 | 0x20;
    }
    iVar1 = FUN_8001ffb4(0x245);
    if (iVar1 != 0) {
      uVar2 = uVar2 | 0x10;
    }
  }
  return uVar2;
}

