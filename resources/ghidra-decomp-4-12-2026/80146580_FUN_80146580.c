// Function: FUN_80146580
// Entry: 80146580
// Size: 124 bytes

uint FUN_80146580(void)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = 0;
  uVar1 = FUN_80020078(0x4e4);
  if (uVar1 != 0) {
    uVar2 = 10;
    uVar1 = FUN_80020078(0xdd);
    if (uVar1 != 0) {
      uVar2 = 0xb;
    }
    uVar1 = FUN_80020078(0x25);
    if (uVar1 != 0) {
      uVar2 = uVar2 | 0x20;
    }
    uVar1 = FUN_80020078(0x245);
    if (uVar1 != 0) {
      uVar2 = uVar2 | 0x10;
    }
  }
  return uVar2;
}

