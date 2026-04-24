// Function: FUN_8028dac8
// Entry: 8028dac8
// Size: 132 bytes

/* WARNING: Removing unreachable block (ram,0x8028db14) */

undefined4 FUN_8028dac8(void)

{
  int iVar1;
  byte bVar2;
  
  iVar1 = FUN_8028adac();
  if (iVar1 == 0) {
    return 1;
  }
  bVar2 = FUN_8028d0e0();
  if (bVar2 != 1) {
    if (bVar2 == 0) {
      return 0;
    }
    if (bVar2 < 3) {
      return 2;
    }
  }
  return 1;
}

