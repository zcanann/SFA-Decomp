// Function: FUN_801023a8
// Entry: 801023a8
// Size: 152 bytes

void FUN_801023a8(void)

{
  int iVar1;
  
  iVar1 = FUN_80134f70();
  if (iVar1 == 0) {
    DAT_803dc5f0 = 0xffff;
    countLeadingZeros(0x49 - DAT_803de190);
    FUN_80100d40();
    *(undefined4 *)(DAT_803de19c + 0x120) = 0;
  }
  return;
}

