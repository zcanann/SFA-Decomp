// Function: FUN_8011c8b0
// Entry: 8011c8b0
// Size: 488 bytes

void FUN_8011c8b0(void)

{
  uint uVar1;
  undefined4 uVar2;
  
  if (DAT_803dc690 != -1) {
    (**(code **)(*DAT_803dd720 + 8))();
  }
  DAT_803dc690 = 3;
  uVar1 = countLeadingZeros((uint)*(byte *)(DAT_803de388 + 2));
  DAT_803a9430 = (**(code **)(*DAT_803dd724 + 0xc))(0x36b,0x22,0,1,(int)(short)(uVar1 >> 5));
  uVar1 = FUN_800e8180(3);
  if ((uVar1 == 0) || (DAT_803dd5e8 != '\0')) {
    PTR_DAT_8031b938[(uint)DAT_8031b940 * 0x3c + -0x5d] = 0xff;
    *(ushort *)(PTR_DAT_8031b938 + (uint)DAT_8031b940 * 0x3c + -0x26) =
         *(ushort *)(PTR_DAT_8031b938 + (uint)DAT_8031b940 * 0x3c + -0x26) | 0x4000;
  }
  else {
    PTR_DAT_8031b938[(uint)DAT_8031b940 * 0x3c + -0x5d] = DAT_8031b940 - 1;
    *(ushort *)(PTR_DAT_8031b938 + (uint)DAT_8031b940 * 0x3c + -0x26) =
         *(ushort *)(PTR_DAT_8031b938 + (uint)DAT_8031b940 * 0x3c + -0x26) & 0xbfff;
    uVar2 = FUN_800e8118(3);
    uVar1 = countLeadingZeros(uVar2);
    DAT_803a9434 = (**(code **)(*DAT_803dd724 + 0xc))(0x36b,0x23,0,1,(int)(short)(uVar1 >> 5));
  }
  (**(code **)(*DAT_803dd724 + 0x20))(DAT_803a9430,1);
  (**(code **)(*DAT_803dd720 + 4))
            (PTR_DAT_8031b938,DAT_8031b940,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
  DAT_803de386 = 2;
  return;
}

