// Function: FUN_8011c5cc
// Entry: 8011c5cc
// Size: 488 bytes

void FUN_8011c5cc(void)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  
  if (DAT_803dba28 != -1) {
    (**(code **)(*DAT_803dcaa0 + 8))();
  }
  DAT_803dba28 = 3;
  uVar1 = countLeadingZeros((uint)*(byte *)(DAT_803dd708 + 2));
  DAT_803a87d0 = (**(code **)(*DAT_803dcaa4 + 0xc))(0x36b,0x22,0,1,(int)(short)(uVar1 >> 5));
  iVar2 = FUN_800e7efc(3);
  if ((iVar2 == 0) || (DAT_803dc968 != '\0')) {
    PTR_DAT_8031ace8[(uint)DAT_8031acf0 * 0x3c + -0x5d] = 0xff;
    *(ushort *)(PTR_DAT_8031ace8 + (uint)DAT_8031acf0 * 0x3c + -0x26) =
         *(ushort *)(PTR_DAT_8031ace8 + (uint)DAT_8031acf0 * 0x3c + -0x26) | 0x4000;
  }
  else {
    PTR_DAT_8031ace8[(uint)DAT_8031acf0 * 0x3c + -0x5d] = DAT_8031acf0 - 1;
    *(ushort *)(PTR_DAT_8031ace8 + (uint)DAT_8031acf0 * 0x3c + -0x26) =
         *(ushort *)(PTR_DAT_8031ace8 + (uint)DAT_8031acf0 * 0x3c + -0x26) & 0xbfff;
    uVar3 = FUN_800e7e94(3);
    uVar1 = countLeadingZeros(uVar3);
    DAT_803a87d4 = (**(code **)(*DAT_803dcaa4 + 0xc))(0x36b,0x23,0,1,(int)(short)(uVar1 >> 5));
  }
  (**(code **)(*DAT_803dcaa4 + 0x20))(DAT_803a87d0,1);
  (**(code **)(*DAT_803dcaa0 + 4))
            (PTR_DAT_8031ace8,DAT_8031acf0,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
  DAT_803dd706 = 2;
  return;
}

