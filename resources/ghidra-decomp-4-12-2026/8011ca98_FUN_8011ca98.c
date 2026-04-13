// Function: FUN_8011ca98
// Entry: 8011ca98
// Size: 704 bytes

void FUN_8011ca98(void)

{
  uint uVar1;
  bool bVar3;
  undefined4 uVar2;
  
  if (DAT_803dc690 != -1) {
    (**(code **)(*DAT_803dd720 + 8))();
  }
  DAT_803dc690 = 1;
  uVar1 = FUN_800e8180(2);
  if (uVar1 == 0) {
    PTR_DAT_8031b918[0x10b] = 0xff;
    *(ushort *)(PTR_DAT_8031b918 + 0x142) = *(ushort *)(PTR_DAT_8031b918 + 0x142) | 0x4000;
  }
  else {
    PTR_DAT_8031b918[0x10b] = 5;
    *(ushort *)(PTR_DAT_8031b918 + 0x142) = *(ushort *)(PTR_DAT_8031b918 + 0x142) & 0xbfff;
    PTR_DAT_8031b918[0x146] = 4;
  }
  (**(code **)(*DAT_803dd720 + 4))
            (PTR_DAT_8031b918,DAT_8031b920,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
  bVar3 = FUN_80245dbc();
  if (bVar3) {
    DAT_803a9430 = (**(code **)(*DAT_803dd724 + 0xc))
                             (0x36c,0x22,0,3,*(undefined *)(DAT_803de388 + 9));
  }
  else {
    DAT_803a9430 = (**(code **)(*DAT_803dd724 + 0xc))(0x36c,0x22,0,3,2);
  }
  DAT_803a9434 = (**(code **)(*DAT_803dd724 + 4))
                           (0x124,0xb2,0,0x7f,*(undefined *)(DAT_803de388 + 10),0x3e);
  DAT_803a9438 = (**(code **)(*DAT_803dd724 + 4))
                           (0x124,0xcc,0,0x7f,*(undefined *)(DAT_803de388 + 0xb),0x3e);
  DAT_803a943c = (**(code **)(*DAT_803dd724 + 4))
                           (0x124,0xe6,0,0x7f,*(undefined *)(DAT_803de388 + 0xc),0x3e);
  *(byte *)(DAT_803a943c + 4) = *(byte *)(DAT_803a943c + 4) | 0x40;
  DAT_803a9440 = 0;
  DAT_803a9444 = 0;
  uVar1 = FUN_800e8180(2);
  if (uVar1 != 0) {
    uVar2 = FUN_8000a398();
    DAT_803a9444 = (**(code **)(*DAT_803dd724 + 0xc))
                             (0x3cb,0x27,0,(int)(short)((short)uVar2 + -1),0);
    *(byte *)(DAT_803a9444 + 4) = *(byte *)(DAT_803a9444 + 4) | 0x80;
  }
  (**(code **)(*DAT_803dd724 + 0x20))(DAT_803a9430,1);
  DAT_803de386 = 2;
  return;
}

