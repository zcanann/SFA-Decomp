// Function: FUN_8011c7b4
// Entry: 8011c7b4
// Size: 704 bytes

void FUN_8011c7b4(void)

{
  int iVar1;
  short sVar2;
  
  if (DAT_803dba28 != -1) {
    (**(code **)(*DAT_803dcaa0 + 8))();
  }
  DAT_803dba28 = 1;
  iVar1 = FUN_800e7efc(2);
  if (iVar1 == 0) {
    PTR_DAT_8031acc8[0x10b] = 0xff;
    *(ushort *)(PTR_DAT_8031acc8 + 0x142) = *(ushort *)(PTR_DAT_8031acc8 + 0x142) | 0x4000;
  }
  else {
    PTR_DAT_8031acc8[0x10b] = 5;
    *(ushort *)(PTR_DAT_8031acc8 + 0x142) = *(ushort *)(PTR_DAT_8031acc8 + 0x142) & 0xbfff;
    PTR_DAT_8031acc8[0x146] = 4;
  }
  (**(code **)(*DAT_803dcaa0 + 4))
            (PTR_DAT_8031acc8,DAT_8031acd0,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
  iVar1 = FUN_802456c4();
  if (iVar1 == 1) {
    DAT_803a87d0 = (**(code **)(*DAT_803dcaa4 + 0xc))
                             (0x36c,0x22,0,3,*(undefined *)(DAT_803dd708 + 9));
  }
  else {
    DAT_803a87d0 = (**(code **)(*DAT_803dcaa4 + 0xc))(0x36c,0x22,0,3,2);
  }
  DAT_803a87d4 = (**(code **)(*DAT_803dcaa4 + 4))
                           (0x124,0xb2,0,0x7f,*(undefined *)(DAT_803dd708 + 10),0x3e);
  DAT_803a87d8 = (**(code **)(*DAT_803dcaa4 + 4))
                           (0x124,0xcc,0,0x7f,*(undefined *)(DAT_803dd708 + 0xb),0x3e);
  DAT_803a87dc = (**(code **)(*DAT_803dcaa4 + 4))
                           (0x124,0xe6,0,0x7f,*(undefined *)(DAT_803dd708 + 0xc),0x3e);
  *(byte *)(DAT_803a87dc + 4) = *(byte *)(DAT_803a87dc + 4) | 0x40;
  DAT_803a87e0 = 0;
  DAT_803a87e4 = 0;
  iVar1 = FUN_800e7efc(2);
  if (iVar1 != 0) {
    sVar2 = FUN_8000a378();
    DAT_803a87e4 = (**(code **)(*DAT_803dcaa4 + 0xc))(0x3cb,0x27,0,(int)(short)(sVar2 + -1),0);
    *(byte *)(DAT_803a87e4 + 4) = *(byte *)(DAT_803a87e4 + 4) | 0x80;
  }
  (**(code **)(*DAT_803dcaa4 + 0x20))(DAT_803a87d0,1);
  DAT_803dd706 = 2;
  return;
}

