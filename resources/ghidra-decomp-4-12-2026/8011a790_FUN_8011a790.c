// Function: FUN_8011a790
// Entry: 8011a790
// Size: 548 bytes

void FUN_8011a790(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (DAT_803dc65b != -1) {
    (**(code **)(*DAT_803dd720 + 8))();
  }
  if ((DAT_803de325 == '\0') && (DAT_803dc084 != '\0')) {
    DAT_803de34d = 1;
    FUN_8000bb38(0,0x418);
    (**(code **)(*DAT_803dd6cc + 8))(0x14,1);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(0);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(1);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(2);
    (**(code **)(*DAT_803dd6f0 + 0x1c))(3);
    DAT_803de34f = 0x23;
    DAT_803de344 = 0;
  }
  else {
    DAT_803dc65b = '\x04';
    iVar2 = 0;
    iVar1 = 0;
    iVar3 = 6;
    do {
      if ((int)(uint)*(byte *)(DAT_803de330 + DAT_803de324 * 0x24 + 0x21) < iVar2) {
        *(ushort *)(PTR_DAT_8031b43c + iVar1 + 0x16) =
             *(ushort *)(PTR_DAT_8031b43c + iVar1 + 0x16) | 0x4000;
      }
      else {
        *(ushort *)(PTR_DAT_8031b43c + iVar1 + 0x16) =
             *(ushort *)(PTR_DAT_8031b43c + iVar1 + 0x16) & 0xbfff;
      }
      if (((int)(*(byte *)(DAT_803de330 + DAT_803de324 * 0x24 + 0x21) - 1) < iVar2) || (4 < iVar2))
      {
        PTR_DAT_8031b43c[iVar1 + 0x1b] = 0xff;
      }
      else {
        PTR_DAT_8031b43c[iVar1 + 0x1b] = (char)iVar2 + '\x01';
      }
      iVar1 = iVar1 + 0x3c;
      iVar2 = iVar2 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
    (**(code **)(*DAT_803dd720 + 4))(PTR_DAT_8031b43c,DAT_8031b440,0,&DAT_8031b448,5,4,0,0,0,0,0,0);
    DAT_803de34e = 2;
  }
  return;
}

