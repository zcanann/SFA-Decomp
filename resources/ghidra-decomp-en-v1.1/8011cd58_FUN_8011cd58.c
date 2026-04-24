// Function: FUN_8011cd58
// Entry: 8011cd58
// Size: 736 bytes

void FUN_8011cd58(void)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  
  if (DAT_803dc690 != -1) {
    (**(code **)(*DAT_803dd720 + 8))();
  }
  DAT_803dc690 = 2;
  iVar4 = -1;
  iVar5 = 3;
  iVar7 = 0xb4;
  do {
    uVar1 = FUN_800e8180(iVar5 - 2U & 0xff);
    if (uVar1 == 0) {
      PTR_DAT_8031b928[iVar7 + -0x21] = (char)iVar4;
      *(ushort *)(PTR_DAT_8031b928 + iVar7 + 0x16) =
           *(ushort *)(PTR_DAT_8031b928 + iVar7 + 0x16) | 0x4000;
    }
    else {
      PTR_DAT_8031b928[iVar7 + -0x21] = (char)iVar5;
      *(ushort *)(PTR_DAT_8031b928 + iVar7 + 0x16) =
           *(ushort *)(PTR_DAT_8031b928 + iVar7 + 0x16) & 0xbfff;
      iVar4 = iVar5;
    }
    iVar7 = iVar7 + -0x3c;
    iVar5 = iVar5 + -1;
  } while (1 < iVar5);
  iVar4 = 1;
  iVar5 = 2;
  iVar7 = 0x78;
  do {
    uVar1 = FUN_800e8180(iVar5 - 2U & 0xff);
    if (uVar1 != 0) {
      PTR_DAT_8031b928[iVar7 + 0x1a] = (char)iVar4;
      *(ushort *)(PTR_DAT_8031b928 + iVar7 + 0x16) =
           *(ushort *)(PTR_DAT_8031b928 + iVar7 + 0x16) & 0xbfff;
      iVar4 = iVar5;
    }
    iVar7 = iVar7 + 0x3c;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 4);
  (**(code **)(*DAT_803dd720 + 4))
            (PTR_DAT_8031b928,DAT_8031b930,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
  DAT_803a9430 = (**(code **)(*DAT_803dd724 + 0xc))(0x366,0x22,0,1,*(undefined *)(DAT_803de388 + 6))
  ;
  uVar1 = countLeadingZeros((uint)*(byte *)(DAT_803de388 + 8));
  DAT_803a9434 = (**(code **)(*DAT_803dd724 + 0xc))(0x36b,0x23,0,1,(int)(short)(uVar1 >> 5));
  puVar6 = &DAT_803a9430;
  uVar1 = 0;
  do {
    uVar2 = FUN_800e8180(uVar1 & 0xff);
    if (uVar2 != 0) {
      if (uVar1 == 1) {
        uVar3 = FUN_800550e0();
        uVar3 = (**(code **)(*DAT_803dd724 + 0xc))(0x507,0x25,0,1,(int)(short)uVar3);
        puVar6[2] = uVar3;
      }
      else {
        uVar3 = FUN_800e8118(uVar1 & 0xff);
        uVar2 = countLeadingZeros(uVar3);
        uVar3 = (**(code **)(*DAT_803dd724 + 0xc))(0x36b,uVar1 + 0x24,0,1,(int)(short)(uVar2 >> 5));
        puVar6[2] = uVar3;
      }
    }
    puVar6 = puVar6 + 1;
    uVar1 = uVar1 + 1;
  } while ((int)uVar1 < 2);
  (**(code **)(*DAT_803dd724 + 0x20))(DAT_803a9430,1);
  DAT_803de386 = 2;
  return;
}

