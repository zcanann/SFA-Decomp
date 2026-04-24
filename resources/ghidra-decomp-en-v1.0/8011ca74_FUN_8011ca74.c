// Function: FUN_8011ca74
// Entry: 8011ca74
// Size: 736 bytes

void FUN_8011ca74(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  short sVar5;
  undefined4 uVar4;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  int iVar9;
  
  if (DAT_803dba28 != -1) {
    (**(code **)(*DAT_803dcaa0 + 8))();
  }
  DAT_803dba28 = 2;
  iVar6 = -1;
  iVar7 = 3;
  iVar9 = 0xb4;
  do {
    iVar3 = FUN_800e7efc(iVar7 - 2U & 0xff);
    if (iVar3 == 0) {
      PTR_DAT_8031acd8[iVar9 + -0x21] = (char)iVar6;
      *(ushort *)(PTR_DAT_8031acd8 + iVar9 + 0x16) =
           *(ushort *)(PTR_DAT_8031acd8 + iVar9 + 0x16) | 0x4000;
    }
    else {
      PTR_DAT_8031acd8[iVar9 + -0x21] = (char)iVar7;
      *(ushort *)(PTR_DAT_8031acd8 + iVar9 + 0x16) =
           *(ushort *)(PTR_DAT_8031acd8 + iVar9 + 0x16) & 0xbfff;
      iVar6 = iVar7;
    }
    iVar9 = iVar9 + -0x3c;
    iVar7 = iVar7 + -1;
  } while (1 < iVar7);
  iVar6 = 1;
  iVar7 = 2;
  iVar9 = 0x78;
  do {
    iVar3 = FUN_800e7efc(iVar7 - 2U & 0xff);
    if (iVar3 != 0) {
      PTR_DAT_8031acd8[iVar9 + 0x1a] = (char)iVar6;
      *(ushort *)(PTR_DAT_8031acd8 + iVar9 + 0x16) =
           *(ushort *)(PTR_DAT_8031acd8 + iVar9 + 0x16) & 0xbfff;
      iVar6 = iVar7;
    }
    iVar9 = iVar9 + 0x3c;
    iVar7 = iVar7 + 1;
  } while (iVar7 < 4);
  (**(code **)(*DAT_803dcaa0 + 4))
            (PTR_DAT_8031acd8,DAT_8031ace0,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
  DAT_803a87d0 = (**(code **)(*DAT_803dcaa4 + 0xc))(0x366,0x22,0,1,*(undefined *)(DAT_803dd708 + 6))
  ;
  uVar1 = countLeadingZeros((uint)*(byte *)(DAT_803dd708 + 8));
  DAT_803a87d4 = (**(code **)(*DAT_803dcaa4 + 0xc))(0x36b,0x23,0,1,(int)(short)(uVar1 >> 5));
  puVar8 = &DAT_803a87d0;
  uVar1 = 0;
  do {
    iVar6 = FUN_800e7efc(uVar1 & 0xff);
    if (iVar6 != 0) {
      if (uVar1 == 1) {
        sVar5 = FUN_80054f64();
        uVar4 = (**(code **)(*DAT_803dcaa4 + 0xc))(0x507,0x25,0,1,(int)sVar5);
        puVar8[2] = uVar4;
      }
      else {
        uVar4 = FUN_800e7e94(uVar1 & 0xff);
        uVar2 = countLeadingZeros(uVar4);
        uVar4 = (**(code **)(*DAT_803dcaa4 + 0xc))(0x36b,uVar1 + 0x24,0,1,(int)(short)(uVar2 >> 5));
        puVar8[2] = uVar4;
      }
    }
    puVar8 = puVar8 + 1;
    uVar1 = uVar1 + 1;
  } while ((int)uVar1 < 2);
  (**(code **)(*DAT_803dcaa4 + 0x20))(DAT_803a87d0,1);
  DAT_803dd706 = 2;
  return;
}

