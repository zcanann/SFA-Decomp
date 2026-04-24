// Function: FUN_8011a4e8
// Entry: 8011a4e8
// Size: 548 bytes

void FUN_8011a4e8(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (DAT_803db9fb != -1) {
    (**(code **)(*DAT_803dcaa0 + 8))();
  }
  if ((DAT_803dd6a5 == '\0') && (DAT_803db424 != '\0')) {
    DAT_803dd6cd = 1;
    FUN_8000bb18(0,0x418);
    (**(code **)(*DAT_803dca4c + 8))(0x14,1);
    (**(code **)(*DAT_803dca70 + 0x1c))(0);
    (**(code **)(*DAT_803dca70 + 0x1c))(1);
    (**(code **)(*DAT_803dca70 + 0x1c))(2);
    (**(code **)(*DAT_803dca70 + 0x1c))(3);
    DAT_803dd6cf = 0x23;
    DAT_803dd6c4 = 0;
  }
  else {
    DAT_803db9fb = '\x04';
    iVar2 = 0;
    iVar1 = 0;
    iVar3 = 6;
    do {
      if ((int)(uint)*(byte *)(DAT_803dd6b0 + DAT_803dd6a4 * 0x24 + 0x21) < iVar2) {
        *(ushort *)(PTR_DAT_8031a7ec + iVar1 + 0x16) =
             *(ushort *)(PTR_DAT_8031a7ec + iVar1 + 0x16) | 0x4000;
      }
      else {
        *(ushort *)(PTR_DAT_8031a7ec + iVar1 + 0x16) =
             *(ushort *)(PTR_DAT_8031a7ec + iVar1 + 0x16) & 0xbfff;
      }
      if (((int)(*(byte *)(DAT_803dd6b0 + DAT_803dd6a4 * 0x24 + 0x21) - 1) < iVar2) || (4 < iVar2))
      {
        PTR_DAT_8031a7ec[iVar1 + 0x1b] = 0xff;
      }
      else {
        PTR_DAT_8031a7ec[iVar1 + 0x1b] = (char)iVar2 + '\x01';
      }
      iVar1 = iVar1 + 0x3c;
      iVar2 = iVar2 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
    (**(code **)(*DAT_803dcaa0 + 4))(PTR_DAT_8031a7ec,DAT_8031a7f0,0,&DAT_8031a7f8,5,4,0,0,0,0,0,0);
    DAT_803dd6ce = 2;
  }
  return;
}

