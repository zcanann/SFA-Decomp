// Function: FUN_801a460c
// Entry: 801a460c
// Size: 1516 bytes

void FUN_801a460c(void)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  char cVar9;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  undefined4 uVar8;
  undefined uVar10;
  int iVar11;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  iVar2 = FUN_802860dc();
  iVar11 = *(int *)(iVar2 + 0xb8);
  iVar3 = FUN_8002b9ec();
  local_28 = DAT_802c22e8;
  local_24 = DAT_802c22ec;
  local_20 = DAT_802c22f0;
  if ((*(byte *)(iVar11 + 0xc) >> 3 & 1) != 0) {
    FUN_8002e0b4(0x47fae);
    FUN_8017c294();
    FUN_8002e0b4(0x47f83);
    FUN_8017c294();
    FUN_8002e0b4(0x47f8f);
    FUN_8017c294();
    FUN_8002e0b4(0x47fa2);
    FUN_8017c294();
    FUN_8002e0b4(0x29f2);
    FUN_8017c294();
    FUN_8002e0b4(0x29f3);
    FUN_8017c294();
    FUN_8002e0b4(0x29ef);
    FUN_8017c294();
    FUN_8002e0b4(0x29ee);
    FUN_8017c294();
    *(byte *)(iVar11 + 0xc) = *(byte *)(iVar11 + 0xc) & 0xf7;
  }
  cVar9 = (**(code **)(*DAT_803dcaac + 0x40))(0x1d);
  if ((cVar9 == '\x01') && (iVar4 = FUN_8001ffb4(0x40), iVar4 != 0)) {
    (**(code **)(*DAT_803dcaac + 0x44))(0x1d,2);
  }
  uVar5 = FUN_8001ffb4(0x974);
  uVar5 = uVar5 & 0xff;
  uVar6 = FUN_8001ffb4(0x975);
  uVar6 = uVar6 & 0xff;
  bVar1 = *(byte *)(iVar11 + 0xc) >> 5 & 1;
  if ((bVar1 == 0) || ((*(byte *)(iVar11 + 0xc) >> 4 & 1) == 0)) {
    if ((bVar1 == 0) && ((*(byte *)(iVar11 + 0xc) >> 4 & 1) == 0)) {
      if ((uVar5 != 0) || (uVar6 != 0)) {
        FUN_8000bb18(0,0x109);
      }
    }
    else if ((uVar5 != 0) && (uVar6 != 0)) {
      FUN_8000bb18(0,0x7e);
    }
  }
  *(byte *)(iVar11 + 0xc) = (byte)(uVar5 << 5) & 0x20 | *(byte *)(iVar11 + 0xc) & 0xdf;
  *(byte *)(iVar11 + 0xc) = (byte)(uVar6 << 4) & 0x10 | *(byte *)(iVar11 + 0xc) & 0xef;
  if (*(int *)(iVar2 + 0xf4) == 0) {
    FUN_80008b74(iVar2,iVar2,0x56,0);
    iVar4 = FUN_8001ffb4(0xd73);
    if (iVar4 == 0) {
      FUN_80008b74(iVar2,iVar2,0xd,0);
      FUN_80008b74(iVar2,iVar2,0x11,0);
      FUN_80008b74(iVar2,iVar2,0xe,0);
      FUN_80088e54((double)FLOAT_803e43ec,0);
      FUN_800200e8(0xd73,1);
    }
    iVar4 = FUN_8001ffb4(0xdca);
    if (iVar4 != 0) {
      FUN_80008b74(iVar2,iVar2,0xd,0);
      FUN_80008b74(iVar2,iVar2,0x7e,0);
      FUN_80008b74(iVar2,iVar2,0x7d,0);
      FUN_80088e54((double)FLOAT_803e43ec,1);
      FUN_800200e8(0xdca,0);
      FUN_8004350c(0,0,1);
    }
    *(undefined4 *)(iVar2 + 0xf4) = 1;
  }
  iVar4 = FUN_8001ffb4(0x94f);
  if ((iVar4 != 0) && ((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0)) {
    FUN_800200e8(0x94e,0);
  }
  iVar4 = FUN_8001ffb4(0x94e);
  if ((iVar4 == 0) || (iVar7 = FUN_80295cd4(iVar3), iVar7 != 0)) {
    if ((iVar4 == 0) && (iVar3 = FUN_80295cd4(iVar3), iVar3 == 0)) {
      uVar8 = FUN_8002b9ec();
      FUN_80295cf4(uVar8,1);
    }
  }
  else {
    uVar8 = FUN_8002b9ec();
    FUN_80295cf4(uVar8,0);
  }
  iVar3 = FUN_8001ffb4(0xd3d);
  if (iVar3 != 0) {
    uVar8 = FUN_800571e4();
    (**(code **)(*DAT_803dcaac + 0x24))(&local_28,0,uVar8,1);
    FUN_800200e8(0xd3d,0);
    FUN_80008b74(iVar2,iVar2,0xd,0);
    FUN_80008b74(iVar2,iVar2,0x11,0);
    FUN_80088e54((double)FLOAT_803e43e8,1);
  }
  iVar2 = (**(code **)(*DAT_803dca50 + 0x10))();
  if (iVar2 == 0x47) {
    if (*(char *)(iVar11 + 0xd) != 'G') {
      FUN_800200e8(0xc0,1);
    }
  }
  else if (*(char *)(iVar11 + 0xd) == 'G') {
    FUN_800200e8(0x1a8,1);
  }
  uVar10 = (**(code **)(*DAT_803dca50 + 0x10))();
  *(undefined *)(iVar11 + 0xd) = uVar10;
  FUN_801d7ed4(iVar11 + 8,4,0xffffffff,0xffffffff,0x983,0xb0);
  FUN_801d7ed4(iVar11 + 8,8,0xffffffff,0xffffffff,0x983,0x38);
  FUN_801d8060(iVar11 + 8,0x100,0xffffffff,0xffffffff,0x983,0x16);
  FUN_801d8060(iVar11 + 8,0x80,0xffffffff,0xffffffff,0x983,0x39);
  iVar2 = FUN_8001ffb4(0x983);
  if (iVar2 == 0) {
    iVar2 = FUN_8001ffb4(0xe23);
    if (iVar2 == 0) {
      FUN_801d8060(iVar11 + 8,0x200,0xffffffff,0xffffffff,0x984,0xad);
      FUN_801d7ed4(iVar11 + 8,0x40,0xffffffff,0xffffffff,0x984,0x16);
    }
    iVar2 = FUN_8001ffb4(0x984);
    if (iVar2 != 0) {
      FUN_801d7ed4(iVar11 + 8,0x20,0xffffffff,0xffffffff,0xe23,0x17);
      FUN_801d8060(iVar11 + 8,0x400,0xffffffff,0xffffffff,0xe23,0x16);
    }
  }
  FUN_801d7ed4(iVar11 + 8,1,0x1a8,0xc0,0xdb8,0xae);
  FUN_801d7ed4(iVar11 + 8,0x10,0xffffffff,0xffffffff,0xe1d,0x36);
  FUN_801d7ed4(iVar11 + 8,0x1000,0xffffffff,0xffffffff,0xe1d,0xf1);
  FUN_801d7ed4(iVar11 + 8,2,0xffffffff,0xffffffff,0xb46,0xaf);
  FUN_801d7ed4(iVar11 + 8,0x800,0xffffffff,0xffffffff,0xcbb,0xc4);
  FUN_80286128();
  return;
}

