// Function: FUN_8025e4d4
// Entry: 8025e4d4
// Size: 556 bytes

undefined4 FUN_8025e4d4(int param_1)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  
  iVar4 = param_1 * 0x110;
  iVar2 = FUN_80253dd0(param_1,0,4);
  if (iVar2 == 0) {
    FUN_802545c4(param_1);
    return 0xfffffffd;
  }
  FUN_80241044(&DAT_803af2c0 + iVar4);
  bVar1 = (&DAT_803af274)[iVar4];
  if (bVar1 != 0xf3) {
    if (bVar1 < 0xf3) {
      if (bVar1 != 0xf1) {
        if (0xf0 < bVar1) {
          FUN_80240fdc(&DAT_803af2c0 + iVar4,0x10624dd3,0,((DAT_800000f8 >> 2) / 1000) * 100,
                       &LAB_8025e430);
        }
        goto LAB_8025e5f4;
      }
    }
    else if (0xf4 < bVar1) goto LAB_8025e5f4;
    uVar5 = *(uint *)(&DAT_803af1ec + iVar4);
    uVar6 = (DAT_800000f8 >> 2) * 2;
    uVar5 = ((int)uVar5 >> 0xd) + (uint)((int)uVar5 < 0 && (uVar5 & 0x1fff) != 0);
    iVar2 = ((int)uVar5 >> 0x1f) * uVar6 + (int)((ulonglong)uVar5 * (ulonglong)uVar6 >> 0x20);
    FUN_80240fdc(&DAT_803af2c0 + iVar4,iVar2,iVar2,uVar5 * uVar6,&LAB_8025e430);
  }
LAB_8025e5f4:
  iVar2 = FUN_802534d8(param_1,&DAT_803af274 + iVar4,*(undefined4 *)(&DAT_803af280 + iVar4),1);
  if (iVar2 == 0) {
    FUN_80253efc(param_1);
    FUN_802545c4(param_1);
    uVar3 = 0xfffffffd;
  }
  else if (((&DAT_803af274)[iVar4] == 'R') &&
          (iVar2 = FUN_802534d8(param_1,(&DAT_803af260)[param_1 * 0x44] + 0x200,
                                *(undefined4 *)(&DAT_803af1f4 + iVar4),1), iVar2 == 0)) {
    FUN_80253efc(param_1);
    FUN_802545c4(param_1);
    uVar3 = 0xfffffffd;
  }
  else if (*(int *)(&DAT_803af284 + iVar4) == -1) {
    FUN_80253efc(param_1);
    FUN_802545c4(param_1);
    uVar3 = 0;
  }
  else {
    if ((&DAT_803af274)[iVar4] == 'R') {
      uVar3 = 0x200;
    }
    else {
      uVar3 = 0x80;
    }
    iVar2 = FUN_80253578(param_1,*(undefined4 *)(&DAT_803af294 + iVar4),uVar3,
                         *(undefined4 *)(&DAT_803af284 + iVar4),&LAB_8025e0a8);
    if (iVar2 == 0) {
      FUN_80253efc(param_1);
      FUN_802545c4(param_1);
      uVar3 = 0xfffffffd;
    }
    else {
      uVar3 = 0;
    }
  }
  return uVar3;
}

