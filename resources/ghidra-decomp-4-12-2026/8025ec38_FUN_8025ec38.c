// Function: FUN_8025ec38
// Entry: 8025ec38
// Size: 556 bytes

undefined4 FUN_8025ec38(int param_1)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  
  iVar4 = param_1 * 0x110;
  iVar2 = FUN_80254534(param_1,0,4);
  if (iVar2 == 0) {
    FUN_80254d28(param_1);
    return 0xfffffffd;
  }
  FUN_8024173c((int *)(&DAT_803aff20 + iVar4));
  bVar1 = (&DAT_803afed4)[iVar4];
  if (bVar1 != 0xf3) {
    if (bVar1 < 0xf3) {
      if (bVar1 != 0xf1) {
        if (0xf0 < bVar1) {
          FUN_802416d4((undefined4 *)(&DAT_803aff20 + iVar4),0x10624dd3,0,
                       (DAT_800000f8 / 4000) * 100,&LAB_8025eb94);
        }
        goto LAB_8025ed58;
      }
    }
    else if (0xf4 < bVar1) goto LAB_8025ed58;
    uVar5 = *(uint *)(&DAT_803afe4c + iVar4);
    uVar6 = (DAT_800000f8 >> 2) * 2;
    uVar5 = ((int)uVar5 >> 0xd) + (uint)((int)uVar5 < 0 && (uVar5 & 0x1fff) != 0);
    iVar2 = ((int)uVar5 >> 0x1f) * uVar6 + (int)((ulonglong)uVar5 * (ulonglong)uVar6 >> 0x20);
    FUN_802416d4((undefined4 *)(&DAT_803aff20 + iVar4),iVar2,iVar2,uVar5 * uVar6,&LAB_8025eb94);
  }
LAB_8025ed58:
  iVar2 = FUN_80253c3c(param_1,&DAT_803afed4 + iVar4,*(int *)(&DAT_803afee0 + iVar4),1);
  if (iVar2 == 0) {
    FUN_80254660(param_1);
    FUN_80254d28(param_1);
    uVar3 = 0xfffffffd;
  }
  else if (((&DAT_803afed4)[iVar4] == 'R') &&
          (iVar2 = FUN_80253c3c(param_1,(byte *)((&DAT_803afec0)[param_1 * 0x44] + 0x200),
                                *(int *)(&DAT_803afe54 + iVar4),1), iVar2 == 0)) {
    FUN_80254660(param_1);
    FUN_80254d28(param_1);
    uVar3 = 0xfffffffd;
  }
  else if (*(int *)(&DAT_803afee4 + iVar4) == -1) {
    FUN_80254660(param_1);
    FUN_80254d28(param_1);
    uVar3 = 0;
  }
  else {
    if ((&DAT_803afed4)[iVar4] == 'R') {
      uVar3 = 0x200;
    }
    else {
      uVar3 = 0x80;
    }
    iVar2 = FUN_80253cdc(param_1,*(uint *)(&DAT_803afef4 + iVar4),uVar3,
                         *(int *)(&DAT_803afee4 + iVar4),&LAB_8025e80c);
    if (iVar2 == 0) {
      FUN_80254660(param_1);
      FUN_80254d28(param_1);
      uVar3 = 0xfffffffd;
    }
    else {
      uVar3 = 0;
    }
  }
  return uVar3;
}

