// Function: FUN_80240400
// Entry: 80240400
// Size: 296 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_80240400(void)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  uint uVar5;
  
  iVar1 = FUN_80244b20();
  if (iVar1 == -0x80000000) {
    DAT_803dddf4 = _DAT_812fdff0;
    DAT_803dddf0 = _DAT_812fdfec;
    if (_DAT_812fdff0 == 0) {
      iVar1 = FUN_802416f0();
      iVar2 = FUN_802416f8();
      uVar3 = FUN_802416f8();
      FUN_800033a8(uVar3,0,iVar1 - iVar2);
    }
    else {
      uVar4 = FUN_802416f8();
      if (uVar4 < DAT_803dddf4) {
        uVar4 = FUN_802416f0();
        if (DAT_803dddf4 < uVar4) {
          iVar1 = FUN_802416f8();
          iVar1 = DAT_803dddf4 - iVar1;
          uVar3 = FUN_802416f8();
          FUN_800033a8(uVar3,0,iVar1);
          uVar5 = FUN_802416f0();
          uVar4 = DAT_803dddf0;
          if (DAT_803dddf0 < uVar5) {
            iVar1 = FUN_802416f0();
            FUN_800033a8(uVar4,0,iVar1 - uVar4);
          }
        }
        else {
          iVar1 = FUN_802416f0();
          iVar2 = FUN_802416f8();
          uVar3 = FUN_802416f8();
          FUN_800033a8(uVar3,0,iVar1 - iVar2);
        }
      }
    }
  }
  else {
    DAT_803dddf4 = 0;
    DAT_803dddf0 = 0;
    iVar1 = FUN_802416f0();
    iVar2 = FUN_802416f8();
    uVar3 = FUN_802416f8();
    FUN_800033a8(uVar3,0,iVar1 - iVar2);
  }
  return;
}

