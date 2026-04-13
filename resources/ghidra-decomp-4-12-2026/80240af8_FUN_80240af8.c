// Function: FUN_80240af8
// Entry: 80240af8
// Size: 296 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_80240af8(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  
  uVar1 = FUN_80245218();
  if (uVar1 == 0x80000000) {
    DAT_803dea74 = _DAT_812fdff0;
    DAT_803dea70 = _DAT_812fdfec;
    if (_DAT_812fdff0 == 0) {
      iVar2 = FUN_80241de8();
      iVar3 = FUN_80241df0();
      iVar4 = FUN_80241df0();
      FUN_800033a8(iVar4,0,iVar2 - iVar3);
    }
    else {
      uVar1 = FUN_80241df0();
      if (uVar1 < DAT_803dea74) {
        uVar1 = FUN_80241de8();
        if (DAT_803dea74 < uVar1) {
          iVar2 = FUN_80241df0();
          uVar1 = DAT_803dea74 - iVar2;
          iVar2 = FUN_80241df0();
          FUN_800033a8(iVar2,0,uVar1);
          uVar5 = FUN_80241de8();
          uVar1 = DAT_803dea70;
          if (DAT_803dea70 < uVar5) {
            iVar2 = FUN_80241de8();
            FUN_800033a8(uVar1,0,iVar2 - uVar1);
          }
        }
        else {
          iVar2 = FUN_80241de8();
          iVar3 = FUN_80241df0();
          iVar4 = FUN_80241df0();
          FUN_800033a8(iVar4,0,iVar2 - iVar3);
        }
      }
    }
  }
  else {
    DAT_803dea74 = 0;
    DAT_803dea70 = 0;
    iVar2 = FUN_80241de8();
    iVar3 = FUN_80241df0();
    iVar4 = FUN_80241df0();
    FUN_800033a8(iVar4,0,iVar2 - iVar3);
  }
  return;
}

