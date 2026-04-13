// Function: FUN_802534e4
// Entry: 802534e4
// Size: 452 bytes

int FUN_802534e4(uint param_1)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int *piVar4;
  longlong *plVar5;
  longlong lVar6;
  
  FUN_80243e74();
  piVar4 = (int *)(&DAT_8032eeac + param_1 * 4);
  iVar3 = *piVar4;
  lVar6 = FUN_802473d4();
  plVar5 = (longlong *)(&DAT_803aef80 + param_1 * 8);
  uVar2 = (uint)lVar6 - *(uint *)(&DAT_803aef84 + param_1 * 8);
  uVar1 = (int)((ulonglong)lVar6 >> 0x20) -
          ((uint)((uint)lVar6 < *(uint *)(&DAT_803aef84 + param_1 * 8)) + *(int *)plVar5);
  if ((DAT_8032ee9c & 0x80 >> (param_1 & 0x3f)) == 0) {
    if (((uint)((DAT_800000f8 / 4000) * 0x32 < uVar2) + (uVar1 ^ 0x80000000) < 0x80000001) &&
       (iVar3 != 8)) {
      FUN_80243e9c();
      return iVar3;
    }
    if ((uint)((DAT_800000f8 / 4000) * 0x4b < uVar2) + (uVar1 ^ 0x80000000) < 0x80000001) {
      *piVar4 = 0x80;
    }
    else {
      *piVar4 = 0x80;
      iVar3 = 0x80;
    }
  }
  else {
    if (iVar3 != 8) {
      lVar6 = FUN_802473d4();
      *plVar5 = lVar6;
      FUN_80243e9c();
      return iVar3;
    }
    *piVar4 = 0x80;
    iVar3 = 0x80;
  }
  lVar6 = FUN_802473d4();
  *plVar5 = lVar6;
  FUN_802530e0(param_1,(undefined4 *)&DAT_803ded04,1,piVar4,3,-0x7fdacdb4,0,
               (DAT_800000f8 / 500000) * 0x41 >> 3);
  FUN_80243e9c();
  return iVar3;
}

