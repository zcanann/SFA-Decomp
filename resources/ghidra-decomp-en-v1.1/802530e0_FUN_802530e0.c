// Function: FUN_802530e0
// Entry: 802530e0
// Size: 364 bytes

undefined4
FUN_802530e0(uint param_1,undefined4 *param_2,int param_3,undefined4 param_4,int param_5,int param_6
            ,int param_7,uint param_8)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  longlong lVar7;
  
  FUN_80243e74();
  if (((&DAT_803aee60)[param_1 * 8] == 0xffffffff) && (DAT_8032ee98 != param_1)) {
    lVar7 = FUN_802473d4();
    uVar2 = (uint)((ulonglong)lVar7 >> 0x20);
    uVar4 = (uint)lVar7;
    if (param_8 != 0 || param_7 != 0) {
      lVar7 = CONCAT44(param_7 + *(int *)(&DAT_803aefa0 + param_1 * 8) +
                                 (uint)CARRY4(param_8,*(uint *)(&DAT_803aefa4 + param_1 * 8)),
                       param_8 + *(uint *)(&DAT_803aefa4 + param_1 * 8));
    }
    uVar6 = (uint)((ulonglong)lVar7 >> 0x20);
    uVar5 = (uint)lVar7;
    if ((uVar2 ^ 0x80000000) < (uint)(uVar4 < uVar5) + (uVar6 ^ 0x80000000)) {
      FUN_802416d4((undefined4 *)(&DAT_803aeee0 + param_1 * 0x28),0x80250000,
                   uVar6 - ((uVar5 < uVar4) + uVar2),uVar5 - uVar4,&LAB_80253054);
    }
    else {
      iVar3 = FUN_80252a9c(param_1,param_2,param_3,param_4,param_5,param_6);
      if (iVar3 != 0) {
        FUN_80243e9c();
        return 1;
      }
    }
    (&DAT_803aee60)[param_1 * 8] = param_1;
    (&DAT_803aee64)[param_1 * 8] = param_2;
    (&DAT_803aee68)[param_1 * 8] = param_3;
    (&DAT_803aee6c)[param_1 * 8] = param_4;
    (&DAT_803aee70)[param_1 * 8] = param_5;
    (&DAT_803aee74)[param_1 * 8] = param_6;
    *(longlong *)(&DAT_803aee78 + param_1 * 8) = lVar7;
    FUN_80243e9c();
    uVar1 = 1;
  }
  else {
    FUN_80243e9c();
    uVar1 = 0;
  }
  return uVar1;
}

