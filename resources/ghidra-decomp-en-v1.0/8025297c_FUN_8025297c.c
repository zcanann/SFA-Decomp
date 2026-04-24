// Function: FUN_8025297c
// Entry: 8025297c
// Size: 364 bytes

undefined4
FUN_8025297c(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5
            ,undefined4 param_6,uint param_7,uint param_8)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  undefined8 uVar7;
  
  uVar1 = FUN_8024377c();
  if (((&DAT_803ae200)[param_1 * 8] == -1) && (DAT_8032e240 != param_1)) {
    uVar7 = FUN_80246c70();
    uVar2 = (uint)((ulonglong)uVar7 >> 0x20);
    uVar4 = (uint)uVar7;
    if ((param_8 | param_7) != 0) {
      uVar7 = CONCAT44(param_7 + *(int *)(&DAT_803ae340 + param_1 * 8) +
                                 (uint)CARRY4(param_8,*(uint *)(&DAT_803ae344 + param_1 * 8)),
                       param_8 + *(uint *)(&DAT_803ae344 + param_1 * 8));
    }
    uVar6 = (uint)((ulonglong)uVar7 >> 0x20);
    uVar5 = (uint)uVar7;
    if ((uVar2 ^ 0x80000000) < (uint)(uVar4 < uVar5) + (uVar6 ^ 0x80000000)) {
      FUN_80240fdc(&DAT_803ae280 + param_1 * 0x28,0x80250000,uVar6 - ((uVar5 < uVar4) + uVar2),
                   uVar5 - uVar4,&LAB_802528f0);
    }
    else {
      iVar3 = FUN_80252338(param_1,param_2,param_3,param_4,param_5,param_6);
      if (iVar3 != 0) {
        FUN_802437a4(uVar1);
        return 1;
      }
    }
    (&DAT_803ae200)[param_1 * 8] = param_1;
    (&DAT_803ae204)[param_1 * 8] = param_2;
    (&DAT_803ae208)[param_1 * 8] = param_3;
    (&DAT_803ae20c)[param_1 * 8] = param_4;
    (&DAT_803ae210)[param_1 * 8] = param_5;
    (&DAT_803ae214)[param_1 * 8] = param_6;
    (&DAT_803ae21c)[param_1 * 8] = uVar5;
    (&DAT_803ae218)[param_1 * 8] = uVar6;
    FUN_802437a4(uVar1);
    uVar1 = 1;
  }
  else {
    FUN_802437a4(uVar1);
    uVar1 = 0;
  }
  return uVar1;
}

