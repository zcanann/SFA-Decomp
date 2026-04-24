// Function: FUN_80248738
// Entry: 80248738
// Size: 664 bytes

undefined4 FUN_80248738(undefined4 param_1,uint param_2,uint param_3,undefined4 param_4)

{
  uint uVar1;
  bool bVar2;
  int iVar3;
  undefined4 extraout_r4;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  longlong lVar7;
  
  DAT_cc006018 = param_2;
  DAT_803aeb44 = param_1;
  DAT_803aeb48 = param_2;
  DAT_803aeb4c = param_3;
  if (DAT_803deb44 == 0) {
    DAT_803aea80 = 0xffffffff;
    DAT_803deb64 = 0;
    FUN_802485a8(param_1,param_2,param_3,param_4);
  }
  else if (DAT_803deb44 == 1) {
    if (DAT_803dd1c0 == 0) {
      uVar4 = (uint)(DAT_803aeb40 + DAT_803aeb3c + -1) >> 0xf;
      iVar3 = FUN_8024becc();
      if (*(char *)(iVar3 + 8) == '\0') {
        iVar3 = 0xf;
      }
      else {
        iVar3 = 5;
      }
      if ((uVar4 - 2 < param_3 >> 0xf) || (param_3 >> 0xf < uVar4 + iVar3 + 3)) {
        bVar2 = true;
      }
      else {
        bVar2 = false;
      }
      if (bVar2) {
        uVar4 = (uint)(DAT_803aeb40 + DAT_803aeb3c + -1) >> 0xf;
        if ((uVar4 == DAT_803aeb4c >> 0xf) || (uVar4 + 1 == DAT_803aeb4c >> 0xf)) {
          lVar7 = FUN_802473d4();
          uVar6 = (uint)lVar7 - DAT_803deb54;
          uVar5 = (int)((ulonglong)lVar7 >> 0x20) -
                  ((uint)((uint)lVar7 < DAT_803deb54) + DAT_803deb50);
          uVar4 = ((DAT_800000f8 >> 2) / 1000) * 5;
          if ((uint)(uVar4 < uVar6) + (uVar5 ^ 0x80000000) < 0x80000001) {
            DAT_803aea80 = 1;
            DAT_803aea94 = 0xffffffff;
            uVar1 = ((DAT_800000f8 >> 2) / 0x1e848) * 500 >> 3;
            DAT_803deb64 = 0;
            DAT_803aea84 = param_1;
            DAT_803aea88 = param_2;
            DAT_803aea8c = param_3;
            DAT_803aea90 = param_4;
            FUN_80241478((undefined4 *)&DAT_803aeac0);
            FUN_802416d4((undefined4 *)&DAT_803aeac0,extraout_r4,
                         (uint)CARRY4(uVar4 - uVar6,uVar1) - ((uVar4 < uVar6) + uVar5),
                         (uVar4 - uVar6) + uVar1,&LAB_802484b4);
          }
          else {
            DAT_803aea80 = 0xffffffff;
            DAT_803deb64 = 0;
            FUN_802485a8(param_1,param_2,param_3,param_4);
          }
        }
        else {
          FUN_802486b8(param_1,param_2,param_3,param_4);
        }
      }
      else {
        DAT_803aea80 = 0xffffffff;
        DAT_803deb64 = 0;
        FUN_802485a8(param_1,param_2,param_3,param_4);
      }
    }
    else {
      FUN_802486b8(param_1,param_2,param_3,param_4);
    }
  }
  return 1;
}

