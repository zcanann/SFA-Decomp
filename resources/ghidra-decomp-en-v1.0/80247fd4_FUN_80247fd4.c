// Function: FUN_80247fd4
// Entry: 80247fd4
// Size: 664 bytes

undefined4 FUN_80247fd4(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  uint uVar1;
  bool bVar2;
  int iVar3;
  undefined4 extraout_r4;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  undefined8 uVar7;
  
  write_volatile_4(DAT_cc006018,param_2);
  DAT_803adee4 = param_1;
  DAT_803adee8 = param_2;
  DAT_803adeec = param_3;
  if (DAT_803ddec4 == 0) {
    DAT_803ade20 = 0xffffffff;
    DAT_803ddee4 = 0;
    FUN_80247e44(param_1,param_2,param_3,param_4);
  }
  else if (DAT_803ddec4 == 1) {
    if (DAT_803dc558 == 0) {
      uVar4 = (uint)(DAT_803adee0 + DAT_803adedc + -1) >> 0xf;
      iVar3 = FUN_8024b768();
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
        uVar4 = (uint)(DAT_803adee0 + DAT_803adedc + -1) >> 0xf;
        if ((uVar4 == DAT_803adeec >> 0xf) || (uVar4 + 1 == DAT_803adeec >> 0xf)) {
          uVar7 = FUN_80246c70();
          uVar6 = (uint)uVar7 - DAT_803dded4;
          uVar5 = (int)((ulonglong)uVar7 >> 0x20) -
                  ((uint)((uint)uVar7 < DAT_803dded4) + DAT_803dded0);
          uVar4 = ((DAT_800000f8 >> 2) / 1000) * 5;
          if ((uint)(uVar4 < uVar6) + (uVar5 ^ 0x80000000) < 0x80000001) {
            DAT_803ade20 = 1;
            DAT_803ade34 = 0xffffffff;
            uVar1 = ((DAT_800000f8 >> 2) / 0x1e848) * 500 >> 3;
            DAT_803ddee4 = 0;
            DAT_803ade24 = param_1;
            DAT_803ade28 = param_2;
            DAT_803ade2c = param_3;
            DAT_803ade30 = param_4;
            FUN_80240d80(&DAT_803ade60);
            FUN_80240fdc(&DAT_803ade60,extraout_r4,
                         (uint)CARRY4(uVar4 - uVar6,uVar1) - ((uVar4 < uVar6) + uVar5),
                         (uVar4 - uVar6) + uVar1,&LAB_80247d50);
          }
          else {
            DAT_803ade20 = 0xffffffff;
            DAT_803ddee4 = 0;
            FUN_80247e44(param_1,param_2,param_3,param_4);
          }
        }
        else {
          FUN_80247f54(param_1,param_2,param_3,param_4);
        }
      }
      else {
        DAT_803ade20 = 0xffffffff;
        DAT_803ddee4 = 0;
        FUN_80247e44(param_1,param_2,param_3,param_4);
      }
    }
    else {
      FUN_80247f54(param_1,param_2,param_3,param_4);
    }
  }
  return 1;
}

