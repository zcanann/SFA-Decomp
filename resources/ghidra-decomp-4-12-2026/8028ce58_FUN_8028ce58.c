// Function: FUN_8028ce58
// Entry: 8028ce58
// Size: 332 bytes

int FUN_8028ce58(int param_1,uint param_2,int *param_3,undefined4 param_4,int param_5)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  
  uVar4 = DAT_80332f68;
  uVar3 = DAT_80332f64;
  uVar2 = DAT_80332f60;
  uVar1 = DAT_80332f5c;
  DAT_80332f68._1_3_ = (uint3)DAT_80332f68._2_2_;
  uVar6 = FUN_8028d1d0(param_2);
  uVar5 = countLeadingZeros(param_5);
  iVar7 = FUN_8028cfa4(uVar6,*param_3,uVar5 >> 5);
  if (iVar7 == 0) {
    FUN_8028b83c();
    if (param_5 == 0) {
      FUN_8028b84c(uVar6,param_1,*param_3);
      FUN_8028b748(uVar6,*param_3);
      if (param_2 != uVar6) {
        FUN_8028b748(param_2,*param_3);
      }
    }
    else {
      FUN_8028b84c(param_1,uVar6,*param_3);
    }
  }
  else {
    *param_3 = 0;
  }
  if (DAT_80332f68._1_1_ != '\0') {
    iVar7 = 0x702;
    *param_3 = 0;
  }
  DAT_80332f5c = uVar1;
  DAT_80332f60 = uVar2;
  DAT_80332f64 = uVar3;
  DAT_80332f68 = uVar4;
  return iVar7;
}

