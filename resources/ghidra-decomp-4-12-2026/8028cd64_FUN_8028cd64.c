// Function: FUN_8028cd64
// Entry: 8028cd64
// Size: 244 bytes

undefined4 FUN_8028cd64(int param_1,uint param_2,int param_3,int *param_4,int param_5)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  
  uVar4 = DAT_80332f68;
  uVar3 = DAT_80332f64;
  uVar2 = DAT_80332f60;
  uVar1 = DAT_80332f5c;
  if (param_2 < 0x25) {
    iVar6 = (param_2 - param_1) + 1;
    DAT_80332f68._1_3_ = (uint3)DAT_80332f68._2_2_;
    *param_4 = iVar6 * 4;
    if (param_5 == 0) {
      uVar5 = FUN_8028763c(param_3,(undefined *)(&DAT_803d9000 + param_1),iVar6);
    }
    else {
      uVar5 = FUN_80287aac(param_3,&DAT_803d9000 + param_1,iVar6);
    }
    if (DAT_80332f68._1_1_ != '\0') {
      uVar5 = 0x702;
      *param_4 = 0;
    }
  }
  else {
    uVar5 = 0x701;
  }
  DAT_80332f5c = uVar1;
  DAT_80332f60 = uVar2;
  DAT_80332f64 = uVar3;
  DAT_80332f68 = uVar4;
  return uVar5;
}

