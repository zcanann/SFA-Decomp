// Function: FUN_8028cc28
// Entry: 8028cc28
// Size: 316 bytes

int FUN_8028cc28(uint param_1,uint param_2,int param_3,int *param_4,int param_5)

{
  int iVar1;
  uint uVar2;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  
  if (param_2 < 0x22) {
    local_30 = DAT_80332f5c;
    local_2c = DAT_80332f60;
    local_28 = DAT_80332f64;
    local_24 = DAT_80332f68;
    DAT_80332f68._1_3_ = (uint3)DAT_80332f68._2_2_;
    FUN_8028b83c();
    FUN_8028b844();
    iVar1 = 0;
    *param_4 = 0;
    while ((param_1 <= param_2 && (iVar1 == 0))) {
      if (param_5 == 0) {
        FUN_802877c4(param_3,(undefined *)&local_38);
        iVar1 = FUN_8028bbe0(&local_38,param_1,0);
      }
      else {
        uVar2 = param_1;
        FUN_8028bbe0(&local_38,param_1,param_5);
        iVar1 = FUN_80287bbc(param_3,uVar2,local_38,local_34);
      }
      param_1 = param_1 + 1;
      *param_4 = *param_4 + 8;
    }
    if (DAT_80332f68._1_1_ != '\0') {
      iVar1 = 0x702;
      *param_4 = 0;
    }
    DAT_80332f5c = local_30;
    DAT_80332f60 = local_2c;
    DAT_80332f64 = local_28;
    DAT_80332f68 = local_24;
  }
  else {
    iVar1 = 0x701;
  }
  return iVar1;
}

