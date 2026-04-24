// Function: FUN_8028c4c4
// Entry: 8028c4c4
// Size: 316 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int FUN_8028c4c4(uint param_1,uint param_2,undefined4 param_3,int *param_4,int param_5)

{
  int iVar1;
  uint uVar2;
  undefined4 extraout_r4;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  uint local_24;
  
  if (param_2 < 0x22) {
    local_30 = DAT_803322fc;
    local_2c = DAT_80332300;
    local_28 = _DAT_80332304;
    local_24 = DAT_80332308;
    DAT_80332308 = DAT_80332308 & 0xff00ffff;
    uVar2 = FUN_8028b0d8();
    FUN_8028b0e0(uVar2 | 0x2000);
    iVar1 = 0;
    *param_4 = 0;
    while ((param_1 <= param_2 && (iVar1 == 0))) {
      if (param_5 == 0) {
        FUN_80287060(param_3,&local_38);
        iVar1 = FUN_8028b47c(&local_38,param_1,0);
      }
      else {
        FUN_8028b47c(&local_38,param_1,param_5);
        iVar1 = FUN_80287458(param_3,extraout_r4,local_38,local_34);
      }
      param_1 = param_1 + 1;
      *param_4 = *param_4 + 8;
    }
    if (DAT_80332308._1_1_ != '\0') {
      iVar1 = 0x702;
      *param_4 = 0;
    }
    DAT_803322fc = local_30;
    DAT_80332300 = local_2c;
    _DAT_80332304 = local_28;
    DAT_80332308 = local_24;
  }
  else {
    iVar1 = 0x701;
  }
  return iVar1;
}

