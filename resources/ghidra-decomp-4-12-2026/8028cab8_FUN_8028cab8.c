// Function: FUN_8028cab8
// Entry: 8028cab8
// Size: 368 bytes

uint FUN_8028cab8(uint param_1,uint param_2,int param_3,int *param_4,int param_5)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  
  uVar4 = DAT_80332f68;
  uVar3 = DAT_80332f64;
  uVar2 = DAT_80332f60;
  uVar1 = DAT_80332f5c;
  if (param_2 < 0x61) {
    DAT_80332f68._1_3_ = (uint3)DAT_80332f68._2_2_;
    *param_4 = 0;
    if (param_1 <= param_2) {
      iVar6 = param_2 - param_1;
      iVar5 = iVar6 + 1;
      *param_4 = *param_4 + iVar5 * 4;
      puVar7 = &DAT_803d91a8 + param_1;
      if (param_5 == 0) {
        if ((puVar7 < (undefined4 *)((int)&DAT_803d91ec + 1U)) &&
           ((undefined4 *)0x803d91e7 < puVar7 + iVar6)) {
          DAT_80332f50 = 1;
        }
        if ((puVar7 < (undefined4 *)((int)&DAT_803d9278 + 1U)) &&
           ((undefined4 *)0x803d9277 < puVar7 + iVar6)) {
          DAT_80332f51 = 1;
        }
        param_1 = FUN_8028763c(param_3,(undefined *)puVar7,iVar5);
      }
      else {
        param_1 = FUN_80287aac(param_3,puVar7,iVar5);
      }
    }
    if (DAT_80332f68._1_1_ != '\0') {
      param_1 = 0x702;
      *param_4 = 0;
    }
  }
  else {
    param_1 = 0x701;
  }
  DAT_80332f5c = uVar1;
  DAT_80332f60 = uVar2;
  DAT_80332f64 = uVar3;
  DAT_80332f68 = uVar4;
  return param_1;
}

