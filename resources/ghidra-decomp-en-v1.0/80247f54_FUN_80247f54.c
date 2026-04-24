// Function: FUN_80247f54
// Entry: 80247f54
// Size: 128 bytes

void FUN_80247f54(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  if ((param_3 & 0xffff8000) == 0) {
    DAT_803ade2c = 0;
  }
  else {
    DAT_803ade2c = (param_3 & 0xffff8000) + DAT_803ddec8;
  }
  DAT_803ade20 = 2;
  DAT_803ade34 = 1;
  DAT_803ade48 = 0xffffffff;
  DAT_803ddee4 = 0;
  DAT_803ade30 = param_4;
  DAT_803ade38 = param_1;
  DAT_803ade3c = param_2;
  DAT_803ade40 = param_3;
  DAT_803ade44 = param_4;
  FUN_8024826c(DAT_803ade2c,param_4);
  return;
}

