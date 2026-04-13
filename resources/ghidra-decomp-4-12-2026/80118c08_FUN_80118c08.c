// Function: FUN_80118c08
// Entry: 80118c08
// Size: 552 bytes

bool FUN_80118c08(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  undefined8 extraout_f1;
  int local_18 [3];
  
  DAT_803de300 = 0;
  if ((DAT_803a6a58 == 0) || (DAT_803a6a5c != '\0')) {
    DAT_803de300 = 0;
    return false;
  }
  if ((int)param_9 < 1) {
    DAT_803a6a70 = DAT_803a6a24;
    DAT_803a6a74 = DAT_803a6a14;
  }
  else {
    if (DAT_803a6a20 == 0) {
      DAT_803de300 = 0;
      return false;
    }
    if (DAT_803a6a10 <= param_9) {
      DAT_803de300 = 0;
      return false;
    }
    iVar1 = FUN_80015888(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         &DAT_803a69c0,&DAT_803a6980,0x20,DAT_803a6a20 + (param_9 - 1) * 4,param_13,
                         param_14,param_15,param_16);
    if (iVar1 < 0) {
      return false;
    }
    DAT_803a6a70 = DAT_803a6a24 + DAT_803a6980;
    DAT_803a6a74 = DAT_803a6984 - DAT_803a6980;
    param_1 = extraout_f1;
  }
  DAT_803a6a90 = 0;
  DAT_803a6a5e = param_10;
  DAT_803a6a78 = param_9;
  if (DAT_803a6a68 == 0) {
    FUN_80119e00(0xf,0);
    if (DAT_803a6a5f != '\0') {
      FUN_8011784c(0xc,0);
    }
    FUN_80119930(8);
  }
  else {
    iVar1 = FUN_80015888(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         &DAT_803a69c0,DAT_803a6a6c,DAT_803a6a18,DAT_803a6a24,param_13,param_14,
                         param_15,param_16);
    if (iVar1 < 0) {
      return false;
    }
    iVar1 = (DAT_803a6a6c + DAT_803a6a70) - DAT_803a6a24;
    FUN_80119e00(0xf,iVar1);
    if (DAT_803a6a5f != '\0') {
      FUN_8011784c(0xc,iVar1);
    }
  }
  FUN_80118e60();
  FUN_80119dcc();
  if (DAT_803a6a5f != '\0') {
    FUN_80117818();
  }
  if (DAT_803a6a68 == 0) {
    FUN_801198fc();
  }
  FUN_80244820((int *)&DAT_803a694c,local_18,1);
  if (local_18[0] != 0) {
    DAT_803a6a5c = '\x01';
    DAT_803a6a5d = 0;
    DAT_803a6aac = 0;
    DAT_803a6ab0 = 0;
    DAT_803a6aa4 = 0;
    DAT_803a6aa8 = 0;
    DAT_803de2e4 = FUN_8024c910(FUN_80118714);
  }
  return local_18[0] != 0;
}

