// Function: FUN_80136ce4
// Entry: 80136ce4
// Size: 228 bytes

void FUN_80136ce4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  undefined4 extraout_r4;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  short *psVar5;
  undefined8 uVar6;
  
  DAT_803dc870 = 0xff;
  DAT_803de610 = 0;
  DAT_803dc871 = 0xff;
  DAT_803de611 = 0;
  if (DAT_803dd5e8 == '\0') {
    DAT_803de654 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xc5
                                ,param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  }
  else {
    DAT_803de654 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                0x647,param_10,param_11,param_12,param_13,param_14,param_15,param_16
                               );
  }
  FLOAT_803de650 = FLOAT_803e2fa8;
  FLOAT_803de64c = FLOAT_803e2fa8;
  uVar6 = FUN_802475b8((float *)&DAT_803aac44);
  iVar3 = 0;
  psVar5 = &DAT_8031da38;
  puVar4 = &DAT_803aabf8;
  uVar2 = extraout_r4;
  do {
    uVar1 = FUN_80054ed0(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)*psVar5,
                         uVar2,param_11,param_12,param_13,param_14,param_15,param_16);
    *puVar4 = uVar1;
    psVar5 = psVar5 + 1;
    puVar4 = puVar4 + 1;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 0x13);
  FLOAT_803de644 = FLOAT_803e2f88;
  DAT_803de612 = 0;
  DAT_803de62c = 0;
  FLOAT_803de634 = FLOAT_803e2fa8;
  FLOAT_803de630 = FLOAT_803e2fa8;
  DAT_803de62b = 1;
  return;
}

