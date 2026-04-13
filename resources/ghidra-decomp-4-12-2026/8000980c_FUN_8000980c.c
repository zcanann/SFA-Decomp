// Function: FUN_8000980c
// Entry: 8000980c
// Size: 276 bytes

void FUN_8000980c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 uVar1;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined4 local_18;
  
  if (DAT_803dd480 != 0) {
    uVar1 = FUN_800238f8(0);
    FUN_800238c4(DAT_803dd480);
    FUN_800238c4(DAT_803dd4b0);
    param_1 = FUN_800238c4(DAT_803dd4d0);
    FUN_800238f8(uVar1);
  }
  DAT_803dd478 = DAT_803dd478 | 1;
  DAT_803dd480 = FUN_8001599c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  DAT_803dd484 = local_18 >> 4;
  DAT_803dd478 = DAT_803dd478 | 2;
  DAT_803dd4b0 = FUN_8001599c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  DAT_803dd4b4 = local_18 >> 5;
  DAT_803dd478 = DAT_803dd478 | 4;
  DAT_803dd4d0 = FUN_8001599c(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                             );
  DAT_803dd4d4 = local_18 / 0x16;
  return;
}

