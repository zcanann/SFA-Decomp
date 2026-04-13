// Function: FUN_800932e8
// Entry: 800932e8
// Size: 180 bytes

void FUN_800932e8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 extraout_r4;
  int iVar1;
  int *piVar2;
  
  iVar1 = 0;
  piVar2 = &DAT_8039b488;
  do {
    if (*piVar2 != 0) {
      param_1 = FUN_80090304(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                             param_10,param_11,param_12,param_13,param_14,param_15,param_16);
      param_10 = extraout_r4;
    }
    *piVar2 = 0;
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 8);
  FLOAT_803dde3c = FLOAT_803dfe20;
  FLOAT_803dde38 = FLOAT_803dfe20;
  FLOAT_803dde34 = FLOAT_803dfe20;
  FLOAT_803dde10 = FLOAT_803dfe20;
  FLOAT_803dc3c0 = FLOAT_803dfe24;
  FLOAT_803dde14 = FLOAT_803dfe20;
  DAT_803dde18 = 0;
  FLOAT_803dc3c4 = FLOAT_803dfe24;
  DAT_803dde19 = 0;
  DAT_803dde1a = 0;
  FLOAT_803dc3c8 = FLOAT_803dfe24;
  DAT_803dde4c = 0;
  FUN_8000a538((int *)0xeb,0);
  return;
}

