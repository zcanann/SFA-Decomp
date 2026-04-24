// Function: FUN_80132294
// Entry: 80132294
// Size: 116 bytes

void FUN_80132294(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  short *psVar3;
  int *piVar4;
  
  iVar2 = 0;
  piVar4 = &DAT_803aaa18;
  psVar3 = &DAT_8031cef8;
  do {
    if (*piVar4 == 0) {
      iVar1 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (int)*psVar3,param_10,param_11,param_12,param_13,param_14,param_15,
                           param_16);
      *piVar4 = iVar1;
    }
    piVar4 = piVar4 + 1;
    psVar3 = psVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 6);
  return;
}

