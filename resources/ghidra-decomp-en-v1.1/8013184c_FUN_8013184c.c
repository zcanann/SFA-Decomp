// Function: FUN_8013184c
// Entry: 8013184c
// Size: 124 bytes

void FUN_8013184c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  undefined4 extraout_r4;
  int iVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  
  iVar2 = 0;
  puVar3 = &DAT_8031ce04;
  do {
    uVar1 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)*(short *)(puVar3 + 1),param_10,param_11,param_12,param_13,param_14,
                         param_15,param_16);
    *puVar3 = uVar1;
    puVar3 = puVar3 + 2;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 6);
  uVar4 = FUN_80014b44(10);
  DAT_803de58c = 0xff;
  FUN_8001bee0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,3,extraout_r4,param_11,
               param_12,param_13,param_14,param_15,param_16);
  DAT_803de579 = 0;
  DAT_803de578 = 1;
  return;
}

