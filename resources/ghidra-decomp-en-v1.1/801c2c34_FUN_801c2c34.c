// Function: FUN_801c2c34
// Entry: 801c2c34
// Size: 96 bytes

void FUN_801c2c34(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  iVar2 = 0;
  puVar4 = (undefined4 *)&DAT_803dcba8;
  puVar3 = (undefined4 *)&DAT_803dcbb0;
  do {
    uVar1 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*puVar4,
                         param_10,param_11,param_12,param_13,param_14,param_15,param_16);
    *puVar3 = uVar1;
    puVar4 = puVar4 + 1;
    puVar3 = puVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 2);
  return;
}

