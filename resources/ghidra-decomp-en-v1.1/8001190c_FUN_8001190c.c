// Function: FUN_8001190c
// Entry: 8001190c
// Size: 272 bytes

void FUN_8001190c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,short *param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,byte *param_14,undefined2 *param_15,undefined4 param_16)

{
  uint uVar1;
  undefined8 uVar2;
  short local_18;
  short local_16;
  short local_14;
  
  uVar1 = (ushort)param_10[4] + 1 & 0xffff;
  local_16 = param_10[1];
  local_14 = param_10[2];
  local_18 = *param_10 + 2;
  uVar2 = FUN_80011014(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10,param_11,uVar1,&local_18,param_14,param_15,param_16);
  local_18 = local_18 + -4;
  local_16 = param_10[1];
  uVar2 = FUN_80011014(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10,param_11,uVar1,&local_18,param_14,param_15,param_16);
  local_18 = local_18 + 2;
  local_14 = local_14 + 2;
  local_16 = param_10[1];
  uVar2 = FUN_80011014(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10,param_11,uVar1,&local_18,param_14,param_15,param_16);
  local_14 = local_14 + -4;
  local_16 = param_10[1];
  FUN_80011014(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
               param_11,uVar1,&local_18,param_14,param_15,param_16);
  return;
}

