// Function: FUN_800118ec
// Entry: 800118ec
// Size: 272 bytes

void FUN_800118ec(undefined4 param_1,short *param_2,undefined4 param_3)

{
  short sVar1;
  short local_18;
  short local_16;
  short local_14;
  
  sVar1 = param_2[4] + 1;
  local_16 = param_2[1];
  local_14 = param_2[2];
  local_18 = *param_2 + 2;
  FUN_80010ff4();
  local_18 = local_18 + -4;
  local_16 = param_2[1];
  FUN_80010ff4(param_1,param_2,param_3,sVar1,&local_18);
  local_18 = local_18 + 2;
  local_14 = local_14 + 2;
  local_16 = param_2[1];
  FUN_80010ff4(param_1,param_2,param_3,sVar1,&local_18);
  local_14 = local_14 + -4;
  local_16 = param_2[1];
  FUN_80010ff4(param_1,param_2,param_3,sVar1,&local_18);
  return;
}

