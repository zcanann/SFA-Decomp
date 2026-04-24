// Function: FUN_8016b6ec
// Entry: 8016b6ec
// Size: 108 bytes

void FUN_8016b6ec(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  iVar1 = *piVar2;
  if ((iVar1 != 0) && (param_10 == 0)) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1);
    *piVar2 = 0;
  }
  (**(code **)(*DAT_803dd6fc + 0x18))(param_9);
  return;
}

