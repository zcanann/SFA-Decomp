// Function: FUN_801ef8e8
// Entry: 801ef8e8
// Size: 168 bytes

void FUN_801ef8e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0x5c);
  *(code **)(param_9 + 0x5e) = FUN_801ef0a0;
  *(undefined4 *)(iVar2 + 0x4c) = *(undefined4 *)(param_9 + 6);
  *(undefined4 *)(iVar2 + 0x50) = *(undefined4 *)(param_9 + 8);
  *(undefined4 *)(iVar2 + 0x54) = *(undefined4 *)(param_9 + 10);
  *(undefined *)(iVar2 + 100) = 100;
  *param_9 = 0x4000;
  uVar1 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x156,
                       param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  *(undefined4 *)(iVar2 + 0x18) = uVar1;
  uVar1 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xc0d,
                       param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  *(undefined4 *)(iVar2 + 0x1c) = uVar1;
  uVar1 = FUN_80013ee8(0x79);
  *(undefined4 *)(iVar2 + 0x14) = uVar1;
  FUN_80035a58((int)param_9,1);
  FUN_800372f8((int)param_9,10);
  return;
}

