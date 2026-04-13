// Function: FUN_801b0d74
// Entry: 801b0d74
// Size: 136 bytes

void FUN_801b0d74(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  uint uVar1;
  uint *puVar2;
  undefined8 uVar3;
  
  puVar2 = *(uint **)(param_9 + 0xb8);
  uVar3 = (**(code **)(*DAT_803dd6f8 + 0x18))();
  uVar1 = puVar2[1];
  if ((uVar1 != 0) && (param_10 == 0)) {
    FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1);
  }
  FUN_8003709c(param_9,0x31);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
  }
  return;
}

