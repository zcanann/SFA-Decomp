// Function: FUN_801342f8
// Entry: 801342f8
// Size: 208 bytes

void FUN_801342f8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar3;
  undefined4 uVar1;
  int iVar2;
  int *in_r6;
  int in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 extraout_f1;
  undefined8 uVar4;
  int local_28;
  int local_24;
  int local_20;
  float local_1c;
  undefined auStack_18 [20];
  
  local_1c = FLOAT_803e2f30;
  local_20 = 0;
  local_24 = 0;
  local_28 = 0;
  bVar3 = FUN_80014074();
  if (bVar3 != 0) {
    FUN_800140dc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  uVar1 = FUN_8002bac4();
  iVar2 = FUN_80036f50(9,uVar1,&local_1c);
  uVar4 = extraout_f1;
  if (iVar2 != 0) {
    in_r6 = &local_28;
    in_r7 = **(int **)(iVar2 + 0x68);
    uVar4 = (**(code **)(in_r7 + 0x54))(iVar2,&local_20,&local_24);
  }
  local_24 = local_28 - (local_24 - local_20);
  if (local_24 < 0) {
    local_24 = 0;
  }
  FUN_8028fde8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)auStack_18,
               &DAT_803dc858,local_24,in_r6,in_r7,in_r8,in_r9,in_r10);
  return;
}

