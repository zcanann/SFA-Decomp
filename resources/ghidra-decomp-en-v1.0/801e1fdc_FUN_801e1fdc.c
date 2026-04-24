// Function: FUN_801e1fdc
// Entry: 801e1fdc
// Size: 280 bytes

void FUN_801e1fdc(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  undefined auStack72 [6];
  undefined2 local_42;
  float local_3c;
  float local_38;
  float local_34;
  longlong local_30;
  longlong local_28;
  
  uVar3 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = *(int *)(iVar1 + 0xb8);
  if (param_6 != '\0') {
    if (*(char *)(iVar2 + 0x70) < '\x02') {
      local_30 = (longlong)(int)*(float *)(iVar2 + 0x88);
      local_42 = (undefined2)(int)*(float *)(iVar2 + 0x88);
      local_34 = FLOAT_803e57fc;
      local_38 = FLOAT_803e5800;
      local_3c = FLOAT_803e5804;
      (**(code **)(*DAT_803dca88 + 8))(iVar1,0xa3,auStack72,2,0xffffffff,0);
      local_28 = (longlong)(int)*(float *)(iVar2 + 0x8c);
      local_42 = (undefined2)(int)*(float *)(iVar2 + 0x8c);
      local_3c = FLOAT_803e5808;
      (**(code **)(*DAT_803dca88 + 8))(iVar1,0xa3,auStack72,2,0xffffffff,0);
    }
    FUN_8003b8f4((double)FLOAT_803e57a4,iVar1,(int)uVar3,param_3,param_4,param_5);
  }
  FUN_80286124();
  return;
}

