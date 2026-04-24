// Function: FUN_80223ef8
// Entry: 80223ef8
// Size: 284 bytes

void FUN_80223ef8(int param_1)

{
  int iVar1;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  local_24 = DAT_802c25b8;
  local_20 = DAT_802c25bc;
  local_1c = DAT_802c25c0;
  local_18 = DAT_802c25c4;
  local_34 = DAT_802c25c8;
  local_30 = DAT_802c25cc;
  local_2c = DAT_802c25d0;
  local_28 = DAT_802c25d4;
  local_38 = 2;
  FUN_80114f64(param_1,iVar1 + 0x35c,0xffffd556,0x638e,8);
  FUN_80113f9c(iVar1 + 0x35c,&local_34,&local_24,8);
  *(byte *)(iVar1 + 0x96d) = *(byte *)(iVar1 + 0x96d) | 0x22;
  (**(code **)(*DAT_803dca9c + 0x8c))
            ((double)FLOAT_803e6d1c,iVar1 + 0x9b0,param_1,&local_38,0xffffffff);
  (**(code **)(*DAT_803dca8c + 4))(param_1,iVar1,4,4);
  FUN_80037200(param_1,3);
  return;
}

