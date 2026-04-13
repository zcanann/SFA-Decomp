// Function: FUN_80224548
// Entry: 80224548
// Size: 284 bytes

void FUN_80224548(int param_1)

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
  local_24 = DAT_802c2d38;
  local_20 = DAT_802c2d3c;
  local_1c = DAT_802c2d40;
  local_18 = DAT_802c2d44;
  local_34 = DAT_802c2d48;
  local_30 = DAT_802c2d4c;
  local_2c = DAT_802c2d50;
  local_28 = DAT_802c2d54;
  local_38 = 2;
  FUN_80115200(param_1,(undefined4 *)(iVar1 + 0x35c),0xd556,0x638e,8);
  FUN_80114238(iVar1 + 0x35c,(wchar_t *)&local_34,(wchar_t *)&local_24);
  *(byte *)(iVar1 + 0x96d) = *(byte *)(iVar1 + 0x96d) | 0x22;
  (**(code **)(*DAT_803dd71c + 0x8c))
            ((double)FLOAT_803e79b4,iVar1 + 0x9b0,param_1,&local_38,0xffffffff);
  (**(code **)(*DAT_803dd70c + 4))(param_1,iVar1,4,4);
  FUN_800372f8(param_1,3);
  return;
}

