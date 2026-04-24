// Function: FUN_802bc3f0
// Entry: 802bc3f0
// Size: 192 bytes

undefined4 FUN_802bc3f0(undefined2 *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  double dVar2;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined auStack80 [76];
  
  *(undefined *)(param_3 + 0x56) = 0;
  *(undefined2 *)(param_3 + 0x6e) = *(undefined2 *)(param_3 + 0x70);
  (**(code **)(*DAT_803dca8c + 0x14))(param_1,*(undefined4 *)(param_1 + 0x5c),2);
  local_5c = *(undefined4 *)(param_1 + 6);
  local_58 = *(undefined4 *)(param_1 + 8);
  local_54 = *(undefined4 *)(param_1 + 10);
  local_68 = *param_1;
  local_66 = param_1[1];
  local_64 = param_1[2];
  local_60 = *(undefined4 *)(param_1 + 4);
  FUN_80021ee8(auStack80,&local_68);
  iVar1 = *(int *)(param_1 + 0x32);
  dVar2 = (double)FLOAT_803e82c0;
  FUN_800226cc(dVar2,dVar2,dVar2,auStack80,iVar1 + 0x20,iVar1 + 0x24,iVar1 + 0x28);
  return 0;
}

