// Function: FUN_802bcb60
// Entry: 802bcb60
// Size: 192 bytes

undefined4 FUN_802bcb60(ushort *param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  double dVar2;
  ushort local_68;
  ushort local_66;
  ushort local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  float afStack_50 [19];
  
  *(undefined *)(param_3 + 0x56) = 0;
  *(undefined2 *)(param_3 + 0x6e) = *(undefined2 *)(param_3 + 0x70);
  (**(code **)(*DAT_803dd70c + 0x14))(param_1,*(undefined4 *)(param_1 + 0x5c),2);
  local_5c = *(undefined4 *)(param_1 + 6);
  local_58 = *(undefined4 *)(param_1 + 8);
  local_54 = *(undefined4 *)(param_1 + 10);
  local_68 = *param_1;
  local_66 = param_1[1];
  local_64 = param_1[2];
  local_60 = *(undefined4 *)(param_1 + 4);
  FUN_80021fac(afStack_50,&local_68);
  iVar1 = *(int *)(param_1 + 0x32);
  dVar2 = (double)FLOAT_803e8f58;
  FUN_80022790(dVar2,dVar2,dVar2,afStack_50,(float *)(iVar1 + 0x20),(float *)(iVar1 + 0x24),
               (float *)(iVar1 + 0x28));
  return 0;
}

