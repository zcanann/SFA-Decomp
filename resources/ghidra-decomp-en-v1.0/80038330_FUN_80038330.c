// Function: FUN_80038330
// Entry: 80038330
// Size: 112 bytes

void FUN_80038330(int param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  undefined2 local_18;
  undefined2 local_16;
  undefined2 local_14;
  float local_10;
  undefined4 local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  iVar1 = *(int *)(*(int *)(param_1 + 0x50) + 0x2c);
  local_c = *(undefined4 *)(iVar1 + param_2 * 0x18);
  iVar1 = iVar1 + param_2 * 0x18;
  local_8 = *(undefined4 *)(iVar1 + 4);
  local_4 = *(undefined4 *)(iVar1 + 8);
  local_18 = *(undefined2 *)(iVar1 + 0xc);
  local_16 = *(undefined2 *)(iVar1 + 0xe);
  local_14 = *(undefined2 *)(iVar1 + 0x10);
  local_10 = FLOAT_803de97c;
  FUN_80021570(&local_18,param_3);
  return;
}

