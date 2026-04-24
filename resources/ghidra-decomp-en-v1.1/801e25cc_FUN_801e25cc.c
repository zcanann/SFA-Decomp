// Function: FUN_801e25cc
// Entry: 801e25cc
// Size: 280 bytes

void FUN_801e25cc(void)

{
  int iVar1;
  char in_r8;
  int iVar2;
  undefined auStack_48 [6];
  undefined2 local_42;
  float local_3c;
  float local_38;
  float local_34;
  longlong local_30;
  longlong local_28;
  
  iVar1 = FUN_8028683c();
  iVar2 = *(int *)(iVar1 + 0xb8);
  if (in_r8 != '\0') {
    if (*(char *)(iVar2 + 0x70) < '\x02') {
      local_30 = (longlong)(int)*(float *)(iVar2 + 0x88);
      local_42 = (undefined2)(int)*(float *)(iVar2 + 0x88);
      local_34 = FLOAT_803e6494;
      local_38 = FLOAT_803e6498;
      local_3c = FLOAT_803e649c;
      (**(code **)(*DAT_803dd708 + 8))(iVar1,0xa3,auStack_48,2,0xffffffff,0);
      local_28 = (longlong)(int)*(float *)(iVar2 + 0x8c);
      local_42 = (undefined2)(int)*(float *)(iVar2 + 0x8c);
      local_3c = FLOAT_803e64a0;
      (**(code **)(*DAT_803dd708 + 8))(iVar1,0xa3,auStack_48,2,0xffffffff,0);
    }
    FUN_8003b9ec(iVar1);
  }
  FUN_80286888();
  return;
}

