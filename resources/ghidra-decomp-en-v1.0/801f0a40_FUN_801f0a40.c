// Function: FUN_801f0a40
// Entry: 801f0a40
// Size: 156 bytes

void FUN_801f0a40(undefined2 *param_1,int param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  FUN_80037964(param_1,4);
  *(undefined **)(param_1 + 0x5e) = &LAB_801f0900;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[1] = *(undefined2 *)(param_2 + 0x1c);
  *(short *)(iVar1 + 4) = (short)*(char *)(param_2 + 0x19);
  *(undefined2 *)(iVar1 + 6) = *(undefined2 *)(param_2 + 0x1a);
  FUN_80030334((double)FLOAT_803e5d08,param_1,*(short *)(iVar1 + 4) + 0x100,0);
  return;
}

