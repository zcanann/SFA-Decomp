// Function: FUN_801e4e60
// Entry: 801e4e60
// Size: 172 bytes

void FUN_801e4e60(undefined2 *param_1,int param_2)

{
  int iVar1;
  
  *(code **)(param_1 + 0x5e) = FUN_801e4ac0;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  *(undefined *)(*(int *)(param_1 + 0x5c) + 4) = 0;
  iVar1 = FUN_8001ffb4(0x75);
  if (iVar1 == 0) {
    FUN_800066e0(param_1,param_1,0x58,0,0,0);
    FUN_800066e0(param_1,param_1,0x6d,0,0,0);
  }
  return;
}

