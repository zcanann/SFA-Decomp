// Function: FUN_801aea90
// Entry: 801aea90
// Size: 76 bytes

void FUN_801aea90(undefined2 *param_1,int param_2)

{
  undefined4 uVar1;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar1 = FUN_800221a0(0,1);
  *(undefined4 *)(param_1 + 0x7a) = uVar1;
  return;
}

