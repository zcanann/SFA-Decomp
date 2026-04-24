// Function: FUN_801e5f20
// Entry: 801e5f20
// Size: 76 bytes

void FUN_801e5f20(undefined2 *param_1,int param_2)

{
  if (param_1[0x23] != 0x803) {
    *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
    FUN_80030334((double)FLOAT_803e5998,param_1,0,0);
  }
  return;
}

