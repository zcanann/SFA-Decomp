// Function: FUN_8021a5d8
// Entry: 8021a5d8
// Size: 84 bytes

void FUN_8021a5d8(undefined2 *param_1,int param_2)

{
  int iVar1;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  iVar1 = *(int *)(param_1 + 0x5c);
  *(float *)(iVar1 + 0xc) = FLOAT_803e69e8;
  *(undefined2 *)(iVar1 + 0x14) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined *)(iVar1 + 0x16) = 3;
  FUN_8008016c(iVar1 + 0x10);
  return;
}

