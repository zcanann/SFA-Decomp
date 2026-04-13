// Function: FUN_8021ac80
// Entry: 8021ac80
// Size: 84 bytes

void FUN_8021ac80(undefined2 *param_1,int param_2)

{
  int iVar1;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  iVar1 = *(int *)(param_1 + 0x5c);
  *(float *)(iVar1 + 0xc) = FLOAT_803e7680;
  *(undefined2 *)(iVar1 + 0x14) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined *)(iVar1 + 0x16) = 3;
  FUN_800803f8((undefined4 *)(iVar1 + 0x10));
  return;
}

