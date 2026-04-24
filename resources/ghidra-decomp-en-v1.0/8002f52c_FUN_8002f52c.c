// Function: FUN_8002f52c
// Entry: 8002f52c
// Size: 72 bytes

void FUN_8002f52c(int param_1,int param_2,short param_3,undefined2 param_4)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
  if (iVar1 == 0) {
    return;
  }
  if (param_2 == 0) {
    iVar1 = *(int *)(iVar1 + 0x2c);
  }
  else {
    iVar1 = *(int *)(iVar1 + 0x30);
  }
  *(undefined2 *)(iVar1 + param_3 * 2 + 0x58) = param_4;
  return;
}

