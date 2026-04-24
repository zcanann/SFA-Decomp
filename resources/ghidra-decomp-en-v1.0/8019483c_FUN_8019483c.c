// Function: FUN_8019483c
// Entry: 8019483c
// Size: 132 bytes

void FUN_8019483c(undefined2 *param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = *(undefined2 *)(param_2 + 0x24);
  FUN_80037200(param_1,0x23);
  FUN_80037200(param_1,0x31);
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x18));
  if (iVar1 != 0) {
    *(byte *)(puVar2 + 1) = *(byte *)(puVar2 + 1) & 0x7f | 0x80;
    *puVar2 = 3000;
  }
  return;
}

