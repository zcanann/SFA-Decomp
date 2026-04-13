// Function: FUN_801f26a4
// Entry: 801f26a4
// Size: 96 bytes

void FUN_801f26a4(int param_1,int param_2)

{
  uint uVar1;
  undefined2 *puVar2;
  
  puVar2 = *(undefined2 **)(param_1 + 0xb8);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  *(char *)(param_1 + 0xad) = (char)uVar1;
  *puVar2 = *(undefined2 *)(param_2 + 0x1a);
  *(undefined *)(puVar2 + 1) = 0;
  return;
}

