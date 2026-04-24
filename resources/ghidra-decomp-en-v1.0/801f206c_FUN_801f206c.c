// Function: FUN_801f206c
// Entry: 801f206c
// Size: 96 bytes

void FUN_801f206c(int param_1,int param_2)

{
  undefined uVar1;
  undefined2 *puVar2;
  
  puVar2 = *(undefined2 **)(param_1 + 0xb8);
  uVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  *(undefined *)(param_1 + 0xad) = uVar1;
  *puVar2 = *(undefined2 *)(param_2 + 0x1a);
  *(undefined *)(puVar2 + 1) = 0;
  return;
}

