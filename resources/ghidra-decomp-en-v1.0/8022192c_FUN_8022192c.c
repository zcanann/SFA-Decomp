// Function: FUN_8022192c
// Entry: 8022192c
// Size: 68 bytes

void FUN_8022192c(int param_1)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0xb8);
  FUN_80037200(param_1,0x3a);
  *(undefined *)(puVar1 + 1) = 0;
  *puVar1 = 0;
  FUN_8008016c(puVar1 + 2);
  return;
}

