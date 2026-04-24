// Function: FUN_80221f7c
// Entry: 80221f7c
// Size: 68 bytes

void FUN_80221f7c(int param_1)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0xb8);
  FUN_800372f8(param_1,0x3a);
  *(undefined *)(puVar1 + 1) = 0;
  *puVar1 = 0;
  FUN_800803f8(puVar1 + 2);
  return;
}

