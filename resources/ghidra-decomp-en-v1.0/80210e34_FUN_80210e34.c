// Function: FUN_80210e34
// Entry: 80210e34
// Size: 80 bytes

void FUN_80210e34(int param_1)

{
  undefined *puVar1;
  
  puVar1 = *(undefined **)(param_1 + 0xb8);
  FUN_80037200(param_1,0x1e);
  *puVar1 = 1;
  *(undefined **)(param_1 + 0xbc) = &LAB_80210be8;
  return;
}

