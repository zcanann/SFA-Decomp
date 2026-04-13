// Function: FUN_80037a5c
// Entry: 80037a5c
// Size: 120 bytes

void FUN_80037a5c(int param_1,int param_2)

{
  undefined4 *puVar1;
  
  if (((param_2 != 0) && (param_1 != 0)) && (*(int *)(param_1 + 0xdc) == 0)) {
    puVar1 = (undefined4 *)FUN_80023d8c((param_2 * 3 + 2) * 4,0xe);
    *puVar1 = 0;
    puVar1[1] = param_2;
    *(undefined4 **)(param_1 + 0xdc) = puVar1;
  }
  return;
}

