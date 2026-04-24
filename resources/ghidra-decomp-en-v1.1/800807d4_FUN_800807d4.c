// Function: FUN_800807d4
// Entry: 800807d4
// Size: 56 bytes

void FUN_800807d4(int param_1)

{
  undefined2 *puVar1;
  
  puVar1 = (undefined2 *)FUN_800396d0(param_1,0);
  if (puVar1 != (undefined2 *)0x0) {
    puVar1[1] = 0;
    *puVar1 = 0;
  }
  return;
}

