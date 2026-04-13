// Function: FUN_8002419c
// Entry: 8002419c
// Size: 92 bytes

undefined4 * FUN_8002419c(undefined4 *param_1)

{
  undefined4 *puVar1;
  
  FUN_80243e74();
  puVar1 = (undefined4 *)*param_1;
  if (puVar1 == (undefined4 *)0x0) {
    FUN_80243e9c();
    puVar1 = (undefined4 *)0x0;
  }
  else {
    *param_1 = *puVar1;
    FUN_80243e9c();
  }
  return puVar1;
}

