// Function: FUN_800240d8
// Entry: 800240d8
// Size: 92 bytes

undefined4 * FUN_800240d8(undefined4 *param_1)

{
  undefined4 *puVar1;
  
  FUN_8024377c();
  puVar1 = (undefined4 *)*param_1;
  if (puVar1 == (undefined4 *)0x0) {
    FUN_802437a4();
    puVar1 = (undefined4 *)0x0;
  }
  else {
    *param_1 = *puVar1;
    FUN_802437a4();
  }
  return puVar1;
}

