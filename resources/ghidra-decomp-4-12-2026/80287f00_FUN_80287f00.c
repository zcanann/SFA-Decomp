// Function: FUN_80287f00
// Entry: 80287f00
// Size: 44 bytes

undefined * FUN_80287f00(int param_1)

{
  undefined *puVar1;
  
  puVar1 = (undefined *)0x0;
  if ((-1 < param_1) && (param_1 < 3)) {
    puVar1 = &DAT_803d7580 + param_1 * 0x890;
  }
  return puVar1;
}

