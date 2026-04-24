// Function: FUN_8028779c
// Entry: 8028779c
// Size: 44 bytes

undefined * FUN_8028779c(int param_1)

{
  undefined *puVar1;
  
  puVar1 = (undefined *)0x0;
  if ((-1 < param_1) && (param_1 < 3)) {
    puVar1 = &DAT_803d6920 + param_1 * 0x890;
  }
  return puVar1;
}

