// Function: FUN_80279004
// Entry: 80279004
// Size: 52 bytes

undefined4 * FUN_80279004(uint param_1)

{
  undefined4 *puVar1;
  
  puVar1 = DAT_803de2f4;
  while( true ) {
    if (puVar1 == (undefined4 *)0x0) {
      return (undefined4 *)0x0;
    }
    if (puVar1[2] == param_1) break;
    if (param_1 < (uint)puVar1[2]) {
      return (undefined4 *)0x0;
    }
    puVar1 = (undefined4 *)*puVar1;
  }
  return puVar1;
}

