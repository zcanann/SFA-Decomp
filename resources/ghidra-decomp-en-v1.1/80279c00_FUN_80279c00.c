// Function: FUN_80279c00
// Entry: 80279c00
// Size: 80 bytes

undefined4 FUN_80279c00(uint param_1)

{
  undefined4 *puVar1;
  
  puVar1 = DAT_803def74;
  if (param_1 != 0xffffffff) {
    for (; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
      if (puVar1[2] == param_1) goto LAB_80279c38;
      if (param_1 < (uint)puVar1[2]) break;
    }
    puVar1 = (undefined4 *)0x0;
LAB_80279c38:
    if (puVar1 != (undefined4 *)0x0) {
      return puVar1[3];
    }
  }
  return 0xffffffff;
}

