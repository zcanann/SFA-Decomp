// Function: FUN_8027949c
// Entry: 8027949c
// Size: 80 bytes

undefined4 FUN_8027949c(uint param_1)

{
  undefined4 *puVar1;
  
  puVar1 = DAT_803de2f4;
  if (param_1 != 0xffffffff) {
    for (; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
      if (puVar1[2] == param_1) goto LAB_802794d4;
      if (param_1 < (uint)puVar1[2]) break;
    }
    puVar1 = (undefined4 *)0x0;
LAB_802794d4:
    if (puVar1 != (undefined4 *)0x0) {
      return puVar1[3];
    }
  }
  return 0xffffffff;
}

