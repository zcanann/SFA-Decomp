// Function: FUN_80015da8
// Entry: 80015da8
// Size: 88 bytes

undefined4 FUN_80015da8(uint param_1,uint *param_2,uint *param_3)

{
  ushort *puVar1;
  int iVar2;
  
  puVar1 = &DAT_802c8fe0;
  iVar2 = 0x7a;
  do {
    if (puVar1[2] == param_1) {
      if (param_2 != (uint *)0x0) {
        *param_2 = (uint)*puVar1;
      }
      if (param_3 != (uint *)0x0) {
        *param_3 = (uint)puVar1[1];
      }
      return 1;
    }
    puVar1 = puVar1 + 3;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return 0;
}

