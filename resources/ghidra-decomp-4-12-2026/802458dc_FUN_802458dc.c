// Function: FUN_802458dc
// Entry: 802458dc
// Size: 92 bytes

undefined2 * FUN_802458dc(void)

{
  undefined2 *puVar1;
  ulonglong uVar2;
  
  uVar2 = FUN_80243e74();
  if (DAT_803ae088 == 0) {
    puVar1 = &DAT_803ae054;
    DAT_803ae088 = 1;
    DAT_803ae084 = (int)(uVar2 >> 0x20);
  }
  else {
    FUN_80243e9c();
    puVar1 = (undefined2 *)0x0;
  }
  return puVar1;
}

