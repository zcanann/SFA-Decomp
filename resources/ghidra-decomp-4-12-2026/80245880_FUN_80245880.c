// Function: FUN_80245880
// Entry: 80245880
// Size: 92 bytes

undefined2 * FUN_80245880(void)

{
  undefined2 *puVar1;
  ulonglong uVar2;
  
  puVar1 = &DAT_803ae040;
  uVar2 = FUN_80243e74();
  if (DAT_803ae088 == 0) {
    DAT_803ae088 = 1;
    DAT_803ae084 = (int)(uVar2 >> 0x20);
  }
  else {
    FUN_80243e9c();
    puVar1 = (undefined2 *)0x0;
  }
  return puVar1;
}

