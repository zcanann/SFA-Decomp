// Function: FUN_80247458
// Entry: 80247458
// Size: 84 bytes

void FUN_80247458(void)

{
  undefined **ppuVar1;
  
  for (ppuVar1 = &PTR_FUN_802c2000; (code *)*ppuVar1 != (code *)0x0; ppuVar1 = ppuVar1 + 1) {
    (*(code *)*ppuVar1)();
  }
  return;
}

