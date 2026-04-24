// Function: FUN_80246cf4
// Entry: 80246cf4
// Size: 84 bytes

void FUN_80246cf4(void)

{
  undefined **ppuVar1;
  
  for (ppuVar1 = &PTR_FUN_802c1880; (code *)*ppuVar1 != (code *)0x0; ppuVar1 = (code **)ppuVar1 + 1)
  {
    (*(code *)*ppuVar1)();
  }
  return;
}

