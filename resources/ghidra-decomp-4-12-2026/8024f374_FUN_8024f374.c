// Function: FUN_8024f374
// Entry: 8024f374
// Size: 164 bytes

void FUN_8024f374(uint param_1,uint param_2)

{
  uint uVar1;
  
  FUN_80243e74();
  if (((DAT_803dec34 & 0x80000000U >> param_1) != 0) &&
     (uVar1 = FUN_802534e4(param_1), (uVar1 & 0x20000000) == 0)) {
    if ((DAT_803dd1fc < 2) && (param_2 == 2)) {
      param_2 = 0;
    }
    FUN_80252d24(param_1,DAT_803dd1f8 | 0x400000 | param_2 & 3);
    FUN_80252d38();
  }
  FUN_80243e9c();
  return;
}

