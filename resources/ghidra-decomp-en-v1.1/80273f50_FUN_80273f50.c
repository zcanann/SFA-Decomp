// Function: FUN_80273f50
// Entry: 80273f50
// Size: 132 bytes

void FUN_80273f50(int param_1)

{
  byte bVar1;
  
  bVar1 = (&DAT_803befe0)[param_1 * 100];
  if ((bVar1 < 3) && (bVar1 != 0)) {
    if (bVar1 == 2) {
      FUN_8027a710((&DAT_803bf020)[param_1 * 0x19]);
    }
    (&DAT_803befe0)[param_1 * 100] = 3;
    (*(code *)(&DAT_803befe4)[param_1 * 0x19])(0,0,0,0,(&DAT_803bf024)[param_1 * 0x19]);
  }
  return;
}

