// Function: FUN_8013146c
// Entry: 8013146c
// Size: 88 bytes

void FUN_8013146c(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = 0;
  puVar2 = &DAT_8031c1b4;
  do {
    FUN_80054308(*puVar2);
    puVar2 = puVar2 + 2;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  FUN_8001bdd4(3);
  return;
}

