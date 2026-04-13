// Function: FUN_80132308
// Entry: 80132308
// Size: 96 bytes

void FUN_80132308(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = 0;
  puVar2 = &DAT_803aaa18;
  do {
    FUN_80054484();
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  return;
}

