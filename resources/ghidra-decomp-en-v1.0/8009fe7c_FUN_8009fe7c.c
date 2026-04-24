// Function: FUN_8009fe7c
// Entry: 8009fe7c
// Size: 84 bytes

void FUN_8009fe7c(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  FUN_8009b254();
  iVar1 = 0;
  puVar2 = &DAT_8039bd58;
  do {
    FUN_80023800(*puVar2);
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x50);
  return;
}

