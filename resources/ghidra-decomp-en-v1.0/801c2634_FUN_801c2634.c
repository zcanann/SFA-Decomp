// Function: FUN_801c2634
// Entry: 801c2634
// Size: 76 bytes

void FUN_801c2634(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = 0;
  puVar2 = (undefined4 *)&DAT_803dbf48;
  do {
    FUN_80054308(*puVar2);
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 2);
  return;
}

