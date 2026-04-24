// Function: FUN_8006cad0
// Entry: 8006cad0
// Size: 84 bytes

void FUN_8006cad0(undefined *param_1)

{
  undefined *puVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 0;
  puVar1 = &DAT_8038df48;
  iVar3 = 0x25;
  while ((puVar1[0x10] == '\0' || (puVar1 != param_1))) {
    puVar1 = puVar1 + 0x14;
    iVar2 = iVar2 + 1;
    iVar3 = iVar3 + -1;
    if (iVar3 == 0) {
      return;
    }
  }
  (&DAT_8038df58)[iVar2 * 0x14] = 0;
  return;
}

