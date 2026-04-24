// Function: FUN_801c2680
// Entry: 801c2680
// Size: 96 bytes

void FUN_801c2680(void)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  iVar2 = 0;
  puVar4 = (undefined4 *)&DAT_803dbf40;
  puVar3 = (undefined4 *)&DAT_803dbf48;
  do {
    uVar1 = FUN_80054d54(*puVar4);
    *puVar3 = uVar1;
    puVar4 = puVar4 + 1;
    puVar3 = puVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 2);
  return;
}

