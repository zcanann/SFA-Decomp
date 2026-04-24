// Function: FUN_800134d4
// Entry: 800134d4
// Size: 156 bytes

void FUN_800134d4(void)

{
  int iVar1;
  undefined2 *puVar2;
  undefined *puVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  int *piVar6;
  
  FUN_802860cc();
  puVar2 = &DAT_803387a0;
  iVar1 = 0;
  piVar6 = &DAT_803387fc;
  puVar5 = &DAT_803387d0;
  puVar4 = &DAT_803387b8;
  puVar3 = &DAT_803dc8d0;
  do {
    if (*piVar6 != 0) {
      FUN_80023800();
      *piVar6 = 0;
    }
    *puVar5 = 0xfffffffe;
    *puVar4 = 0x40000000;
    *puVar3 = 0;
    *puVar2 = 0;
    puVar2[1] = 0;
    piVar6 = piVar6 + 1;
    puVar5 = puVar5 + 1;
    puVar4 = puVar4 + 1;
    puVar3 = puVar3 + 1;
    puVar2 = puVar2 + 2;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  FUN_80286118();
  return;
}

