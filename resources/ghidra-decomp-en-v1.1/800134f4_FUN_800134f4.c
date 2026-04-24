// Function: FUN_800134f4
// Entry: 800134f4
// Size: 156 bytes

void FUN_800134f4(void)

{
  int iVar1;
  undefined2 *puVar2;
  undefined *puVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  uint *puVar6;
  
  FUN_80286830();
  puVar2 = &DAT_80339400;
  iVar1 = 0;
  puVar6 = &DAT_8033945c;
  puVar5 = &DAT_80339430;
  puVar4 = &DAT_80339418;
  puVar3 = &DAT_803dd550;
  do {
    if (*puVar6 != 0) {
      FUN_800238c4(*puVar6);
      *puVar6 = 0;
    }
    *puVar5 = 0xfffffffe;
    *puVar4 = 0x40000000;
    *puVar3 = 0;
    *puVar2 = 0;
    puVar2[1] = 0;
    puVar6 = puVar6 + 1;
    puVar5 = puVar5 + 1;
    puVar4 = puVar4 + 1;
    puVar3 = puVar3 + 1;
    puVar2 = puVar2 + 2;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 6);
  FUN_8028687c();
  return;
}

