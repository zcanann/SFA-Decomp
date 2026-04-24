// Function: FUN_8028d0b4
// Entry: 8028d0b4
// Size: 224 bytes

int FUN_8028d0b4(void)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  undefined *puVar4;
  uint uVar5;
  
  iVar1 = 0;
  puVar4 = &DAT_803d99a4 + DAT_803d8888;
  uVar2 = 0x800 - DAT_803d8888;
  if (DAT_803d8888 < 0x800) {
    uVar5 = uVar2 >> 3;
    uVar3 = uVar2;
    if (uVar5 == 0) goto LAB_8028d130;
    do {
      *puVar4 = 0;
      puVar4[1] = 0;
      puVar4[2] = 0;
      puVar4[3] = 0;
      puVar4[4] = 0;
      puVar4[5] = 0;
      puVar4[6] = 0;
      puVar4[7] = 0;
      puVar4 = puVar4 + 8;
      uVar5 = uVar5 - 1;
    } while (uVar5 != 0);
    for (uVar3 = uVar2 & 7; uVar3 != 0; uVar3 = uVar3 - 1) {
LAB_8028d130:
      *puVar4 = 0;
      puVar4 = puVar4 + 1;
    }
    DAT_803d8888 = DAT_803d8888 + uVar2;
  }
  if (DAT_803d8888 != 0) {
    uVar2 = (*DAT_80332370)(&DAT_803d99a4);
    DAT_803d8888 = 0;
    iVar1 = (int)(-uVar2 | uVar2) >> 0x1f;
  }
  return iVar1;
}

