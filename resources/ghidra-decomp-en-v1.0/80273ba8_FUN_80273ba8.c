// Function: FUN_80273ba8
// Entry: 80273ba8
// Size: 388 bytes

undefined4 FUN_80273ba8(short param_1)

{
  short sVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  
  FUN_80284af4();
  uVar5 = (uint)DAT_803de28c;
  uVar4 = 0;
  for (puVar3 = &DAT_803c4278; ((int)uVar4 < (int)uVar5 && (param_1 != *(short *)(puVar3 + 1)));
      puVar3 = puVar3 + 2) {
    uVar4 = uVar4 + 1;
  }
  if ((uVar4 == uVar5) ||
     (sVar1 = (&DAT_803c427e)[uVar4 * 4], (&DAT_803c427e)[uVar4 * 4] = sVar1 + -1,
     (short)(sVar1 + -1) != 0)) {
    FUN_80284abc();
    return 0;
  }
  iVar2 = uVar4 + 1;
  uVar4 = uVar5 - iVar2;
  puVar3 = &DAT_803c4278 + iVar2 * 2;
  if (iVar2 < (int)uVar5) {
    uVar5 = uVar4 >> 3;
    if (uVar5 != 0) {
      do {
        puVar3[-2] = *puVar3;
        puVar3[-1] = puVar3[1];
        *puVar3 = puVar3[2];
        puVar3[1] = puVar3[3];
        puVar3[2] = puVar3[4];
        puVar3[3] = puVar3[5];
        puVar3[4] = puVar3[6];
        puVar3[5] = puVar3[7];
        puVar3[6] = puVar3[8];
        puVar3[7] = puVar3[9];
        puVar3[8] = puVar3[10];
        puVar3[9] = puVar3[0xb];
        puVar3[10] = puVar3[0xc];
        puVar3[0xb] = puVar3[0xd];
        puVar3[0xc] = puVar3[0xe];
        puVar3[0xd] = puVar3[0xf];
        puVar3 = puVar3 + 0x10;
        uVar5 = uVar5 - 1;
      } while (uVar5 != 0);
      uVar4 = uVar4 & 7;
      if (uVar4 == 0) goto LAB_80273cf4;
    }
    do {
      puVar3[-2] = *puVar3;
      puVar3[-1] = puVar3[1];
      puVar3 = puVar3 + 2;
      uVar4 = uVar4 - 1;
    } while (uVar4 != 0);
  }
LAB_80273cf4:
  DAT_803de28c = DAT_803de28c - 1;
  FUN_80284abc();
  return 1;
}

