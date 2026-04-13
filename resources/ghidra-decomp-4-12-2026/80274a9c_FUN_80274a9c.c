// Function: FUN_80274a9c
// Entry: 80274a9c
// Size: 388 bytes

undefined4 FUN_80274a9c(short param_1)

{
  short sVar2;
  int iVar1;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  
  FUN_80285258();
  uVar5 = (uint)DAT_803def0a;
  uVar4 = 0;
  for (puVar3 = &DAT_803c0ed8; ((int)uVar4 < (int)uVar5 && (param_1 != *(short *)(puVar3 + 1)));
      puVar3 = puVar3 + 2) {
    uVar4 = uVar4 + 1;
  }
  if ((uVar4 == uVar5) ||
     (sVar2 = *(short *)((int)&DAT_803c0edc + uVar4 * 8 + 2) + -1,
     *(short *)((int)&DAT_803c0edc + uVar4 * 8 + 2) = sVar2, sVar2 != 0)) {
    FUN_80285220();
    return 0;
  }
  iVar1 = uVar4 + 1;
  uVar4 = uVar5 - iVar1;
  puVar3 = &DAT_803c0ed8 + iVar1 * 2;
  if (iVar1 < (int)uVar5) {
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
      if (uVar4 == 0) goto LAB_80274be8;
    }
    do {
      puVar3[-2] = *puVar3;
      puVar3[-1] = puVar3[1];
      puVar3 = puVar3 + 2;
      uVar4 = uVar4 - 1;
    } while (uVar4 != 0);
  }
LAB_80274be8:
  DAT_803def0a = DAT_803def0a - 1;
  FUN_80285220();
  return 1;
}

