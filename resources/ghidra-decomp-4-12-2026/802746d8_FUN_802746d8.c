// Function: FUN_802746d8
// Entry: 802746d8
// Size: 460 bytes

undefined4 FUN_802746d8(short param_1)

{
  short sVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  
  FUN_80285258();
  uVar5 = (uint)DAT_803def0e;
  uVar4 = 0;
  for (puVar3 = &DAT_803c56d8; ((int)uVar4 < (int)uVar5 && (param_1 != *(short *)(puVar3 + 1)));
      puVar3 = puVar3 + 3) {
    uVar4 = uVar4 + 1;
  }
  if ((uVar4 == uVar5) ||
     (sVar1 = *(short *)(&DAT_803c56e0 + uVar4 * 3),
     *(short *)(&DAT_803c56e0 + uVar4 * 3) = sVar1 + -1, (short)(sVar1 + -1) != 0)) {
    FUN_80285220();
    return 0;
  }
  iVar2 = uVar4 + 1;
  uVar4 = uVar5 - iVar2;
  puVar3 = &DAT_803c56d8 + iVar2 * 3;
  if (iVar2 < (int)uVar5) {
    uVar5 = uVar4 >> 3;
    if (uVar5 != 0) {
      do {
        puVar3[-3] = *puVar3;
        puVar3[-2] = puVar3[1];
        puVar3[-1] = puVar3[2];
        *puVar3 = puVar3[3];
        puVar3[1] = puVar3[4];
        puVar3[2] = puVar3[5];
        puVar3[3] = puVar3[6];
        puVar3[4] = puVar3[7];
        puVar3[5] = puVar3[8];
        puVar3[6] = puVar3[9];
        puVar3[7] = puVar3[10];
        puVar3[8] = puVar3[0xb];
        puVar3[9] = puVar3[0xc];
        puVar3[10] = puVar3[0xd];
        puVar3[0xb] = puVar3[0xe];
        puVar3[0xc] = puVar3[0xf];
        puVar3[0xd] = puVar3[0x10];
        puVar3[0xe] = puVar3[0x11];
        puVar3[0xf] = puVar3[0x12];
        puVar3[0x10] = puVar3[0x13];
        puVar3[0x11] = puVar3[0x14];
        puVar3[0x12] = puVar3[0x15];
        puVar3[0x13] = puVar3[0x16];
        puVar3[0x14] = puVar3[0x17];
        puVar3 = puVar3 + 0x18;
        uVar5 = uVar5 - 1;
      } while (uVar5 != 0);
      uVar4 = uVar4 & 7;
      if (uVar4 == 0) goto LAB_8027486c;
    }
    do {
      puVar3[-3] = *puVar3;
      puVar3[-2] = puVar3[1];
      puVar3[-1] = puVar3[2];
      puVar3 = puVar3 + 3;
      uVar4 = uVar4 - 1;
    } while (uVar4 != 0);
  }
LAB_8027486c:
  DAT_803def0e = DAT_803def0e - 1;
  FUN_80285220();
  return 1;
}

