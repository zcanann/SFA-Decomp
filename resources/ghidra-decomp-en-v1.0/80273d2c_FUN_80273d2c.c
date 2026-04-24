// Function: FUN_80273d2c
// Entry: 80273d2c
// Size: 584 bytes

undefined4 FUN_80273d2c(ushort param_1,undefined4 param_2,undefined2 param_3)

{
  uint uVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  
  FUN_80284af4();
  uVar3 = (uint)DAT_803de28e;
  iVar4 = 0;
  for (puVar2 = &DAT_803c4a78; (iVar4 < (int)uVar3 && (*(ushort *)(puVar2 + 1) < param_1));
      puVar2 = puVar2 + 3) {
    iVar4 = iVar4 + 1;
  }
  if (iVar4 < (int)uVar3) {
    if (param_1 == (&DAT_803c4a7c)[iVar4 * 6]) {
      (&DAT_803c4a80)[iVar4 * 6] = (&DAT_803c4a80)[iVar4 * 6] + 1;
      FUN_80284abc();
      return 0;
    }
    if (0xff < uVar3) {
      FUN_80284abc();
      return 0;
    }
    uVar1 = uVar3 - iVar4;
    puVar2 = &DAT_803c4a78 + (uVar3 - 1) * 3;
    if (iVar4 <= (int)(uVar3 - 1)) {
      uVar3 = uVar1 >> 3;
      if (uVar3 != 0) {
        do {
          puVar2[3] = *puVar2;
          puVar2[4] = puVar2[1];
          puVar2[5] = puVar2[2];
          *puVar2 = puVar2[-3];
          puVar2[1] = puVar2[-2];
          puVar2[2] = puVar2[-1];
          puVar2[-3] = puVar2[-6];
          puVar2[-2] = puVar2[-5];
          puVar2[-1] = puVar2[-4];
          puVar2[-6] = puVar2[-9];
          puVar2[-5] = puVar2[-8];
          puVar2[-4] = puVar2[-7];
          puVar2[-9] = puVar2[-0xc];
          puVar2[-8] = puVar2[-0xb];
          puVar2[-7] = puVar2[-10];
          puVar2[-0xc] = puVar2[-0xf];
          puVar2[-0xb] = puVar2[-0xe];
          puVar2[-10] = puVar2[-0xd];
          puVar2[-0xf] = puVar2[-0x12];
          puVar2[-0xe] = puVar2[-0x11];
          puVar2[-0xd] = puVar2[-0x10];
          puVar2[-0x12] = puVar2[-0x15];
          puVar2[-0x11] = puVar2[-0x14];
          puVar2[-0x10] = puVar2[-0x13];
          puVar2 = puVar2 + -0x18;
          uVar3 = uVar3 - 1;
        } while (uVar3 != 0);
        uVar1 = uVar1 & 7;
        if (uVar1 == 0) goto LAB_80273f30;
      }
      do {
        puVar2[3] = *puVar2;
        puVar2[4] = puVar2[1];
        puVar2[5] = puVar2[2];
        puVar2 = puVar2 + -3;
        uVar1 = uVar1 - 1;
      } while (uVar1 != 0);
    }
  }
  else if (0xff < uVar3) {
    FUN_80284abc();
    return 0;
  }
LAB_80273f30:
  DAT_803de28e = DAT_803de28e + 1;
  (&DAT_803c4a7c)[iVar4 * 6] = param_1;
  (&DAT_803c4a78)[iVar4 * 3] = param_2;
  (&DAT_803c4a7e)[iVar4 * 6] = param_3;
  (&DAT_803c4a80)[iVar4 * 6] = 1;
  FUN_80284abc();
  return 1;
}

