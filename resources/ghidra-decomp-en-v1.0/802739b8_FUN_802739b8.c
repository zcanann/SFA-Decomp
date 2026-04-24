// Function: FUN_802739b8
// Entry: 802739b8
// Size: 496 bytes

undefined4 FUN_802739b8(ushort param_1,undefined4 param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  
  FUN_80284af4();
  uVar3 = (uint)DAT_803de28c;
  iVar4 = 0;
  for (puVar2 = &DAT_803c4278; (iVar4 < (int)uVar3 && (*(ushort *)(puVar2 + 1) < param_1));
      puVar2 = puVar2 + 2) {
    iVar4 = iVar4 + 1;
  }
  if (iVar4 < (int)uVar3) {
    if (param_1 == (&DAT_803c427c)[iVar4 * 4]) {
      (&DAT_803c427e)[iVar4 * 4] = (&DAT_803c427e)[iVar4 * 4] + 1;
      FUN_80284abc();
      return 0;
    }
    if (0xff < uVar3) {
      FUN_80284abc();
      return 0;
    }
    uVar1 = uVar3 - iVar4;
    puVar2 = &DAT_803c4278 + (uVar3 - 1) * 2;
    if (iVar4 <= (int)(uVar3 - 1)) {
      uVar3 = uVar1 >> 3;
      if (uVar3 != 0) {
        do {
          puVar2[2] = *puVar2;
          puVar2[3] = puVar2[1];
          *puVar2 = puVar2[-2];
          puVar2[1] = puVar2[-1];
          puVar2[-2] = puVar2[-4];
          puVar2[-1] = puVar2[-3];
          puVar2[-4] = puVar2[-6];
          puVar2[-3] = puVar2[-5];
          puVar2[-6] = puVar2[-8];
          puVar2[-5] = puVar2[-7];
          puVar2[-8] = puVar2[-10];
          puVar2[-7] = puVar2[-9];
          puVar2[-10] = puVar2[-0xc];
          puVar2[-9] = puVar2[-0xb];
          puVar2[-0xc] = puVar2[-0xe];
          puVar2[-0xb] = puVar2[-0xd];
          puVar2 = puVar2 + -0x10;
          uVar3 = uVar3 - 1;
        } while (uVar3 != 0);
        uVar1 = uVar1 & 7;
        if (uVar1 == 0) goto LAB_80273b6c;
      }
      do {
        puVar2[2] = *puVar2;
        puVar2[3] = puVar2[1];
        puVar2 = puVar2 + -2;
        uVar1 = uVar1 - 1;
      } while (uVar1 != 0);
    }
  }
  else if (0xff < uVar3) {
    FUN_80284abc();
    return 0;
  }
LAB_80273b6c:
  DAT_803de28c = DAT_803de28c + 1;
  (&DAT_803c427c)[iVar4 * 4] = param_1;
  (&DAT_803c4278)[iVar4 * 2] = param_2;
  (&DAT_803c427e)[iVar4 * 4] = 1;
  FUN_80284abc();
  return 1;
}

