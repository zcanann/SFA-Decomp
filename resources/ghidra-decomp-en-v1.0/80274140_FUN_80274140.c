// Function: FUN_80274140
// Entry: 80274140
// Size: 504 bytes

undefined4 FUN_80274140(ushort param_1,undefined4 param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  
  FUN_80284af4();
  uVar3 = (uint)DAT_803de28a;
  iVar4 = 0;
  for (puVar2 = &DAT_803c0278; (iVar4 < (int)uVar3 && (*(ushort *)(puVar2 + 1) < param_1));
      puVar2 = puVar2 + 2) {
    iVar4 = iVar4 + 1;
  }
  if (iVar4 < (int)uVar3) {
    if (param_1 == (&DAT_803c027c)[iVar4 * 4]) {
      FUN_80284abc();
      (&DAT_803c027e)[iVar4 * 4] = (&DAT_803c027e)[iVar4 * 4] + 1;
      return 0;
    }
    if (0x7ff < uVar3) {
      FUN_80284abc();
      return 0;
    }
    uVar1 = uVar3 - iVar4;
    puVar2 = &DAT_803c0278 + (uVar3 - 1) * 2;
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
        if (uVar1 == 0) goto LAB_802742f8;
      }
      do {
        puVar2[2] = *puVar2;
        puVar2[3] = puVar2[1];
        puVar2 = puVar2 + -2;
        uVar1 = uVar1 - 1;
      } while (uVar1 != 0);
    }
  }
  else if (0x7ff < uVar3) {
    FUN_80284abc();
    return 0;
  }
LAB_802742f8:
  DAT_803de28a = DAT_803de28a + 1;
  (&DAT_803c027c)[iVar4 * 4] = param_1;
  (&DAT_803c0278)[iVar4 * 2] = param_2;
  (&DAT_803c027e)[iVar4 * 4] = 1;
  FUN_80284abc();
  return 1;
}

