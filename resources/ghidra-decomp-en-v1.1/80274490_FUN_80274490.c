// Function: FUN_80274490
// Entry: 80274490
// Size: 584 bytes

undefined4 FUN_80274490(ushort param_1,undefined4 param_2,undefined2 param_3)

{
  uint uVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  
  FUN_80285258();
  uVar3 = (uint)DAT_803def0e;
  iVar4 = 0;
  for (puVar2 = &DAT_803c56d8; (iVar4 < (int)uVar3 && (*(ushort *)(puVar2 + 1) < param_1));
      puVar2 = puVar2 + 3) {
    iVar4 = iVar4 + 1;
  }
  if (iVar4 < (int)uVar3) {
    if (param_1 == *(ushort *)(&DAT_803c56dc + iVar4 * 3)) {
      *(short *)(&DAT_803c56e0 + iVar4 * 3) = *(short *)(&DAT_803c56e0 + iVar4 * 3) + 1;
      FUN_80285220();
      return 0;
    }
    if (0xff < uVar3) {
      FUN_80285220();
      return 0;
    }
    uVar1 = uVar3 - iVar4;
    puVar2 = &DAT_803c56d8 + (uVar3 - 1) * 3;
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
        if (uVar1 == 0) goto LAB_80274694;
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
    FUN_80285220();
    return 0;
  }
LAB_80274694:
  DAT_803def0e = DAT_803def0e + 1;
  *(ushort *)(&DAT_803c56dc + iVar4 * 3) = param_1;
  (&DAT_803c56d8)[iVar4 * 3] = param_2;
  *(undefined2 *)((int)&DAT_803c56dc + iVar4 * 0xc + 2) = param_3;
  *(undefined2 *)(&DAT_803c56e0 + iVar4 * 3) = 1;
  FUN_80285220();
  return 1;
}

