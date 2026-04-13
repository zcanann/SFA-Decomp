// Function: FUN_8027411c
// Entry: 8027411c
// Size: 496 bytes

undefined4 FUN_8027411c(ushort param_1,undefined4 param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  
  FUN_80285258();
  uVar3 = (uint)DAT_803def0c;
  iVar4 = 0;
  for (puVar2 = &DAT_803c4ed8; (iVar4 < (int)uVar3 && (*(ushort *)(puVar2 + 1) < param_1));
      puVar2 = puVar2 + 2) {
    iVar4 = iVar4 + 1;
  }
  if (iVar4 < (int)uVar3) {
    if (param_1 == *(ushort *)(&DAT_803c4edc + iVar4 * 2)) {
      *(short *)((int)&DAT_803c4edc + iVar4 * 8 + 2) =
           *(short *)((int)&DAT_803c4edc + iVar4 * 8 + 2) + 1;
      FUN_80285220();
      return 0;
    }
    if (0xff < uVar3) {
      FUN_80285220();
      return 0;
    }
    uVar1 = uVar3 - iVar4;
    puVar2 = &DAT_803c4ed8 + (uVar3 - 1) * 2;
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
        if (uVar1 == 0) goto LAB_802742d0;
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
    FUN_80285220();
    return 0;
  }
LAB_802742d0:
  DAT_803def0c = DAT_803def0c + 1;
  *(ushort *)(&DAT_803c4edc + iVar4 * 2) = param_1;
  (&DAT_803c4ed8)[iVar4 * 2] = param_2;
  *(undefined2 *)((int)&DAT_803c4edc + iVar4 * 8 + 2) = 1;
  FUN_80285220();
  return 1;
}

