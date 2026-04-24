// Function: FUN_80275024
// Entry: 80275024
// Size: 784 bytes

undefined4 FUN_80275024(uint param_1,undefined4 param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  undefined2 *puVar4;
  undefined4 *puVar5;
  int iVar6;
  uint uVar7;
  
  FUN_80285258();
  uVar2 = param_1 >> 4 & 0xffc;
  uVar3 = (uint)*(ushort *)((int)&DAT_803c62d8 + uVar2);
  uVar1 = param_1 >> 6 & 0x3ff;
  if (uVar3 == 0) {
    uVar3 = (uint)DAT_803def10;
    *(ushort *)((int)&DAT_803c62da + uVar2) = DAT_803def10;
    uVar2 = uVar3;
  }
  else {
    uVar2 = (uint)*(ushort *)((int)&DAT_803c62da + uVar2);
    iVar6 = 0;
    while ((iVar6 < (int)uVar3 &&
           ((uint)*(ushort *)(&DAT_803c6adc + (uVar2 + iVar6) * 8) < (param_1 & 0xffff)))) {
      iVar6 = iVar6 + 1;
    }
    if (iVar6 < (int)uVar3) {
      uVar3 = uVar2 + iVar6;
      iVar6 = uVar3 * 8;
      if ((param_1 & 0xffff) == (uint)*(ushort *)(&DAT_803c6adc + iVar6)) {
        *(short *)(&DAT_803c6ade + iVar6) = *(short *)(&DAT_803c6ade + iVar6) + 1;
        FUN_80285220();
        return 0;
      }
    }
    else {
      uVar3 = uVar2 + iVar6;
    }
  }
  if (0x7ff < DAT_803def10) {
    FUN_80285220();
    return 0;
  }
  iVar6 = 0x40;
  puVar4 = &DAT_803c62d8;
  do {
    if (uVar2 < (ushort)puVar4[1]) {
      puVar4[1] = puVar4[1] + 1;
    }
    if (uVar2 < (ushort)puVar4[3]) {
      puVar4[3] = puVar4[3] + 1;
    }
    if (uVar2 < (ushort)puVar4[5]) {
      puVar4[5] = puVar4[5] + 1;
    }
    if (uVar2 < (ushort)puVar4[7]) {
      puVar4[7] = puVar4[7] + 1;
    }
    if (uVar2 < (ushort)puVar4[9]) {
      puVar4[9] = puVar4[9] + 1;
    }
    if (uVar2 < (ushort)puVar4[0xb]) {
      puVar4[0xb] = puVar4[0xb] + 1;
    }
    if (uVar2 < (ushort)puVar4[0xd]) {
      puVar4[0xd] = puVar4[0xd] + 1;
    }
    if (uVar2 < (ushort)puVar4[0xf]) {
      puVar4[0xf] = puVar4[0xf] + 1;
    }
    puVar4 = puVar4 + 0x10;
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  iVar6 = DAT_803def10 - 1;
  uVar2 = DAT_803def10 - uVar3;
  puVar5 = (undefined4 *)(&DAT_803c6ad8 + iVar6 * 8);
  if ((int)uVar3 <= iVar6) {
    uVar7 = uVar2 >> 3;
    if (uVar7 != 0) {
      do {
        puVar5[2] = *puVar5;
        puVar5[3] = puVar5[1];
        *puVar5 = puVar5[-2];
        puVar5[1] = puVar5[-1];
        puVar5[-2] = puVar5[-4];
        puVar5[-1] = puVar5[-3];
        puVar5[-4] = puVar5[-6];
        puVar5[-3] = puVar5[-5];
        puVar5[-6] = puVar5[-8];
        puVar5[-5] = puVar5[-7];
        puVar5[-8] = puVar5[-10];
        puVar5[-7] = puVar5[-9];
        puVar5[-10] = puVar5[-0xc];
        puVar5[-9] = puVar5[-0xb];
        puVar5[-0xc] = puVar5[-0xe];
        puVar5[-0xb] = puVar5[-0xd];
        puVar5 = puVar5 + -0x10;
        uVar7 = uVar7 - 1;
      } while (uVar7 != 0);
      uVar2 = uVar2 & 7;
      if (uVar2 == 0) goto LAB_802752cc;
    }
    do {
      puVar5[2] = *puVar5;
      puVar5[3] = puVar5[1];
      puVar5 = puVar5 + -2;
      uVar2 = uVar2 - 1;
    } while (uVar2 != 0);
  }
LAB_802752cc:
  iVar6 = uVar3 * 8;
  *(short *)(&DAT_803c6adc + iVar6) = (short)param_1;
  *(undefined4 *)(&DAT_803c6ad8 + iVar6) = param_2;
  *(undefined2 *)(&DAT_803c6ade + iVar6) = 1;
  (&DAT_803c62d8)[uVar1 * 2] = (&DAT_803c62d8)[uVar1 * 2] + 1;
  DAT_803def10 = DAT_803def10 + 1;
  FUN_80285220();
  return 1;
}

