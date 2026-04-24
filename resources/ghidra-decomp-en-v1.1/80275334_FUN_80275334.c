// Function: FUN_80275334
// Entry: 80275334
// Size: 668 bytes

undefined4 FUN_80275334(uint param_1)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined2 *puVar5;
  undefined4 *puVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  
  FUN_80285258();
  uVar3 = param_1 >> 4 & 0xffc;
  if (*(short *)((int)&DAT_803c62d8 + uVar3) == 0) goto LAB_802755b0;
  uVar7 = (uint)*(ushort *)((int)&DAT_803c62da + uVar3);
  iVar8 = 0;
  while ((iVar8 < (int)(uint)*(ushort *)((int)&DAT_803c62d8 + uVar3) &&
         ((param_1 & 0xffff) != (uint)*(ushort *)(&DAT_803c6adc + (uVar7 + iVar8) * 8)))) {
    iVar8 = iVar8 + 1;
  }
  if ((int)(uint)*(ushort *)((int)&DAT_803c62d8 + uVar3) <= iVar8) goto LAB_802755b0;
  iVar2 = (uVar7 + iVar8) * 8;
  sVar1 = *(short *)(&DAT_803c6ade + iVar2);
  *(short *)(&DAT_803c6ade + iVar2) = sVar1 + -1;
  if ((short)(sVar1 + -1) != 0) goto LAB_802755b0;
  iVar8 = uVar7 + iVar8 + 1;
  uVar4 = (uint)DAT_803def10 - iVar8;
  puVar6 = (undefined4 *)(&DAT_803c6ad8 + iVar8 * 8);
  if (iVar8 < (int)(uint)DAT_803def10) {
    uVar9 = uVar4 >> 3;
    if (uVar9 != 0) {
      do {
        puVar6[-2] = *puVar6;
        puVar6[-1] = puVar6[1];
        *puVar6 = puVar6[2];
        puVar6[1] = puVar6[3];
        puVar6[2] = puVar6[4];
        puVar6[3] = puVar6[5];
        puVar6[4] = puVar6[6];
        puVar6[5] = puVar6[7];
        puVar6[6] = puVar6[8];
        puVar6[7] = puVar6[9];
        puVar6[8] = puVar6[10];
        puVar6[9] = puVar6[0xb];
        puVar6[10] = puVar6[0xc];
        puVar6[0xb] = puVar6[0xd];
        puVar6[0xc] = puVar6[0xe];
        puVar6[0xd] = puVar6[0xf];
        puVar6 = puVar6 + 0x10;
        uVar9 = uVar9 - 1;
      } while (uVar9 != 0);
      uVar4 = uVar4 & 7;
      if (uVar4 == 0) goto LAB_802754a8;
    }
    do {
      puVar6[-2] = *puVar6;
      puVar6[-1] = puVar6[1];
      puVar6 = puVar6 + 2;
      uVar4 = uVar4 - 1;
    } while (uVar4 != 0);
  }
LAB_802754a8:
  iVar8 = 0x40;
  puVar5 = &DAT_803c62d8;
  do {
    if (uVar7 < (ushort)puVar5[1]) {
      puVar5[1] = puVar5[1] - 1;
    }
    if (uVar7 < (ushort)puVar5[3]) {
      puVar5[3] = puVar5[3] - 1;
    }
    if (uVar7 < (ushort)puVar5[5]) {
      puVar5[5] = puVar5[5] - 1;
    }
    if (uVar7 < (ushort)puVar5[7]) {
      puVar5[7] = puVar5[7] - 1;
    }
    if (uVar7 < (ushort)puVar5[9]) {
      puVar5[9] = puVar5[9] - 1;
    }
    if (uVar7 < (ushort)puVar5[0xb]) {
      puVar5[0xb] = puVar5[0xb] - 1;
    }
    if (uVar7 < (ushort)puVar5[0xd]) {
      puVar5[0xd] = puVar5[0xd] - 1;
    }
    if (uVar7 < (ushort)puVar5[0xf]) {
      puVar5[0xf] = puVar5[0xf] - 1;
    }
    puVar5 = puVar5 + 0x10;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  *(short *)((int)&DAT_803c62d8 + uVar3) = *(short *)((int)&DAT_803c62d8 + uVar3) + -1;
  DAT_803def10 = DAT_803def10 - 1;
LAB_802755b0:
  FUN_80285220();
  return 0;
}

