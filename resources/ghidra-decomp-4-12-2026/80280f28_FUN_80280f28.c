// Function: FUN_80280f28
// Entry: 80280f28
// Size: 276 bytes

void FUN_80280f28(double param_1,int param_2)

{
  undefined4 *puVar1;
  int *piVar2;
  undefined4 *puVar3;
  uint uVar4;
  undefined4 *puVar5;
  uint uVar6;
  
  uVar4 = 0;
  uVar6 = (uint)DAT_803defeb;
  for (piVar2 = &DAT_803cd570; (uVar6 != 0 && (*(int *)(param_2 + 0x40) != *piVar2));
      piVar2 = piVar2 + 4) {
    uVar4 = uVar4 + 1;
    uVar6 = uVar6 - 1;
  }
  if (uVar4 == DAT_803defeb) {
    (&DAT_803cd574)[uVar4 * 4] = 0;
    (&DAT_803cd578)[uVar4 * 4] = 0;
    (&DAT_803cd57c)[uVar4 * 8] = 0;
    (&DAT_803cd570)[uVar4 * 4] = *(undefined4 *)(param_2 + 0x40);
    DAT_803defeb = DAT_803defeb + 1;
  }
  (&DAT_803cd57c)[uVar4 * 8] = (&DAT_803cd57c)[uVar4 * 8] + 1;
  puVar1 = (undefined4 *)(&DAT_803cd578)[uVar4 * 4];
  puVar5 = (undefined4 *)0x0;
  while ((puVar3 = puVar1, puVar3 != (undefined4 *)0x0 && ((double)(float)puVar3[1] <= param_1))) {
    puVar5 = puVar3;
    puVar1 = (undefined4 *)*puVar3;
  }
  if (puVar5 == (undefined4 *)0x0) {
    (&DAT_803cd578)[uVar4 * 4] = &DAT_803ce070 + (uint)DAT_803defed * 0xc;
  }
  else {
    *puVar5 = &DAT_803ce070 + (uint)DAT_803defed * 0xc;
  }
  uVar6 = (uint)DAT_803defed;
  *(undefined4 **)(&DAT_803ce070 + uVar6 * 0xc) = puVar3;
  *(int *)(&DAT_803ce078 + uVar6 * 0xc) = param_2;
  uVar6 = (uint)DAT_803defed;
  DAT_803defed = DAT_803defed + 1;
  *(float *)(&DAT_803ce074 + uVar6 * 0xc) = (float)param_1;
  return;
}

