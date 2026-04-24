// Function: FUN_802807c4
// Entry: 802807c4
// Size: 276 bytes

void FUN_802807c4(double param_1,int param_2)

{
  undefined4 *puVar1;
  int *piVar2;
  undefined4 *puVar3;
  uint uVar4;
  undefined4 *puVar5;
  uint uVar6;
  
  uVar4 = 0;
  uVar6 = (uint)DAT_803de36b;
  for (piVar2 = &DAT_803cc910; (uVar6 != 0 && (*(int *)(param_2 + 0x40) != *piVar2));
      piVar2 = piVar2 + 4) {
    uVar4 = uVar4 + 1;
    uVar6 = uVar6 - 1;
  }
  if (uVar4 == DAT_803de36b) {
    (&DAT_803cc914)[uVar4 * 4] = 0;
    (&DAT_803cc918)[uVar4 * 4] = 0;
    (&DAT_803cc91c)[uVar4 * 8] = 0;
    (&DAT_803cc910)[uVar4 * 4] = *(undefined4 *)(param_2 + 0x40);
    DAT_803de36b = DAT_803de36b + 1;
  }
  (&DAT_803cc91c)[uVar4 * 8] = (&DAT_803cc91c)[uVar4 * 8] + 1;
  puVar1 = (undefined4 *)(&DAT_803cc918)[uVar4 * 4];
  puVar5 = (undefined4 *)0x0;
  while ((puVar3 = puVar1, puVar3 != (undefined4 *)0x0 && ((double)(float)puVar3[1] <= param_1))) {
    puVar5 = puVar3;
    puVar1 = (undefined4 *)*puVar3;
  }
  if (puVar5 == (undefined4 *)0x0) {
    (&DAT_803cc918)[uVar4 * 4] = &DAT_803cd410 + (uint)DAT_803de36d * 0xc;
  }
  else {
    *puVar5 = &DAT_803cd410 + (uint)DAT_803de36d * 0xc;
  }
  uVar6 = (uint)DAT_803de36d;
  *(undefined4 **)(&DAT_803cd410 + uVar6 * 0xc) = puVar3;
  *(int *)(&DAT_803cd418 + uVar6 * 0xc) = param_2;
  uVar6 = (uint)DAT_803de36d;
  DAT_803de36d = DAT_803de36d + 1;
  *(float *)(&DAT_803cd414 + uVar6 * 0xc) = (float)param_1;
  return;
}

