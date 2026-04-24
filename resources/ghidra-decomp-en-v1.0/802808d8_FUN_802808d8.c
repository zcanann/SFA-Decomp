// Function: FUN_802808d8
// Entry: 802808d8
// Size: 304 bytes

undefined4
FUN_802808d8(double param_1,double param_2,double param_3,double param_4,double param_5,int param_6)

{
  int iVar1;
  undefined4 *puVar2;
  int *piVar3;
  uint uVar4;
  uint uVar5;
  undefined4 *puVar6;
  uint uVar7;
  
  uVar4 = (uint)DAT_803de36b;
  uVar5 = 0;
  uVar7 = uVar4;
  for (piVar3 = &DAT_803cc910; (uVar7 != 0 && (*(int *)(param_6 + 0x40) != *piVar3));
      piVar3 = piVar3 + 4) {
    uVar5 = uVar5 + 1;
    uVar7 = uVar7 - 1;
  }
  if (uVar5 == uVar4) {
    if (uVar4 == 0x40) {
      return 0;
    }
    (&DAT_803cc914)[uVar5 * 4] = 0;
    (&DAT_803cc918)[uVar5 * 4] = 0;
    (&DAT_803cc91c)[uVar5 * 8] = 0;
    (&DAT_803cc910)[uVar5 * 4] = *(undefined4 *)(param_6 + 0x40);
    DAT_803de36b = DAT_803de36b + 1;
  }
  uVar7 = (uint)DAT_803de36c;
  if (uVar7 == 0x40) {
    return 0;
  }
  puVar2 = (undefined4 *)(&DAT_803cc914)[uVar5 * 4];
  if ((undefined4 *)(&DAT_803cc914)[uVar5 * 4] == (undefined4 *)0x0) {
    *(undefined4 *)(&DAT_803ccd10 + uVar7 * 0x1c) = 0;
    (&DAT_803cc914)[uVar5 * 4] = &DAT_803ccd10 + uVar7 * 0x1c;
  }
  else {
    do {
      puVar6 = puVar2;
      puVar2 = (undefined4 *)*puVar6;
      if (puVar2 == (undefined4 *)0x0) break;
    } while (param_1 <= (double)(float)puVar6[1]);
    *(undefined4 **)(&DAT_803ccd10 + uVar7 * 0x1c) = puVar2;
    *puVar6 = &DAT_803ccd10 + uVar7 * 0x1c;
  }
  iVar1 = (uint)DAT_803de36c * 0x1c;
  *(int *)(&DAT_803ccd28 + iVar1) = param_6;
  *(float *)(&DAT_803ccd24 + iVar1) = (float)param_5;
  *(float *)(&DAT_803ccd18 + iVar1) = (float)param_2;
  *(float *)(&DAT_803ccd1c + iVar1) = (float)param_3;
  *(float *)(&DAT_803ccd20 + iVar1) = (float)param_4;
  uVar7 = (uint)DAT_803de36c;
  DAT_803de36c = DAT_803de36c + 1;
  *(float *)(&DAT_803ccd14 + uVar7 * 0x1c) = (float)param_1;
  return 1;
}

