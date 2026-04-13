// Function: FUN_8028103c
// Entry: 8028103c
// Size: 304 bytes

undefined4
FUN_8028103c(double param_1,double param_2,double param_3,double param_4,double param_5,int param_6)

{
  int iVar1;
  undefined4 *puVar2;
  int *piVar3;
  uint uVar4;
  uint uVar5;
  undefined4 *puVar6;
  uint uVar7;
  
  uVar4 = (uint)DAT_803defeb;
  uVar5 = 0;
  uVar7 = uVar4;
  for (piVar3 = &DAT_803cd570; (uVar7 != 0 && (*(int *)(param_6 + 0x40) != *piVar3));
      piVar3 = piVar3 + 4) {
    uVar5 = uVar5 + 1;
    uVar7 = uVar7 - 1;
  }
  if (uVar5 == uVar4) {
    if (uVar4 == 0x40) {
      return 0;
    }
    (&DAT_803cd574)[uVar5 * 4] = 0;
    (&DAT_803cd578)[uVar5 * 4] = 0;
    (&DAT_803cd57c)[uVar5 * 8] = 0;
    (&DAT_803cd570)[uVar5 * 4] = *(undefined4 *)(param_6 + 0x40);
    DAT_803defeb = DAT_803defeb + 1;
  }
  uVar7 = (uint)DAT_803defec;
  if (uVar7 == 0x40) {
    return 0;
  }
  puVar2 = (undefined4 *)(&DAT_803cd574)[uVar5 * 4];
  if ((undefined4 *)(&DAT_803cd574)[uVar5 * 4] == (undefined4 *)0x0) {
    *(undefined4 *)(&DAT_803cd970 + uVar7 * 0x1c) = 0;
    (&DAT_803cd574)[uVar5 * 4] = &DAT_803cd970 + uVar7 * 0x1c;
  }
  else {
    do {
      puVar6 = puVar2;
      puVar2 = (undefined4 *)*puVar6;
      if (puVar2 == (undefined4 *)0x0) break;
    } while (param_1 <= (double)(float)puVar6[1]);
    *(undefined4 **)(&DAT_803cd970 + uVar7 * 0x1c) = puVar2;
    *puVar6 = &DAT_803cd970 + uVar7 * 0x1c;
  }
  iVar1 = (uint)DAT_803defec * 0x1c;
  *(int *)(&DAT_803cd988 + iVar1) = param_6;
  *(float *)(&DAT_803cd984 + iVar1) = (float)param_5;
  *(float *)(&DAT_803cd978 + iVar1) = (float)param_2;
  *(float *)(&DAT_803cd97c + iVar1) = (float)param_3;
  *(float *)(&DAT_803cd980 + iVar1) = (float)param_4;
  uVar7 = (uint)DAT_803defec;
  DAT_803defec = DAT_803defec + 1;
  *(float *)(&DAT_803cd974 + uVar7 * 0x1c) = (float)param_1;
  return 1;
}

