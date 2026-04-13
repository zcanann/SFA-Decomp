// Function: FUN_8002b830
// Entry: 8002b830
// Size: 260 bytes

void FUN_8002b830(int param_1)

{
  uint uVar1;
  int *piVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  
  iVar5 = 0;
  iVar4 = (int)DAT_803dd7f4;
  for (piVar2 = &DAT_80341508; (iVar5 < iVar4 && (*piVar2 != param_1)); piVar2 = piVar2 + 1) {
    iVar5 = iVar5 + 1;
  }
  if (iVar5 == iVar4) {
    return;
  }
  puVar3 = &DAT_80341508 + iVar5;
  uVar1 = (iVar4 + -1) - iVar5;
  if (iVar5 < iVar4 + -1) {
    uVar6 = uVar1 >> 3;
    if (uVar6 != 0) {
      do {
        *puVar3 = puVar3[1];
        puVar3[1] = puVar3[2];
        puVar3[2] = puVar3[3];
        puVar3[3] = puVar3[4];
        puVar3[4] = puVar3[5];
        puVar3[5] = puVar3[6];
        puVar3[6] = puVar3[7];
        puVar3[7] = puVar3[8];
        puVar3 = puVar3 + 8;
        uVar6 = uVar6 - 1;
      } while (uVar6 != 0);
      uVar1 = uVar1 & 7;
      if (uVar1 == 0) goto LAB_8002b90c;
    }
    do {
      *puVar3 = puVar3[1];
      puVar3 = puVar3 + 1;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
  }
LAB_8002b90c:
  DAT_803dd7f4 = DAT_803dd7f4 + -1;
  return;
}

