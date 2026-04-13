// Function: FUN_8001fe5c
// Entry: 8001fe5c
// Size: 220 bytes

void FUN_8001fe5c(int param_1)

{
  uint uVar1;
  int *piVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  
  iVar4 = 0;
  uVar1 = (uint)DAT_803dd6c8;
  for (piVar2 = (int *)&DAT_803dd768;
      (iVar5 = -1, uVar1 != 0 && (iVar5 = iVar4, *piVar2 != param_1)); piVar2 = piVar2 + 1) {
    iVar4 = iVar4 + 1;
    uVar1 = uVar1 - 1;
  }
  puVar3 = (undefined4 *)(&DAT_803dd768 + iVar5 * 4);
  iVar4 = DAT_803dd6c8 - 1;
  uVar1 = iVar4 - iVar5;
  if (iVar5 < iVar4) {
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
      if (uVar1 == 0) goto LAB_8001ff28;
    }
    do {
      *puVar3 = puVar3[1];
      puVar3 = puVar3 + 1;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
  }
LAB_8001ff28:
  DAT_803dd6c8 = DAT_803dd6c8 - 1;
  return;
}

