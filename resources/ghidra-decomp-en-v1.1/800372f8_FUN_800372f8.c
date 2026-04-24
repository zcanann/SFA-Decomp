// Function: FUN_800372f8
// Entry: 800372f8
// Size: 588 bytes

/* WARNING: Removing unreachable block (ram,0x80037324) */

void FUN_800372f8(int param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  char *pcVar3;
  undefined4 *puVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  
  if (param_2 < 0) {
    return;
  }
  if (0x53 < param_2) {
    return;
  }
  uVar6 = (uint)(byte)(&DAT_80343958)[param_2];
  uVar5 = (uint)(byte)(&DAT_80343959)[param_2];
  piVar2 = &DAT_80343558 + uVar6;
  iVar1 = uVar5 - uVar6;
  if (uVar6 < uVar5) {
    do {
      if (*piVar2 == param_1) {
        return;
      }
      piVar2 = piVar2 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
  if (uVar5 != uVar6) {
    uVar6 = uVar5 - 1;
  }
  DAT_803dd870 = DAT_803dd870 + 1;
  iVar1 = DAT_803dd870 - 1;
  puVar4 = &DAT_80343558 + iVar1;
  uVar5 = iVar1 - uVar6;
  if ((int)uVar6 < iVar1) {
    uVar7 = uVar5 >> 3;
    if (uVar7 != 0) {
      do {
        *puVar4 = puVar4[-1];
        puVar4[-1] = puVar4[-2];
        puVar4[-2] = puVar4[-3];
        puVar4[-3] = puVar4[-4];
        puVar4[-4] = puVar4[-5];
        puVar4[-5] = puVar4[-6];
        puVar4[-6] = puVar4[-7];
        puVar4[-7] = puVar4[-8];
        puVar4 = puVar4 + -8;
        uVar7 = uVar7 - 1;
      } while (uVar7 != 0);
      uVar5 = uVar5 & 7;
      if (uVar5 == 0) goto LAB_80037454;
    }
    do {
      *puVar4 = puVar4[-1];
      puVar4 = puVar4 + -1;
      uVar5 = uVar5 - 1;
    } while (uVar5 != 0);
  }
LAB_80037454:
  (&DAT_80343558)[uVar6] = param_1;
  pcVar3 = &DAT_80343959 + param_2;
  uVar5 = 0x55 - (param_2 + 1);
  if (param_2 + 1 < 0x55) {
    uVar6 = uVar5 >> 3;
    if (uVar6 != 0) {
      do {
        *pcVar3 = *pcVar3 + '\x01';
        pcVar3[1] = pcVar3[1] + '\x01';
        pcVar3[2] = pcVar3[2] + '\x01';
        pcVar3[3] = pcVar3[3] + '\x01';
        pcVar3[4] = pcVar3[4] + '\x01';
        pcVar3[5] = pcVar3[5] + '\x01';
        pcVar3[6] = pcVar3[6] + '\x01';
        pcVar3[7] = pcVar3[7] + '\x01';
        pcVar3 = pcVar3 + 8;
        uVar6 = uVar6 - 1;
      } while (uVar6 != 0);
      uVar5 = uVar5 & 7;
      if (uVar5 == 0) {
        return;
      }
    }
    do {
      *pcVar3 = *pcVar3 + '\x01';
      pcVar3 = pcVar3 + 1;
      uVar5 = uVar5 - 1;
    } while (uVar5 != 0);
  }
  return;
}

