// Function: FUN_8003709c
// Entry: 8003709c
// Size: 496 bytes

void FUN_8003709c(int param_1,int param_2)

{
  uint uVar1;
  int *piVar2;
  undefined4 *puVar3;
  char *pcVar4;
  uint uVar5;
  
  if (param_2 < 0) {
    return;
  }
  if (0x53 < param_2) {
    return;
  }
  uVar5 = (uint)(byte)(&DAT_80343958)[param_2];
  for (piVar2 = &DAT_80343558 + uVar5;
      ((int)uVar5 < (int)(uint)(byte)(&DAT_80343959)[param_2] && (*piVar2 != param_1));
      piVar2 = piVar2 + 1) {
    uVar5 = uVar5 + 1;
  }
  if ((int)(uint)(byte)(&DAT_80343959)[param_2] <= (int)uVar5) {
    return;
  }
  DAT_803dd870 = DAT_803dd870 - 1;
  puVar3 = &DAT_80343558 + uVar5;
  uVar1 = DAT_803dd870 - uVar5;
  if ((int)uVar5 < (int)(uint)DAT_803dd870) {
    uVar5 = uVar1 >> 3;
    if (uVar5 != 0) {
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
        uVar5 = uVar5 - 1;
      } while (uVar5 != 0);
      uVar1 = uVar1 & 7;
      if (uVar1 == 0) goto LAB_800371b8;
    }
    do {
      *puVar3 = puVar3[1];
      puVar3 = puVar3 + 1;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
  }
LAB_800371b8:
  pcVar4 = &DAT_80343959 + param_2;
  uVar5 = 0x55 - (param_2 + 1);
  if (0x54 < param_2 + 1) {
    return;
  }
  uVar1 = uVar5 >> 3;
  if (uVar1 != 0) {
    do {
      *pcVar4 = *pcVar4 + -1;
      pcVar4[1] = pcVar4[1] + -1;
      pcVar4[2] = pcVar4[2] + -1;
      pcVar4[3] = pcVar4[3] + -1;
      pcVar4[4] = pcVar4[4] + -1;
      pcVar4[5] = pcVar4[5] + -1;
      pcVar4[6] = pcVar4[6] + -1;
      pcVar4[7] = pcVar4[7] + -1;
      pcVar4 = pcVar4 + 8;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
    uVar5 = uVar5 & 7;
    if (uVar5 == 0) {
      return;
    }
  }
  do {
    *pcVar4 = *pcVar4 + -1;
    pcVar4 = pcVar4 + 1;
    uVar5 = uVar5 - 1;
  } while (uVar5 != 0);
  return;
}

