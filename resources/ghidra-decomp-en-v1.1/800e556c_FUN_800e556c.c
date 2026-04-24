// Function: FUN_800e556c
// Entry: 800e556c
// Size: 312 bytes

void FUN_800e556c(int param_1)

{
  uint uVar1;
  undefined4 *puVar2;
  int *piVar3;
  int iVar4;
  uint uVar5;
  
  if (DAT_803de0f0 == 0x514) {
    FUN_8007d858();
    return;
  }
  iVar4 = 0;
  for (piVar3 = &DAT_803a2448;
      (iVar4 < DAT_803de0f0 && (*(uint *)(*piVar3 + 0x14) < *(uint *)(param_1 + 0x14)));
      piVar3 = piVar3 + 1) {
    iVar4 = iVar4 + 1;
  }
  puVar2 = &DAT_803a2448 + DAT_803de0f0;
  uVar1 = DAT_803de0f0 - iVar4;
  if (iVar4 < DAT_803de0f0) {
    uVar5 = uVar1 >> 3;
    if (uVar5 != 0) {
      do {
        *puVar2 = puVar2[-1];
        puVar2[-1] = puVar2[-2];
        puVar2[-2] = puVar2[-3];
        puVar2[-3] = puVar2[-4];
        puVar2[-4] = puVar2[-5];
        puVar2[-5] = puVar2[-6];
        puVar2[-6] = puVar2[-7];
        puVar2[-7] = puVar2[-8];
        puVar2 = puVar2 + -8;
        uVar5 = uVar5 - 1;
      } while (uVar5 != 0);
      uVar1 = uVar1 & 7;
      if (uVar1 == 0) goto LAB_800e5678;
    }
    do {
      *puVar2 = puVar2[-1];
      puVar2 = puVar2 + -1;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
  }
LAB_800e5678:
  DAT_803de0f0 = DAT_803de0f0 + 1;
  (&DAT_803a2448)[iVar4] = param_1;
  return;
}

