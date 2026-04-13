// Function: FUN_8001f448
// Entry: 8001f448
// Size: 324 bytes

void FUN_8001f448(uint param_1)

{
  uint *puVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  
  iVar4 = 0;
  uVar3 = (uint)DAT_803dd6b0;
  uVar5 = uVar3;
  for (puVar1 = &DAT_8033cb20; (uVar5 != 0 && (*puVar1 != param_1)); puVar1 = puVar1 + 1) {
    iVar4 = iVar4 + 1;
    uVar5 = uVar5 - 1;
  }
  if ((int)uVar3 <= iVar4) goto LAB_8001f554;
  puVar2 = &DAT_8033cb20 + iVar4;
  uVar5 = (uVar3 - 1) - iVar4;
  if (iVar4 < (int)(uVar3 - 1)) {
    uVar3 = uVar5 >> 3;
    if (uVar3 != 0) {
      do {
        *puVar2 = puVar2[1];
        puVar2[1] = puVar2[2];
        puVar2[2] = puVar2[3];
        puVar2[3] = puVar2[4];
        puVar2[4] = puVar2[5];
        puVar2[5] = puVar2[6];
        puVar2[6] = puVar2[7];
        puVar2[7] = puVar2[8];
        puVar2 = puVar2 + 8;
        uVar3 = uVar3 - 1;
      } while (uVar3 != 0);
      uVar5 = uVar5 & 7;
      if (uVar5 == 0) goto LAB_8001f548;
    }
    do {
      *puVar2 = puVar2[1];
      puVar2 = puVar2 + 1;
      uVar5 = uVar5 - 1;
    } while (uVar5 != 0);
  }
LAB_8001f548:
  DAT_803dd6b0 = DAT_803dd6b0 - 1;
LAB_8001f554:
  if ((*(char *)(param_1 + 0x2f8) == '\x02') && (*(int *)(param_1 + 0x2e8) != 0)) {
    FUN_80054484();
  }
  FUN_800238c4(param_1);
  return;
}

