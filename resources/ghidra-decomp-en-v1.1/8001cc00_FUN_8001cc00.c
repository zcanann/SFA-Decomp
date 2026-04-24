// Function: FUN_8001cc00
// Entry: 8001cc00
// Size: 352 bytes

void FUN_8001cc00(uint *param_1)

{
  uint *puVar1;
  undefined4 *puVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  
  uVar5 = *param_1;
  if (uVar5 == 0) {
    return;
  }
  iVar3 = 0;
  uVar4 = (uint)DAT_803dd6b0;
  uVar6 = uVar4;
  for (puVar1 = &DAT_8033cb20; (uVar6 != 0 && (*puVar1 != uVar5)); puVar1 = puVar1 + 1) {
    iVar3 = iVar3 + 1;
    uVar6 = uVar6 - 1;
  }
  if ((int)uVar4 <= iVar3) goto LAB_8001cd1c;
  puVar2 = &DAT_8033cb20 + iVar3;
  uVar6 = (uVar4 - 1) - iVar3;
  if (iVar3 < (int)(uVar4 - 1)) {
    uVar4 = uVar6 >> 3;
    if (uVar4 != 0) {
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
        uVar4 = uVar4 - 1;
      } while (uVar4 != 0);
      uVar6 = uVar6 & 7;
      if (uVar6 == 0) goto LAB_8001cd10;
    }
    do {
      *puVar2 = puVar2[1];
      puVar2 = puVar2 + 1;
      uVar6 = uVar6 - 1;
    } while (uVar6 != 0);
  }
LAB_8001cd10:
  DAT_803dd6b0 = DAT_803dd6b0 - 1;
LAB_8001cd1c:
  if ((*(char *)(uVar5 + 0x2f8) == '\x02') && (*(int *)(uVar5 + 0x2e8) != 0)) {
    FUN_80054484();
  }
  FUN_800238c4(uVar5);
  *param_1 = 0;
  return;
}

