// Function: FUN_8001cb3c
// Entry: 8001cb3c
// Size: 352 bytes

void FUN_8001cb3c(int *param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  
  iVar5 = *param_1;
  if (iVar5 == 0) {
    return;
  }
  iVar3 = 0;
  uVar4 = (uint)DAT_803dca30;
  uVar6 = uVar4;
  for (piVar1 = &DAT_8033bec0; (uVar6 != 0 && (*piVar1 != iVar5)); piVar1 = piVar1 + 1) {
    iVar3 = iVar3 + 1;
    uVar6 = uVar6 - 1;
  }
  if ((int)uVar4 <= iVar3) goto LAB_8001cc58;
  puVar2 = &DAT_8033bec0 + iVar3;
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
      if (uVar6 == 0) goto LAB_8001cc4c;
    }
    do {
      *puVar2 = puVar2[1];
      puVar2 = puVar2 + 1;
      uVar6 = uVar6 - 1;
    } while (uVar6 != 0);
  }
LAB_8001cc4c:
  DAT_803dca30 = DAT_803dca30 - 1;
LAB_8001cc58:
  if ((*(char *)(iVar5 + 0x2f8) == '\x02') && (*(int *)(iVar5 + 0x2e8) != 0)) {
    FUN_80054308();
  }
  FUN_80023800(iVar5);
  *param_1 = 0;
  return;
}

