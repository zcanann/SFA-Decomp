// Function: FUN_800e0bf4
// Entry: 800e0bf4
// Size: 540 bytes

uint FUN_800e0bf4(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  uint *puVar8;
  uint *puVar9;
  int iVar10;
  int iVar11;
  uint *puVar12;
  undefined local_88 [4];
  uint local_84 [24];
  
  iVar5 = 0;
  piVar2 = &DAT_803a17e8;
  iVar11 = 0;
  while ((iVar5 < DAT_803dd478 && (iVar11 < 0x14))) {
    iVar4 = iVar11;
    if (*(char *)(*piVar2 + 0x19) == '\x17') {
      iVar4 = iVar11 + 1;
      local_84[iVar11] = *(uint *)(*piVar2 + 0x14);
    }
    piVar2 = piVar2 + 1;
    iVar5 = iVar5 + 1;
    iVar11 = iVar4;
  }
  puVar12 = local_84 + iVar11;
  do {
    puVar9 = puVar12;
    if (iVar11 == 0) {
      return 0xffffffff;
    }
    iVar5 = FUN_800e1ff4(param_1,param_2,param_3,local_84[0],local_88);
    if (iVar5 != 0) {
      return local_84[0];
    }
    if ((int)local_84[0] < 0) {
      iVar7 = 0;
    }
    else {
      iVar4 = DAT_803dd478 + -1;
      iVar5 = 0;
      while (iVar5 <= iVar4) {
        iVar3 = iVar4 + iVar5 >> 1;
        iVar7 = (&DAT_803a17e8)[iVar3];
        if (*(uint *)(iVar7 + 0x14) < local_84[0]) {
          iVar5 = iVar3 + 1;
        }
        else {
          if (*(uint *)(iVar7 + 0x14) <= local_84[0]) goto LAB_800e0d24;
          iVar4 = iVar3 + -1;
        }
      }
      iVar7 = 0;
    }
LAB_800e0d24:
    cVar1 = *(char *)(iVar7 + 0x18);
    iVar5 = 0;
    puVar8 = local_84;
    puVar12 = puVar9;
    while (iVar5 < iVar11) {
      uVar6 = *puVar8;
      if ((int)uVar6 < 0) {
        iVar10 = 0;
      }
      else {
        iVar3 = 0;
        iVar4 = DAT_803dd478 + -1;
        while (iVar3 <= iVar4) {
          iVar7 = iVar4 + iVar3 >> 1;
          iVar10 = (&DAT_803a17e8)[iVar7];
          if (*(uint *)(iVar10 + 0x14) < uVar6) {
            iVar3 = iVar7 + 1;
          }
          else {
            if (*(uint *)(iVar10 + 0x14) <= uVar6) goto LAB_800e0dac;
            iVar4 = iVar7 + -1;
          }
        }
        iVar10 = 0;
      }
LAB_800e0dac:
      if (*(char *)(iVar10 + 0x18) == cVar1) {
        puVar9 = puVar9 + -1;
        puVar12 = puVar12 + -1;
        iVar11 = iVar11 + -1;
        *puVar8 = *puVar9;
      }
      else {
        puVar8 = puVar8 + 1;
        iVar5 = iVar5 + 1;
      }
    }
  } while( true );
}

