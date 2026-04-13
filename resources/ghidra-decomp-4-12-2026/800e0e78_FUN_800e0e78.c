// Function: FUN_800e0e78
// Entry: 800e0e78
// Size: 540 bytes

uint FUN_800e0e78(undefined8 param_1,double param_2,double param_3)

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
  uint local_84 [24];
  
  iVar5 = 0;
  piVar2 = &DAT_803a2448;
  iVar11 = 0;
  while ((iVar5 < DAT_803de0f0 && (iVar11 < 0x14))) {
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
    iVar5 = FUN_800e2278(param_1,param_2,param_3);
    if (iVar5 != 0) {
      return local_84[0];
    }
    if ((int)local_84[0] < 0) {
      iVar7 = 0;
    }
    else {
      iVar4 = DAT_803de0f0 + -1;
      iVar5 = 0;
      while (iVar5 <= iVar4) {
        iVar3 = iVar4 + iVar5 >> 1;
        iVar7 = (&DAT_803a2448)[iVar3];
        if (*(uint *)(iVar7 + 0x14) < local_84[0]) {
          iVar5 = iVar3 + 1;
        }
        else {
          if (*(uint *)(iVar7 + 0x14) <= local_84[0]) goto LAB_800e0fa8;
          iVar4 = iVar3 + -1;
        }
      }
      iVar7 = 0;
    }
LAB_800e0fa8:
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
        iVar4 = DAT_803de0f0 + -1;
        while (iVar3 <= iVar4) {
          iVar7 = iVar4 + iVar3 >> 1;
          iVar10 = (&DAT_803a2448)[iVar7];
          if (*(uint *)(iVar10 + 0x14) < uVar6) {
            iVar3 = iVar7 + 1;
          }
          else {
            if (*(uint *)(iVar10 + 0x14) <= uVar6) goto LAB_800e1030;
            iVar4 = iVar7 + -1;
          }
        }
        iVar10 = 0;
      }
LAB_800e1030:
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

