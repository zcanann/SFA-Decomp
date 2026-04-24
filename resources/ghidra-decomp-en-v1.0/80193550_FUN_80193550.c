// Function: FUN_80193550
// Entry: 80193550
// Size: 352 bytes

void FUN_80193550(void)

{
  int iVar1;
  int iVar2;
  ushort *puVar3;
  uint uVar4;
  ushort *puVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined8 uVar15;
  undefined auStack88 [4];
  float local_54;
  undefined4 local_48;
  uint uStack68;
  
  uVar15 = FUN_802860bc();
  iVar1 = (int)((ulonglong)uVar15 >> 0x20);
  piVar9 = *(int **)(iVar1 + 0xb8);
  iVar8 = *(int *)(iVar1 + 0x4c);
  if ((int)uVar15 == 0) {
    FUN_8005b2fc((double)*(float *)(iVar1 + 0xc),(double)*(float *)(iVar1 + 0x10),
                 (double)*(float *)(iVar1 + 0x14));
    iVar2 = FUN_8005aeec();
    if (iVar2 != 0) {
      iVar12 = 0;
      for (iVar11 = 0; iVar11 < (int)(uint)*(ushort *)(iVar2 + 0x9a); iVar11 = iVar11 + 1) {
        puVar3 = (ushort *)FUN_800606ec(iVar2,iVar11);
        uVar4 = FUN_80060678();
        if (*(byte *)(iVar8 + 0x25) == uVar4) {
          iVar13 = iVar12;
          for (uVar4 = (uint)*puVar3; (int)uVar4 < (int)(uint)puVar3[10]; uVar4 = uVar4 + 1) {
            puVar5 = (ushort *)FUN_800606dc(iVar2,uVar4);
            iVar10 = 0;
            iVar14 = iVar13;
            do {
              iVar7 = *(int *)(iVar2 + 0x58) + (uint)*puVar5 * 6;
              FUN_800605f0(iVar7,auStack88);
              iVar6 = piVar9[1];
              if (iVar6 != 0) {
                uStack68 = (int)*(short *)(iVar6 + iVar14) ^ 0x80000000;
                local_48 = 0x43300000;
                local_54 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e3fc8);
                FUN_8006058c(iVar7,auStack88);
              }
              iVar14 = iVar14 + 2;
              iVar13 = iVar13 + 2;
              iVar12 = iVar12 + 2;
              puVar5 = puVar5 + 1;
              iVar10 = iVar10 + 1;
            } while (iVar10 < 3);
          }
        }
      }
    }
  }
  if (*piVar9 != 0) {
    FUN_80023800();
  }
  FUN_80036fa4(iVar1,0x31);
  FUN_80286108();
  return;
}

