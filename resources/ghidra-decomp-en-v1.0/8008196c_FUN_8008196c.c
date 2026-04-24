// Function: FUN_8008196c
// Entry: 8008196c
// Size: 644 bytes

int FUN_8008196c(int param_1)

{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  int iVar11;
  int *piVar12;
  int iVar13;
  undefined auStack24 [4];
  int local_14 [3];
  
  piVar6 = (int *)FUN_8002e0fc(auStack24,local_14);
  piVar12 = *(int **)(param_1 + 0xb8);
  iVar8 = *(int *)(param_1 + 0x4c);
  if (*(short *)(param_1 + 0x44) == 0x11) {
    *piVar12 = 0;
    return -1;
  }
  sVar1 = *(short *)(iVar8 + 0x1c);
  if (sVar1 == 2) {
    iVar8 = FUN_8002b9ac();
    *piVar12 = iVar8;
    goto LAB_80081b9c;
  }
  if (sVar1 < 2) {
    if (sVar1 == 0) {
      *piVar12 = 0;
      goto LAB_80081b9c;
    }
    if (-1 < sVar1) {
      iVar8 = FUN_8002b9ec();
      *piVar12 = iVar8;
      goto LAB_80081b9c;
    }
  }
  else if (sVar1 < 4) {
    *piVar12 = 0;
    *(char *)((int)piVar12 + 0x7b) = (char)*(undefined2 *)(iVar8 + 0x1c) + -2;
    if (DAT_803dd064 != 0) {
      DAT_803dd064 = 0;
    }
    if (((&DAT_80399e50)[*(char *)((int)piVar12 + 0x57)] & 0x10) == 0) {
      (**(code **)(*DAT_803dca50 + 0x5c))(0x41,1);
    }
    goto LAB_80081b9c;
  }
  *piVar12 = 0;
  iVar11 = *(short *)(iVar8 + 0x1c) + -4;
  if ((iVar11 == 0x1f) || (*(short *)(iVar8 + 0x1c) == 4)) {
    iVar8 = FUN_8002b9ec();
    *piVar12 = iVar8;
  }
  else if (piVar12[0x43] == 0) {
    fVar5 = FLOAT_803deff0;
    for (iVar8 = 0; iVar8 < local_14[0]; iVar8 = iVar8 + 1) {
      iVar10 = *piVar6;
      iVar7 = 0;
      iVar13 = 0x10;
      piVar9 = (int *)(&DAT_80396918 + *(char *)((int)piVar12 + 0x57) * 0x80);
      do {
        if (*piVar9 == iVar10) {
          iVar7 = *(int *)((int)(&DAT_80396918 + *(char *)((int)piVar12 + 0x57) * 0x80) +
                          (iVar7 * 2 + 1) * 4);
          goto LAB_80081b18;
        }
        piVar9 = piVar9 + 2;
        iVar7 = iVar7 + 1;
        iVar13 = iVar13 + -1;
      } while (iVar13 != 0);
      iVar7 = 0;
LAB_80081b18:
      if (iVar7 == param_1) {
        *piVar12 = iVar10;
        break;
      }
      if (((iVar7 == 0) && (*(short *)(iVar10 + 0x46) == iVar11)) &&
         ((fVar2 = *(float *)(param_1 + 0xc) - *(float *)(iVar10 + 0xc),
          fVar3 = *(float *)(param_1 + 0x10) - *(float *)(iVar10 + 0x10),
          fVar4 = *(float *)(param_1 + 0x14) - *(float *)(iVar10 + 0x14),
          fVar2 = fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3, fVar5 < FLOAT_803defb0 ||
          (fVar2 < fVar5)))) {
        *piVar12 = iVar10;
        fVar5 = fVar2;
      }
      piVar6 = piVar6 + 1;
    }
  }
  else {
    iVar8 = FUN_8002e0b4(piVar12[0x43]);
    *piVar12 = iVar8;
  }
LAB_80081b9c:
  if (*piVar12 == 0) {
    iVar8 = -1;
  }
  else {
    if ((*(char *)((int)piVar12 + 0x57) < '\x19') && (*(short *)(*piVar12 + 0xb4) != -1)) {
      FUN_80080c18();
    }
    iVar8 = (int)*(short *)(*piVar12 + 0x48);
  }
  return iVar8;
}

