// Function: FUN_8002eeb8
// Entry: 8002eeb8
// Size: 1100 bytes

undefined4 FUN_8002eeb8(double param_1,double param_2,int param_3,int param_4)

{
  int iVar1;
  int iVar2;
  char cVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  undefined4 uVar7;
  uint uVar8;
  int iVar9;
  int *piVar10;
  int iVar11;
  int iVar12;
  byte bVar13;
  uint uVar14;
  undefined uVar15;
  undefined8 local_28;
  
  uVar7 = 0;
  piVar10 = *(int **)(*(int *)(param_3 + 0x7c) + *(char *)(param_3 + 0xad) * 4);
  if (*(short *)(*piVar10 + 0xec) == 0) {
    uVar7 = 0;
  }
  else {
    iVar11 = piVar10[0xc];
    *(float *)(iVar11 + 0xc) = (float)(param_1 * (double)*(float *)(iVar11 + 0x14));
    if (*(short *)(iVar11 + 0x58) != 0) {
      if ((*(byte *)(iVar11 + 99) & 8) != 0) {
        *(undefined4 *)(iVar11 + 0x10) = *(undefined4 *)(iVar11 + 0xc);
      }
      *(float *)(iVar11 + 8) =
           (float)((double)*(float *)(iVar11 + 0x10) * param_2 + (double)*(float *)(iVar11 + 8));
      fVar5 = FLOAT_803df570;
      fVar4 = *(float *)(iVar11 + 0x18);
      if (*(char *)(iVar11 + 0x61) == '\0') {
        fVar5 = *(float *)(iVar11 + 8);
        fVar6 = FLOAT_803df570;
        if ((FLOAT_803df570 <= fVar5) && (fVar6 = fVar5, fVar4 < fVar5)) {
          fVar6 = fVar4;
        }
        *(float *)(iVar11 + 8) = fVar6;
      }
      else {
        if (*(float *)(iVar11 + 8) < FLOAT_803df570) {
          while (*(float *)(iVar11 + 8) < fVar5) {
            *(float *)(iVar11 + 8) = *(float *)(iVar11 + 8) + fVar4;
          }
        }
        if (fVar4 <= *(float *)(iVar11 + 8)) {
          while (fVar4 <= *(float *)(iVar11 + 8)) {
            *(float *)(iVar11 + 8) = *(float *)(iVar11 + 8) - fVar4;
          }
        }
      }
      if ((*(byte *)(iVar11 + 99) & 2) == 0) {
        uVar8 = (uint)-(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                (uint)*(ushort *)(iVar11 + 0x5e)) -
                                              DOUBLE_803df568) * param_2 -
                              (double)(float)((double)CONCAT44(0x43300000,
                                                               *(ushort *)(iVar11 + 0x58) ^
                                                               0x80000000) - DOUBLE_803df580));
        fVar4 = FLOAT_803df570;
        if ((-1 < (int)uVar8) &&
           (uVar8 = uVar8 ^ 0x80000000, fVar4 = FLOAT_803df574,
           (float)((double)CONCAT44(0x43300000,uVar8) - DOUBLE_803df580) <= FLOAT_803df574)) {
          local_28 = (double)CONCAT44(0x43300000,uVar8);
          fVar4 = (float)(local_28 - DOUBLE_803df580);
        }
        *(short *)(iVar11 + 0x58) = (short)(int)fVar4;
      }
      if (*(short *)(iVar11 + 0x58) == 0) {
        *(undefined2 *)(iVar11 + 0x5c) = 0;
      }
    }
    fVar4 = *(float *)(param_3 + 0x9c);
    *(float *)(param_3 + 0x9c) = fVar4 + (float)(param_1 * param_2);
    fVar6 = FLOAT_803df570;
    fVar5 = FLOAT_803df560;
    if (*(float *)(param_3 + 0x9c) < FLOAT_803df560) {
      if (*(float *)(param_3 + 0x9c) < FLOAT_803df570) {
        if (*(char *)(iVar11 + 0x60) == '\0') {
          *(float *)(param_3 + 0x9c) = FLOAT_803df570;
        }
        else {
          while (*(float *)(param_3 + 0x9c) < fVar6) {
            *(float *)(param_3 + 0x9c) = *(float *)(param_3 + 0x9c) + fVar5;
          }
        }
        uVar7 = 1;
      }
    }
    else {
      if (*(char *)(iVar11 + 0x60) == '\0') {
        *(float *)(param_3 + 0x9c) = FLOAT_803df560;
      }
      else {
        while (fVar5 <= *(float *)(param_3 + 0x9c)) {
          *(float *)(param_3 + 0x9c) = *(float *)(param_3 + 0x9c) - fVar5;
        }
      }
      uVar7 = 1;
    }
    if ((param_4 != 0) && (*(undefined *)(param_4 + 0x12) = 0, *(int *)(param_3 + 0x60) != 0)) {
      *(undefined *)(param_4 + 0x1b) = 0;
      iVar11 = **(int **)(param_3 + 0x60) >> 1;
      if (iVar11 != 0) {
        iVar1 = (int)(FLOAT_803df578 * fVar4);
        iVar2 = (int)(FLOAT_803df578 * *(float *)(param_3 + 0x9c));
        bVar13 = iVar2 < iVar1;
        if ((float)(param_1 * param_2) < FLOAT_803df570) {
          bVar13 = bVar13 | 2;
        }
        iVar12 = 0;
        iVar9 = 0;
        while ((iVar12 < iVar11 && (*(char *)(param_4 + 0x1b) < '\b'))) {
          uVar14 = (uint)*(short *)(*(int *)(*(int *)(param_3 + 0x60) + 4) + iVar9);
          uVar8 = uVar14 & 0x1ff;
          uVar14 = uVar14 >> 9 & 0x7f;
          if (uVar14 != 0x7f) {
            uVar15 = (undefined)uVar14;
            if (((bVar13 == 0) && (iVar1 <= (int)uVar8)) && ((int)uVar8 < iVar2)) {
              cVar3 = *(char *)(param_4 + 0x1b);
              *(char *)(param_4 + 0x1b) = cVar3 + '\x01';
              *(undefined *)(param_4 + cVar3 + 0x13) = uVar15;
            }
            if ((bVar13 == 1) && ((iVar1 <= (int)uVar8 || ((int)uVar8 < iVar2)))) {
              cVar3 = *(char *)(param_4 + 0x1b);
              *(char *)(param_4 + 0x1b) = cVar3 + '\x01';
              *(undefined *)(param_4 + cVar3 + 0x13) = uVar15;
            }
            if (((bVar13 == 3) && (iVar2 < (int)uVar8)) && ((int)uVar8 <= iVar1)) {
              cVar3 = *(char *)(param_4 + 0x1b);
              *(char *)(param_4 + 0x1b) = cVar3 + '\x01';
              *(undefined *)(param_4 + cVar3 + 0x13) = uVar15;
            }
            if ((bVar13 == 2) && ((iVar2 < (int)uVar8 || ((int)uVar8 <= iVar1)))) {
              cVar3 = *(char *)(param_4 + 0x1b);
              *(char *)(param_4 + 0x1b) = cVar3 + '\x01';
              *(undefined *)(param_4 + cVar3 + 0x13) = uVar15;
            }
          }
          iVar9 = iVar9 + 2;
          iVar12 = iVar12 + 1;
        }
      }
    }
  }
  return uVar7;
}

