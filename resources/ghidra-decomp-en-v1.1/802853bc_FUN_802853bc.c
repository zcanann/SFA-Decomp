// Function: FUN_802853bc
// Entry: 802853bc
// Size: 1012 bytes

undefined4
FUN_802853bc(double param_1,double param_2,double param_3,double param_4,double param_5,int param_6)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  byte bVar7;
  byte bVar8;
  int iVar9;
  int *piVar10;
  int iVar11;
  int *piVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  undefined8 local_78;
  
  dVar15 = (double)FLOAT_803e8590;
  if ((((((param_1 < dVar15) || (dVar13 = (double)FLOAT_803e8594, dVar13 < param_1)) ||
        (param_2 < (double)FLOAT_803e8598)) ||
       (((double)FLOAT_803e859c < param_2 || (param_3 < dVar15)))) ||
      ((dVar13 < param_3 || ((param_4 < dVar15 || (dVar13 < param_4)))))) ||
     ((param_5 < dVar15 || ((double)FLOAT_803e85a0 < param_5)))) {
    uVar2 = 0;
  }
  else {
    FUN_800033a8(param_6,0,0x13c);
    dVar16 = (double)FLOAT_803e8590;
    dVar13 = (double)(float)((double)FLOAT_803e85a4 * param_2);
    iVar11 = 0;
    iVar4 = param_6;
    dVar15 = DOUBLE_803e85b0;
    for (bVar7 = 0; bVar7 < 3; bVar7 = bVar7 + 1) {
      iVar5 = iVar11 * 0x14;
      iVar6 = iVar11 << 2;
      piVar12 = &DAT_80332e80;
      for (bVar8 = 0; bVar8 < 2; bVar8 = bVar8 + 1) {
        iVar3 = *piVar12;
        iVar9 = param_6 + iVar5;
        uVar1 = (iVar3 + 2) * 4;
        *(uint *)(iVar9 + 0x80) = uVar1;
        uVar2 = FUN_802852d0();
        *(undefined4 *)(iVar9 + 0x84) = uVar2;
        FUN_800033a8(*(int *)(iVar9 + 0x84),0,uVar1);
        *(float *)(iVar9 + 0x88) = (float)dVar16;
        *(int *)(iVar9 + 0x7c) = *(int *)(iVar9 + 0x78) + (iVar3 + 2 >> 1) * -4;
        while (*(int *)(iVar9 + 0x7c) < 0) {
          *(int *)(iVar9 + 0x7c) = *(int *)(iVar9 + 0x7c) + *(int *)(iVar9 + 0x80);
        }
        *(int *)(iVar9 + 0x78) = 0;
        *(int *)(iVar9 + 0x7c) = 0;
        *(int *)(iVar9 + 0x7c) = *(int *)(iVar9 + 0x78) + *piVar12 * -4;
        while (*(int *)(iVar9 + 0x7c) < 0) {
          *(int *)(iVar9 + 0x7c) = *(int *)(iVar9 + 0x7c) + *(int *)(iVar9 + 0x80);
        }
        local_78 = (double)CONCAT44(0x43300000,*piVar12 * -3 ^ 0x80000000);
        dVar14 = FUN_80295318((double)FLOAT_803e859c,
                              (double)(float)((double)(float)(local_78 - dVar15) / dVar13));
        *(float *)(param_6 + iVar6 + 0xf4) = (float)dVar14;
        piVar12 = piVar12 + 1;
        iVar6 = iVar6 + 4;
        iVar5 = iVar5 + 0x14;
      }
      iVar6 = iVar11 * 0x14;
      piVar12 = &DAT_80332e80;
      for (bVar8 = 0; bVar8 < 2; bVar8 = bVar8 + 1) {
        iVar5 = piVar12[2];
        piVar10 = (int *)(param_6 + iVar6);
        uVar1 = (iVar5 + 2) * 4;
        piVar10[2] = uVar1;
        iVar3 = FUN_802852d0();
        piVar10[3] = iVar3;
        FUN_800033a8(piVar10[3],0,uVar1);
        piVar10[4] = (int)(float)dVar16;
        piVar10[1] = *piVar10 + (iVar5 + 2 >> 1) * -4;
        while (piVar10[1] < 0) {
          piVar10[1] = piVar10[1] + piVar10[2];
        }
        *piVar10 = 0;
        piVar10[1] = 0;
        piVar10[1] = *piVar10 + piVar12[2] * -4;
        while (piVar10[1] < 0) {
          piVar10[1] = piVar10[1] + piVar10[2];
        }
        piVar12 = piVar12 + 1;
        iVar6 = iVar6 + 0x14;
      }
      *(float *)(iVar4 + 0x10c) = (float)dVar16;
      iVar11 = iVar11 + 2;
      iVar4 = iVar4 + 4;
    }
    *(float *)(param_6 + 0xf0) = (float)param_1;
    *(float *)(param_6 + 0x118) = (float)param_3;
    *(float *)(param_6 + 0x11c) = (float)param_4;
    if (*(float *)(param_6 + 0x11c) < FLOAT_803e85a8) {
      *(float *)(param_6 + 0x11c) = FLOAT_803e85a8;
    }
    *(float *)(param_6 + 0x11c) =
         FLOAT_803e8594 - (FLOAT_803e85a8 + FLOAT_803e85ac * *(float *)(param_6 + 0x11c));
    if ((double)FLOAT_803e8590 == param_5) {
      *(undefined4 *)(param_6 + 0x120) = 0;
      *(undefined4 *)(param_6 + 0x130) = 0;
      *(undefined4 *)(param_6 + 0x124) = 0;
      *(undefined4 *)(param_6 + 0x134) = 0;
      *(undefined4 *)(param_6 + 0x128) = 0;
      *(undefined4 *)(param_6 + 0x138) = 0;
      *(undefined4 *)(param_6 + 300) = 0;
    }
    else {
      *(int *)(param_6 + 0x120) = (int)((double)FLOAT_803e85a4 * param_5);
      iVar4 = param_6;
      for (bVar7 = 0; bVar7 < 3; bVar7 = bVar7 + 1) {
        uVar2 = FUN_802852d0();
        *(undefined4 *)(iVar4 + 0x124) = uVar2;
        FUN_800033a8(*(int *)(iVar4 + 0x124),0,*(int *)(param_6 + 0x120) << 2);
        *(undefined4 *)(iVar4 + 0x130) = *(undefined4 *)(iVar4 + 0x124);
        iVar4 = iVar4 + 4;
      }
    }
    uVar2 = 1;
  }
  return uVar2;
}

