// Function: FUN_802185cc
// Entry: 802185cc
// Size: 1012 bytes

/* WARNING: Removing unreachable block (ram,0x80218614) */
/* WARNING: Removing unreachable block (ram,0x8021899c) */

void FUN_802185cc(undefined2 *param_1)

{
  float fVar1;
  bool bVar2;
  int iVar3;
  undefined2 uVar5;
  int iVar4;
  byte bVar6;
  uint uVar7;
  int iVar8;
  byte bVar9;
  int *piVar10;
  undefined4 uVar11;
  undefined8 uVar12;
  double dVar13;
  undefined8 in_f31;
  int local_48;
  undefined auStack68 [12];
  undefined auStack56 [28];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  piVar10 = *(int **)(param_1 + 0x5c);
  bVar2 = false;
  bVar9 = *(byte *)(piVar10 + 1);
  if (bVar9 == 2) {
    *(undefined *)(param_1 + 0x1b) = 0;
    if (piVar10[2] == 0) {
      FUN_80035f00();
    }
    piVar10[2] = piVar10[2] + (uint)DAT_803db410;
    if (0x80 < piVar10[2]) {
      FUN_80035f00(param_1);
      FUN_8000b824(param_1,0x173);
      FUN_8000b824(param_1,0x3c5);
      *(undefined *)(piVar10 + 1) = 1;
    }
  }
  else if (bVar9 < 2) {
    if ((bVar9 != 0) &&
       (fVar1 = (float)piVar10[3] + FLOAT_803db414, piVar10[3] = (int)fVar1, FLOAT_803e6968 < fVar1)
       ) {
      FUN_8002cbc4();
      goto LAB_8021899c;
    }
  }
  else if (bVar9 == 4) {
    iVar3 = FUN_8002b9ec();
    dVar13 = (double)FLOAT_803e695c;
    if ((((double)*(float *)(iVar3 + 0x24) != dVar13) ||
        ((double)*(float *)(iVar3 + 0x28) != dVar13)) ||
       ((double)*(float *)(iVar3 + 0x2c) != dVar13)) {
      dVar13 = (double)FUN_802477f0(iVar3 + 0x24);
    }
    dVar13 = (double)(float)((double)FLOAT_803dc2b8 + dVar13);
    FUN_80221c18(dVar13,iVar3,param_1 + 6,auStack56);
    FUN_80247754(auStack56,param_1 + 6,auStack68);
    FUN_80247794(auStack68,auStack68);
    FUN_80247778((double)(float)(dVar13 * (double)FLOAT_803dc2b4),auStack68,auStack68);
    FUN_80247778((double)FLOAT_803dc2b0,param_1 + 0x12,param_1 + 0x12);
    FUN_80247730(param_1 + 0x12,auStack68,param_1 + 0x12);
    uVar12 = FUN_802931a0((double)(*(float *)(param_1 + 0x12) * *(float *)(param_1 + 0x12) +
                                  *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16)));
    uVar5 = FUN_800217c0((double)*(float *)(param_1 + 0x12),(double)*(float *)(param_1 + 0x16));
    *param_1 = uVar5;
    uVar5 = FUN_800217c0((double)*(float *)(param_1 + 0x14),uVar12);
    param_1[1] = uVar5;
    FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414),param_1);
    bVar2 = true;
  }
  else if (bVar9 < 4) {
    bVar2 = true;
    FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414));
  }
  if (bVar2) {
    iVar8 = *(int *)(*(int *)(param_1 + 0x2a) + 0x50);
    local_48 = 0;
    iVar4 = FUN_8003687c(param_1,&local_48,0,0);
    bVar9 = 0;
    uVar7 = (uint)DAT_803db410;
    iVar3 = piVar10[2];
    piVar10[2] = iVar3 - uVar7;
    if (((int)(iVar3 - uVar7) < 0) || (iVar4 != 0)) {
      bVar9 = 1;
    }
    bVar6 = 0;
    if ((iVar8 != 0) && (*(short *)(iVar8 + 0x46) != 0x2ab)) {
      bVar6 = 1;
    }
    bVar9 = bVar9 | bVar6 | *(byte *)(*(int *)(param_1 + 0x2a) + 0xad);
    if (*(char *)(piVar10 + 1) == '\x04') {
      iVar3 = FUN_8002b9ec();
      dVar13 = (double)FUN_80021704(param_1 + 0xc,iVar3 + 0x18);
      if (dVar13 < (double)FLOAT_803dc2bc) {
        bVar9 = bVar9 | 1;
      }
    }
    if ((local_48 != 0) && (*(short *)(local_48 + 0x46) == 0x2ab)) {
      bVar9 = 0;
    }
    if (bVar9 != 0) {
      *(undefined *)(piVar10 + 1) = 2;
      piVar10[2] = 0;
      if ((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 8) != 0) {
        FUN_8000bb18(param_1,0x172);
      }
      if (*(char *)(param_1 + 0x56) == '\x02') {
        FUN_8009ab70((double)FLOAT_803e6940,param_1,3,0,0,0,0,0,3);
      }
      else {
        FUN_8009ab70((double)FLOAT_803e6940,param_1,1,0,0,0,0,0,3);
      }
      if (*piVar10 != 0) {
        FUN_8001f384();
        *piVar10 = 0;
      }
    }
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x4c) = 0x10;
    *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x48) = 0x10;
  }
  if ((*piVar10 != 0) && (iVar3 = FUN_8001db64(), iVar3 != 0)) {
    FUN_8001d6b0(*piVar10);
  }
LAB_8021899c:
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  return;
}

