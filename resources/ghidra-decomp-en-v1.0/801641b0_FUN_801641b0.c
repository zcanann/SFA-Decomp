// Function: FUN_801641b0
// Entry: 801641b0
// Size: 1936 bytes

/* WARNING: Removing unreachable block (ram,0x80164914) */
/* WARNING: Removing unreachable block (ram,0x80164904) */
/* WARNING: Removing unreachable block (ram,0x8016490c) */
/* WARNING: Removing unreachable block (ram,0x8016491c) */

void FUN_801641b0(int param_1)

{
  char cVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  float *pfVar5;
  uint uVar6;
  int iVar7;
  undefined4 uVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f28;
  double dVar12;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar13;
  undefined8 in_f31;
  double dVar14;
  int local_88;
  int local_84;
  undefined auStack128 [4];
  undefined auStack124 [4];
  longlong local_78;
  double local_70;
  undefined4 local_68;
  uint uStack100;
  double local_60;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  fVar2 = FLOAT_803e2fc0;
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  iVar7 = *(int *)(param_1 + 0xb8);
  cVar1 = *(char *)(iVar7 + 0x278);
  if (cVar1 == '\0') {
    if (*(float *)(iVar7 + 0x26c) <= *(float *)(param_1 + 8)) {
      *(undefined *)(iVar7 + 0x278) = 1;
    }
    else {
      *(float *)(param_1 + 8) = *(float *)(iVar7 + 0x270) * FLOAT_803db414 + *(float *)(param_1 + 8)
      ;
    }
  }
  else if (cVar1 == '\x01') {
    iVar4 = FUN_8003687c(param_1,&local_84,auStack124,auStack128);
    if (iVar4 != 0) {
      FUN_80035f20(param_1);
      *(undefined *)(iVar7 + 0x278) = 2;
      *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 3;
      if (*(short *)(param_1 + 0x46) == 0x4c1) {
        *(float *)(iVar7 + 0x2a0) = FLOAT_803e2f9c;
      }
    }
  }
  else if (cVar1 == '\x02') {
    iVar4 = FUN_8002b9ec();
    dVar14 = (double)(*(float *)(param_1 + 0xc) - *(float *)(iVar4 + 0xc));
    dVar13 = (double)(*(float *)(param_1 + 0x14) - *(float *)(iVar4 + 0x14));
    dVar12 = (double)(float)(dVar14 * dVar14 + (double)(float)(dVar13 * dVar13));
    iVar4 = FUN_8002b9ac();
    if ((iVar4 != 0) && (*(short *)(iVar4 + 0x46) == 0x24)) {
      if (dVar12 < (double)FLOAT_803e2fa0) {
        (**(code **)(**(int **)(iVar4 + 0x68) + 0x28))(iVar4,param_1,0,1);
      }
      dVar11 = (double)(*(float *)(param_1 + 0xc) - *(float *)(iVar4 + 0xc));
      dVar10 = (double)(*(float *)(param_1 + 0x14) - *(float *)(iVar4 + 0x14));
      dVar9 = (double)(float)(dVar11 * dVar11 + (double)(float)(dVar10 * dVar10));
      if (dVar9 < dVar12) {
        dVar12 = dVar9;
        dVar13 = dVar10;
        dVar14 = dVar11;
      }
    }
    dVar12 = (double)FUN_802931a0(dVar12);
    local_78 = (longlong)(int)dVar12;
    *(short *)(iVar7 + 0x268) = (short)(int)dVar12;
    dVar11 = (double)(*(float *)(param_1 + 0xc) - *(float *)(iVar7 + 0x288));
    dVar10 = (double)(*(float *)(param_1 + 0x14) - *(float *)(iVar7 + 0x28c));
    dVar9 = (double)FUN_802931a0((double)(float)(dVar11 * dVar11 + (double)(float)(dVar10 * dVar10))
                                );
    local_70 = (double)(longlong)(int)dVar9;
    *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) & 0xf7;
    fVar3 = FLOAT_803e2fa8;
    fVar2 = FLOAT_803e2fa4;
    dVar12 = DOUBLE_803e2f90;
    uStack100 = (uint)*(ushort *)(iVar7 + 0x268);
    if ((FLOAT_803e2fa4 <= (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803e2f90)) ||
       (uStack100 == 0)) {
      uVar6 = (int)dVar9 & 0xffff;
      local_60 = (double)CONCAT44(0x43300000,uVar6);
      if ((FLOAT_803e2f5c < (float)(local_60 - DOUBLE_803e2f90)) && (uVar6 != 0)) {
        local_60 = (double)CONCAT44(0x43300000,uVar6);
        dVar12 = (double)(FLOAT_803e2f5c * (float)(local_60 - DOUBLE_803e2f90));
        *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) - (float)(dVar11 / dVar12);
        *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) - (float)(dVar10 / dVar12);
      }
    }
    else {
      *(float *)(param_1 + 0x24) =
           *(float *)(param_1 + 0x24) -
           (float)(dVar14 / (double)(FLOAT_803e2fa8 *
                                    ((float)((double)CONCAT44(0x43300000,uStack100) -
                                            DOUBLE_803e2f90) - FLOAT_803e2fa4)));
      local_70 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar7 + 0x268));
      *(float *)(param_1 + 0x2c) =
           *(float *)(param_1 + 0x2c) -
           (float)(dVar13 / (double)(fVar3 * ((float)(local_70 - dVar12) - fVar2)));
      fVar2 = FLOAT_803e2fac;
      iVar4 = (int)(FLOAT_803e2fac * *(float *)(param_1 + 0x24));
      local_78 = (longlong)iVar4;
      *(short *)(iVar7 + 0x27c) = (short)iVar4;
      iVar4 = (int)(fVar2 * *(float *)(param_1 + 0x2c));
      local_60 = (double)(longlong)iVar4;
      *(short *)(iVar7 + 0x27e) = (short)iVar4;
      *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 8;
    }
    local_68 = 0x43300000;
    FUN_80163bbc(param_1,iVar7);
    (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,iVar7);
    *(float *)(iVar7 + 0x2a0) = *(float *)(iVar7 + 0x2a0) - FLOAT_803db414;
    if (FLOAT_803e2f68 <= *(float *)(iVar7 + 0x2a0)) {
      iVar4 = FUN_8003687c(param_1,&local_84,auStack124,auStack128);
      if ((iVar4 != 0) && (*(short *)(local_84 + 0x46) != *(short *)(param_1 + 0x46))) {
        if (*(short *)(param_1 + 0x46) == 0x4ba) {
          *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 3;
          *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) & 0xef;
          *(undefined *)(iVar7 + 0x278) = 3;
          *(float *)(iVar7 + 0x270) = FLOAT_803e2fb0;
          *(float *)(iVar7 + 0x2a0) = FLOAT_803e2fb4;
          FUN_8002b884(param_1,1);
        }
        else {
          *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
        }
      }
    }
    else {
      *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
    }
  }
  else if (cVar1 == '\x03') {
    iVar4 = FUN_8002b9ec();
    dVar12 = (double)FUN_8002166c(iVar4 + 0x18,param_1 + 0x18);
    if ((double)FLOAT_803e2fb8 <= dVar12) {
      *(float *)(iVar7 + 0x270) = *(float *)(iVar7 + 0x270) - FLOAT_803db414;
      *(float *)(iVar7 + 0x2a0) = *(float *)(iVar7 + 0x2a0) - FLOAT_803db414;
      if (FLOAT_803e2f68 <= *(float *)(iVar7 + 0x2a0)) {
        if (FLOAT_803e2f68 < *(float *)(iVar7 + 0x270)) {
          iVar4 = FUN_8003687c(param_1,&local_84,auStack124,auStack128);
          if ((iVar4 != 0) && (*(short *)(local_84 + 0x46) != *(short *)(param_1 + 0x46))) {
            *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
          }
        }
        else {
          *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
        }
      }
      else {
        *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
      }
    }
    else {
      *(undefined2 *)(iVar7 + 0x298) = 0x195;
      *(undefined2 *)(iVar7 + 0x29a) = 0;
      *(float *)(iVar7 + 0x29c) = FLOAT_803e2f98;
      FUN_800378c4(iVar4,0x7000a,param_1,iVar7 + 0x298);
      *(undefined *)(iVar7 + 0x278) = 4;
    }
    FUN_80163990(param_1,iVar7);
    (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,iVar7);
  }
  else if (cVar1 == '\x04') {
    while (iVar4 = FUN_800374ec(param_1,&local_88,0,0), iVar4 != 0) {
      if (local_88 == 0x7000b) {
        FUN_8001ff3c(0x194);
        FUN_8000bb18(param_1,0x49);
        *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
      }
    }
  }
  else if (cVar1 == '\x06') {
    pfVar5 = *(float **)(iVar7 + 0x290);
    dVar13 = (double)(*pfVar5 - *(float *)(param_1 + 0xc));
    dVar14 = (double)(pfVar5[1] - *(float *)(param_1 + 0x10));
    dVar9 = (double)(pfVar5[2] - *(float *)(param_1 + 0x14));
    dVar12 = (double)FUN_802931a0((double)(float)(dVar9 * dVar9 +
                                                 (double)(float)(dVar13 * dVar13 +
                                                                (double)(float)(dVar14 * dVar14))));
    *(float *)(iVar7 + 0x294) = FLOAT_803db414 * FLOAT_803e2f98 + *(float *)(iVar7 + 0x294);
    fVar2 = FLOAT_803e2fbc;
    *(float *)(param_1 + 0x24) =
         FLOAT_803e2fbc * (float)(dVar13 / dVar12) * *(float *)(iVar7 + 0x294);
    *(float *)(param_1 + 0x28) = fVar2 * (float)(dVar14 / dVar12) * *(float *)(iVar7 + 0x294);
    *(float *)(param_1 + 0x2c) = fVar2 * (float)(dVar9 / dVar12) * *(float *)(iVar7 + 0x294);
    dVar12 = (double)FUN_8002166c(param_1 + 0xc,*(undefined4 *)(iVar7 + 0x290));
    FUN_8002b95c((double)(*(float *)(param_1 + 0x24) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x28) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x2c) * FLOAT_803db414),param_1);
    dVar13 = (double)FUN_8002166c(param_1 + 0xc,*(undefined4 *)(iVar7 + 0x290));
    fVar2 = FLOAT_803e2f98;
    if (dVar12 < dVar13) {
      *(float *)(param_1 + 0xc) =
           (**(float **)(iVar7 + 0x290) - *(float *)(param_1 + 0xc)) * FLOAT_803e2f98 +
           *(float *)(param_1 + 0xc);
      *(float *)(param_1 + 0x10) =
           (*(float *)(*(int *)(iVar7 + 0x290) + 4) - *(float *)(param_1 + 0x10)) * fVar2 +
           *(float *)(param_1 + 0x10);
      *(float *)(param_1 + 0x14) =
           (*(float *)(*(int *)(iVar7 + 0x290) + 8) - *(float *)(param_1 + 0x14)) * fVar2 +
           *(float *)(param_1 + 0x14);
    }
  }
  else if (cVar1 == '\a') {
    for (uVar6 = 0; (int)(uVar6 & 0xffff) < (int)FLOAT_803db414; uVar6 = uVar6 + 1) {
      *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * fVar2;
    }
    *(undefined4 *)(param_1 + 0xc) = **(undefined4 **)(iVar7 + 0x290);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*(int *)(iVar7 + 0x290) + 4);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(*(int *)(iVar7 + 0x290) + 8);
  }
  else if (FLOAT_803e2f68 < *(float *)(iVar7 + 0x270)) {
    *(float *)(iVar7 + 0x270) = *(float *)(iVar7 + 0x270) - FLOAT_803db414;
  }
  else {
    FUN_8002cbc4();
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  return;
}

