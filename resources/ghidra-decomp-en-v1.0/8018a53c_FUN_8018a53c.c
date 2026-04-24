// Function: FUN_8018a53c
// Entry: 8018a53c
// Size: 896 bytes

/* WARNING: Removing unreachable block (ram,0x8018a5b4) */
/* WARNING: Removing unreachable block (ram,0x8018a894) */

void FUN_8018a53c(short *param_1,int param_2)

{
  byte bVar2;
  uint uVar1;
  undefined unaff_r28;
  float *pfVar3;
  undefined4 uVar4;
  undefined8 in_f31;
  double dVar5;
  double local_30;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  pfVar3 = *(float **)(param_1 + 0x5c);
  FUN_80037200(param_1,0x41);
  *param_1 = (ushort)*(byte *)(param_2 + 0x18) << 8;
  bVar2 = *(byte *)(param_2 + 0x1d);
  if (2 < bVar2) {
    bVar2 = 2;
  }
  if (*(char *)(param_2 + 0x1c) != '\x02') {
    dVar5 = (double)FLOAT_803e3bbc;
    goto LAB_8018a5e8;
  }
  if (bVar2 != 1) {
    if (bVar2 == 0) {
      unaff_r28 = 0;
      dVar5 = (double)FLOAT_803e3c0c;
      goto LAB_8018a5e8;
    }
    if (bVar2 < 3) {
      unaff_r28 = 2;
      dVar5 = (double)FLOAT_803e3c08;
      goto LAB_8018a5e8;
    }
  }
  unaff_r28 = 1;
  dVar5 = (double)FLOAT_803e3bbc;
LAB_8018a5e8:
  if (*(int *)(param_1 + 0x2a) != 0) {
    FUN_80035974(param_1,(int)((double)(float)((double)CONCAT44(0x43300000,
                                                                (int)*(short *)(*(int *)(param_1 +
                                                                                        0x2a) + 0x5a
                                                                               ) ^ 0x80000000) -
                                              DOUBLE_803e3bd0) * dVar5));
  }
  *(float *)(param_1 + 4) = (float)((double)*(float *)(*(int *)(param_1 + 0x28) + 4) * dVar5);
  if (*(float *)(param_1 + 4) < FLOAT_803e3c10) {
    *(float *)(param_1 + 4) = FLOAT_803e3c10;
  }
  bVar2 = *(byte *)(param_2 + 0x1c);
  if (bVar2 == 3) {
    local_30 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
    dVar5 = (double)FUN_80293e80((double)((FLOAT_803e3bf4 * (float)(local_30 - DOUBLE_803e3bd0)) /
                                         FLOAT_803e3bf8));
    *pfVar3 = FLOAT_803e3c14 * *(float *)(param_1 + 4) * (float)((double)FLOAT_803e3c18 * dVar5) +
              *(float *)(param_1 + 6);
    dVar5 = (double)FUN_80294204((double)((FLOAT_803e3bf4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e3bd0)) / FLOAT_803e3bf8));
    pfVar3[1] = FLOAT_803e3c14 * *(float *)(param_1 + 4) * (float)((double)FLOAT_803e3c18 * dVar5) +
                *(float *)(param_1 + 10);
  }
  else if ((bVar2 < 3) && (1 < bVar2)) {
    *(undefined *)(param_1 + 0x72) = unaff_r28;
    local_30 = (double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000);
    dVar5 = (double)FUN_80293e80((double)((FLOAT_803e3bf4 * (float)(local_30 - DOUBLE_803e3bd0)) /
                                         FLOAT_803e3bf8));
    *pfVar3 = -(FLOAT_803e3c14 * *(float *)(param_1 + 4) * (float)((double)FLOAT_803e3c18 * dVar5) -
               *(float *)(param_1 + 6));
    dVar5 = (double)FUN_80294204((double)((FLOAT_803e3bf4 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e3bd0)) / FLOAT_803e3bf8));
    pfVar3[1] = -(FLOAT_803e3c14 * *(float *)(param_1 + 4) * (float)((double)FLOAT_803e3c18 * dVar5)
                 - *(float *)(param_1 + 10));
  }
  else {
    *pfVar3 = *(float *)(param_1 + 6);
    pfVar3[1] = *(float *)(param_1 + 10);
  }
  if (*(short *)(param_2 + 0x22) < 1) {
    *(byte *)((int)pfVar3 + 0x1d) = *(byte *)((int)pfVar3 + 0x1d) & 0x7f | 0x80;
  }
  else {
    uVar1 = FUN_8001ffb4();
    *(byte *)((int)pfVar3 + 0x1d) =
         (byte)((uVar1 & 0xff) << 7) | *(byte *)((int)pfVar3 + 0x1d) & 0x7f;
  }
  *(byte *)((int)pfVar3 + 0x1d) = *(byte *)((int)pfVar3 + 0x1d) & 0xef;
  if (0 < *(short *)(param_2 + 0x24)) {
    uVar1 = FUN_8001ffb4();
    *(byte *)((int)pfVar3 + 0x1d) = (byte)((uVar1 & 1) << 6) | *(byte *)((int)pfVar3 + 0x1d) & 0xbf;
    if ((uVar1 & 1) != 0) {
      bVar2 = *(byte *)(param_2 + 0x1c);
      if (bVar2 == 4) {
        *(byte *)((int)pfVar3 + 0x1d) = *(byte *)((int)pfVar3 + 0x1d) & 0xbf;
      }
      else if (((bVar2 < 4) && (bVar2 != 2)) && (1 < bVar2)) {
        FUN_80030304((double)FLOAT_803e3bbc,param_1);
      }
    }
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

