// Function: FUN_8001e928
// Entry: 8001e928
// Size: 876 bytes

/* WARNING: Removing unreachable block (ram,0x8001ec6c) */
/* WARNING: Removing unreachable block (ram,0x8001ec5c) */
/* WARNING: Removing unreachable block (ram,0x8001ec4c) */
/* WARNING: Removing unreachable block (ram,0x8001ec54) */
/* WARNING: Removing unreachable block (ram,0x8001ec64) */
/* WARNING: Removing unreachable block (ram,0x8001ec74) */

void FUN_8001e928(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined4 param_7,undefined4 param_8,int *param_9)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  int unaff_r29;
  int iVar7;
  int *piVar8;
  undefined4 uVar9;
  double extraout_f1;
  double dVar10;
  undefined8 in_f26;
  double dVar11;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined8 uVar12;
  float local_108;
  float local_104;
  float local_100;
  undefined auStack252 [12];
  int local_f0 [20];
  undefined4 local_a0;
  uint uStack156;
  undefined4 local_98;
  uint uStack148;
  undefined4 local_90;
  uint uStack140;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  uVar12 = FUN_802860d4();
  local_108 = FLOAT_803de790 * (float)(extraout_f1 + param_4);
  local_104 = FLOAT_803de790 * (float)(param_2 + param_5);
  local_100 = FLOAT_803de790 * (float)(param_3 + param_6);
  piVar8 = &DAT_8033bec0;
  iVar5 = 0;
  dVar11 = extraout_f1;
  for (iVar7 = 0; iVar6 = iVar5, iVar7 < (int)(uint)DAT_803dca30; iVar7 = iVar7 + 1) {
    unaff_r29 = *piVar8;
    if ((((*(char *)(unaff_r29 + 0x4c) != '\0') && (*(int *)(unaff_r29 + 0x50) == 2)) &&
        (FLOAT_803de75c < *(float *)(unaff_r29 + 0x144))) && (*(char *)(unaff_r29 + 0x2fb) != '\0'))
    {
      FUN_80247754(&local_108,unaff_r29 + 0x10,auStack252);
      dVar10 = (double)FUN_802477f0(auStack252);
      fVar1 = *(float *)(unaff_r29 + 0x144);
      if ((((dVar11 <= (double)(*(float *)(unaff_r29 + 0x10) + fVar1)) &&
           (param_2 <= (double)(*(float *)(unaff_r29 + 0x14) + fVar1))) &&
          ((param_3 <= (double)(*(float *)(unaff_r29 + 0x18) + fVar1) &&
           (((double)(*(float *)(unaff_r29 + 0x10) - fVar1) <= param_4 &&
            ((double)(*(float *)(unaff_r29 + 0x14) - fVar1) <= param_5)))))) &&
         ((double)(*(float *)(unaff_r29 + 0x18) - fVar1) <= param_6)) {
        fVar1 = FLOAT_803de760 /
                (*(float *)(unaff_r29 + 0x124) +
                (float)(dVar10 * (double)(float)((double)*(float *)(unaff_r29 + 300) * dVar10) +
                       (double)(float)((double)*(float *)(unaff_r29 + 0x128) * dVar10)));
        uStack156 = (uint)*(byte *)(unaff_r29 + 0xa8);
        local_a0 = 0x43300000;
        fVar3 = fVar1 * (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(unaff_r29 + 0xa8)) -
                               DOUBLE_803de770);
        fVar2 = FLOAT_803de75c;
        if ((FLOAT_803de75c <= fVar3) && (fVar2 = fVar3, FLOAT_803de76c < fVar3)) {
          fVar2 = FLOAT_803de76c;
        }
        uStack148 = (uint)*(byte *)(unaff_r29 + 0xa9);
        local_98 = 0x43300000;
        fVar3 = fVar1 * (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(unaff_r29 + 0xa9)) -
                               DOUBLE_803de770);
        fVar4 = FLOAT_803de75c;
        if ((FLOAT_803de75c <= fVar3) && (fVar4 = fVar3, FLOAT_803de76c < fVar3)) {
          fVar4 = FLOAT_803de76c;
        }
        uStack140 = (uint)*(byte *)(unaff_r29 + 0xaa);
        local_90 = 0x43300000;
        fVar1 = fVar1 * (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(unaff_r29 + 0xaa)) -
                               DOUBLE_803de770);
        fVar3 = FLOAT_803de75c;
        if ((FLOAT_803de75c <= fVar1) && (fVar3 = fVar1, FLOAT_803de76c < fVar1)) {
          fVar3 = FLOAT_803de76c;
        }
        if (fVar4 < fVar2) {
          fVar4 = fVar2;
        }
        *(float *)(unaff_r29 + 0x130) = fVar4;
        if (fVar3 < *(float *)(unaff_r29 + 0x130)) {
          fVar3 = *(float *)(unaff_r29 + 0x130);
        }
        *(float *)(unaff_r29 + 0x130) = fVar3;
        iVar6 = iVar5 + 1;
        local_f0[iVar5] = unaff_r29;
        if (0x13 < iVar6) break;
      }
    }
    piVar8 = piVar8 + 1;
    iVar5 = iVar6;
  }
  iVar5 = (int)uVar12;
  if (iVar6 < (int)uVar12) {
    iVar5 = iVar6;
  }
  *param_9 = 0;
  fVar1 = FLOAT_803de75c;
  while (*param_9 < iVar5) {
    piVar8 = local_f0;
    iVar7 = iVar6;
    fVar3 = FLOAT_803de75c;
    if (0 < iVar6) {
      do {
        fVar2 = *(float *)(*piVar8 + 0x130);
        if (fVar3 < fVar2) {
          unaff_r29 = *piVar8;
          fVar3 = fVar2;
        }
        piVar8 = piVar8 + 1;
        iVar7 = iVar7 + -1;
      } while (iVar7 != 0);
    }
    iVar7 = *param_9;
    *param_9 = iVar7 + 1;
    *(int *)((int)((ulonglong)uVar12 >> 0x20) + iVar7 * 4) = unaff_r29;
    *(float *)(unaff_r29 + 0x130) = fVar1;
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  __psq_l0(auStack56,uVar9);
  __psq_l1(auStack56,uVar9);
  __psq_l0(auStack72,uVar9);
  __psq_l1(auStack72,uVar9);
  __psq_l0(auStack88,uVar9);
  __psq_l1(auStack88,uVar9);
  FUN_80286120();
  return;
}

