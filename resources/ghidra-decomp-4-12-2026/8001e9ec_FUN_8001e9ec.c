// Function: FUN_8001e9ec
// Entry: 8001e9ec
// Size: 876 bytes

/* WARNING: Removing unreachable block (ram,0x8001ed38) */
/* WARNING: Removing unreachable block (ram,0x8001ed30) */
/* WARNING: Removing unreachable block (ram,0x8001ed28) */
/* WARNING: Removing unreachable block (ram,0x8001ed20) */
/* WARNING: Removing unreachable block (ram,0x8001ed18) */
/* WARNING: Removing unreachable block (ram,0x8001ed10) */
/* WARNING: Removing unreachable block (ram,0x8001ea24) */
/* WARNING: Removing unreachable block (ram,0x8001ea1c) */
/* WARNING: Removing unreachable block (ram,0x8001ea14) */
/* WARNING: Removing unreachable block (ram,0x8001ea0c) */
/* WARNING: Removing unreachable block (ram,0x8001ea04) */
/* WARNING: Removing unreachable block (ram,0x8001e9fc) */

void FUN_8001e9ec(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
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
  double extraout_f1;
  double dVar9;
  double in_f26;
  double dVar10;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  float local_108;
  float local_104;
  float local_100;
  float afStack_fc [3];
  int local_f0 [20];
  undefined4 local_a0;
  uint uStack_9c;
  undefined4 local_98;
  uint uStack_94;
  undefined4 local_90;
  uint uStack_8c;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  uVar11 = FUN_80286838();
  local_108 = FLOAT_803df410 * (float)(extraout_f1 + param_4);
  local_104 = FLOAT_803df410 * (float)(param_2 + param_5);
  local_100 = FLOAT_803df410 * (float)(param_3 + param_6);
  piVar8 = &DAT_8033cb20;
  iVar5 = 0;
  dVar10 = extraout_f1;
  for (iVar7 = 0; iVar6 = iVar5, iVar7 < (int)(uint)DAT_803dd6b0; iVar7 = iVar7 + 1) {
    unaff_r29 = *piVar8;
    if ((((*(char *)(unaff_r29 + 0x4c) != '\0') && (*(int *)(unaff_r29 + 0x50) == 2)) &&
        (FLOAT_803df3dc < *(float *)(unaff_r29 + 0x144))) && (*(char *)(unaff_r29 + 0x2fb) != '\0'))
    {
      FUN_80247eb8(&local_108,(float *)(unaff_r29 + 0x10),afStack_fc);
      dVar9 = FUN_80247f54(afStack_fc);
      fVar1 = *(float *)(unaff_r29 + 0x144);
      if ((((dVar10 <= (double)(*(float *)(unaff_r29 + 0x10) + fVar1)) &&
           (param_2 <= (double)(*(float *)(unaff_r29 + 0x14) + fVar1))) &&
          ((param_3 <= (double)(*(float *)(unaff_r29 + 0x18) + fVar1) &&
           (((double)(*(float *)(unaff_r29 + 0x10) - fVar1) <= param_4 &&
            ((double)(*(float *)(unaff_r29 + 0x14) - fVar1) <= param_5)))))) &&
         ((double)(*(float *)(unaff_r29 + 0x18) - fVar1) <= param_6)) {
        fVar1 = FLOAT_803df3e0 /
                (*(float *)(unaff_r29 + 0x124) +
                (float)(dVar9 * (double)(float)((double)*(float *)(unaff_r29 + 300) * dVar9) +
                       (double)(float)((double)*(float *)(unaff_r29 + 0x128) * dVar9)));
        uStack_9c = (uint)*(byte *)(unaff_r29 + 0xa8);
        local_a0 = 0x43300000;
        fVar3 = fVar1 * (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(unaff_r29 + 0xa8)) -
                               DOUBLE_803df3f0);
        fVar2 = FLOAT_803df3dc;
        if ((FLOAT_803df3dc <= fVar3) && (fVar2 = fVar3, FLOAT_803df3ec < fVar3)) {
          fVar2 = FLOAT_803df3ec;
        }
        uStack_94 = (uint)*(byte *)(unaff_r29 + 0xa9);
        local_98 = 0x43300000;
        fVar3 = fVar1 * (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(unaff_r29 + 0xa9)) -
                               DOUBLE_803df3f0);
        fVar4 = FLOAT_803df3dc;
        if ((FLOAT_803df3dc <= fVar3) && (fVar4 = fVar3, FLOAT_803df3ec < fVar3)) {
          fVar4 = FLOAT_803df3ec;
        }
        uStack_8c = (uint)*(byte *)(unaff_r29 + 0xaa);
        local_90 = 0x43300000;
        fVar1 = fVar1 * (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(unaff_r29 + 0xaa)) -
                               DOUBLE_803df3f0);
        fVar3 = FLOAT_803df3dc;
        if ((FLOAT_803df3dc <= fVar1) && (fVar3 = fVar1, FLOAT_803df3ec < fVar1)) {
          fVar3 = FLOAT_803df3ec;
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
  iVar5 = (int)uVar11;
  if (iVar6 < (int)uVar11) {
    iVar5 = iVar6;
  }
  *param_9 = 0;
  fVar1 = FLOAT_803df3dc;
  while (*param_9 < iVar5) {
    piVar8 = local_f0;
    iVar7 = iVar6;
    fVar3 = FLOAT_803df3dc;
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
    *(int *)((int)((ulonglong)uVar11 >> 0x20) + iVar7 * 4) = unaff_r29;
    *(float *)(unaff_r29 + 0x130) = fVar1;
  }
  FUN_80286884();
  return;
}

