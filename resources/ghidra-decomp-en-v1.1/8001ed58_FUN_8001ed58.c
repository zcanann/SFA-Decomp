// Function: FUN_8001ed58
// Entry: 8001ed58
// Size: 804 bytes

void FUN_8001ed58(undefined4 param_1,undefined4 param_2,int param_3,int *param_4,uint param_5)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int unaff_r28;
  int iVar9;
  int *piVar10;
  int iVar11;
  double dVar12;
  undefined8 uVar13;
  float afStack_a8 [3];
  int local_9c [21];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  uVar13 = FUN_8028682c();
  iVar11 = (int)((ulonglong)uVar13 >> 0x20);
  if (iVar11 == 0) {
    uVar5 = 1;
  }
  else {
    uVar5 = 1 << (uint)*(byte *)(*(int *)(iVar11 + 0x50) + 0x8d) & 0xff;
  }
  piVar10 = &DAT_8033cb20;
  iVar8 = 0;
  for (iVar9 = 0; iVar7 = iVar8, iVar9 < (int)(uint)DAT_803dd6b0; iVar9 = iVar9 + 1) {
    unaff_r28 = *piVar10;
    if (((*(char *)(unaff_r28 + 0x4c) != '\0') &&
        (uVar6 = *(uint *)(unaff_r28 + 0x50), (uVar6 & param_5) != 0)) &&
       ((uVar5 & *(byte *)(unaff_r28 + 100)) != 0)) {
      if (uVar6 == 4) {
        *(float *)(unaff_r28 + 0x130) = FLOAT_803df3e8;
      }
      else if (uVar6 == 8) {
        if ((*(int *)(unaff_r28 + 0x16c) == 0) ||
           (uVar6 = FUN_8001ce70(unaff_r28,iVar11), (uVar6 & 0xff) == 0)) {
          *(float *)(unaff_r28 + 0x130) = FLOAT_803df3dc;
        }
        else {
          FUN_80247eb8((float *)(iVar11 + 0x18),(float *)(unaff_r28 + 0x10),afStack_a8);
          dVar12 = FUN_80247f54(afStack_a8);
          *(float *)(unaff_r28 + 0x130) =
               (float)((double)FLOAT_803df3e4 + (double)(float)((double)FLOAT_803df3e4 / dVar12));
          dVar12 = FUN_8001d13c(unaff_r28,iVar11);
          *(float *)(unaff_r28 + 0x134) = (float)dVar12;
        }
      }
      else {
        dVar12 = FUN_8001d13c(unaff_r28,iVar11);
        *(float *)(unaff_r28 + 0x134) = (float)dVar12;
        fVar1 = *(float *)(unaff_r28 + 0x134);
        uStack_44 = (uint)*(byte *)(unaff_r28 + 0xa8);
        local_48 = 0x43300000;
        fVar2 = fVar1 * (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(unaff_r28 + 0xa8)) -
                               DOUBLE_803df3f0);
        fVar3 = FLOAT_803df3dc;
        if ((FLOAT_803df3dc <= fVar2) && (fVar3 = fVar2, FLOAT_803df3ec < fVar2)) {
          fVar3 = FLOAT_803df3ec;
        }
        uStack_3c = (uint)*(byte *)(unaff_r28 + 0xa9);
        local_40 = 0x43300000;
        fVar2 = fVar1 * (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(unaff_r28 + 0xa9)) -
                               DOUBLE_803df3f0);
        fVar4 = FLOAT_803df3dc;
        if ((FLOAT_803df3dc <= fVar2) && (fVar4 = fVar2, FLOAT_803df3ec < fVar2)) {
          fVar4 = FLOAT_803df3ec;
        }
        uStack_34 = (uint)*(byte *)(unaff_r28 + 0xaa);
        local_38 = 0x43300000;
        fVar1 = fVar1 * (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(unaff_r28 + 0xaa)) -
                               DOUBLE_803df3f0);
        fVar2 = FLOAT_803df3dc;
        if ((FLOAT_803df3dc <= fVar1) && (fVar2 = fVar1, FLOAT_803df3ec < fVar1)) {
          fVar2 = FLOAT_803df3ec;
        }
        if (fVar4 < fVar3) {
          fVar4 = fVar3;
        }
        *(float *)(unaff_r28 + 0x130) = fVar4;
        if (fVar2 < *(float *)(unaff_r28 + 0x130)) {
          fVar2 = *(float *)(unaff_r28 + 0x130);
        }
        *(float *)(unaff_r28 + 0x130) = fVar2;
      }
      if (FLOAT_803df3dc < *(float *)(unaff_r28 + 0x130)) {
        uStack_34 = (uint)*(byte *)(unaff_r28 + 0x2fc) << 8 ^ 0x80000000;
        local_38 = 0x43300000;
        *(float *)(unaff_r28 + 0x130) =
             *(float *)(unaff_r28 + 0x130) +
             (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df400);
        iVar7 = iVar8 + 1;
        local_9c[iVar8] = unaff_r28;
        if (0x13 < iVar7) break;
      }
    }
    piVar10 = piVar10 + 1;
    iVar8 = iVar7;
  }
  if (iVar7 < param_3) {
    param_3 = iVar7;
  }
  *param_4 = 0;
  while (*param_4 < param_3) {
    piVar10 = local_9c;
    iVar11 = iVar7;
    fVar1 = FLOAT_803df3dc;
    if (0 < iVar7) {
      do {
        fVar2 = *(float *)(*piVar10 + 0x130);
        if (fVar1 < fVar2) {
          unaff_r28 = *piVar10;
          fVar1 = fVar2;
        }
        piVar10 = piVar10 + 1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
    }
    iVar11 = *param_4;
    *param_4 = iVar11 + 1;
    *(int *)((int)uVar13 + iVar11 * 4) = unaff_r28;
    *(float *)(unaff_r28 + 0x130) = -*(float *)(unaff_r28 + 0x130);
  }
  FUN_80286878();
  return;
}

