// Function: FUN_8001ec94
// Entry: 8001ec94
// Size: 804 bytes

void FUN_8001ec94(undefined4 param_1,undefined4 param_2,int param_3,int *param_4,uint param_5)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  uint uVar5;
  uint uVar6;
  char cVar7;
  int iVar8;
  int iVar9;
  int unaff_r28;
  int iVar10;
  int *piVar11;
  int iVar12;
  double dVar13;
  undefined8 uVar14;
  undefined auStack168 [12];
  int local_9c [21];
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  
  uVar14 = FUN_802860c8();
  iVar12 = (int)((ulonglong)uVar14 >> 0x20);
  if (iVar12 == 0) {
    uVar5 = 1;
  }
  else {
    uVar5 = 1 << (uint)*(byte *)(*(int *)(iVar12 + 0x50) + 0x8d) & 0xff;
  }
  piVar11 = &DAT_8033bec0;
  iVar9 = 0;
  for (iVar10 = 0; iVar8 = iVar9, iVar10 < (int)(uint)DAT_803dca30; iVar10 = iVar10 + 1) {
    unaff_r28 = *piVar11;
    if (((*(char *)(unaff_r28 + 0x4c) != '\0') &&
        (uVar6 = *(uint *)(unaff_r28 + 0x50), (uVar6 & param_5) != 0)) &&
       ((uVar5 & *(byte *)(unaff_r28 + 100)) != 0)) {
      if (uVar6 == 4) {
        *(float *)(unaff_r28 + 0x130) = FLOAT_803de768;
      }
      else if (uVar6 == 8) {
        if ((*(int *)(unaff_r28 + 0x16c) == 0) ||
           (cVar7 = FUN_8001cdac(unaff_r28,iVar12), cVar7 == '\0')) {
          *(float *)(unaff_r28 + 0x130) = FLOAT_803de75c;
        }
        else {
          FUN_80247754(iVar12 + 0x18,unaff_r28 + 0x10,auStack168);
          dVar13 = (double)FUN_802477f0(auStack168);
          *(float *)(unaff_r28 + 0x130) =
               (float)((double)FLOAT_803de764 + (double)(float)((double)FLOAT_803de764 / dVar13));
          dVar13 = (double)FUN_8001d078(unaff_r28,iVar12);
          *(float *)(unaff_r28 + 0x134) = (float)dVar13;
        }
      }
      else {
        dVar13 = (double)FUN_8001d078(unaff_r28,iVar12);
        *(float *)(unaff_r28 + 0x134) = (float)dVar13;
        fVar1 = *(float *)(unaff_r28 + 0x134);
        uStack68 = (uint)*(byte *)(unaff_r28 + 0xa8);
        local_48 = 0x43300000;
        fVar2 = fVar1 * (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(unaff_r28 + 0xa8)) -
                               DOUBLE_803de770);
        fVar3 = FLOAT_803de75c;
        if ((FLOAT_803de75c <= fVar2) && (fVar3 = fVar2, FLOAT_803de76c < fVar2)) {
          fVar3 = FLOAT_803de76c;
        }
        uStack60 = (uint)*(byte *)(unaff_r28 + 0xa9);
        local_40 = 0x43300000;
        fVar2 = fVar1 * (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(unaff_r28 + 0xa9)) -
                               DOUBLE_803de770);
        fVar4 = FLOAT_803de75c;
        if ((FLOAT_803de75c <= fVar2) && (fVar4 = fVar2, FLOAT_803de76c < fVar2)) {
          fVar4 = FLOAT_803de76c;
        }
        uStack52 = (uint)*(byte *)(unaff_r28 + 0xaa);
        local_38 = 0x43300000;
        fVar1 = fVar1 * (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(unaff_r28 + 0xaa)) -
                               DOUBLE_803de770);
        fVar2 = FLOAT_803de75c;
        if ((FLOAT_803de75c <= fVar1) && (fVar2 = fVar1, FLOAT_803de76c < fVar1)) {
          fVar2 = FLOAT_803de76c;
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
      if (FLOAT_803de75c < *(float *)(unaff_r28 + 0x130)) {
        uStack52 = (uint)*(byte *)(unaff_r28 + 0x2fc) << 8 ^ 0x80000000;
        local_38 = 0x43300000;
        *(float *)(unaff_r28 + 0x130) =
             *(float *)(unaff_r28 + 0x130) +
             (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803de780);
        iVar8 = iVar9 + 1;
        local_9c[iVar9] = unaff_r28;
        if (0x13 < iVar8) break;
      }
    }
    piVar11 = piVar11 + 1;
    iVar9 = iVar8;
  }
  if (iVar8 < param_3) {
    param_3 = iVar8;
  }
  *param_4 = 0;
  while (*param_4 < param_3) {
    piVar11 = local_9c;
    iVar12 = iVar8;
    fVar1 = FLOAT_803de75c;
    if (0 < iVar8) {
      do {
        fVar2 = *(float *)(*piVar11 + 0x130);
        if (fVar1 < fVar2) {
          unaff_r28 = *piVar11;
          fVar1 = fVar2;
        }
        piVar11 = piVar11 + 1;
        iVar12 = iVar12 + -1;
      } while (iVar12 != 0);
    }
    iVar12 = *param_4;
    *param_4 = iVar12 + 1;
    *(int *)((int)uVar14 + iVar12 * 4) = unaff_r28;
    *(float *)(unaff_r28 + 0x130) = -*(float *)(unaff_r28 + 0x130);
  }
  FUN_80286114();
  return;
}

