// Function: FUN_8003a478
// Entry: 8003a478
// Size: 1332 bytes

/* WARNING: Removing unreachable block (ram,0x8003a98c) */
/* WARNING: Removing unreachable block (ram,0x8003a984) */
/* WARNING: Removing unreachable block (ram,0x8003a97c) */
/* WARNING: Removing unreachable block (ram,0x8003a974) */
/* WARNING: Removing unreachable block (ram,0x8003a4a0) */
/* WARNING: Removing unreachable block (ram,0x8003a498) */
/* WARNING: Removing unreachable block (ram,0x8003a490) */
/* WARNING: Removing unreachable block (ram,0x8003a488) */

void FUN_8003a478(undefined4 param_1,undefined4 param_2,float *param_3,int param_4,short *param_5,
                 undefined4 param_6,short param_7)

{
  short sVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  short *psVar5;
  int iVar6;
  short *psVar7;
  int iVar8;
  short *psVar9;
  int iVar10;
  int iVar11;
  short sVar12;
  int iVar13;
  short *psVar14;
  uint *puVar15;
  short *psVar16;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar17;
  short local_88 [6];
  uint uStack_7c;
  longlong local_78;
  undefined8 local_70;
  undefined8 local_68;
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
  uVar17 = FUN_80286834();
  psVar5 = (short *)((ulonglong)uVar17 >> 0x20);
  psVar14 = param_5 + 0xf;
  fVar2 = *param_3 - *(float *)((int)uVar17 + 0xc);
  fVar3 = param_3[2] - *(float *)((int)uVar17 + 0x14);
  FUN_80293900((double)(fVar2 * fVar2 + fVar3 * fVar3));
  iVar6 = FUN_80021884();
  local_88[2] = (short)iVar6 - *psVar5;
  if (0x8000 < local_88[2]) {
    local_88[2] = local_88[2] + 1;
  }
  if (local_88[2] < -0x8000) {
    local_88[2] = local_88[2] + -1;
  }
  iVar6 = FUN_80021884();
  local_88[3] = param_7 + (short)iVar6;
  if (0x8000 < local_88[3]) {
    local_88[3] = local_88[3] + 1;
  }
  if (local_88[3] < -0x8000) {
    local_88[3] = local_88[3] + -1;
  }
  if ((char)DAT_803dd880 < '\0') {
    local_88[2] = local_88[2] + -0x8000;
    local_88[3] = -local_88[3];
    DAT_803dd880 = DAT_803dd880 & 0x7f;
  }
  iVar6 = 0;
  puVar15 = &DAT_802cba60;
  do {
    psVar16 = (short *)0x0;
    iVar8 = *(int *)(psVar5 + 0x28);
    if (iVar8 != 0) {
      iVar10 = 0;
      iVar11 = 0;
      for (uVar4 = (uint)*(byte *)(iVar8 + 0x5a); uVar4 != 0; uVar4 = uVar4 - 1) {
        if ((*(char *)(*(int *)(iVar8 + 0x10) + *(char *)((int)psVar5 + 0xad) + iVar10 + 1) != -1)
           && (*puVar15 == (uint)*(byte *)(*(int *)(iVar8 + 0x10) + iVar10))) {
          psVar16 = (short *)(*(int *)(psVar5 + 0x36) + iVar11);
        }
        iVar10 = *(char *)(iVar8 + 0x55) + iVar10 + 1;
        iVar11 = iVar11 + 0x12;
      }
    }
    if (psVar16 == (short *)0x0) break;
    uVar4 = 0;
    psVar7 = local_88 + 2;
    psVar9 = local_88;
    iVar8 = 2;
    do {
      if ((uVar4 & 1 ^ uVar4 >> 0x1f) == uVar4 >> 0x1f) {
        local_70 = (double)CONCAT44(0x43300000,(int)*param_5 ^ 0x80000000);
        iVar10 = (int)(FLOAT_803df66c * (float)(local_70 - DOUBLE_803df650));
        local_68 = (double)(longlong)iVar10;
        sVar12 = (short)iVar10;
      }
      else {
        uStack_7c = (int)*psVar14 ^ 0x80000000U;
        local_88[4] = 0x4330;
        local_88[5] = 0;
        iVar10 = (int)(FLOAT_803df66c *
                      (float)((double)CONCAT44(0x43300000,(int)*psVar14 ^ 0x80000000U) -
                             DOUBLE_803df650));
        local_78 = (longlong)iVar10;
        sVar12 = (short)iVar10;
      }
      sVar1 = *psVar7;
      *psVar9 = sVar1;
      if ((int)sVar12 < (int)sVar1) {
        *psVar9 = sVar12;
        *psVar7 = sVar1 - sVar12;
      }
      else {
        iVar10 = -(int)sVar12;
        if (sVar1 < iVar10) {
          *psVar9 = (short)iVar10;
          *psVar7 = sVar1 + sVar12;
        }
        else {
          *psVar7 = 0;
        }
      }
      psVar7 = psVar7 + 1;
      psVar9 = psVar9 + 1;
      uVar4 = uVar4 + 1;
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
    if (param_4 == 0) {
      iVar10 = (int)(short)((short)((int)psVar16[1] + (int)local_88[0] >> 1) - psVar16[1]);
      uVar4 = (uint)DAT_803dc070;
      local_68 = (double)CONCAT44(0x43300000,-(int)*param_5 ^ 0x80000000);
      iVar8 = uVar4 * ((int)(short)(int)(FLOAT_803df66c * (float)(local_68 - DOUBLE_803df650)) /
                      DAT_803dc0c0);
      if (iVar8 <= iVar10) {
        local_68 = (double)CONCAT44(0x43300000,(int)*param_5 ^ 0x80000000);
        iVar11 = uVar4 * ((int)(short)(int)(FLOAT_803df66c * (float)(local_68 - DOUBLE_803df650)) /
                         DAT_803dc0c0);
        iVar8 = iVar10;
        if (iVar11 < iVar10) {
          iVar8 = iVar11;
        }
      }
      iVar13 = (int)(short)((short)((int)*psVar16 + (int)local_88[1] >> 1) - *psVar16);
      local_68 = (double)CONCAT44(0x43300000,(int)*psVar14 ^ 0x80000000);
      iVar10 = (int)(FLOAT_803df66c * (float)(local_68 - DOUBLE_803df650));
      local_70 = (double)(longlong)iVar10;
      iVar11 = (int)(short)iVar10;
      iVar10 = uVar4 * (-iVar11 / (DAT_803dc0c0 << 1));
      if ((iVar10 <= iVar13) &&
         (iVar11 = uVar4 * (iVar11 / (DAT_803dc0c0 << 1)), iVar10 = iVar13, iVar11 < iVar13)) {
        iVar10 = iVar11;
      }
      *psVar16 = *psVar16 + (short)iVar10;
      psVar16[1] = psVar16[1] + (short)iVar8;
    }
    else {
      *(short *)(param_4 + 0x14) = local_88[0];
      FUN_80039ab8(param_4,(int)psVar16);
      *(short *)(param_4 + 0x44) = local_88[1];
      FUN_8003992c((double)FLOAT_803df658,(double)FLOAT_803df65c,param_4 + 0x30,psVar16);
      param_4 = param_4 + 0x60;
    }
    puVar15 = puVar15 + 1;
    psVar14 = psVar14 + 1;
    param_5 = param_5 + 1;
    iVar6 = iVar6 + 1;
  } while (iVar6 < 10);
  FUN_80286880();
  return;
}

