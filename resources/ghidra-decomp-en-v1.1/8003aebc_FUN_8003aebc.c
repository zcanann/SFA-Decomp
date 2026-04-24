// Function: FUN_8003aebc
// Entry: 8003aebc
// Size: 780 bytes

/* WARNING: Removing unreachable block (ram,0x8003b1a8) */
/* WARNING: Removing unreachable block (ram,0x8003b1a0) */
/* WARNING: Removing unreachable block (ram,0x8003b198) */
/* WARNING: Removing unreachable block (ram,0x8003b190) */
/* WARNING: Removing unreachable block (ram,0x8003aee4) */
/* WARNING: Removing unreachable block (ram,0x8003aedc) */
/* WARNING: Removing unreachable block (ram,0x8003aed4) */
/* WARNING: Removing unreachable block (ram,0x8003aecc) */

void FUN_8003aebc(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,uint param_5,
                 uint param_6)

{
  int iVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  short sVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  short *psVar9;
  int iVar10;
  int iVar11;
  short *psVar12;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar13;
  short local_88 [4];
  undefined4 local_80;
  uint uStack_7c;
  longlong local_78;
  undefined8 local_70;
  double local_68;
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
  uVar13 = FUN_8028683c();
  psVar9 = (short *)((ulonglong)uVar13 >> 0x20);
  iVar7 = (int)uVar13;
  psVar12 = (short *)0x0;
  iVar8 = *(int *)(psVar9 + 0x28);
  if (iVar8 != 0) {
    iVar10 = 0;
    iVar11 = 0;
    for (uVar4 = (uint)*(byte *)(iVar8 + 0x5a); uVar4 != 0; uVar4 = uVar4 - 1) {
      if ((*(char *)(*(int *)(iVar8 + 0x10) + *(char *)((int)psVar9 + 0xad) + iVar10 + 1) != -1) &&
         (*(char *)(*(int *)(iVar8 + 0x10) + iVar10) == '\0')) {
        psVar12 = (short *)(*(int *)(psVar9 + 0x36) + iVar11);
      }
      iVar10 = *(char *)(iVar8 + 0x55) + iVar10 + 1;
      iVar11 = iVar11 + 0x12;
    }
  }
  if (psVar12 != (short *)0x0) {
    if (iVar7 == 0) {
      psVar12[1] = psVar12[1] >> 1;
      *psVar12 = *psVar12 >> 1;
    }
    else {
      fVar2 = *(float *)(psVar9 + 6) - *(float *)(iVar7 + 0xc);
      fVar3 = *(float *)(psVar9 + 10) - *(float *)(iVar7 + 0x14);
      FUN_80293900((double)(fVar2 * fVar2 + fVar3 * fVar3));
      iVar7 = FUN_80021884();
      local_88[0] = (short)iVar7 - *psVar9;
      if (0x8000 < local_88[0]) {
        local_88[0] = local_88[0] + 1;
      }
      if (local_88[0] < -0x8000) {
        local_88[0] = local_88[0] + -1;
      }
      if ((param_5 & 0xff) != 0) {
        local_88[0] = local_88[0] + -0x8000;
      }
      iVar7 = FUN_80021884();
      local_88[1] = (short)iVar7 + -0x3fff;
      uStack_7c = param_4 ^ 0x80000000;
      local_80 = 0x43300000;
      iVar7 = (int)(FLOAT_803df66c *
                   (float)((double)CONCAT44(0x43300000,param_4 ^ 0x80000000) - DOUBLE_803df650));
      local_78 = (longlong)iVar7;
      sVar5 = (short)iVar7;
      psVar9 = local_88;
      local_70 = (double)CONCAT44(0x43300000,param_6 ^ 0x80000000);
      fVar2 = FLOAT_803df66c * (float)(local_70 - DOUBLE_803df650);
      iVar7 = (int)fVar2;
      local_68 = (double)(longlong)iVar7;
      iVar8 = -(int)(short)iVar7;
      iVar10 = -(int)sVar5;
      iVar11 = 2;
      iVar7 = param_3;
      do {
        *psVar9 = *psVar9 - *(short *)(iVar7 + 0x14);
        sVar6 = *psVar9;
        if (sVar6 < iVar8) {
          sVar6 = (short)iVar8;
        }
        else {
          iVar1 = (int)fVar2;
          local_68 = (double)(longlong)iVar1;
          if ((int)(short)iVar1 < (int)sVar6) {
            local_70 = (double)(longlong)iVar1;
            sVar6 = (short)iVar1;
          }
        }
        *psVar9 = sVar6;
        *(short *)(iVar7 + 0x14) = *(short *)(iVar7 + 0x14) + *psVar9;
        if ((int)sVar5 < (int)*(short *)(iVar7 + 0x14)) {
          *(short *)(iVar7 + 0x14) = sVar5;
        }
        if (*(short *)(iVar7 + 0x14) < iVar10) {
          *(short *)(iVar7 + 0x14) = (short)iVar10;
        }
        iVar7 = iVar7 + 0x30;
        psVar9 = psVar9 + 1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      psVar12[1] = *(short *)(param_3 + 0x14);
      *psVar12 = *(short *)(param_3 + 0x44);
    }
  }
  FUN_80286888();
  return;
}

