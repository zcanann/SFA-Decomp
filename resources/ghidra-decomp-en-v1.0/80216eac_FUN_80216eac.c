// Function: FUN_80216eac
// Entry: 80216eac
// Size: 940 bytes

/* WARNING: Removing unreachable block (ram,0x80217238) */

void FUN_80216eac(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,float *param_5)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  short *psVar5;
  short *psVar6;
  uint uVar7;
  undefined2 uVar8;
  short sVar9;
  short sVar10;
  int iVar11;
  int iVar12;
  undefined4 uVar13;
  double dVar14;
  undefined8 in_f31;
  undefined8 uVar15;
  double local_48;
  double local_40;
  double local_38;
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar15 = FUN_802860d8();
  psVar5 = (short *)((ulonglong)uVar15 >> 0x20);
  iVar11 = (int)uVar15;
  psVar6 = (short *)FUN_800395d8(psVar5,0xb);
  if (psVar6 == (short *)0x0) {
    uVar7 = 0;
  }
  else if (iVar11 == 0) {
    *psVar5 = *psVar5 >> 1;
    *psVar6 = *psVar6 >> 1;
    uVar7 = 0;
  }
  else {
    fVar3 = *(float *)(iVar11 + 0xc) - *param_5;
    fVar1 = *(float *)(iVar11 + 0x10);
    fVar2 = param_5[1];
    fVar4 = *(float *)(iVar11 + 0x14) - param_5[2];
    uVar15 = FUN_802931a0((double)(fVar3 * fVar3 + fVar4 * fVar4));
    uVar8 = FUN_800217c0((double)fVar3,(double)fVar4);
    sVar9 = FUN_800217c0((double)(fVar1 - fVar2),uVar15);
    if (psVar5[0x23] == 0x417) {
      sVar9 = -sVar9;
    }
    if ((int)param_4 < 0x168) {
      local_48 = (double)CONCAT44(0x43300000,param_4 ^ 0x80000000);
      sVar10 = (short)(int)(FLOAT_803e68e0 * (float)(local_48 - DOUBLE_803e68d8));
      iVar12 = (int)sVar10;
      iVar11 = -iVar12;
      *(undefined2 *)(param_3 + 0x14) = uVar8;
      if (iVar12 < *(short *)(param_3 + 0x14)) {
        *(short *)(param_3 + 0x14) = sVar10;
      }
      if (*(short *)(param_3 + 0x14) < iVar11) {
        *(short *)(param_3 + 0x14) = (short)iVar11;
      }
      *(short *)(param_3 + 0x44) = sVar9;
      if (iVar12 < *(short *)(param_3 + 0x44)) {
        *(short *)(param_3 + 0x44) = sVar10;
      }
      if (*(short *)(param_3 + 0x44) < iVar11) {
        *(short *)(param_3 + 0x44) = (short)iVar11;
      }
    }
    else {
      *(undefined2 *)(param_3 + 0x14) = uVar8;
      *(short *)(param_3 + 0x44) = sVar9;
    }
    sVar9 = *(short *)(param_3 + 0x14) - *psVar5;
    if (0x8000 < sVar9) {
      sVar9 = sVar9 + 1;
    }
    if (sVar9 < -0x8000) {
      sVar9 = sVar9 + -1;
    }
    iVar11 = -(int)DAT_803dc2ae;
    if (iVar11 <= sVar9) {
      if ((int)DAT_803dc2ae < (int)sVar9) {
        sVar9 = DAT_803dc2ae;
      }
      iVar11 = (int)sVar9;
    }
    local_40 = (double)CONCAT44(0x43300000,(int)(short)iVar11 ^ 0x80000000);
    dVar14 = (double)FUN_80021370((double)(float)(local_40 - DOUBLE_803e68d8),(double)FLOAT_803e68e4
                                  ,(double)FLOAT_803db414);
    local_48 = (double)CONCAT44(0x43300000,(int)*psVar5 ^ 0x80000000);
    *psVar5 = (short)(int)((double)(float)(local_48 - DOUBLE_803e68d8) + dVar14);
    if (psVar6 != (short *)0x0) {
      sVar9 = *(short *)(param_3 + 0x44) - *psVar6;
      if (0x8000 < sVar9) {
        sVar9 = sVar9 + 1;
      }
      if (sVar9 < -0x8000) {
        sVar9 = sVar9 + -1;
      }
      iVar11 = -(int)DAT_803dc2ae;
      if (iVar11 <= sVar9) {
        if ((int)DAT_803dc2ae < (int)sVar9) {
          sVar9 = DAT_803dc2ae;
        }
        iVar11 = (int)sVar9;
      }
      local_38 = (double)CONCAT44(0x43300000,(int)(short)iVar11 ^ 0x80000000);
      dVar14 = (double)FUN_80021370((double)(float)(local_38 - DOUBLE_803e68d8),
                                    (double)FLOAT_803e68e4,(double)FLOAT_803db414);
      local_40 = (double)CONCAT44(0x43300000,(int)*psVar6 ^ 0x80000000);
      *psVar6 = (short)(int)((double)(float)(local_40 - DOUBLE_803e68d8) + dVar14);
    }
    uVar7 = (int)*psVar5 - (int)*(short *)(param_3 + 0x14);
    if ((int)uVar7 < 0) {
      uVar7 = -uVar7;
    }
    uVar7 = ((int)(uVar7 ^ 0x100) >> 1) - ((uVar7 ^ 0x100) & uVar7) >> 0x1f;
  }
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  FUN_80286124(uVar7);
  return;
}

