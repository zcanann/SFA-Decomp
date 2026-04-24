// Function: FUN_80217524
// Entry: 80217524
// Size: 940 bytes

/* WARNING: Removing unreachable block (ram,0x802178b0) */
/* WARNING: Removing unreachable block (ram,0x80217534) */

void FUN_80217524(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,float *param_5)

{
  float fVar1;
  float fVar2;
  short sVar3;
  short *psVar4;
  short *psVar5;
  int iVar6;
  int iVar7;
  short sVar8;
  int iVar9;
  double dVar10;
  undefined8 uVar11;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  
  uVar11 = FUN_8028683c();
  psVar4 = (short *)((ulonglong)uVar11 >> 0x20);
  iVar6 = (int)uVar11;
  psVar5 = (short *)FUN_800396d0((int)psVar4,0xb);
  if (psVar5 != (short *)0x0) {
    if (iVar6 == 0) {
      *psVar4 = *psVar4 >> 1;
      *psVar5 = *psVar5 >> 1;
    }
    else {
      fVar1 = *(float *)(iVar6 + 0xc) - *param_5;
      fVar2 = *(float *)(iVar6 + 0x14) - param_5[2];
      FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
      iVar6 = FUN_80021884();
      iVar7 = FUN_80021884();
      sVar3 = (short)iVar7;
      if (psVar4[0x23] == 0x417) {
        sVar3 = -sVar3;
      }
      if ((int)param_4 < 0x168) {
        local_48 = (double)CONCAT44(0x43300000,param_4 ^ 0x80000000);
        sVar8 = (short)(int)(FLOAT_803e7578 * (float)(local_48 - DOUBLE_803e7570));
        iVar9 = (int)sVar8;
        iVar7 = -iVar9;
        *(short *)(param_3 + 0x14) = (short)iVar6;
        if (iVar9 < *(short *)(param_3 + 0x14)) {
          *(short *)(param_3 + 0x14) = sVar8;
        }
        if (*(short *)(param_3 + 0x14) < iVar7) {
          *(short *)(param_3 + 0x14) = (short)iVar7;
        }
        *(short *)(param_3 + 0x44) = sVar3;
        if (iVar9 < *(short *)(param_3 + 0x44)) {
          *(short *)(param_3 + 0x44) = sVar8;
        }
        if (*(short *)(param_3 + 0x44) < iVar7) {
          *(short *)(param_3 + 0x44) = (short)iVar7;
        }
      }
      else {
        *(short *)(param_3 + 0x14) = (short)iVar6;
        *(short *)(param_3 + 0x44) = sVar3;
      }
      sVar3 = *(short *)(param_3 + 0x14) - *psVar4;
      if (0x8000 < sVar3) {
        sVar3 = sVar3 + 1;
      }
      if (sVar3 < -0x8000) {
        sVar3 = sVar3 + -1;
      }
      iVar6 = -(int)DAT_803dcf16;
      if (iVar6 <= sVar3) {
        if ((int)DAT_803dcf16 < (int)sVar3) {
          sVar3 = DAT_803dcf16;
        }
        iVar6 = (int)sVar3;
      }
      local_40 = (double)CONCAT44(0x43300000,(int)(short)iVar6 ^ 0x80000000);
      dVar10 = FUN_80021434((double)(float)(local_40 - DOUBLE_803e7570),(double)FLOAT_803e757c,
                            (double)FLOAT_803dc074);
      local_48 = (double)CONCAT44(0x43300000,(int)*psVar4 ^ 0x80000000);
      *psVar4 = (short)(int)((double)(float)(local_48 - DOUBLE_803e7570) + dVar10);
      if (psVar5 != (short *)0x0) {
        sVar3 = *(short *)(param_3 + 0x44) - *psVar5;
        if (0x8000 < sVar3) {
          sVar3 = sVar3 + 1;
        }
        if (sVar3 < -0x8000) {
          sVar3 = sVar3 + -1;
        }
        iVar6 = -(int)DAT_803dcf16;
        if (iVar6 <= sVar3) {
          if ((int)DAT_803dcf16 < (int)sVar3) {
            sVar3 = DAT_803dcf16;
          }
          iVar6 = (int)sVar3;
        }
        local_38 = (double)CONCAT44(0x43300000,(int)(short)iVar6 ^ 0x80000000);
        dVar10 = FUN_80021434((double)(float)(local_38 - DOUBLE_803e7570),(double)FLOAT_803e757c,
                              (double)FLOAT_803dc074);
        local_40 = (double)CONCAT44(0x43300000,(int)*psVar5 ^ 0x80000000);
        *psVar5 = (short)(int)((double)(float)(local_40 - DOUBLE_803e7570) + dVar10);
      }
    }
  }
  FUN_80286888();
  return;
}

