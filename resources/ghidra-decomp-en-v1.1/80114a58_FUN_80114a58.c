// Function: FUN_80114a58
// Entry: 80114a58
// Size: 864 bytes

/* WARNING: Removing unreachable block (ram,0x80114d98) */
/* WARNING: Removing unreachable block (ram,0x80114d90) */
/* WARNING: Removing unreachable block (ram,0x80114a70) */
/* WARNING: Removing unreachable block (ram,0x80114a68) */

void FUN_80114a58(undefined4 param_1,undefined4 param_2,int param_3,float *param_4,byte *param_5,
                 undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  short sVar1;
  short *psVar2;
  int iVar3;
  short *psVar4;
  float *pfVar5;
  byte *pbVar6;
  double extraout_f1;
  double dVar7;
  double dVar8;
  double dVar9;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f30;
  double dVar10;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  float local_68;
  float local_64;
  float local_60;
  float local_5c [2];
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined8 local_48;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar11 = FUN_80286840();
  psVar2 = (short *)((ulonglong)uVar11 >> 0x20);
  psVar4 = (short *)uVar11;
  if (psVar4 != (short *)0x0) {
    local_64 = *(float *)(psVar4 + 6) - *(float *)(psVar2 + 6);
    dVar9 = (double)local_64;
    local_60 = *(float *)(psVar4 + 8) - *(float *)(psVar2 + 8);
    local_5c[0] = *(float *)(psVar4 + 10) - *(float *)(psVar2 + 10);
    pfVar5 = param_4;
    pbVar6 = param_5;
    dVar10 = extraout_f1;
    dVar7 = FUN_80293900((double)(local_5c[0] * local_5c[0] +
                                 (float)(dVar9 * dVar9) + local_60 * local_60));
    if ((double)(float)((double)FLOAT_803e2934 * dVar10) <= dVar7) {
      FUN_80070320(&local_64,&local_60,local_5c);
      *(float *)(psVar2 + 0x12) = local_64 * (float)(dVar10 * (double)FLOAT_803dc074);
      *(float *)(psVar2 + 0x14) = local_60 * (float)(dVar10 * (double)FLOAT_803dc074);
      *(float *)(psVar2 + 0x16) = local_5c[0] * (float)(dVar10 * (double)FLOAT_803dc074);
      if (((*param_5 & 1) != 0) &&
         (iVar3 = FUN_80065a20((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                               (double)*(float *)(psVar2 + 10),psVar2,&local_68,0), iVar3 == 0)) {
        *(float *)(psVar2 + 8) = *(float *)(psVar2 + 8) - local_68;
      }
      if ((*param_5 & 2) != 0) {
        sVar1 = *psVar4 - *psVar2;
        if (0x8000 < sVar1) {
          sVar1 = sVar1 + 1;
        }
        if (sVar1 < -0x8000) {
          sVar1 = sVar1 + -1;
        }
        uStack_54 = (int)*psVar2 ^ 0x80000000;
        local_5c[1] = 176.0;
        uStack_4c = (int)sVar1 ^ 0x80000000;
        local_50 = 0x43300000;
        iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e2918) +
                     (float)((double)((FLOAT_803e2938 +
                                      (float)((double)CONCAT44(0x43300000,uStack_4c) -
                                             DOUBLE_803e2918)) *
                                     (float)(dVar10 * (double)FLOAT_803dc074)) / dVar7));
        local_48 = (longlong)iVar3;
        *psVar2 = (short)iVar3;
      }
      dVar7 = (double)*(float *)(psVar2 + 0x14);
      dVar8 = (double)*(float *)(psVar2 + 0x16);
      FUN_8002ba34((double)*(float *)(psVar2 + 0x12),dVar7,dVar8,(int)psVar2);
      if (param_3 != -1) {
        if (psVar2[0x50] != param_3) {
          FUN_8003042c((double)FLOAT_803e2910,dVar7,dVar8,dVar9,in_f5,in_f6,in_f7,in_f8,psVar2,
                       param_3,0,pfVar5,pbVar6,param_6,param_7,param_8);
        }
        iVar3 = FUN_80021884();
        sVar1 = *psVar2 - (short)iVar3;
        if (0x8000 < sVar1) {
          sVar1 = sVar1 + 1;
        }
        if (sVar1 < -0x8000) {
          sVar1 = sVar1 + -1;
        }
        local_48 = CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000);
        dVar7 = (double)FUN_80294964();
        FUN_8002f6cc((double)(float)(dVar10 * -dVar7),(int)psVar2,param_4);
      }
    }
    else {
      *(undefined4 *)(psVar2 + 6) = *(undefined4 *)(psVar4 + 6);
      *(undefined4 *)(psVar2 + 8) = *(undefined4 *)(psVar4 + 8);
      *(undefined4 *)(psVar2 + 10) = *(undefined4 *)(psVar4 + 10);
      if (((*param_5 & 1) != 0) &&
         (iVar3 = FUN_80065a20((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                               (double)*(float *)(psVar2 + 10),psVar2,&local_68,0), iVar3 == 0)) {
        *(float *)(psVar2 + 8) = *(float *)(psVar2 + 8) - local_68;
      }
    }
  }
  FUN_8028688c();
  return;
}

