// Function: FUN_80166cec
// Entry: 80166cec
// Size: 528 bytes

/* WARNING: Removing unreachable block (ram,0x80166ed4) */
/* WARNING: Removing unreachable block (ram,0x80166ecc) */
/* WARNING: Removing unreachable block (ram,0x80166ec4) */
/* WARNING: Removing unreachable block (ram,0x80166ebc) */
/* WARNING: Removing unreachable block (ram,0x80166eb4) */
/* WARNING: Removing unreachable block (ram,0x80166eac) */
/* WARNING: Removing unreachable block (ram,0x80166d24) */
/* WARNING: Removing unreachable block (ram,0x80166d1c) */
/* WARNING: Removing unreachable block (ram,0x80166d14) */
/* WARNING: Removing unreachable block (ram,0x80166d0c) */
/* WARNING: Removing unreachable block (ram,0x80166d04) */
/* WARNING: Removing unreachable block (ram,0x80166cfc) */

void FUN_80166cec(int param_1,int param_2,float *param_3,float *param_4)

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  
  dVar2 = (double)FLOAT_803e3cb8;
  dVar5 = (double)*(float *)(param_1 + 0xc);
  dVar10 = (double)(float)(dVar2 * (double)*(float *)(param_2 + 0x7c) + dVar5);
  dVar6 = (double)*(float *)(param_1 + 0x10);
  dVar9 = (double)(float)(dVar2 * (double)*(float *)(param_2 + 0x80) + dVar6);
  dVar7 = (double)*(float *)(param_1 + 0x14);
  dVar8 = (double)(float)(dVar2 * (double)*(float *)(param_2 + 0x84) + dVar7);
  dVar3 = (double)(float)(dVar2 * (double)*(float *)(param_1 + 0x24) + dVar5);
  dVar4 = (double)(float)(dVar2 * (double)*(float *)(param_1 + 0x28) + dVar6);
  dVar2 = (double)(float)(dVar2 * (double)*(float *)(param_1 + 0x2c) + dVar7);
  dVar11 = (double)(float)(dVar6 * (double)(float)(dVar8 - dVar2) +
                          (double)(float)(dVar9 * (double)(float)(dVar2 - dVar7) +
                                         (double)(float)(dVar4 * (double)(float)(dVar7 - dVar8))));
  dVar7 = (double)(float)(dVar7 * (double)(float)(dVar10 - dVar3) +
                         (double)(float)(dVar8 * (double)(float)(dVar3 - dVar5) +
                                        (double)(float)(dVar2 * (double)(float)(dVar5 - dVar10))));
  dVar3 = (double)(float)(dVar5 * (double)(float)(dVar9 - dVar4) +
                         (double)(float)(dVar10 * (double)(float)(dVar4 - dVar6) +
                                        (double)(float)(dVar3 * (double)(float)(dVar6 - dVar9))));
  dVar2 = FUN_80293900((double)(float)(dVar3 * dVar3 +
                                      (double)(float)(dVar11 * dVar11 +
                                                     (double)(float)(dVar7 * dVar7))));
  if ((double)FLOAT_803e3c74 < dVar2) {
    dVar2 = (double)(float)((double)FLOAT_803e3c8c / dVar2);
    dVar11 = (double)(float)(dVar11 * dVar2);
    dVar7 = (double)(float)(dVar7 * dVar2);
    dVar3 = (double)(float)(dVar3 * dVar2);
  }
  local_98 = (float)dVar11;
  local_94 = (float)dVar7;
  local_90 = (float)dVar3;
  local_8c = -(float)(dVar8 * dVar3 +
                     (double)(float)(dVar10 * dVar11 + (double)(float)(dVar9 * dVar7)));
  FUN_80022974(&local_98,param_3,&local_88);
  FUN_800228f0(&local_88);
  fVar1 = FLOAT_803e3c9c;
  *(float *)(param_1 + 0x24) = FLOAT_803e3c9c * local_88;
  *(float *)(param_1 + 0x28) = fVar1 * local_84;
  *(float *)(param_1 + 0x2c) = fVar1 * local_80;
  *(float *)(param_2 + 0x7c) = *param_3;
  *(float *)(param_2 + 0x80) = param_3[1];
  *(float *)(param_2 + 0x84) = param_3[2];
  *(float *)(param_2 + 0x88) = param_3[3];
  *(float *)(param_1 + 0xc) = *param_4 + *(float *)(param_2 + 0x7c);
  *(float *)(param_1 + 0x10) = param_4[1] + *(float *)(param_2 + 0x80);
  *(float *)(param_1 + 0x14) = param_4[2] + *(float *)(param_2 + 0x84);
  return;
}

