// Function: FUN_80021c64
// Entry: 80021c64
// Size: 800 bytes

/* WARNING: Removing unreachable block (ram,0x80021f64) */
/* WARNING: Removing unreachable block (ram,0x80021f5c) */
/* WARNING: Removing unreachable block (ram,0x80021f54) */
/* WARNING: Removing unreachable block (ram,0x80021f4c) */
/* WARNING: Removing unreachable block (ram,0x80021f44) */
/* WARNING: Removing unreachable block (ram,0x80021c94) */
/* WARNING: Removing unreachable block (ram,0x80021c8c) */
/* WARNING: Removing unreachable block (ram,0x80021c84) */
/* WARNING: Removing unreachable block (ram,0x80021c7c) */
/* WARNING: Removing unreachable block (ram,0x80021c74) */

void FUN_80021c64(float *param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  
  dVar4 = (double)FUN_80293a9c();
  dVar9 = (double)((float)((double)CONCAT44(0x43300000,
                                            (int)((double)FLOAT_803df450 * dVar4) ^ 0x80000000) -
                          DOUBLE_803df460) * FLOAT_803df470);
  dVar4 = (double)FUN_80293fb4();
  dVar8 = (double)((float)((double)CONCAT44(0x43300000,
                                            (int)((double)FLOAT_803df450 * dVar4) ^ 0x80000000) -
                          DOUBLE_803df460) * FLOAT_803df470);
  dVar4 = (double)FUN_80293a9c();
  dVar7 = (double)((float)((double)CONCAT44(0x43300000,
                                            (int)((double)FLOAT_803df450 * dVar4) ^ 0x80000000) -
                          DOUBLE_803df460) * FLOAT_803df470);
  dVar4 = (double)FUN_80293fb4();
  dVar6 = (double)((float)((double)CONCAT44(0x43300000,
                                            (int)((double)FLOAT_803df450 * dVar4) ^ 0x80000000) -
                          DOUBLE_803df460) * FLOAT_803df470);
  dVar4 = (double)FUN_80293a9c();
  dVar5 = (double)((float)((double)CONCAT44(0x43300000,
                                            (int)((double)FLOAT_803df450 * dVar4) ^ 0x80000000) -
                          DOUBLE_803df460) * FLOAT_803df470);
  dVar4 = (double)FUN_80293fb4();
  dVar4 = (double)((float)((double)CONCAT44(0x43300000,
                                            (int)((double)FLOAT_803df450 * dVar4) ^ 0x80000000) -
                          DOUBLE_803df460) * FLOAT_803df470);
  *param_1 = (float)(dVar8 * dVar4) - (float)((double)(float)(dVar7 * dVar5) * dVar9);
  param_1[1] = (float)((double)(float)(dVar7 * dVar4) * dVar9) + (float)(dVar8 * dVar5);
  param_1[2] = -(float)(dVar9 * dVar6);
  fVar1 = FLOAT_803df440;
  param_1[3] = FLOAT_803df440;
  param_1[4] = -(float)(dVar6 * dVar5);
  param_1[5] = (float)(dVar6 * dVar4);
  param_1[6] = (float)dVar7;
  param_1[7] = fVar1;
  param_1[8] = (float)((double)(float)(dVar7 * dVar5) * dVar8) + (float)(dVar9 * dVar4);
  param_1[9] = (float)(dVar9 * dVar5) - (float)((double)(float)(dVar7 * dVar4) * dVar8);
  param_1[10] = (float)(dVar8 * dVar6);
  param_1[0xb] = fVar1;
  fVar1 = *(float *)(param_2 + 0xc);
  fVar2 = *(float *)(param_2 + 0x10);
  fVar3 = *(float *)(param_2 + 0x14);
  param_1[0xc] = param_1[4] * fVar2 + *param_1 * fVar1 + param_1[8] * fVar3;
  param_1[0xd] = param_1[5] * fVar2 + param_1[1] * fVar1 + param_1[9] * fVar3;
  param_1[0xe] = param_1[6] * fVar2 + param_1[2] * fVar1 + param_1[10] * fVar3;
  param_1[0xf] = FLOAT_803df444;
  return;
}

