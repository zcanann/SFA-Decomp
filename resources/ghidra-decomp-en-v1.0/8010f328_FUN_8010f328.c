// Function: FUN_8010f328
// Entry: 8010f328
// Size: 456 bytes

/* WARNING: Removing unreachable block (ram,0x8010f4c4) */
/* WARNING: Removing unreachable block (ram,0x8010f4bc) */
/* WARNING: Removing unreachable block (ram,0x8010f4cc) */

void FUN_8010f328(short *param_1)

{
  float fVar1;
  short sVar2;
  short *psVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 in_f29;
  double dVar9;
  undefined8 in_f30;
  undefined8 in_f31;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  longlong local_58;
  undefined4 local_50;
  uint uStack76;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  local_68 = FLOAT_803e1a88;
  local_64 = FLOAT_803e1a8c;
  local_60 = FLOAT_803e1a88;
  local_5c = FLOAT_803e1a88;
  dVar5 = (double)FUN_80010dc0((double)*(float *)(DAT_803dd590 + 4),&local_68,0);
  psVar3 = *(short **)(param_1 + 0x52);
  local_58 = (longlong)(int)((double)FLOAT_803e1a90 * dVar5);
  sVar2 = (-0x8000 - *psVar3) + (short)(int)((double)FLOAT_803e1a90 * dVar5);
  uStack76 = (int)sVar2 ^ 0x80000000;
  local_50 = 0x43300000;
  dVar9 = (double)((FLOAT_803e1a94 *
                   (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e1ab8)) /
                  FLOAT_803e1a98);
  dVar6 = (double)FUN_80294204(dVar9);
  dVar9 = (double)FUN_80293e80(dVar9);
  dVar8 = (double)FLOAT_803e1a9c;
  dVar7 = (double)FLOAT_803e1aa0;
  *(float *)(param_1 + 6) =
       *(float *)(psVar3 + 0xc) + (float)(dVar8 * dVar6 - (double)(float)(dVar7 * dVar9));
  *(float *)(param_1 + 10) =
       *(float *)(psVar3 + 0x10) + (float)(dVar8 * dVar9 + (double)(float)(dVar7 * dVar6));
  fVar1 = FLOAT_803e1aa4;
  *(float *)(param_1 + 8) =
       -(float)((double)FLOAT_803e1aa8 * dVar5 - (double)(FLOAT_803e1aa4 + *(float *)(psVar3 + 0xe))
               );
  param_1[1] = 0x11c6 - (short)(int)(fVar1 * (float)((double)FLOAT_803e1aac * dVar5));
  *param_1 = sVar2 + 0x1ffe;
  param_1[2] = 0;
  *(undefined *)((int)param_1 + 0x13b) = 0;
  *(float *)(param_1 + 0x5a) = FLOAT_803e1ab0;
  *(float *)(DAT_803dd590 + 4) = FLOAT_803e1ab4 * FLOAT_803db414 + *(float *)(DAT_803dd590 + 4);
  if (FLOAT_803e1a8c < *(float *)(DAT_803dd590 + 4)) {
    *(float *)(DAT_803dd590 + 4) = FLOAT_803e1a8c;
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  return;
}

