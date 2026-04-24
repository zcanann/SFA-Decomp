// Function: FUN_802471e0
// Entry: 802471e0
// Size: 260 bytes

/* WARNING: Removing unreachable block (ram,0x8024724c) */

double FUN_802471e0(undefined8 param_1,int param_2,undefined4 param_3)

{
  undefined4 uVar1;
  float fVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  undefined4 uVar13;
  float fVar14;
  float fVar15;
  undefined auStack68 [8];
  float local_3c;
  
  uVar1 = 0;
  uVar13 = SUB84((double)FLOAT_803e761c,0);
  dVar3 = (double)FUN_802949e4(param_1);
  dVar4 = (double)FUN_80294850(param_1);
  fVar14 = (float)((ulonglong)(double)(float)((double)FLOAT_803e7618 - dVar4) >> 0x20);
  FUN_80247794(param_3,auStack68);
  fVar9 = (float)__psq_l0(auStack68,uVar1);
  fVar11 = (float)__psq_l1(auStack68,uVar1);
  dVar5 = (double)local_3c;
  fVar15 = (float)((ulonglong)dVar4 >> 0x20);
  fVar7 = fVar9 * fVar14;
  fVar2 = (float)((ulonglong)dVar5 >> 0x20);
  fVar6 = fVar11 * fVar14 * fVar11;
  fVar12 = (float)((ulonglong)dVar3 >> 0x20);
  fVar10 = fVar9 * fVar12;
  fVar12 = fVar11 * fVar12;
  fVar8 = fVar11 * fVar14 * fVar2;
  __psq_st0(param_2 + 8,fVar7 * fVar2 + fVar12,uVar1);
  __psq_st1(param_2 + 8,uVar13,uVar1);
  __psq_st0(param_2,fVar7 * fVar9 + fVar15,uVar1);
  __psq_st1(param_2,SUB84(-(double)(float)(dVar5 * dVar3 - (double)CONCAT44(fVar7 * fVar11,fVar6)),0
                         ),uVar1);
  __psq_st0(param_2 + 0x10,
            (int)((ulonglong)(double)(float)(dVar5 * dVar3 + (double)CONCAT44(fVar7 * fVar11,fVar6))
                 >> 0x20),uVar1);
  __psq_st1(param_2 + 0x10,fVar15 + fVar6,uVar1);
  __psq_st0(param_2 + 0x18,-fVar10 + fVar8,uVar1);
  __psq_st1(param_2 + 0x18,uVar13,uVar1);
  __psq_st0(param_2 + 0x20,fVar7 * fVar2 + -fVar12,uVar1);
  __psq_st1(param_2 + 0x20,fVar10 + fVar8,uVar1);
  __psq_st0(param_2 + 0x28,fVar2 * fVar14 * fVar2 + fVar15,uVar1);
  __psq_st1(param_2 + 0x28,uVar13,uVar1);
  return dVar5;
}

