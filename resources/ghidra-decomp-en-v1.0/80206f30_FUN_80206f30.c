// Function: FUN_80206f30
// Entry: 80206f30
// Size: 604 bytes

/* WARNING: Removing unreachable block (ram,0x80207168) */

void FUN_80206f30(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  short *psVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  psVar7 = *(short **)(param_1 + 0xb8);
  iVar4 = FUN_8002b9ec();
  iVar5 = 0;
  fVar1 = *(float *)(iVar4 + 0xc) - *(float *)(param_1 + 0xc);
  fVar2 = *(float *)(iVar4 + 0x10) - *(float *)(param_1 + 0x10);
  fVar3 = *(float *)(iVar4 + 0x14) - *(float *)(param_1 + 0x14);
  if ((fVar1 <= FLOAT_803e6438) &&
     (-(float)((double)CONCAT44(0x43300000,(int)*psVar7 ^ 0x80000000) - DOUBLE_803e6440) < fVar1)) {
    iVar5 = 1;
  }
  if ((FLOAT_803e6438 < fVar1) &&
     (fVar1 < (float)((double)CONCAT44(0x43300000,(int)*psVar7 ^ 0x80000000) - DOUBLE_803e6440))) {
    iVar5 = iVar5 + 1;
  }
  if ((fVar3 <= FLOAT_803e6438) &&
     (-(float)((double)CONCAT44(0x43300000,(int)psVar7[1] ^ 0x80000000) - DOUBLE_803e6440) < fVar3))
  {
    iVar5 = iVar5 + 1;
  }
  if ((FLOAT_803e6438 < fVar3) &&
     (fVar3 < (float)((double)CONCAT44(0x43300000,(int)psVar7[1] ^ 0x80000000) - DOUBLE_803e6440)))
  {
    iVar5 = iVar5 + 1;
  }
  if ((fVar2 <= FLOAT_803e6438) &&
     (-(float)((double)CONCAT44(0x43300000,(int)psVar7[2] ^ 0x80000000) - DOUBLE_803e6440) < fVar2))
  {
    iVar5 = iVar5 + 1;
  }
  if ((FLOAT_803e6438 < fVar2) &&
     (fVar2 < (float)((double)CONCAT44(0x43300000,(int)psVar7[2] ^ 0x80000000) - DOUBLE_803e6440)))
  {
    iVar5 = iVar5 + 1;
  }
  if (iVar5 == 3) {
    uVar6 = FUN_800221a0(0xffffffe9,0x17);
    dVar9 = (double)(float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e6440);
    dVar10 = (double)(float)((double)FLOAT_803e644c * dVar9);
    uVar6 = FUN_800221a0(dVar9,0xffffffe9,0x17);
    FUN_802960e4(dVar10,(double)(FLOAT_803e644c *
                                (float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) -
                                       DOUBLE_803e6440)),iVar4);
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  return;
}

