// Function: FUN_80207568
// Entry: 80207568
// Size: 604 bytes

/* WARNING: Removing unreachable block (ram,0x802077a0) */
/* WARNING: Removing unreachable block (ram,0x80207578) */

void FUN_80207568(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  
  psVar6 = *(short **)(param_1 + 0xb8);
  iVar4 = FUN_8002bac4();
  iVar5 = 0;
  fVar1 = *(float *)(iVar4 + 0xc) - *(float *)(param_1 + 0xc);
  fVar2 = *(float *)(iVar4 + 0x10) - *(float *)(param_1 + 0x10);
  fVar3 = *(float *)(iVar4 + 0x14) - *(float *)(param_1 + 0x14);
  if ((fVar1 <= FLOAT_803e70d0) &&
     (-(float)((double)CONCAT44(0x43300000,(int)*psVar6 ^ 0x80000000) - DOUBLE_803e70d8) < fVar1)) {
    iVar5 = 1;
  }
  if ((FLOAT_803e70d0 < fVar1) &&
     (fVar1 < (float)((double)CONCAT44(0x43300000,(int)*psVar6 ^ 0x80000000) - DOUBLE_803e70d8))) {
    iVar5 = iVar5 + 1;
  }
  if ((fVar3 <= FLOAT_803e70d0) &&
     (-(float)((double)CONCAT44(0x43300000,(int)psVar6[1] ^ 0x80000000) - DOUBLE_803e70d8) < fVar3))
  {
    iVar5 = iVar5 + 1;
  }
  if ((FLOAT_803e70d0 < fVar3) &&
     (fVar3 < (float)((double)CONCAT44(0x43300000,(int)psVar6[1] ^ 0x80000000) - DOUBLE_803e70d8)))
  {
    iVar5 = iVar5 + 1;
  }
  if ((fVar2 <= FLOAT_803e70d0) &&
     (-(float)((double)CONCAT44(0x43300000,(int)psVar6[2] ^ 0x80000000) - DOUBLE_803e70d8) < fVar2))
  {
    iVar5 = iVar5 + 1;
  }
  if ((FLOAT_803e70d0 < fVar2) &&
     (fVar2 < (float)((double)CONCAT44(0x43300000,(int)psVar6[2] ^ 0x80000000) - DOUBLE_803e70d8)))
  {
    iVar5 = iVar5 + 1;
  }
  if (iVar5 == 3) {
    FUN_80022264(0xffffffe9,0x17);
    FUN_80022264(0xffffffe9,0x17);
    FUN_80296844();
  }
  return;
}

