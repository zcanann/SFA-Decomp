// Function: FUN_80247730
// Entry: 80247730
// Size: 36 bytes

/* WARNING: Removing unreachable block (ram,0x80247744) */
/* WARNING: Removing unreachable block (ram,0x80247734) */
/* WARNING: Removing unreachable block (ram,0x80247730) */
/* WARNING: Removing unreachable block (ram,0x80247740) */
/* WARNING: Removing unreachable block (ram,0x8024774c) */

void FUN_80247730(int param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  
  fVar1 = (float)__psq_l0(param_1,0);
  fVar2 = (float)__psq_l1(param_1,0);
  fVar3 = (float)__psq_l0(param_2,0);
  fVar4 = (float)__psq_l1(param_2,0);
  __psq_st0(param_3,fVar1 + fVar3,0);
  __psq_st1(param_3,fVar2 + fVar4,0);
  fVar1 = (float)__psq_l0(param_1 + 8,0);
  fVar2 = (float)__psq_l0(param_2 + 8,0);
  __psq_st0(param_3 + 8,fVar1 + fVar2,0);
  return;
}

