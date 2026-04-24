// Function: FUN_80247778
// Entry: 80247778
// Size: 28 bytes

/* WARNING: Removing unreachable block (ram,0x8024777c) */
/* WARNING: Removing unreachable block (ram,0x80247778) */
/* WARNING: Removing unreachable block (ram,0x8024778c) */

void FUN_80247778(undefined8 param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  
  fVar3 = (float)((ulonglong)param_1 >> 0x20);
  fVar1 = (float)__psq_l0(param_2,0);
  fVar2 = (float)__psq_l1(param_2,0);
  fVar4 = (float)__psq_l0(param_2 + 8,0);
  __psq_st0(param_3,fVar1 * fVar3,0);
  __psq_st1(param_3,fVar2 * fVar3,0);
  __psq_st0(param_3 + 8,fVar4 * fVar3,0);
  return;
}

