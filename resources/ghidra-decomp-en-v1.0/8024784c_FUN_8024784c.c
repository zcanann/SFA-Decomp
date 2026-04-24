// Function: FUN_8024784c
// Entry: 8024784c
// Size: 60 bytes

/* WARNING: Removing unreachable block (ram,0x8024784c) */
/* WARNING: Removing unreachable block (ram,0x80247854) */
/* WARNING: Removing unreachable block (ram,0x80247878) */

undefined8 FUN_8024784c(int param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  
  fVar3 = (float)__psq_l0(param_2,0);
  fVar4 = (float)__psq_l1(param_2,0);
  fVar1 = (float)__psq_l0(param_1,0);
  fVar2 = (float)__psq_l1(param_1,0);
  __psq_st0(param_3,fVar2 * SUB84((double)*(float *)(param_2 + 8),0) -
                    fVar4 * SUB84((double)*(float *)(param_1 + 8),0),0);
  __psq_st0(param_3 + 4,
            -(fVar1 * (float)((ulonglong)(double)*(float *)(param_2 + 8) >> 0x20) -
             fVar3 * (float)((ulonglong)(double)*(float *)(param_1 + 8) >> 0x20)),0);
  __psq_st1(param_3 + 4,-(fVar2 * fVar3 - fVar4 * fVar1),0);
  return CONCAT44(fVar3,fVar4);
}

