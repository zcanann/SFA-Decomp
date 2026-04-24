// Function: FUN_8024782c
// Entry: 8024782c
// Size: 32 bytes

/* WARNING: Removing unreachable block (ram,0x80247838) */
/* WARNING: Removing unreachable block (ram,0x8024782c) */
/* WARNING: Removing unreachable block (ram,0x80247830) */
/* WARNING: Removing unreachable block (ram,0x8024783c) */

undefined8 FUN_8024782c(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  
  fVar1 = (float)__psq_l0(param_1 + 4,0);
  fVar2 = (float)__psq_l1(param_1 + 4,0);
  fVar3 = (float)__psq_l0(param_2 + 4,0);
  fVar4 = (float)__psq_l1(param_2 + 4,0);
  fVar6 = (float)__psq_l0(param_1,0);
  __psq_l1(param_1,0);
  fVar5 = (float)__psq_l0(param_2,0);
  __psq_l1(param_2,0);
  return CONCAT44(fVar6 * fVar5 + fVar1 * fVar3 + fVar2 * fVar4,fVar2 * fVar4);
}

