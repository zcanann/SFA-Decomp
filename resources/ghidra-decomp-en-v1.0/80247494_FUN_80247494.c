// Function: FUN_80247494
// Entry: 80247494
// Size: 84 bytes

/* WARNING: Removing unreachable block (ram,0x802474d4) */
/* WARNING: Removing unreachable block (ram,0x802474c4) */
/* WARNING: Removing unreachable block (ram,0x802474b4) */
/* WARNING: Removing unreachable block (ram,0x802474a4) */
/* WARNING: Removing unreachable block (ram,0x80247498) */
/* WARNING: Removing unreachable block (ram,0x80247494) */
/* WARNING: Removing unreachable block (ram,0x8024749c) */
/* WARNING: Removing unreachable block (ram,0x802474ac) */
/* WARNING: Removing unreachable block (ram,0x802474bc) */
/* WARNING: Removing unreachable block (ram,0x802474cc) */
/* WARNING: Removing unreachable block (ram,0x802474e0) */

undefined8 FUN_80247494(int param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  
  fVar1 = (float)__psq_l0(param_2,0);
  fVar2 = (float)__psq_l1(param_2,0);
  fVar4 = (float)__psq_l0(param_1,0);
  fVar5 = (float)__psq_l1(param_1,0);
  fVar3 = (float)__psq_l0(param_2 + 8,0);
  fVar6 = (float)__psq_l0(param_1 + 8,0);
  fVar7 = (float)__psq_l1(param_1 + 8,0);
  fVar8 = (float)__psq_l0(param_1 + 0x10,0);
  fVar9 = (float)__psq_l1(param_1 + 0x10,0);
  fVar10 = (float)__psq_l0(param_1 + 0x18,0);
  fVar11 = (float)__psq_l1(param_1 + 0x18,0);
  __psq_st0(param_3,fVar6 * fVar3 + fVar4 * fVar1 + fVar7 * 1.0 + fVar5 * fVar2,0);
  fVar4 = (float)__psq_l0(param_1 + 0x20,0);
  fVar5 = (float)__psq_l1(param_1 + 0x20,0);
  fVar6 = (float)__psq_l0(param_1 + 0x28,0);
  fVar7 = (float)__psq_l1(param_1 + 0x28,0);
  __psq_st0(param_3 + 4,fVar10 * fVar3 + fVar8 * fVar1 + fVar11 * 1.0 + fVar9 * fVar2,0);
  __psq_st0(param_3 + 8,fVar6 * fVar3 + fVar4 * fVar1 + fVar7 * 1.0 + fVar5 * fVar2,0);
  return CONCAT44(fVar3,0x3f800000);
}

