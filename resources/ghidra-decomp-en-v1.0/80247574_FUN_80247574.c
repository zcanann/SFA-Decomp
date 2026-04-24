// Function: FUN_80247574
// Entry: 80247574
// Size: 84 bytes

/* WARNING: Removing unreachable block (ram,0x802475b8) */
/* WARNING: Removing unreachable block (ram,0x802475a4) */
/* WARNING: Removing unreachable block (ram,0x80247594) */
/* WARNING: Removing unreachable block (ram,0x80247584) */
/* WARNING: Removing unreachable block (ram,0x80247578) */
/* WARNING: Removing unreachable block (ram,0x80247574) */
/* WARNING: Removing unreachable block (ram,0x8024757c) */
/* WARNING: Removing unreachable block (ram,0x8024758c) */
/* WARNING: Removing unreachable block (ram,0x8024759c) */
/* WARNING: Removing unreachable block (ram,0x802475b0) */
/* WARNING: Removing unreachable block (ram,0x802475c0) */

undefined8 FUN_80247574(int param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  
  fVar1 = (float)__psq_l0(param_1,0);
  fVar2 = (float)__psq_l1(param_1,0);
  fVar11 = (float)__psq_l0(param_2,0);
  fVar12 = (float)__psq_l1(param_2,0);
  fVar5 = (float)__psq_l0(param_1 + 0x10,0);
  fVar6 = (float)__psq_l1(param_1 + 0x10,0);
  fVar8 = (float)__psq_l0(param_1 + 0x20,0);
  fVar9 = (float)__psq_l1(param_1 + 0x20,0);
  fVar13 = (float)__psq_l0(param_2 + 8,0);
  fVar7 = (float)__psq_l0(param_1 + 0x18,0);
  __psq_l1(param_1 + 0x18,0);
  fVar10 = (float)__psq_l0(param_1 + 0x28,0);
  __psq_l1(param_1 + 0x28,0);
  fVar3 = (float)__psq_l0(param_1 + 8,0);
  uVar4 = __psq_l1(param_1 + 8,0);
  __psq_st0(param_3,fVar3 * fVar13 + fVar1 * fVar11 + fVar2 * fVar12,0);
  __psq_st0(param_3 + 4,fVar7 * fVar13 + fVar5 * fVar11 + fVar6 * fVar12,0);
  __psq_st0(param_3 + 8,fVar10 * fVar13 + fVar8 * fVar11 + fVar9 * fVar12,0);
  return CONCAT44(fVar3,uVar4);
}

