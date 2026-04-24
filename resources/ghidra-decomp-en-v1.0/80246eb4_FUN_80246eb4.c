// Function: FUN_80246eb4
// Entry: 80246eb4
// Size: 204 bytes

/* WARNING: Removing unreachable block (ram,0x80246f18) */
/* WARNING: Removing unreachable block (ram,0x80246f08) */
/* WARNING: Removing unreachable block (ram,0x80246ef8) */
/* WARNING: Removing unreachable block (ram,0x80246ee8) */
/* WARNING: Removing unreachable block (ram,0x80246ed8) */
/* WARNING: Removing unreachable block (ram,0x80246ec0) */
/* WARNING: Removing unreachable block (ram,0x80246eb8) */
/* WARNING: Removing unreachable block (ram,0x80246ec8) */
/* WARNING: Removing unreachable block (ram,0x80246ee0) */
/* WARNING: Removing unreachable block (ram,0x80246ef0) */
/* WARNING: Removing unreachable block (ram,0x80246f00) */
/* WARNING: Removing unreachable block (ram,0x80246f10) */
/* WARNING: Removing unreachable block (ram,0x80246f1c) */

undefined8 FUN_80246eb4(int param_1,int param_2,int param_3)

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
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  float fVar18;
  float fVar19;
  float fVar20;
  float fVar21;
  float fVar22;
  float fVar23;
  float fVar24;
  float fVar25;
  float fVar26;
  
  fVar1 = (float)__psq_l0(param_1,0);
  fVar2 = (float)__psq_l1(param_1,0);
  fVar13 = (float)__psq_l0(param_2,0);
  fVar14 = (float)__psq_l1(param_2,0);
  fVar15 = (float)__psq_l0(param_2 + 8,0);
  fVar16 = (float)__psq_l1(param_2 + 8,0);
  fVar17 = (float)__psq_l0(param_2 + 0x10,0);
  fVar18 = (float)__psq_l1(param_2 + 0x10,0);
  fVar5 = (float)__psq_l0(param_1 + 0x10,0);
  fVar6 = (float)__psq_l1(param_1 + 0x10,0);
  fVar25 = (float)__psq_l0(0x803dc550,0);
  fVar26 = (float)__psq_l1(0x803dc550,0);
  fVar19 = (float)__psq_l0(param_2 + 0x18,0);
  fVar20 = (float)__psq_l1(param_2 + 0x18,0);
  fVar3 = (float)__psq_l0(param_1 + 8,0);
  fVar4 = (float)__psq_l1(param_1 + 8,0);
  fVar7 = (float)__psq_l0(param_1 + 0x18,0);
  fVar8 = (float)__psq_l1(param_1 + 0x18,0);
  fVar21 = (float)__psq_l0(param_2 + 0x20,0);
  fVar22 = (float)__psq_l1(param_2 + 0x20,0);
  fVar23 = (float)__psq_l0(param_2 + 0x28,0);
  fVar24 = (float)__psq_l1(param_2 + 0x28,0);
  fVar9 = (float)__psq_l0(param_1 + 0x20,0);
  fVar10 = (float)__psq_l1(param_1 + 0x20,0);
  fVar11 = (float)__psq_l0(param_1 + 0x28,0);
  fVar12 = (float)__psq_l1(param_1 + 0x28,0);
  __psq_st0(param_3,fVar21 * fVar3 + fVar17 * fVar2 + fVar13 * fVar1,0);
  __psq_st1(param_3,fVar22 * fVar3 + fVar18 * fVar2 + fVar14 * fVar1,0);
  __psq_st0(param_3 + 0x10,fVar21 * fVar7 + fVar17 * fVar6 + fVar13 * fVar5,0);
  __psq_st1(param_3 + 0x10,fVar22 * fVar7 + fVar18 * fVar6 + fVar14 * fVar5,0);
  __psq_st0(param_3 + 8,fVar25 * fVar4 + fVar23 * fVar3 + fVar19 * fVar2 + fVar15 * fVar1,0);
  __psq_st1(param_3 + 8,fVar26 * fVar4 + fVar24 * fVar3 + fVar20 * fVar2 + fVar16 * fVar1,0);
  __psq_st0(param_3 + 0x18,fVar25 * fVar8 + fVar23 * fVar7 + fVar19 * fVar6 + fVar15 * fVar5,0);
  __psq_st1(param_3 + 0x18,fVar26 * fVar8 + fVar24 * fVar7 + fVar20 * fVar6 + fVar16 * fVar5,0);
  __psq_st0(param_3 + 0x20,fVar21 * fVar11 + fVar17 * fVar10 + fVar13 * fVar9,0);
  __psq_st1(param_3 + 0x20,fVar22 * fVar11 + fVar18 * fVar10 + fVar14 * fVar9,0);
  __psq_st0(param_3 + 0x28,fVar25 * fVar12 + fVar23 * fVar11 + fVar19 * fVar10 + fVar15 * fVar9,0);
  __psq_st1(param_3 + 0x28,fVar26 * fVar12 + fVar24 * fVar11 + fVar20 * fVar10 + fVar16 * fVar9,0);
  return CONCAT44(fVar3,fVar4);
}

