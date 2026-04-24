// Function: FUN_802479d0
// Entry: 802479d0
// Size: 76 bytes

/* WARNING: Removing unreachable block (ram,0x802479e4) */
/* WARNING: Removing unreachable block (ram,0x802479d8) */
/* WARNING: Removing unreachable block (ram,0x802479d0) */
/* WARNING: Removing unreachable block (ram,0x802479d4) */
/* WARNING: Removing unreachable block (ram,0x802479dc) */
/* WARNING: Removing unreachable block (ram,0x802479ec) */

undefined8 FUN_802479d0(int param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined4 uVar11;
  undefined4 uVar12;
  
  uVar1 = __psq_l0(param_1,0);
  uVar2 = __psq_l1(param_1,0);
  uVar5 = __psq_l0(param_1 + 0x10,0);
  uVar6 = __psq_l1(param_1 + 0x10,0);
  uVar9 = __psq_l0(param_1 + 0x20,0);
  uVar10 = __psq_l1(param_1 + 0x20,0);
  uVar3 = __psq_l0(param_1 + 8,0);
  uVar4 = __psq_l1(param_1 + 8,0);
  uVar7 = __psq_l0(param_1 + 0x18,0);
  uVar8 = __psq_l1(param_1 + 0x18,0);
  uVar11 = __psq_l0(param_1 + 0x28,0);
  uVar12 = __psq_l1(param_1 + 0x28,0);
  __psq_st0(param_2,uVar1,0);
  __psq_st1(param_2,uVar5,0);
  __psq_st0(param_2 + 8,uVar9,0);
  __psq_st1(param_2 + 8,uVar2,0);
  __psq_st0(param_2 + 0x10,uVar6,0);
  __psq_st1(param_2 + 0x10,uVar10,0);
  __psq_st0(param_2 + 0x18,uVar3,0);
  __psq_st1(param_2 + 0x18,uVar7,0);
  __psq_st0(param_2 + 0x20,uVar11,0);
  __psq_st1(param_2 + 0x20,uVar4,0);
  __psq_st0(param_2 + 0x28,uVar8,0);
  __psq_st1(param_2 + 0x28,uVar12,0);
  return CONCAT44(uVar3,uVar4);
}

