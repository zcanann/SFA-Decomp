// Function: FUN_8025d084
// Entry: 8025d084
// Size: 36 bytes

/* WARNING: Removing unreachable block (ram,0x8025d08c) */
/* WARNING: Removing unreachable block (ram,0x8025d084) */
/* WARNING: Removing unreachable block (ram,0x8025d088) */
/* WARNING: Removing unreachable block (ram,0x8025d090) */

undefined8 FUN_8025d084(int param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  
  uVar1 = __psq_l0(param_1,0);
  uVar2 = __psq_l1(param_1,0);
  uVar3 = __psq_l0(param_1 + 8,0);
  uVar4 = __psq_l1(param_1 + 8,0);
  uVar5 = __psq_l0(param_1 + 0x10,0);
  uVar6 = __psq_l1(param_1 + 0x10,0);
  uVar7 = __psq_l0(param_1 + 0x18,0);
  uVar8 = __psq_l1(param_1 + 0x18,0);
  __psq_st0(param_2,uVar1,0);
  __psq_st1(param_2,uVar2,0);
  __psq_st0(param_2,uVar3,0);
  __psq_st1(param_2,uVar4,0);
  __psq_st0(param_2,uVar5,0);
  __psq_st1(param_2,uVar6,0);
  __psq_st0(param_2,uVar7,0);
  __psq_st1(param_2,uVar8,0);
  return CONCAT44(uVar3,uVar4);
}

