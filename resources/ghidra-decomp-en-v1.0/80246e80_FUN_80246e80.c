// Function: FUN_80246e80
// Entry: 80246e80
// Size: 52 bytes

/* WARNING: Removing unreachable block (ram,0x80246e80) */
/* WARNING: Removing unreachable block (ram,0x80246e88) */
/* WARNING: Removing unreachable block (ram,0x80246e90) */
/* WARNING: Removing unreachable block (ram,0x80246e98) */
/* WARNING: Removing unreachable block (ram,0x80246ea0) */
/* WARNING: Removing unreachable block (ram,0x80246ea8) */

undefined8 FUN_80246e80(int param_1,int param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  
  uVar1 = __psq_l0(param_1,0);
  uVar2 = __psq_l1(param_1,0);
  __psq_st0(param_2,uVar1,0);
  __psq_st1(param_2,uVar2,0);
  uVar1 = __psq_l0(param_1 + 8,0);
  uVar2 = __psq_l1(param_1 + 8,0);
  __psq_st0(param_2 + 8,uVar1,0);
  __psq_st1(param_2 + 8,uVar2,0);
  uVar3 = __psq_l0(param_1 + 0x10,0);
  uVar4 = __psq_l1(param_1 + 0x10,0);
  __psq_st0(param_2 + 0x10,uVar3,0);
  __psq_st1(param_2 + 0x10,uVar4,0);
  uVar3 = __psq_l0(param_1 + 0x18,0);
  uVar4 = __psq_l1(param_1 + 0x18,0);
  __psq_st0(param_2 + 0x18,uVar3,0);
  __psq_st1(param_2 + 0x18,uVar4,0);
  uVar3 = __psq_l0(param_1 + 0x20,0);
  uVar4 = __psq_l1(param_1 + 0x20,0);
  __psq_st0(param_2 + 0x20,uVar3,0);
  __psq_st1(param_2 + 0x20,uVar4,0);
  uVar3 = __psq_l0(param_1 + 0x28,0);
  uVar4 = __psq_l1(param_1 + 0x28,0);
  __psq_st0(param_2 + 0x28,uVar3,0);
  __psq_st1(param_2 + 0x28,uVar4,0);
  return CONCAT44(uVar1,uVar2);
}

