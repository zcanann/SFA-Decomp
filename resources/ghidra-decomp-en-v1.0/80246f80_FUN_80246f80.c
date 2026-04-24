// Function: FUN_80246f80
// Entry: 80246f80
// Size: 80 bytes

/* WARNING: Removing unreachable block (ram,0x80246f9c) */
/* WARNING: Removing unreachable block (ram,0x80246f94) */
/* WARNING: Removing unreachable block (ram,0x80246f84) */
/* WARNING: Removing unreachable block (ram,0x80246f8c) */
/* WARNING: Removing unreachable block (ram,0x80246fa4) */

undefined8 FUN_80246f80(int param_1,int param_2)

{
  double dVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  
  dVar1 = (double)FLOAT_803e761c;
  uVar2 = __psq_l0(param_1,0);
  uVar3 = __psq_l1(param_1,0);
  *(float *)(param_2 + 0x2c) = FLOAT_803e761c;
  uVar5 = __psq_l0(param_1 + 0x10,0);
  uVar6 = __psq_l1(param_1 + 0x10,0);
  uVar7 = __psq_l0(param_1 + 8,0);
  __psq_l0(param_1 + 0x18,0);
  __psq_st0(param_2,uVar2,0);
  __psq_st1(param_2,uVar5,0);
  uVar5 = __psq_l0(param_1 + 0x20,0);
  uVar4 = __psq_l1(param_1 + 0x20,0);
  __psq_st0(param_2 + 0x10,uVar3,0);
  __psq_st1(param_2 + 0x10,uVar6,0);
  uVar2 = (undefined4)((ulonglong)dVar1 >> 0x20);
  __psq_st0(param_2 + 0x20,uVar7,0);
  __psq_st1(param_2 + 0x20,uVar7,0);
  __psq_st0(param_2 + 8,uVar5,0);
  __psq_st1(param_2 + 8,uVar2,0);
  __psq_st0(param_2 + 0x18,uVar4,0);
  __psq_st1(param_2 + 0x18,uVar2,0);
  *(undefined4 *)(param_2 + 0x28) = *(undefined4 *)(param_1 + 0x28);
  return CONCAT44(uVar5,uVar4);
}

