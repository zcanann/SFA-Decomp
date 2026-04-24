// Function: FUN_80246e54
// Entry: 80246e54
// Size: 44 bytes

undefined8 FUN_80246e54(int param_1)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
  uVar1 = (undefined4)((ulonglong)(double)FLOAT_803e761c >> 0x20);
  __psq_st0(param_1 + 8,uVar1,0);
  uVar2 = SUB84((double)FLOAT_803e761c,0);
  __psq_st1(param_1 + 8,uVar2,0);
  uVar3 = SUB84((double)FLOAT_803e7618,0);
  __psq_st0(param_1 + 0x18,uVar1,0);
  __psq_st1(param_1 + 0x18,uVar2,0);
  __psq_st0(param_1 + 0x20,uVar1,0);
  __psq_st1(param_1 + 0x20,uVar2,0);
  __psq_st0(param_1 + 0x10,uVar1,0);
  __psq_st1(param_1 + 0x10,uVar3,0);
  __psq_st0(param_1,uVar3,0);
  __psq_st1(param_1,uVar1,0);
  __psq_st0(param_1 + 0x28,uVar3,0);
  __psq_st1(param_1 + 0x28,uVar1,0);
  return CONCAT44(uVar3,uVar1);
}

