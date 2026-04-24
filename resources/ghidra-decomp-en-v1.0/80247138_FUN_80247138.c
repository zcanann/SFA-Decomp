// Function: FUN_80247138
// Entry: 80247138
// Size: 168 bytes

/* WARNING: Removing unreachable block (ram,0x80247164) */
/* WARNING: Removing unreachable block (ram,0x8024717c) */

void FUN_80247138(undefined8 param_1,undefined8 param_2,int param_3,uint param_4)

{
  undefined4 uVar1;
  undefined4 uVar2;
  float fVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  
  uVar4 = (undefined4)((ulonglong)param_2 >> 0x20);
  fVar3 = (float)((ulonglong)param_1 >> 0x20);
  param_4 = param_4 | 0x20;
  uVar5 = (undefined4)((ulonglong)(double)FLOAT_803e7618 >> 0x20);
  uVar2 = SUB84((double)FLOAT_803e761c,0);
  uVar1 = (undefined4)((ulonglong)(double)FLOAT_803e761c >> 0x20);
  if (param_4 == 0x78) {
    __psq_st0(param_3,uVar5,0);
    __psq_st0(param_3 + 4,uVar1,0);
    __psq_st1(param_3 + 4,uVar2,0);
    __psq_st0(param_3 + 0xc,uVar1,0);
    __psq_st1(param_3 + 0xc,uVar2,0);
    __psq_st0(param_3 + 0x1c,uVar1,0);
    __psq_st1(param_3 + 0x1c,uVar2,0);
    __psq_st0(param_3 + 0x2c,uVar1,0);
    __psq_st0(param_3 + 0x24,fVar3,0);
    __psq_st1(param_3 + 0x24,uVar4,0);
    __psq_st0(param_3 + 0x14,uVar4,0);
    __psq_st1(param_3 + 0x14,-fVar3,0);
  }
  else if (param_4 == 0x79) {
    __psq_st0(param_3 + 0x18,uVar1,0);
    __psq_st1(param_3 + 0x18,uVar2,0);
    __psq_st0(param_3,uVar4,0);
    __psq_st1(param_3,uVar1,0);
    __psq_st0(param_3 + 0x28,uVar4,0);
    __psq_st1(param_3 + 0x28,uVar1,0);
    __psq_st0(param_3 + 0x10,uVar1,0);
    __psq_st1(param_3 + 0x10,uVar5,0);
    __psq_st0(param_3 + 8,fVar3,0);
    __psq_st1(param_3 + 8,fVar3,0);
    __psq_st0(param_3 + 0x20,-fVar3,0);
    __psq_st1(param_3 + 0x20,uVar1,0);
  }
  else if (param_4 == 0x7a) {
    __psq_st0(param_3 + 8,uVar1,0);
    __psq_st1(param_3 + 8,uVar2,0);
    __psq_st0(param_3 + 0x18,uVar1,0);
    __psq_st1(param_3 + 0x18,uVar2,0);
    __psq_st0(param_3 + 0x20,uVar1,0);
    __psq_st1(param_3 + 0x20,uVar2,0);
    __psq_st0(param_3 + 0x10,fVar3,0);
    __psq_st1(param_3 + 0x10,uVar4,0);
    __psq_st0(param_3,uVar4,0);
    __psq_st1(param_3,uVar4,0);
    __psq_st0(param_3 + 0x28,uVar5,0);
    __psq_st1(param_3 + 0x28,uVar1,0);
  }
  return;
}

