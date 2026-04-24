// Function: FUN_801bab88
// Entry: 801bab88
// Size: 304 bytes

/* WARNING: Removing unreachable block (ram,0x801bac98) */

undefined4 FUN_801bab88(undefined8 param_1,int param_2,int param_3)

{
  float fVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (*(char *)(param_3 + 0x27a) != '\0') {
    *(float *)(param_3 + 0x2a0) = FLOAT_803e4c08;
    if (*(char *)(param_3 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e4bd8,param_2,0x12,0);
      *(undefined *)(param_3 + 0x346) = 0;
    }
    *(undefined2 *)(param_2 + 0xa2) = 0xffff;
    fVar1 = FLOAT_803e4bd8;
    *(float *)(param_3 + 0x280) = FLOAT_803e4bd8;
    *(float *)(param_3 + 0x284) = fVar1;
  }
  if ((FLOAT_803e4c0c < *(float *)(param_2 + 0x98)) || (*(char *)(param_3 + 0x346) != '\0')) {
    uVar2 = 8;
  }
  else {
    if (FLOAT_803e4c10 < *(float *)(param_2 + 0x98)) {
      DAT_803ddb80 = DAT_803ddb80 | 0x10;
    }
    (**(code **)(*DAT_803dca8c + 0x34))(param_2,param_3,0,5,&DAT_80325aa0);
    (**(code **)(*DAT_803dca8c + 0x30))(param_1,param_2,param_3,0xf0);
    uVar2 = 0;
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return uVar2;
}

