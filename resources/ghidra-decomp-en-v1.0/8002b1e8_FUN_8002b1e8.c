// Function: FUN_8002b1e8
// Entry: 8002b1e8
// Size: 196 bytes

/* WARNING: Removing unreachable block (ram,0x8002b284) */

void FUN_8002b1e8(int param_1,undefined4 param_2,float *param_3,char param_4)

{
  undefined4 uVar1;
  double in_f31;
  undefined auStack104 [72];
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  if (param_4 != '\0') {
    in_f31 = (double)*(float *)(param_1 + 8);
    *(float *)(param_1 + 8) = FLOAT_803de890;
  }
  FUN_8002b47c(param_1,auStack104,0);
  FUN_80247494(auStack104,param_2,param_3);
  if (param_4 != '\0') {
    *(float *)(param_1 + 8) = (float)in_f31;
  }
  *param_3 = *param_3 + FLOAT_803dcdd8;
  param_3[2] = param_3[2] + FLOAT_803dcddc;
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  return;
}

