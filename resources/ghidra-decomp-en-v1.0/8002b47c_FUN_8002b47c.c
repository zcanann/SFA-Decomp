// Function: FUN_8002b47c
// Entry: 8002b47c
// Size: 268 bytes

/* WARNING: Removing unreachable block (ram,0x8002b564) */

void FUN_8002b47c(int param_1,undefined4 param_2,char param_3)

{
  undefined4 uVar1;
  double in_f31;
  undefined auStack104 [76];
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  if (*(int *)(param_1 + 0x30) == 0) {
    *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) - FLOAT_803dcdd8;
    *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) - FLOAT_803dcddc;
  }
  if ((param_3 != '\0') &&
     (in_f31 = (double)*(float *)(param_1 + 8), (*(ushort *)(param_1 + 0xb0) & 8) == 0)) {
    *(float *)(param_1 + 8) = FLOAT_803de890;
  }
  FUN_80021570(param_1,param_2);
  if (param_3 != '\0') {
    *(float *)(param_1 + 8) = (float)in_f31;
  }
  if (*(int *)(param_1 + 0x30) == 0) {
    *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + FLOAT_803dcdd8;
    *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) + FLOAT_803dcddc;
  }
  else {
    FUN_8002b47c(*(int *)(param_1 + 0x30),auStack104,1);
    FUN_80246eb4(auStack104,param_2,param_2);
  }
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  return;
}

