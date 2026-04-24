// Function: FUN_801132f4
// Entry: 801132f4
// Size: 164 bytes

/* WARNING: Removing unreachable block (ram,0x80113378) */

void FUN_801132f4(double param_1,int param_2,uint *param_3,char param_4)

{
  float fVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  *param_3 = *param_3 | 0x8000;
  *(undefined2 *)(param_3 + 0xcc) = 0;
  if (*(int *)(param_2 + 0x54) != 0) {
    FUN_80035df4(param_2,0,0,0xffffffff);
  }
  if (param_4 != -1) {
    *(char *)((int)param_3 + 0x25f) = param_4;
  }
  param_3[0xa9] = (uint)(float)param_1;
  fVar1 = FLOAT_803e1c2c;
  param_3[0xa4] = (uint)FLOAT_803e1c2c;
  param_3[0xa3] = (uint)fVar1;
  param_3[199] = 0;
  param_3[0xc6] = 0;
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return;
}

