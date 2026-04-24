// Function: FUN_800d82a8
// Entry: 800d82a8
// Size: 364 bytes

/* WARNING: Removing unreachable block (ram,0x800d83f4) */

void FUN_800d82a8(double param_1,undefined2 *param_2,uint *param_3)

{
  undefined4 uVar1;
  undefined8 in_f31;
  undefined4 local_88;
  undefined4 local_84;
  undefined auStack128 [4];
  undefined2 local_7c;
  undefined2 local_7a;
  undefined2 local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  undefined auStack100 [76];
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if ((*param_3 & 0x2000000) == 0) {
    if ((*param_3 & 0x200000) == 0) {
      *(float *)(param_2 + 0x14) = *(float *)(param_2 + 0x14) * FLOAT_803e058c;
      *(float *)(param_2 + 0x14) =
           -(float)((double)(float)param_3[0xa9] * param_1 - (double)*(float *)(param_2 + 0x14));
    }
    if (((*(byte *)(param_3 + 0xd3) & 1) == 0) || ((*(byte *)(param_3 + 0xd3) & 4) != 0)) {
      local_7c = *param_2;
      local_7a = param_2[1];
      local_78 = 0;
      local_74 = FLOAT_803e0588;
      local_70 = FLOAT_803e0570;
      local_6c = FLOAT_803e0570;
      local_68 = FLOAT_803e0570;
      FUN_80021ee8(auStack100,&local_7c);
      if ((*param_3 & 0x10000) == 0) {
        FUN_800226cc((double)(float)param_3[0xa1],(double)FLOAT_803e0570,
                     -(double)(float)param_3[0xa0],auStack100,&local_84,auStack128,&local_88);
      }
      else {
        FUN_800226cc((double)(float)param_3[0xa1],(double)(float)param_3[0xa2],
                     -(double)(float)param_3[0xa0],auStack100,&local_84,param_2 + 0x14,&local_88);
      }
      *(undefined4 *)(param_2 + 0x12) = local_84;
      *(undefined4 *)(param_2 + 0x16) = local_88;
    }
    FUN_8002b95c((double)(float)((double)*(float *)(param_2 + 0x12) * param_1),
                 (double)(float)((double)*(float *)(param_2 + 0x14) * param_1),
                 (double)(float)((double)*(float *)(param_2 + 0x16) * param_1),param_2);
  }
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  return;
}

