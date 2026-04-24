// Function: FUN_802b1bf8
// Entry: 802b1bf8
// Size: 612 bytes

/* WARNING: Removing unreachable block (ram,0x802b1e2c) */
/* WARNING: Removing unreachable block (ram,0x802b1e34) */

void FUN_802b1bf8(int param_1,int param_2,uint *param_3)

{
  undefined4 uVar1;
  double dVar2;
  undefined8 in_f30;
  double dVar3;
  undefined8 in_f31;
  double dVar4;
  undefined auStack216 [4];
  undefined2 local_d4;
  undefined2 local_d2;
  undefined2 local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  undefined auStack188 [68];
  undefined4 local_78;
  uint uStack116;
  longlong local_70;
  undefined4 local_68;
  uint uStack100;
  longlong local_60;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar1 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  if (((*(byte *)(param_3 + 0xd3) & 2) == 0) && ((*(byte *)(param_3 + 0xd3) & 1) == 0)) {
    dVar4 = (double)(float)param_3[0xa0];
    dVar3 = (double)(float)param_3[0xa1];
    if ((*(byte *)(param_2 + 0x3f0) >> 5 & 1) != 0) {
      dVar4 = (double)(float)(dVar4 + (double)*(float *)(param_2 + 0x43c));
      dVar3 = (double)(float)(dVar3 + (double)*(float *)(param_2 + 0x440));
    }
    local_d4 = *(undefined2 *)(param_2 + 0x484);
    local_d2 = 0;
    local_d0 = 0;
    local_cc = FLOAT_803e7ee0;
    local_c8 = FLOAT_803e7ea4;
    local_c4 = FLOAT_803e7ea4;
    local_c0 = FLOAT_803e7ea4;
    FUN_80021ee8(auStack188,&local_d4);
    FUN_800226cc(dVar3,(double)FLOAT_803e7ea4,-dVar4,auStack188,param_1 + 0x24,auStack216,
                 param_1 + 0x2c);
    *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) + *(float *)(param_2 + 0x890);
    *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) + *(float *)(param_2 + 0x894);
  }
  else {
    uStack116 = (int)*(short *)(param_2 + 0x484) ^ 0x80000000;
    local_78 = 0x43300000;
    dVar4 = (double)FUN_80293e80((double)((FLOAT_803e7f94 *
                                          (float)((double)CONCAT44(0x43300000,uStack116) -
                                                 DOUBLE_803e7ec0)) / FLOAT_803e7f98));
    local_70 = (longlong)(int)dVar4;
    uStack100 = (int)*(short *)(param_2 + 0x484) ^ 0x80000000;
    local_68 = 0x43300000;
    dVar2 = (double)FUN_80294204((double)((FLOAT_803e7f94 *
                                          (float)((double)CONCAT44(0x43300000,uStack100) -
                                                 DOUBLE_803e7ec0)) / FLOAT_803e7f98));
    dVar3 = DOUBLE_803e7ec0;
    local_60 = (longlong)(int)dVar2;
    uStack84 = (int)dVar2 ^ 0x80000000;
    local_58 = 0x43300000;
    uStack76 = (int)dVar4 ^ 0x80000000;
    local_50 = 0x43300000;
    param_3[0xa1] =
         (uint)(*(float *)(param_1 + 0x24) *
                (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e7ec0) -
               *(float *)(param_1 + 0x2c) *
               (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e7ec0));
    local_48 = 0x43300000;
    local_40 = 0x43300000;
    param_3[0xa0] =
         (uint)(-*(float *)(param_1 + 0x2c) * (float)((double)CONCAT44(0x43300000,uStack84) - dVar3)
               - *(float *)(param_1 + 0x24) * (float)((double)CONCAT44(0x43300000,uStack76) - dVar3)
               );
    uStack68 = uStack84;
    uStack60 = uStack76;
  }
  if ((*param_3 & 0x200000) == 0) {
    dVar3 = (double)FUN_80292b44((double)FLOAT_803e8140,(double)FLOAT_803db414);
    *(float *)(param_1 + 0x28) = (float)((double)*(float *)(param_1 + 0x28) * dVar3);
    *(float *)(param_1 + 0x28) =
         -((float)param_3[0xa9] * FLOAT_803db414 - *(float *)(param_1 + 0x28));
  }
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  __psq_l0(auStack24,uVar1);
  __psq_l1(auStack24,uVar1);
  return;
}

