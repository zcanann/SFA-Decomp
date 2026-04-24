// Function: FUN_80154328
// Entry: 80154328
// Size: 448 bytes

void FUN_80154328(undefined2 *param_1,int param_2)

{
  double dVar1;
  float local_88;
  undefined auStack132 [4];
  float local_80;
  undefined2 local_7c;
  undefined2 local_7a;
  undefined2 local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  undefined auStack100 [68];
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  undefined4 local_10;
  uint uStack12;
  
  *(float *)(param_2 + 0x330) = *(float *)(param_2 + 0x330) - FLOAT_803db414;
  if (*(float *)(param_2 + 0x330) <= FLOAT_803e2990) {
    uStack28 = FUN_800221a0(0x1e,0x3c);
    uStack28 = uStack28 ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(param_2 + 0x330) = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e29a8);
    local_70 = *(float *)(param_1 + 6);
    local_6c = FLOAT_803e2990;
    local_68 = *(float *)(param_1 + 10);
    local_7c = *param_1;
    local_7a = 0;
    local_78 = 0;
    local_74 = FLOAT_803e2994;
    FUN_80021ee8(auStack100,&local_7c);
    uStack20 = FUN_800221a0(0xffffffec,0x14);
    uStack20 = uStack20 ^ 0x80000000;
    local_18 = 0x43300000;
    local_80 = FLOAT_803e2998 +
               (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e29a8) / FLOAT_803e299c;
    uStack12 = FUN_800221a0(0xffffffec,0x14);
    uStack12 = uStack12 ^ 0x80000000;
    local_10 = 0x43300000;
    local_88 = FLOAT_803e29a0 +
               (float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e29a8) / FLOAT_803e299c;
    FUN_800226cc((double)local_80,(double)FLOAT_803e2990,auStack100,&local_80,auStack132,&local_88);
    (**(code **)(*DAT_803dca98 + 0x14))
              ((double)local_80,(double)*(float *)(param_2 + 0x32c),(double)local_88,
               (double)FLOAT_803e2990,0,3);
    dVar1 = (double)FUN_802931a0((double)(*(float *)(param_1 + 0x12) * *(float *)(param_1 + 0x12) +
                                         *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16)));
    if ((double)FLOAT_803e29a4 < dVar1) {
      FUN_8000bae0((double)local_70,(double)local_6c,(double)local_68,param_1,0x235);
    }
  }
  return;
}

