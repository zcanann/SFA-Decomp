// Function: FUN_801547d4
// Entry: 801547d4
// Size: 448 bytes

void FUN_801547d4(ushort *param_1,int param_2)

{
  double dVar1;
  float local_88;
  float fStack_84;
  float local_80;
  ushort local_7c [4];
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float afStack_64 [17];
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  
  *(float *)(param_2 + 0x330) = *(float *)(param_2 + 0x330) - FLOAT_803dc074;
  if (*(float *)(param_2 + 0x330) <= FLOAT_803e3628) {
    uStack_1c = FUN_80022264(0x1e,0x3c);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(param_2 + 0x330) = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e3640);
    local_70 = *(float *)(param_1 + 6);
    local_6c = FLOAT_803e3628;
    local_68 = *(float *)(param_1 + 10);
    local_7c[0] = *param_1;
    local_7c[1] = 0;
    local_7c[2] = 0;
    local_74 = FLOAT_803e362c;
    FUN_80021fac(afStack_64,local_7c);
    uStack_14 = FUN_80022264(0xffffffec,0x14);
    uStack_14 = uStack_14 ^ 0x80000000;
    local_18 = 0x43300000;
    local_80 = FLOAT_803e3630 +
               (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e3640) / FLOAT_803e3634;
    uStack_c = FUN_80022264(0xffffffec,0x14);
    uStack_c = uStack_c ^ 0x80000000;
    local_10 = 0x43300000;
    local_88 = FLOAT_803e3638 +
               (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e3640) / FLOAT_803e3634;
    FUN_80022790((double)local_80,(double)FLOAT_803e3628,(double)local_88,afStack_64,&local_80,
                 &fStack_84,&local_88);
    (**(code **)(*DAT_803dd718 + 0x14))
              ((double)local_80,(double)*(float *)(param_2 + 0x32c),(double)local_88,
               (double)FLOAT_803e3628,0,3);
    dVar1 = FUN_80293900((double)(*(float *)(param_1 + 0x12) * *(float *)(param_1 + 0x12) +
                                 *(float *)(param_1 + 0x16) * *(float *)(param_1 + 0x16)));
    if ((double)FLOAT_803e363c < dVar1) {
      FUN_8000bb00((double)local_70,(double)local_6c,(double)local_68,(uint)param_1,0x235);
    }
  }
  return;
}

