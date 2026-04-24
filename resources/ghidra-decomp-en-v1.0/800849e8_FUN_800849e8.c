// Function: FUN_800849e8
// Entry: 800849e8
// Size: 624 bytes

/* WARNING: Removing unreachable block (ram,0x80084c2c) */
/* WARNING: Removing unreachable block (ram,0x80084c24) */
/* WARNING: Removing unreachable block (ram,0x80084c34) */

void FUN_800849e8(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (iVar2 != 0) {
    if (*(int *)(param_2 + 0x28) < 0) {
      dVar6 = (double)(*(float *)(param_1 + 0xc) - *(float *)(iVar2 + 8));
      dVar7 = (double)(*(float *)(param_1 + 0x14) - *(float *)(iVar2 + 0x10));
      uStack76 = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
      local_50 = 0x43300000;
      dVar4 = (double)FUN_80293e80((double)((FLOAT_803defe8 *
                                            (float)((double)CONCAT44(0x43300000,uStack76) -
                                                   DOUBLE_803defb8)) / FLOAT_803defec));
      uStack68 = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
      local_48 = 0x43300000;
      dVar5 = (double)FUN_80294204((double)((FLOAT_803defe8 *
                                            (float)((double)CONCAT44(0x43300000,uStack68) -
                                                   DOUBLE_803defb8)) / FLOAT_803defec));
      *(float *)(param_1 + 0xc) =
           (float)(dVar4 * dVar7 + (double)(float)(dVar5 * dVar6 + (double)*(float *)(iVar2 + 8)));
      *(float *)(param_1 + 0x14) =
           -(float)(dVar4 * dVar6 -
                   (double)(float)(dVar5 * dVar7 + (double)*(float *)(iVar2 + 0x10)));
    }
    else {
      iVar1 = (**(code **)(*DAT_803dca9c + 0x1c))();
      if (iVar1 != 0) {
        local_5c = *(float *)(param_1 + 0xc);
        local_68 = local_5c - *(float *)(iVar2 + 8);
        dVar5 = (double)local_68;
        local_58 = *(float *)(param_1 + 0x10);
        local_64 = local_58 - *(float *)(iVar2 + 0xc);
        local_54 = *(float *)(param_1 + 0x14);
        local_60 = local_54 - *(float *)(iVar2 + 0x10);
        dVar4 = (double)local_60;
        if (*(int *)(iVar1 + 0x1c) < 0) {
          *(float *)(param_1 + 0xc) = local_5c;
          *(float *)(param_1 + 0x10) = local_58;
          *(float *)(param_1 + 0x14) = local_54;
        }
        else {
          iVar1 = FUN_800844b8(*(undefined4 *)(param_2 + 0x2c),&local_68,&local_5c,param_2 + 0x1a,
                               *(undefined *)(param_2 + 0x7a));
          if (iVar1 == 0) {
            uStack68 = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
            local_48 = 0x43300000;
            dVar6 = (double)FUN_80293e80((double)((FLOAT_803defe8 *
                                                  (float)((double)CONCAT44(0x43300000,uStack68) -
                                                         DOUBLE_803defb8)) / FLOAT_803defec));
            uStack76 = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
            local_50 = 0x43300000;
            dVar7 = (double)FUN_80294204((double)((FLOAT_803defe8 *
                                                  (float)((double)CONCAT44(0x43300000,uStack76) -
                                                         DOUBLE_803defb8)) / FLOAT_803defec));
            *(float *)(param_1 + 0xc) =
                 (float)(dVar6 * dVar4 +
                        (double)(float)(dVar7 * dVar5 + (double)*(float *)(iVar2 + 8)));
            *(float *)(param_1 + 0x14) =
                 -(float)(dVar6 * dVar5 -
                         (double)(float)(dVar7 * dVar4 + (double)*(float *)(iVar2 + 0x10)));
          }
          else {
            *(float *)(param_1 + 0xc) = local_5c;
            *(float *)(param_1 + 0x10) = local_58;
            *(float *)(param_1 + 0x14) = local_54;
          }
        }
      }
    }
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  __psq_l0(auStack40,uVar3);
  __psq_l1(auStack40,uVar3);
  return;
}

