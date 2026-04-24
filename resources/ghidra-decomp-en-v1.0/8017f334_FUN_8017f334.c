// Function: FUN_8017f334
// Entry: 8017f334
// Size: 448 bytes

/* WARNING: Removing unreachable block (ram,0x8017f4cc) */

void FUN_8017f334(short *param_1,undefined4 param_2,int *param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 in_f31;
  double dVar6;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar1 = FUN_8002b9ec();
  FUN_8000b7bc(param_1,0x40);
  iVar3 = *param_3;
  if (((iVar3 != 0) && (*(int *)(iVar3 + 0xc4) != 0)) &&
     (FLOAT_803e3870 <= *(float *)(param_1 + 0x4c))) {
    *param_3 = 0;
    FUN_80037cb0(param_1,iVar3);
    uVar2 = FUN_800221a0(0x27,0x2c);
    dVar6 = (double)((float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3860) /
                    FLOAT_803e3874);
    uVar2 = FUN_800217c0((double)(*(float *)(param_1 + 6) - *(float *)(iVar1 + 0xc)),
                         (double)(*(float *)(param_1 + 10) - *(float *)(iVar1 + 0x14)));
    FUN_800221a0((uVar2 & 0xffff) - 0x1000,(uVar2 & 0xffff) + 0x1000);
    dVar5 = (double)FUN_80293e80((double)((FLOAT_803e3878 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e3860)) / FLOAT_803e387c));
    *(float *)(iVar3 + 0x24) = (float)(dVar6 * dVar5);
    dVar5 = (double)FUN_80294204((double)((FLOAT_803e3878 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e3860)) / FLOAT_803e387c));
    *(float *)(iVar3 + 0x2c) = (float)(dVar6 * dVar5);
    FUN_8000bb18(param_1,0x5e);
  }
  if (FLOAT_803e3858 <= *(float *)(param_1 + 0x4c)) {
    *(undefined *)((int)param_3 + 0xf) = 2;
    param_3[2] = (int)FLOAT_803e3880;
    FUN_80030334((double)FLOAT_803e385c,param_1,2,0);
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

