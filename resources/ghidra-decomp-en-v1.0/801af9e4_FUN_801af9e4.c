// Function: FUN_801af9e4
// Entry: 801af9e4
// Size: 416 bytes

/* WARNING: Removing unreachable block (ram,0x801afb60) */

void FUN_801af9e4(short *param_1,uint param_2,uint param_3)

{
  undefined4 uVar1;
  int *piVar2;
  undefined4 uVar3;
  double dVar4;
  undefined8 in_f31;
  double dVar5;
  undefined auStack8 [8];
  
  dVar4 = DOUBLE_803e47e8;
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  piVar2 = *(int **)(param_1 + 0x5c);
  dVar5 = (double)(FLOAT_803e47d8 *
                  (float)((double)CONCAT44(0x43300000,param_3 ^ 0x80000000) - DOUBLE_803e47e8));
  uVar1 = *(undefined4 *)(*piVar2 + 0xc);
  *(undefined4 *)(param_1 + 0xc) = uVar1;
  *(undefined4 *)(param_1 + 6) = uVar1;
  uVar1 = *(undefined4 *)(*piVar2 + 0x10);
  *(undefined4 *)(param_1 + 0xe) = uVar1;
  *(undefined4 *)(param_1 + 8) = uVar1;
  uVar1 = *(undefined4 *)(*piVar2 + 0x14);
  *(undefined4 *)(param_1 + 0x10) = uVar1;
  *(undefined4 *)(param_1 + 10) = uVar1;
  *(undefined4 *)(param_1 + 0x46) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0x48) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x4a) = *(undefined4 *)(param_1 + 10);
  *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
  *param_1 = (short)((int)*(char *)(*(int *)(param_1 + 0x26) + 0x18) << 8);
  dVar4 = (double)FUN_80293e80((double)((FLOAT_803e47dc *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) - dVar4
                                               )) / FLOAT_803e47e0));
  *(float *)(param_1 + 0x12) = (float)(dVar5 * -dVar4);
  dVar4 = DOUBLE_803e47e8;
  *(float *)(param_1 + 0x14) =
       FLOAT_803e47d8 * (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e47e8)
  ;
  dVar4 = (double)FUN_80294204((double)((FLOAT_803e47dc *
                                        (float)((double)CONCAT44(0x43300000,
                                                                 (int)*param_1 ^ 0x80000000) - dVar4
                                               )) / FLOAT_803e47e0));
  *(float *)(param_1 + 0x16) = (float)(dVar5 * -dVar4);
  param_1[3] = param_1[3] & 0xbfff;
  FUN_80035f20(param_1);
  *(byte *)(piVar2 + 4) = *(byte *)(piVar2 + 4) & 0xef;
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return;
}

