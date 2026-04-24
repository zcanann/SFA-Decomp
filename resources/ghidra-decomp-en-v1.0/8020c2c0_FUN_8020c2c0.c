// Function: FUN_8020c2c0
// Entry: 8020c2c0
// Size: 396 bytes

/* WARNING: Removing unreachable block (ram,0x8020c428) */

void FUN_8020c2c0(short *param_1)

{
  int iVar1;
  short *psVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  psVar2 = *(short **)(param_1 + 0x5c);
  iVar1 = FUN_8002e0b4(0x42fe7);
  *param_1 = *param_1 + psVar2[2];
  param_1[1] = param_1[1] + psVar2[1];
  param_1[2] = param_1[2] + *psVar2;
  psVar2[3] = psVar2[3] + (short)(0x9c4 / (int)psVar2[4]);
  dVar4 = (double)FUN_8029374c(3000);
  dVar5 = (double)FUN_80293234(psVar2[3]);
  *(float *)(param_1 + 6) =
       (float)((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                (int)psVar2[4] ^ 0x80000000) -
                                              DOUBLE_803e65d8) * dVar5) * dVar4 +
              (double)*(float *)(iVar1 + 0xc));
  dVar4 = (double)FUN_80293234(3000);
  dVar5 = (double)FUN_80293234(psVar2[3]);
  *(float *)(param_1 + 8) =
       (float)((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                (int)psVar2[4] ^ 0x80000000) -
                                              DOUBLE_803e65d8) * dVar5) * dVar4 +
              (double)(*(float *)(iVar1 + 0x10) +
                      (float)((double)CONCAT44(0x43300000,(int)psVar2[5] ^ 0x80000000) -
                             DOUBLE_803e65d8)));
  dVar4 = (double)FUN_8029374c(psVar2[3]);
  *(float *)(param_1 + 10) =
       (float)((double)(float)((double)CONCAT44(0x43300000,(int)psVar2[4] ^ 0x80000000) -
                              DOUBLE_803e65d8) * dVar4 + (double)*(float *)(iVar1 + 0x14));
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return;
}

