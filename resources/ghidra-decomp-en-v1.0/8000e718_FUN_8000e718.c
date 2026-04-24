// Function: FUN_8000e718
// Entry: 8000e718
// Size: 252 bytes

/* WARNING: Removing unreachable block (ram,0x8000e7e8) */
/* WARNING: Removing unreachable block (ram,0x8000e7d8) */
/* WARNING: Removing unreachable block (ram,0x8000e7d0) */
/* WARNING: Removing unreachable block (ram,0x8000e7e0) */
/* WARNING: Removing unreachable block (ram,0x8000e7f0) */

void FUN_8000e718(double param_1,double param_2,double param_3,double param_4,double param_5)

{
  int iVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  double dVar4;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack72 [16];
  undefined auStack56 [16];
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
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  iVar1 = 0;
  puVar2 = &DAT_803381d0;
  do {
    dVar4 = (double)FUN_802931a0((double)((float)(param_3 - (double)*(float *)(puVar2 + 10)) *
                                          (float)(param_3 - (double)*(float *)(puVar2 + 10)) +
                                         (float)(param_1 - (double)*(float *)(puVar2 + 6)) *
                                         (float)(param_1 - (double)*(float *)(puVar2 + 6)) +
                                         (float)(param_2 - (double)*(float *)(puVar2 + 8)) *
                                         (float)(param_2 - (double)*(float *)(puVar2 + 8))));
    if (dVar4 < param_4) {
      *(float *)(puVar2 + 0x16) =
           (float)((double)(float)(param_5 * (double)(float)(param_4 - dVar4)) / param_4);
      *(undefined *)((int)puVar2 + 0x5d) = 0;
    }
    puVar2 = puVar2 + 0x30;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 8);
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  __psq_l0(auStack40,uVar3);
  __psq_l1(auStack40,uVar3);
  __psq_l0(auStack56,uVar3);
  __psq_l1(auStack56,uVar3);
  __psq_l0(auStack72,uVar3);
  __psq_l1(auStack72,uVar3);
  return;
}

