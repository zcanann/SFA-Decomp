// Function: FUN_8006b558
// Entry: 8006b558
// Size: 728 bytes

/* WARNING: Removing unreachable block (ram,0x8006b80c) */
/* WARNING: Removing unreachable block (ram,0x8006b7fc) */
/* WARNING: Removing unreachable block (ram,0x8006b7f4) */
/* WARNING: Removing unreachable block (ram,0x8006b804) */
/* WARNING: Removing unreachable block (ram,0x8006b814) */

void FUN_8006b558(int param_1)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  undefined4 uVar4;
  undefined8 in_f27;
  double dVar5;
  undefined8 in_f28;
  double dVar6;
  undefined8 in_f29;
  double dVar7;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined auStack168 [4];
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  undefined auStack144 [60];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
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
  FUN_8002b47c(param_1,auStack144,0);
  FUN_8000eb88((double)(*(float *)(param_1 + 0xc) - FLOAT_803dcdd8),
               (double)*(float *)(param_1 + 0x10),
               (double)(*(float *)(param_1 + 0x14) - FLOAT_803dcddc),
               (double)(FLOAT_803ded0c * *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8)),
               &local_94,&local_98,&local_9c,&local_a0,&local_a4,auStack168);
  local_a0 = FLOAT_803ded14 * local_a0 + FLOAT_803ded10;
  local_a4 = FLOAT_803ded18 * local_a4 + FLOAT_803ded10;
  fVar1 = local_a4;
  if (local_a4 < local_a0) {
    fVar1 = local_a0;
  }
  dVar8 = (double)(FLOAT_803ded1c / fVar1);
  dVar7 = (double)(float)((double)*(float *)(param_1 + 8) * dVar8);
  dVar5 = -(double)local_94;
  dVar9 = (double)local_98;
  FUN_8025d300((double)(float)((double)FLOAT_803ded14 * dVar5),
               (double)(float)((double)FLOAT_803ded18 * dVar9),(double)FLOAT_803ded20,
               (double)FLOAT_803ded24,(double)FLOAT_803ded28,(double)FLOAT_803ded2c);
  if (FLOAT_803ded28 <= local_9c) {
    **(float **)(param_1 + 100) = FLOAT_803ded28;
  }
  else {
    dVar6 = (double)*(float *)(param_1 + 8);
    *(float *)(param_1 + 8) = (float)dVar7;
    FUN_80041d28(1);
    FUN_8003b958(0,0,0,0,param_1,1);
    FUN_80041d28(0);
    *(float *)(param_1 + 8) = (float)dVar6;
    iVar2 = FUN_8002b588(param_1);
    *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
    FUN_80070310(1,3,1);
    FUN_80258c9c(0x100,0xb0,0x80,0x80);
    FUN_80258da0(0x80,0x80,0x2a,0);
    FUN_802594a8((&DAT_8038e1dc)[DAT_803dcf8c] + 0x60,1);
    FUN_8006a028((&DAT_8038e1dc)[(DAT_803dcf8c + 1) % 3],0x80,0x10,0);
    **(float **)(param_1 + 100) = (float)((double)FLOAT_803ded2c / dVar8);
  }
  FUN_8000f780();
  dVar7 = (double)FLOAT_803ded14;
  *(float *)(*(int *)(param_1 + 100) + 0x14) = (float)(dVar7 * -dVar5);
  dVar5 = (double)FLOAT_803ded18;
  *(float *)(*(int *)(param_1 + 100) + 0x18) = (float)(dVar5 * -dVar9);
  *(float *)(*(int *)(param_1 + 100) + 0x14) =
       (float)((double)*(float *)(*(int *)(param_1 + 100) + 0x14) + dVar7);
  *(float *)(*(int *)(param_1 + 100) + 0x18) =
       (float)((double)*(float *)(*(int *)(param_1 + 100) + 0x18) + dVar5);
  fVar1 = FLOAT_803ded1c;
  pfVar3 = *(float **)(param_1 + 100);
  pfVar3[5] = -(FLOAT_803ded1c * *pfVar3 - pfVar3[5]);
  pfVar3 = *(float **)(param_1 + 100);
  pfVar3[6] = -(fVar1 * *pfVar3 - pfVar3[6]);
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  __psq_l0(auStack56,uVar4);
  __psq_l1(auStack56,uVar4);
  __psq_l0(auStack72,uVar4);
  __psq_l1(auStack72,uVar4);
  return;
}

