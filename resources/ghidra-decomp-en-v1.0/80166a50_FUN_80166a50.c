// Function: FUN_80166a50
// Entry: 80166a50
// Size: 556 bytes

/* WARNING: Removing unreachable block (ram,0x80166c54) */
/* WARNING: Removing unreachable block (ram,0x80166c44) */
/* WARNING: Removing unreachable block (ram,0x80166b38) */
/* WARNING: Removing unreachable block (ram,0x80166c3c) */
/* WARNING: Removing unreachable block (ram,0x80166c4c) */
/* WARNING: Removing unreachable block (ram,0x80166c5c) */

void FUN_80166a50(double param_1,double param_2,double param_3,double param_4,int param_5)

{
  byte bVar1;
  int iVar2;
  undefined4 uVar3;
  double dVar4;
  undefined8 in_f27;
  double dVar5;
  undefined8 in_f28;
  double dVar6;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar7;
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
  iVar2 = *(int *)(*(int *)(param_5 + 0xb8) + 0x40c);
  if ((*(byte *)(iVar2 + 0x92) >> 2 & 1) == 0) {
    dVar7 = (double)(float)(param_1 - (double)*(float *)(param_5 + 0xc));
    dVar6 = (double)(float)(param_2 - (double)*(float *)(param_5 + 0x10));
    dVar5 = (double)(float)(param_3 - (double)*(float *)(param_5 + 0x14));
    dVar4 = (double)FUN_802931a0((double)(float)(dVar5 * dVar5 +
                                                (double)(float)(dVar7 * dVar7 +
                                                               (double)(float)(dVar6 * dVar6))));
    if ((double)FLOAT_803e2fdc <= dVar4) {
      dVar4 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar4);
      dVar7 = (double)(float)(dVar7 * dVar4);
      dVar6 = (double)(float)(dVar6 * dVar4);
      dVar5 = (double)(float)(dVar5 * dVar4);
    }
    dVar7 = (double)(float)(param_4 * (double)(float)(dVar7 - (double)*(float *)(param_5 + 0x24)) +
                           (double)*(float *)(param_5 + 0x24));
    dVar6 = (double)(float)(param_4 * (double)(float)(dVar6 - (double)*(float *)(param_5 + 0x28)) +
                           (double)*(float *)(param_5 + 0x28));
    dVar4 = (double)(float)(param_4 * (double)(float)(dVar5 - (double)*(float *)(param_5 + 0x2c)) +
                           (double)*(float *)(param_5 + 0x2c));
    bVar1 = *(byte *)(iVar2 + 0x90);
    if (bVar1 < 4) {
      if (bVar1 < 2) {
        dVar7 = (double)FLOAT_803e2fdc;
        dVar5 = (double)FUN_802931a0((double)(float)(dVar6 * dVar6 + (double)(float)(dVar4 * dVar4))
                                    );
        if (dVar5 != (double)FLOAT_803e2fdc) {
          dVar5 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar5);
          dVar6 = (double)(float)(dVar6 * dVar5);
          dVar4 = (double)(float)(dVar4 * dVar5);
        }
      }
      else {
        dVar4 = (double)FLOAT_803e2fdc;
        dVar5 = (double)FUN_802931a0((double)(float)(dVar7 * dVar7 + (double)(float)(dVar6 * dVar6))
                                    );
        if (dVar5 != (double)FLOAT_803e2fdc) {
          dVar5 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar5);
          dVar7 = (double)(float)(dVar7 * dVar5);
          dVar6 = (double)(float)(dVar6 * dVar5);
        }
      }
    }
    else if (bVar1 == 6) {
      dVar5 = (double)(float)(dVar4 * (double)*(float *)(iVar2 + 0x84) +
                             (double)(float)(dVar7 * (double)*(float *)(iVar2 + 0x7c) +
                                            (double)(float)(dVar6 * (double)*(float *)(iVar2 + 0x80)
                                                           )));
      dVar7 = -(double)(float)(dVar5 * (double)*(float *)(iVar2 + 0x7c) - dVar7);
      dVar6 = -(double)(float)(dVar5 * (double)*(float *)(iVar2 + 0x80) - dVar6);
      dVar4 = -(double)(float)(dVar5 * (double)*(float *)(iVar2 + 0x84) - dVar4);
      dVar5 = (double)FUN_802931a0((double)(float)(dVar4 * dVar4 +
                                                  (double)(float)(dVar7 * dVar7 +
                                                                 (double)(float)(dVar6 * dVar6))));
      if (dVar5 != (double)FLOAT_803e2fdc) {
        dVar5 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar5);
        dVar7 = (double)(float)(dVar7 * dVar5);
        dVar6 = (double)(float)(dVar6 * dVar5);
        dVar4 = (double)(float)(dVar4 * dVar5);
      }
    }
    else if (bVar1 < 6) {
      dVar6 = (double)FLOAT_803e2fdc;
      dVar5 = (double)FUN_802931a0((double)(float)(dVar7 * dVar7 + (double)(float)(dVar4 * dVar4)));
      if (dVar5 != (double)FLOAT_803e2fdc) {
        dVar5 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar5);
        dVar7 = (double)(float)(dVar7 * dVar5);
        dVar4 = (double)(float)(dVar4 * dVar5);
      }
    }
    *(float *)(param_5 + 0x24) = (float)dVar7;
    *(float *)(param_5 + 0x28) = (float)dVar6;
    *(float *)(param_5 + 0x2c) = (float)dVar4;
  }
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

