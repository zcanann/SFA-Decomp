// Function: FUN_8006ff0c
// Entry: 8006ff0c
// Size: 664 bytes

/* WARNING: Removing unreachable block (ram,0x8007017c) */
/* WARNING: Removing unreachable block (ram,0x8007016c) */
/* WARNING: Removing unreachable block (ram,0x8007015c) */
/* WARNING: Removing unreachable block (ram,0x80070154) */
/* WARNING: Removing unreachable block (ram,0x80070164) */
/* WARNING: Removing unreachable block (ram,0x80070174) */
/* WARNING: Removing unreachable block (ram,0x80070184) */

void FUN_8006ff0c(double param_1,double param_2,double param_3,double param_4,double param_5,
                 float *param_6,short *param_7)

{
  undefined4 uVar1;
  double dVar2;
  undefined8 in_f25;
  double dVar3;
  undefined8 in_f26;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double local_80;
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar1 = 0;
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
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  FUN_80070234();
  local_80 = (double)CONCAT44(0x43300000,(int)((double)FLOAT_803dee6c * param_1) ^ 0x80000000);
  dVar3 = (double)((FLOAT_803dee68 * (float)(local_80 - DOUBLE_803dee88)) / FLOAT_803dee70);
  dVar2 = (double)FUN_80293e80(dVar3);
  dVar3 = (double)FUN_80294204(dVar3);
  *param_6 = (float)((double)(float)(dVar3 / dVar2) / param_2);
  param_6[5] = (float)(dVar3 / dVar2);
  param_6[10] = (float)(-param_3 / (double)(float)(param_4 - param_3));
  param_6[0xb] = FLOAT_803dee74;
  param_6[0xe] = (float)((double)(float)(-param_3 * param_4) / (double)(float)(param_4 - param_3));
  param_6[0xf] = FLOAT_803dee78;
  *param_6 = (float)((double)*param_6 * param_5);
  param_6[1] = (float)((double)param_6[1] * param_5);
  param_6[2] = (float)((double)param_6[2] * param_5);
  param_6[3] = (float)((double)param_6[3] * param_5);
  param_6[4] = (float)((double)param_6[4] * param_5);
  param_6[5] = (float)((double)param_6[5] * param_5);
  param_6[6] = (float)((double)param_6[6] * param_5);
  param_6[7] = (float)((double)param_6[7] * param_5);
  param_6[8] = (float)((double)param_6[8] * param_5);
  param_6[9] = (float)((double)param_6[9] * param_5);
  param_6[10] = (float)((double)param_6[10] * param_5);
  param_6[0xb] = (float)((double)param_6[0xb] * param_5);
  param_6[0xc] = (float)((double)param_6[0xc] * param_5);
  param_6[0xd] = (float)((double)param_6[0xd] * param_5);
  param_6[0xe] = (float)((double)param_6[0xe] * param_5);
  param_6[0xf] = (float)((double)param_6[0xf] * param_5);
  if (param_7 != (short *)0x0) {
    if (FLOAT_803dee7c < (float)(param_3 + param_4)) {
      *param_7 = (short)(int)(FLOAT_803dee80 / (float)(param_3 + param_4));
      if (*param_7 == 0) {
        *param_7 = 1;
      }
    }
    else {
      *param_7 = -1;
    }
  }
  FLOAT_803dd038 = (float)ABS(param_3);
  FLOAT_803dd034 = (float)ABS(param_4);
  FUN_802475c8(param_1,param_2,&DAT_803968c0);
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  __psq_l0(auStack24,uVar1);
  __psq_l1(auStack24,uVar1);
  __psq_l0(auStack40,uVar1);
  __psq_l1(auStack40,uVar1);
  __psq_l0(auStack56,uVar1);
  __psq_l1(auStack56,uVar1);
  __psq_l0(auStack72,uVar1);
  __psq_l1(auStack72,uVar1);
  __psq_l0(auStack88,uVar1);
  __psq_l1(auStack88,uVar1);
  __psq_l0(auStack104,uVar1);
  __psq_l1(auStack104,uVar1);
  DAT_803dd03c = 0;
  return;
}

