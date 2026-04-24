// Function: FUN_801033ac
// Entry: 801033ac
// Size: 240 bytes

/* WARNING: Removing unreachable block (ram,0x80103478) */
/* WARNING: Removing unreachable block (ram,0x80103470) */
/* WARNING: Removing unreachable block (ram,0x80103480) */

void FUN_801033ac(double param_1,double param_2,double param_3,undefined4 param_4)

{
  undefined4 uVar1;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
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
  FUN_800033a8(DAT_803dd524,0,0x144);
  *(float *)(DAT_803dd524 + 0xc) = (float)param_1;
  *(float *)(DAT_803dd524 + 0x10) = (float)param_2;
  *(float *)(DAT_803dd524 + 0x14) = (float)param_3;
  *(float *)(DAT_803dd524 + 0x18) = (float)param_1;
  *(float *)(DAT_803dd524 + 0x1c) = (float)param_2;
  *(float *)(DAT_803dd524 + 0x20) = (float)param_3;
  *(float *)(DAT_803dd524 + 0xa8) = (float)param_1;
  *(float *)(DAT_803dd524 + 0xac) = (float)param_2;
  *(float *)(DAT_803dd524 + 0xb0) = (float)param_3;
  *(float *)(DAT_803dd524 + 0xb8) = (float)param_1;
  *(float *)(DAT_803dd524 + 0xbc) = (float)param_2;
  *(float *)(DAT_803dd524 + 0xc0) = (float)param_3;
  *(undefined4 *)(DAT_803dd524 + 0xa4) = param_4;
  *(float *)(DAT_803dd524 + 0xb4) = FLOAT_803e1684;
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  __psq_l0(auStack24,uVar1);
  __psq_l1(auStack24,uVar1);
  __psq_l0(auStack40,uVar1);
  __psq_l1(auStack40,uVar1);
  DAT_803dd4ca = 0;
  return;
}

