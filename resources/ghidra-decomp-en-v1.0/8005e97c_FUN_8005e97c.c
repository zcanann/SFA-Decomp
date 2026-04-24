// Function: FUN_8005e97c
// Entry: 8005e97c
// Size: 296 bytes

/* WARNING: Removing unreachable block (ram,0x8005ea8c) */
/* WARNING: Removing unreachable block (ram,0x8005ea7c) */
/* WARNING: Removing unreachable block (ram,0x8005ea84) */
/* WARNING: Removing unreachable block (ram,0x8005ea94) */

undefined4
FUN_8005e97c(double param_1,double param_2,double param_3,double param_4,double param_5,
            double param_6,float *param_7)

{
  byte bVar1;
  undefined4 uVar2;
  float *pfVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f28;
  double dVar7;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  pfVar3 = (float *)&DAT_8038793c;
  iVar4 = 5;
  while( true ) {
    bVar1 = *(byte *)(pfVar3 + 4);
    dVar6 = param_1;
    dVar9 = param_2;
    if ((bVar1 & 1) != 0) {
      dVar6 = param_2;
      dVar9 = param_1;
    }
    dVar5 = param_3;
    dVar8 = param_4;
    if ((bVar1 & 2) != 0) {
      dVar5 = param_4;
      dVar8 = param_3;
    }
    dVar7 = param_6;
    dVar10 = param_5;
    if ((bVar1 & 4) != 0) {
      dVar7 = param_5;
      dVar10 = param_6;
    }
    if ((*param_7 +
         pfVar3[3] +
         (float)(dVar10 * (double)pfVar3[2] +
                (double)(float)(dVar6 * (double)*pfVar3 + (double)(float)(dVar5 * (double)pfVar3[1])
                               )) < FLOAT_803debcc) &&
       (*param_7 +
        pfVar3[3] +
        (float)(dVar7 * (double)pfVar3[2] +
               (double)(float)(dVar9 * (double)*pfVar3 + (double)(float)(dVar8 * (double)pfVar3[1]))
               ) < FLOAT_803debcc)) break;
    pfVar3 = pfVar3 + 5;
    param_7 = param_7 + 1;
    iVar4 = iVar4 + -1;
    if (iVar4 == 0) {
      uVar2 = 1;
LAB_8005ea7c:
      __psq_l0(auStack8,0);
      __psq_l1(auStack8,0);
      __psq_l0(auStack24,0);
      __psq_l1(auStack24,0);
      __psq_l0(auStack40,0);
      __psq_l1(auStack40,0);
      __psq_l0(auStack56,0);
      __psq_l1(auStack56,0);
      return uVar2;
    }
  }
  uVar2 = 0;
  goto LAB_8005ea7c;
}

