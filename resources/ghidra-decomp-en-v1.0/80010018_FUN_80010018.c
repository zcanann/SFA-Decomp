// Function: FUN_80010018
// Entry: 80010018
// Size: 776 bytes

/* WARNING: Removing unreachable block (ram,0x800102f8) */
/* WARNING: Removing unreachable block (ram,0x800102e8) */
/* WARNING: Removing unreachable block (ram,0x800102d8) */
/* WARNING: Removing unreachable block (ram,0x800102c8) */
/* WARNING: Removing unreachable block (ram,0x800102b8) */
/* WARNING: Removing unreachable block (ram,0x800102a8) */
/* WARNING: Removing unreachable block (ram,0x800102b0) */
/* WARNING: Removing unreachable block (ram,0x800102c0) */
/* WARNING: Removing unreachable block (ram,0x800102d0) */
/* WARNING: Removing unreachable block (ram,0x800102e0) */
/* WARNING: Removing unreachable block (ram,0x800102f0) */
/* WARNING: Removing unreachable block (ram,0x80010300) */

void FUN_80010018(undefined4 param_1,undefined4 param_2,int param_3,float *param_4,float *param_5,
                 float *param_6,uint param_7,code *param_8)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  double in_f20;
  double in_f21;
  double in_f22;
  double in_f23;
  double in_f24;
  double in_f25;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  undefined8 uVar5;
  float local_118;
  float local_114;
  float local_110;
  float local_10c;
  float local_108;
  float local_104;
  float local_100;
  float local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  undefined4 local_e8;
  uint uStack228;
  undefined auStack184 [16];
  undefined auStack168 [16];
  undefined auStack152 [16];
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,SUB84(in_f30,0),0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,SUB84(in_f29,0),0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,SUB84(in_f28,0),0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,SUB84(in_f27,0),0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,SUB84(in_f26,0),0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,SUB84(in_f25,0),0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,SUB84(in_f24,0),0);
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,SUB84(in_f23,0),0);
  __psq_st0(auStack152,(int)((ulonglong)in_f22 >> 0x20),0);
  __psq_st1(auStack152,SUB84(in_f22,0),0);
  __psq_st0(auStack168,(int)((ulonglong)in_f21 >> 0x20),0);
  __psq_st1(auStack168,SUB84(in_f21,0),0);
  __psq_st0(auStack184,(int)((ulonglong)in_f20 >> 0x20),0);
  __psq_st1(auStack184,SUB84(in_f20,0),0);
  uVar5 = FUN_802860d0();
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  iVar3 = (int)uVar5;
  if (param_7 != DAT_803db270) {
    uStack228 = param_7 ^ 0x80000000;
    local_e8 = 0x43300000;
    FLOAT_803dc8b0 =
         FLOAT_803de674 / (float)((double)CONCAT44(0x43300000,uStack228) - DOUBLE_803de688);
    DAT_80338790 = FLOAT_803dc8b0 * FLOAT_803dc8b0;
    DAT_80338794 = FLOAT_803de660 * DAT_80338790;
    DAT_80338798 = FLOAT_803dc8b0 * DAT_80338790;
    DAT_8033879c = FLOAT_803de680 * DAT_80338798;
    DAT_803db270 = param_7;
  }
  if (iVar2 != 0) {
    (*param_8)(iVar2,&local_f8);
    in_f31 = (double)local_ec;
    in_f30 = (double)(FLOAT_803dc8b0 * local_f0 +
                     DAT_80338798 * local_f8 + (float)((double)DAT_80338790 * (double)local_f4));
    in_f28 = (double)(DAT_8033879c * local_f8);
    in_f29 = (double)(float)((double)DAT_80338794 * (double)local_f4 + in_f28);
  }
  if (iVar3 != 0) {
    (*param_8)(iVar3,&local_108);
    in_f27 = (double)local_fc;
    in_f26 = (double)(FLOAT_803dc8b0 * local_100 +
                     DAT_80338798 * local_108 + (float)((double)DAT_80338790 * (double)local_104));
    in_f24 = (double)(DAT_8033879c * local_108);
    in_f25 = (double)(float)((double)DAT_80338794 * (double)local_104 + in_f24);
  }
  if (param_3 != 0) {
    (*param_8)(param_3,&local_118);
    in_f23 = (double)local_10c;
    in_f22 = (double)(FLOAT_803dc8b0 * local_110 +
                     DAT_80338798 * local_118 + (float)((double)DAT_80338790 * (double)local_114));
    in_f20 = (double)(DAT_8033879c * local_118);
    in_f21 = (double)(float)((double)DAT_80338794 * (double)local_114 + in_f20);
  }
  iVar1 = param_7 + 1;
  if (-1 < (int)param_7) {
    do {
      if (iVar2 != 0) {
        *param_4 = (float)in_f31;
        in_f31 = (double)(float)(in_f31 + in_f30);
        in_f30 = (double)(float)(in_f30 + in_f29);
        in_f29 = (double)(float)(in_f29 + in_f28);
      }
      if (iVar3 != 0) {
        *param_5 = (float)in_f27;
        in_f27 = (double)(float)(in_f27 + in_f26);
        in_f26 = (double)(float)(in_f26 + in_f25);
        in_f25 = (double)(float)(in_f25 + in_f24);
      }
      if (param_3 != 0) {
        *param_6 = (float)in_f23;
        in_f23 = (double)(float)(in_f23 + in_f22);
        in_f22 = (double)(float)(in_f22 + in_f21);
        in_f21 = (double)(float)(in_f21 + in_f20);
      }
      param_4 = param_4 + 1;
      param_5 = param_5 + 1;
      param_6 = param_6 + 1;
      iVar1 = iVar1 + -1;
    } while (iVar1 != 0);
  }
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
  __psq_l0(auStack88,uVar4);
  __psq_l1(auStack88,uVar4);
  __psq_l0(auStack104,uVar4);
  __psq_l1(auStack104,uVar4);
  __psq_l0(auStack120,uVar4);
  __psq_l1(auStack120,uVar4);
  __psq_l0(auStack136,uVar4);
  __psq_l1(auStack136,uVar4);
  __psq_l0(auStack152,uVar4);
  __psq_l1(auStack152,uVar4);
  __psq_l0(auStack168,uVar4);
  __psq_l1(auStack168,uVar4);
  __psq_l0(auStack184,uVar4);
  __psq_l1(auStack184,uVar4);
  FUN_8028611c();
  return;
}

