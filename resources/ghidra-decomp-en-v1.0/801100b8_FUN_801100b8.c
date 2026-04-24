// Function: FUN_801100b8
// Entry: 801100b8
// Size: 292 bytes

/* WARNING: Removing unreachable block (ram,0x801101b4) */
/* WARNING: Removing unreachable block (ram,0x801101bc) */

void FUN_801100b8(int param_1,undefined4 param_2,float *param_3)

{
  short *psVar1;
  undefined4 uVar2;
  double dVar3;
  undefined8 in_f30;
  double dVar4;
  double dVar5;
  undefined8 in_f31;
  undefined auStack72 [4];
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack52;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  psVar1 = *(short **)(param_1 + 0xa4);
  uStack52 = (int)*psVar1 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar4 = (double)((FLOAT_803e1b00 *
                   (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e1b10)) /
                  FLOAT_803e1b04);
  dVar3 = (double)FUN_80293e80(dVar4);
  dVar4 = (double)FUN_80294204(dVar4);
  dVar5 = (double)*(float *)(psVar1 + 0xc);
  local_44 = (float)(dVar3 * (double)FLOAT_803db9c8 + dVar5);
  local_40 = FLOAT_803e1b08 + *(float *)(psVar1 + 0xe);
  dVar3 = (double)*(float *)(psVar1 + 0x10);
  local_3c = (float)(dVar4 * (double)FLOAT_803db9c8 + dVar3);
  FUN_80103664(&local_44,psVar1,&local_44,auStack72);
  dVar3 = (double)FUN_802931a0((double)((float)((double)local_44 - dVar5) *
                                        (float)((double)local_44 - dVar5) +
                                       (float)((double)local_3c - dVar3) *
                                       (float)((double)local_3c - dVar3)));
  if (param_3 == (float *)0x0) {
    FLOAT_803db9c8 = FLOAT_803e1b1c;
    FLOAT_803dd5ac = FLOAT_803e1b08;
  }
  else {
    FLOAT_803db9c8 = *param_3;
    FLOAT_803dd5ac = param_3[1];
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  __psq_l0(auStack24,uVar2);
  __psq_l1(auStack24,uVar2);
  FLOAT_803dd5b0 = (float)dVar3;
  return;
}

