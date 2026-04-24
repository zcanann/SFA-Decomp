// Function: FUN_800d87b8
// Entry: 800d87b8
// Size: 420 bytes

/* WARNING: Removing unreachable block (ram,0x800d8934) */

void FUN_800d87b8(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f31;
  float local_38 [2];
  longlong local_30;
  undefined4 local_28;
  uint uStack36;
  undefined auStack8 [8];
  
  uVar3 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (DAT_803dd434 != '\0') {
    if ((*(float *)(param_2 + 0x280) <= FLOAT_803e0570) ||
       (*(short *)(param_1 + 0xa0) == DAT_803dd43c)) {
      if ((*(float *)(param_2 + 0x280) < FLOAT_803e0570) &&
         (*(short *)(param_1 + 0xa0) != DAT_803dd438)) {
        FUN_80030334((double)*(float *)(param_1 + 0x98),param_1,DAT_803dd438,0);
        *(undefined *)(param_2 + 0x346) = 0;
      }
    }
    else {
      FUN_80030334((double)*(float *)(param_1 + 0x98),param_1,DAT_803dd43c,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    dVar5 = (double)FUN_802931a0((double)(*(float *)(param_2 + 0x280) * *(float *)(param_2 + 0x280)
                                         + *(float *)(param_2 + 0x284) * *(float *)(param_2 + 0x284)
                                         ));
    iVar1 = FUN_8002f5d4(param_1,local_38);
    if (iVar1 != 0) {
      *(float *)(param_2 + 0x2a0) = local_38[0];
    }
    dVar4 = (double)FLOAT_803e0570;
    if (dVar4 != dVar5) {
      dVar4 = (double)(float)((double)*(float *)(param_2 + 0x284) / dVar5);
    }
    local_38[0] = (float)dVar4;
    uVar2 = (uint)(FLOAT_803e05a0 * (float)dVar4);
    local_30 = (longlong)(int)uVar2;
    if ((int)uVar2 < 0) {
      uVar2 = -uVar2;
    }
    uStack36 = uVar2 ^ 0x80000000;
    local_28 = 0x43300000;
    if (FLOAT_803e05a0 < (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0598)) {
      uVar2 = 0x4000;
    }
    if (*(float *)(param_2 + 0x284) <= FLOAT_803e0570) {
      FUN_8002ed6c(param_1,param_3,uVar2);
    }
    else {
      FUN_8002ed6c(param_1,param_4,uVar2);
    }
  }
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  return;
}

