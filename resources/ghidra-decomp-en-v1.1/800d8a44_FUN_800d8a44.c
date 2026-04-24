// Function: FUN_800d8a44
// Entry: 800d8a44
// Size: 420 bytes

/* WARNING: Removing unreachable block (ram,0x800d8bc0) */
/* WARNING: Removing unreachable block (ram,0x800d8a54) */

void FUN_800d8a44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,uint param_11,uint param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  double dVar3;
  double dVar4;
  float local_38 [2];
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  
  if (DAT_803de0b4 != '\0') {
    if ((*(float *)(param_10 + 0x280) <= FLOAT_803e11f0) ||
       (*(short *)(param_9 + 0xa0) == DAT_803de0bc)) {
      if ((*(float *)(param_10 + 0x280) < FLOAT_803e11f0) &&
         (*(short *)(param_9 + 0xa0) != DAT_803de0b8)) {
        FUN_8003042c((double)*(float *)(param_9 + 0x98),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8,param_9,DAT_803de0b8,0,param_12,param_13,param_14,param_15,
                     param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else {
      FUN_8003042c((double)*(float *)(param_9 + 0x98),param_2,param_3,param_4,param_5,param_6,
                   param_7,param_8,param_9,DAT_803de0bc,0,param_12,param_13,param_14,param_15,
                   param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    dVar4 = FUN_80293900((double)(*(float *)(param_10 + 0x280) * *(float *)(param_10 + 0x280) +
                                 *(float *)(param_10 + 0x284) * *(float *)(param_10 + 0x284)));
    iVar1 = FUN_8002f6cc(dVar4,param_9,local_38);
    if (iVar1 != 0) {
      *(float *)(param_10 + 0x2a0) = local_38[0];
    }
    dVar3 = (double)FLOAT_803e11f0;
    if (dVar3 != dVar4) {
      dVar3 = (double)(float)((double)*(float *)(param_10 + 0x284) / dVar4);
    }
    local_38[0] = (float)dVar3;
    uVar2 = (uint)(FLOAT_803e1220 * (float)dVar3);
    local_30 = (longlong)(int)uVar2;
    if ((int)uVar2 < 0) {
      uVar2 = -uVar2;
    }
    uStack_24 = uVar2 ^ 0x80000000;
    local_28 = 0x43300000;
    if (FLOAT_803e1220 < (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1218)) {
      uVar2 = 0x4000;
    }
    dVar4 = (double)*(float *)(param_10 + 0x284);
    if (dVar4 <= (double)FLOAT_803e11f0) {
      FUN_8002ee64(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_11,
                   (short)uVar2);
    }
    else {
      FUN_8002ee64(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_12,
                   (short)uVar2);
    }
  }
  return;
}

