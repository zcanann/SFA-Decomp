// Function: FUN_8023039c
// Entry: 8023039c
// Size: 296 bytes

undefined4
FUN_8023039c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            char *param_10,int param_11)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  
  if (((byte)param_10[0x14] >> 4 & 1) == 0) {
    if ((*(float *)(param_9 + 0x14) - *(float *)(param_11 + 0x14) <= FLOAT_803e7d38) &&
       (FLOAT_803e7d38 <= *(float *)(param_9 + 0x14) - *(float *)(param_11 + 0x88))) {
      dVar5 = (double)(*(float *)(param_9 + 0xc) - *(float *)(param_11 + 0xc));
      fVar1 = *(float *)(param_9 + 0x10) - *(float *)(param_11 + 0x10);
      dVar4 = FUN_80293900((double)(float)(dVar5 * dVar5 + (double)(fVar1 * fVar1)));
      if (dVar4 < (double)FLOAT_803e7d44) {
        return 1;
      }
      if ((*param_10 == '\x02') && (((byte)param_10[0x14] >> 5 & 1) != 0)) {
        FUN_80125e88(dVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,10);
      }
    }
  }
  else {
    fVar1 = *(float *)(param_9 + 0xc) - *(float *)(param_11 + 0xc);
    fVar2 = *(float *)(param_9 + 0x10) - *(float *)(param_11 + 0x10);
    if (fVar2 < FLOAT_803e7d38) {
      fVar2 = -fVar2;
    }
    fVar3 = *(float *)(param_9 + 0x14) - *(float *)(param_11 + 0x14);
    if ((fVar2 <= FLOAT_803e7d3c) && (fVar1 * fVar1 + fVar3 * fVar3 < FLOAT_803e7d40)) {
      return 1;
    }
  }
  return 0;
}

