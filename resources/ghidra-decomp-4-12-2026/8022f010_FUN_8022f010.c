// Function: FUN_8022f010
// Entry: 8022f010
// Size: 536 bytes

void FUN_8022f010(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  float fVar1;
  int iVar2;
  byte *pbVar3;
  double dVar4;
  double dVar5;
  
  pbVar3 = *(byte **)(param_9 + 0xb8);
  iVar2 = FUN_8022de2c();
  if ((iVar2 == 0) || ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)) {
    dVar5 = (double)*(float *)(pbVar3 + 0x10);
    dVar4 = (double)FLOAT_803e7ca0;
    if (dVar5 <= dVar4) {
      FUN_80035eec(param_9,0xf,pbVar3[0x18],0);
      *(undefined *)(param_9 + 0x36) = 0xff;
      fVar1 = FLOAT_803e7ca0;
      dVar5 = (double)*(float *)(pbVar3 + 4);
      dVar4 = (double)FLOAT_803e7ca0;
      if (dVar4 < dVar5) {
        *(float *)(pbVar3 + 4) = (float)(dVar5 - (double)FLOAT_803dc074);
        if (dVar4 < (double)*(float *)(pbVar3 + 4)) {
          if (*(char *)(*(int *)(param_9 + 0x54) + 0xad) != '\0') {
            if (*(short *)(param_9 + 0x46) != 0x6ae) {
              FUN_8000b4f0(param_9,0x2b3,4);
            }
            *(float *)(pbVar3 + 0x10) = FLOAT_803e7cc0;
            *(undefined *)(param_9 + 0x36) = 0;
            FUN_800998ec(param_9,(uint)*pbVar3);
            if (*(uint *)(pbVar3 + 0x14) != 0) {
              FUN_8001f448(*(uint *)(pbVar3 + 0x14));
              pbVar3[0x14] = 0;
              pbVar3[0x15] = 0;
              pbVar3[0x16] = 0;
              pbVar3[0x17] = 0;
            }
          }
          FUN_8002ba34((double)(*(float *)(param_9 + 0x24) * FLOAT_803dc074),
                       (double)(*(float *)(param_9 + 0x28) * FLOAT_803dc074),
                       (double)(*(float *)(param_9 + 0x2c) * FLOAT_803dc074),param_9);
          if (*(short *)(param_9 + 0x46) == 0x80d) {
            *(short *)(param_9 + 4) = *(short *)(param_9 + 4) + *(short *)(pbVar3 + 0x1a);
            *(short *)(param_9 + 2) = *(short *)(param_9 + 2) + *(short *)(pbVar3 + 0x1c);
          }
          if (*(short *)(param_9 + 0x46) == 0x7e4) {
            *(float *)(param_9 + 8) = *(float *)(param_9 + 8) + FLOAT_803dd038;
            FUN_80035a6c(param_9,(short)(int)(*(float *)(param_9 + 8) * FLOAT_803dd040));
            *(short *)(param_9 + 4) =
                 (short)(int)((float)((double)CONCAT44(0x43300000,
                                                       (int)*(short *)(param_9 + 4) ^ 0x80000000) -
                                     DOUBLE_803e7cb8) + FLOAT_803dd03c);
          }
        }
        else {
          *(float *)(pbVar3 + 4) = fVar1;
          FUN_8002cc9c(dVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
        }
      }
    }
    else {
      *(float *)(pbVar3 + 0x10) = (float)(dVar5 - (double)FLOAT_803dc074);
      if ((double)*(float *)(pbVar3 + 0x10) <= dVar4) {
        FUN_8002cc9c(dVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      }
    }
  }
  else {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

