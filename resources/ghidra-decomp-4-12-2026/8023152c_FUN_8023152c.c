// Function: FUN_8023152c
// Entry: 8023152c
// Size: 424 bytes

void FUN_8023152c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  uint uVar1;
  float fVar2;
  uint uVar3;
  float *pfVar4;
  float *pfVar5;
  double dVar6;
  double dVar7;
  float local_48;
  float local_44;
  float local_40;
  longlong local_38;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  longlong local_20;
  longlong local_18;
  undefined8 local_10;
  
  pfVar5 = *(float **)(param_9 + 0xb8);
  if (*(char *)(pfVar5 + 6) == '\0') {
    uVar3 = (uint)-pfVar5[3];
    local_38 = (longlong)(int)uVar3;
    uVar1 = (uint)pfVar5[3];
    local_30 = (longlong)(int)uVar1;
    uStack_24 = FUN_80022264(uVar3,uVar1);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    local_48 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e7d90);
    uVar3 = (uint)-pfVar5[4];
    local_20 = (longlong)(int)uVar3;
    uVar1 = (uint)pfVar5[4];
    local_18 = (longlong)(int)uVar1;
    uVar3 = FUN_80022264(uVar3,uVar1);
    local_10 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
    local_44 = (float)(local_10 - DOUBLE_803e7d90);
    local_40 = pfVar5[5];
    pfVar4 = (float *)FUN_8000f578();
    FUN_80247bf8(pfVar4,&local_48,(float *)(param_9 + 0xc));
    *(float *)(param_9 + 0xc) = *(float *)(param_9 + 0xc) + FLOAT_803dda58;
    *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) + FLOAT_803dda5c;
    *(byte *)(pfVar5 + 6) = *(byte *)(pfVar5 + 6) | 1;
    pfVar5[2] = FLOAT_803e7d9c;
  }
  fVar2 = FLOAT_803e7d9c;
  dVar7 = (double)pfVar5[1];
  dVar6 = (double)FLOAT_803e7d9c;
  if (dVar6 < dVar7) {
    pfVar5[1] = (float)(dVar7 - (double)FLOAT_803dc074);
    if (dVar6 < (double)pfVar5[1]) {
      FUN_8002ba34(dVar6,dVar6,(double)(*pfVar5 * FLOAT_803dc074),param_9);
      pfVar5[2] = FLOAT_803e7da0 * FLOAT_803dc074 + pfVar5[2];
      if (FLOAT_803e7da4 < pfVar5[2]) {
        pfVar5[2] = FLOAT_803e7da4;
      }
      *(char *)(param_9 + 0x36) = (char)(int)pfVar5[2];
    }
    else {
      pfVar5[1] = fVar2;
      FUN_8002cc9c(dVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
    }
  }
  return;
}

