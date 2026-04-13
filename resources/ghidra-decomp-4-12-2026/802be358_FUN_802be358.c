// Function: FUN_802be358
// Entry: 802be358
// Size: 332 bytes

undefined4
FUN_802be358(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_9 + 0xb8);
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  iVar3 = FUN_80114e4c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_11,(float *)(iVar5 + 0x3ec),0,0,param_14,param_15,param_16);
  if (iVar3 == 0) {
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_11 + 0x8b); iVar3 = iVar3 + 1) {
      bVar1 = *(byte *)(param_11 + iVar3 + 0x81);
      if (0xd < bVar1) {
        if (bVar1 == 0x10) {
          *(byte *)(iVar5 + 0x9fd) = *(byte *)(iVar5 + 0x9fd) & 0xfe;
          *(byte *)(*(int *)(param_9 + 0x54) + 0x62) =
               *(byte *)(*(int *)(param_9 + 0x54) + 0x62) | 0x20;
        }
        else if (bVar1 < 0x10) {
          *(byte *)(iVar5 + 0x9fd) = *(byte *)(iVar5 + 0x9fd) | 1;
          *(byte *)(*(int *)(param_9 + 0x54) + 0x62) =
               *(byte *)(*(int *)(param_9 + 0x54) + 0x62) & 0xdf;
        }
      }
    }
    *(uint *)(iVar5 + 0xeb8) = *(uint *)(iVar5 + 0xeb8) | 0x800000;
    (**(code **)(*DAT_803dd728 + 0x20))(param_9,iVar5 + 4);
    fVar2 = FLOAT_803e8f9c;
    *(float *)(iVar5 + 0x294) = FLOAT_803e8f9c;
    *(float *)(iVar5 + 0x284) = fVar2;
    *(float *)(iVar5 + 0x280) = fVar2;
    *(float *)(param_9 + 0x24) = fVar2;
    *(float *)(param_9 + 0x28) = fVar2;
    *(float *)(param_9 + 0x2c) = fVar2;
    uVar4 = 0;
  }
  else {
    uVar4 = 1;
  }
  return uVar4;
}

