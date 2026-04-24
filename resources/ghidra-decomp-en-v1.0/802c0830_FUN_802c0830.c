// Function: FUN_802c0830
// Entry: 802c0830
// Size: 328 bytes

undefined4 FUN_802c0830(int param_1,int param_2)

{
  short sVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(byte *)(iVar3 + 0xbc0) = *(byte *)(iVar3 + 0xbc0) & 0xef;
    *(float *)(param_1 + 0x28) = FLOAT_803e83a4;
    if ((*(byte *)(iVar3 + 0xbc0) >> 5 & 1) != 0) {
      *(byte *)(iVar3 + 0xbc0) = *(byte *)(iVar3 + 0xbc0) & 0xdf;
      FUN_802bf0c8(param_1,param_2,*(byte *)(iVar3 + 0xbc0) >> 5 & 1);
    }
  }
  sVar1 = *(short *)(param_1 + 0xa0);
  if (sVar1 == 0x20c) {
    if (*(char *)(param_2 + 0x346) != '\0') {
      *(byte *)(iVar3 + 0xad5) = *(byte *)(iVar3 + 0xad5) & 0xfd;
      return 3;
    }
  }
  else if ((sVar1 < 0x20c) && (sVar1 == 0x203)) {
    if (*(short *)(iVar3 + 0xbb0) != 0) {
      FUN_80030334((double)FLOAT_803e83a4,param_1,0x20c,0);
      *(float *)(param_2 + 0x2a0) = FLOAT_803e8408;
    }
  }
  else {
    FUN_80030334((double)FLOAT_803e83a4,param_1,0x203,0);
    *(byte *)(iVar3 + 0xad5) = *(byte *)(iVar3 + 0xad5) | 2;
    fVar2 = FLOAT_803e83a4;
    *(float *)(param_2 + 0x294) = FLOAT_803e83a4;
    *(float *)(param_2 + 0x284) = fVar2;
    *(float *)(param_2 + 0x280) = fVar2;
    *(float *)(param_1 + 0x24) = fVar2;
    *(float *)(param_1 + 0x28) = fVar2;
    *(float *)(param_1 + 0x2c) = fVar2;
    *(float *)(param_2 + 0x2a0) = FLOAT_803e8408;
  }
  return 0;
}

