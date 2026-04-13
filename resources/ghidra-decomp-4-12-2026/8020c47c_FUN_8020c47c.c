// Function: FUN_8020c47c
// Entry: 8020c47c
// Size: 672 bytes

void FUN_8020c47c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  short sVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint *puVar5;
  double dVar6;
  double dVar7;
  undefined8 local_20;
  
  puVar5 = *(uint **)(param_9 + 0xb8);
  iVar4 = *(int *)(param_9 + 0x4c);
  uVar2 = FUN_800803dc((float *)(puVar5 + 3));
  if (uVar2 == 0) {
    FUN_8000da78(param_9,0x479);
    if ((char)*(byte *)((int)puVar5 + 0x79) < '\0') {
      *(byte *)((int)puVar5 + 0x79) = *(byte *)((int)puVar5 + 0x79) & 0x7f;
    }
    sVar1 = *(short *)(param_9 + 0x46);
    if (sVar1 == 0x727) {
      iVar3 = FUN_8002bac4();
      iVar3 = FUN_80297a08(iVar3);
      if (iVar3 == 0) {
        FUN_80035eec(param_9,0xe,1,0);
      }
      else {
        FUN_80035ea4(param_9);
        FUN_80036018(param_9);
      }
    }
    else if ((sVar1 < 0x727) && (sVar1 == 0x709)) {
      iVar3 = FUN_8002bac4();
      dVar6 = (double)FUN_800217c8((float *)(iVar3 + 0x18),(float *)(param_9 + 0x18));
      local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar4 + 0x1c) << 1 ^ 0x80000000);
      if (dVar6 < (double)(float)(local_20 - DOUBLE_803e7238)) {
        iVar3 = FUN_8002bac4();
        FUN_80036548(iVar3,param_9,'\x05',1,0);
      }
    }
    if (*puVar5 == 0) {
      iVar3 = *(int *)(param_9 + 0x4c);
      FUN_80036018(param_9);
      *puVar5 = (uint)*(byte *)(iVar3 + 0x19);
      FUN_80035a6c(param_9,(short)puVar5[0x1d]);
    }
    if ((*(short *)(param_9 + 0x46) == 0x709) && ((float)puVar5[0x1a] < FLOAT_803e7224)) {
      local_20 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
      puVar5[0x1a] = (uint)(FLOAT_803e7244 * (float)(local_20 - DOUBLE_803e7250) +
                           (float)puVar5[0x1a]);
      *(float *)(param_9 + 8) =
           ((float)puVar5[0x1a] *
           *(float *)(*(int *)(param_9 + 0x50) + 4) *
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar4 + 0x1c) ^ 0x80000000) -
                  DOUBLE_803e7238)) / FLOAT_803e7248;
    }
  }
  else {
    dVar7 = (double)(float)puVar5[3];
    dVar6 = DOUBLE_803e7238;
    if (dVar7 < (double)(float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(iVar4 + 0x1c) ^ 0x80000000) -
                               DOUBLE_803e7238)) {
      FUN_80036018(param_9);
      dVar7 = (double)FLOAT_803e7240;
      dVar6 = (double)FUN_80035a6c(param_9,(short)(int)((float)(dVar7 + (double)(float)((double)
                                                  CONCAT44(0x43300000,
                                                           (int)*(short *)(iVar4 + 0x1c) ^
                                                           0x80000000) - DOUBLE_803e7238)) -
                                                  (float)puVar5[3]));
    }
    iVar3 = FUN_80080434((float *)(puVar5 + 3));
    if (iVar3 != 0) {
      *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) & 0xbfff;
      *(byte *)((int)puVar5 + 0x79) = *(byte *)((int)puVar5 + 0x79) & 0x7f | 0x80;
      if (*(int *)(iVar4 + 0x14) == -1) {
        FUN_8002cc9c(dVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      }
    }
  }
  return;
}

