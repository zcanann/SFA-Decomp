// Function: FUN_80155df4
// Entry: 80155df4
// Size: 356 bytes

void FUN_80155df4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9,int param_10)

{
  short sVar1;
  uint uVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  ushort local_18 [2];
  float afStack_14 [3];
  
  if (*(char *)(param_10 + 0x33a) == '\0') {
    FUN_80155960(param_9,param_10);
  }
  else if ((*(short *)(*(int *)(param_10 + 0x29c) + 0x44) == 1) &&
          (uVar2 = FUN_8029641c(*(int *)(param_10 + 0x29c)), uVar2 != 0)) {
    FUN_80035eec((int)param_9,10,1,0);
    sVar1 = *(short *)(param_9 + 0x28);
    if (sVar1 == 3) {
      FUN_80155460((double)FLOAT_803e3698,(short *)param_9,param_10,0x19);
    }
    else if ((sVar1 == 0) || (sVar1 == 1)) {
      FUN_80155460((double)FLOAT_803e36c8,(short *)param_9,param_10,0x19);
    }
    FUN_801551b8((int)param_9,param_10,local_18,afStack_14);
    if (((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) ||
       ((local_18[0] < 0x5dc && (*(short *)(param_9 + 0x28) != 1)))) {
      if (local_18[0] < 0x5dc) {
        FUN_8000bb38((uint)param_9,0x251);
        FUN_8014d504((double)FLOAT_803e36c8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)param_9,param_10,1,0,0,in_r8,in_r9,in_r10);
      }
      else {
        FUN_8014d504((double)FLOAT_803e36c8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)param_9,param_10,3,0,0,in_r8,in_r9,in_r10);
      }
    }
  }
  else {
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
  }
  return;
}

