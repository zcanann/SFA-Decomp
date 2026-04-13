// Function: FUN_8020c228
// Entry: 8020c228
// Size: 596 bytes

void FUN_8020c228(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  int local_38;
  uint local_34;
  float fStack_30;
  undefined4 uStack_2c;
  undefined4 auStack_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  piVar4 = *(int **)(param_9 + 0xb8);
  if (*piVar4 != 0) {
    iVar2 = FUN_80080434((float *)(piVar4 + 4));
    iVar3 = FUN_80036868(param_9,&local_38,(int *)0x0,&local_34,&fStack_30,&uStack_2c,auStack_28);
    if (iVar3 == 0) {
      piVar4[2] = 0;
    }
    else if (((*(short *)(local_38 + 0x46) != 0x35f) && (piVar4[2] != local_38)) &&
            (iVar3 = FUN_80080100((int *)piVar4[0x1b],2,iVar3), iVar3 != -1)) {
      piVar4[2] = local_38;
      param_1 = FUN_802224e4(param_9,&fStack_30);
      *piVar4 = *piVar4 - local_34;
      if (*piVar4 < 1) {
        iVar2 = 1;
      }
      else {
        param_1 = FUN_8000bb38(param_9,0x496);
      }
    }
    if (iVar2 != 0) {
      iVar2 = *(int *)(param_9 + 0x4c);
      *piVar4 = 0;
      sVar1 = *(short *)(param_9 + 0x46);
      if (sVar1 == 0x727) {
        uStack_1c = (int)*(short *)(iVar2 + 0x1c) ^ 0x80000000;
        local_20 = 0x43300000;
        param_1 = FUN_8009adfc((double)(float)((double)CONCAT44(0x43300000,uStack_1c) -
                                              DOUBLE_803e7238),param_2,param_3,param_4,param_5,
                               param_6,param_7,param_8,param_9,1,0,0,0,0,1,1);
      }
      else if ((sVar1 < 0x727) && (sVar1 == 0x709)) {
        FUN_8000bb38(param_9,0x2f9);
        uStack_1c = piVar4[0x1d] << 1 ^ 0x80000000;
        local_20 = 0x43300000;
        FUN_8009adfc((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e7238),
                     param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,1,1,1,0,1,0);
        param_1 = FUN_80221fc8(param_9,piVar4 + 5,3,(uint *)(piVar4 + 0x19));
      }
      if (*(short *)(iVar2 + 0x1a) == 0) {
        if (*(int *)(iVar2 + 0x14) == -1) {
          FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
        }
        else {
          FUN_8002cf80(param_9);
          FUN_80035ff8(param_9);
          *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
        }
      }
      else {
        FUN_80080404((float *)(piVar4 + 3),*(short *)(iVar2 + 0x1a));
        *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
        FUN_80035ff8(param_9);
      }
    }
  }
  return;
}

