// Function: FUN_8003586c
// Entry: 8003586c
// Size: 180 bytes

void FUN_8003586c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,int param_12,int param_13,
                 int param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  short *psVar2;
  int iVar3;
  short *psVar4;
  
  psVar4 = *(short **)(*(int *)(param_9 + 0x50) + 0x24);
  *(undefined2 *)(param_12 + 4) = 0;
  if (psVar4 != (short *)0x0) {
    iVar3 = 0;
    for (psVar2 = psVar4; *psVar2 != -1; psVar2 = psVar2 + 3) {
      if (param_13 == *psVar2) {
        sVar1 = psVar4[iVar3 + 1];
        *(short *)(param_12 + 4) = psVar4[iVar3 + 2];
        if (*(short *)(param_12 + 6) < *(short *)(param_12 + 4)) {
          *(short *)(param_12 + 4) = *(short *)(param_12 + 6);
        }
        if (param_14 == 0) {
          FUN_8001f7e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       *(undefined4 *)(param_12 + 8),0x41,(int)sVar1,(int)*(short *)(param_12 + 4),
                       param_13,0,param_15,param_16);
          return;
        }
        FUN_800490c4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x41,
                     *(undefined4 *)(param_12 + 8),(int)sVar1,(int)*(short *)(param_12 + 4),param_13
                     ,param_14,param_15,param_16);
        return;
      }
      iVar3 = iVar3 + 3;
    }
  }
  return;
}

