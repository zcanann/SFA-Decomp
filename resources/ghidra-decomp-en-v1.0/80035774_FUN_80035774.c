// Function: FUN_80035774
// Entry: 80035774
// Size: 180 bytes

void FUN_80035774(int param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5,
                 int param_6)

{
  short sVar1;
  short *psVar2;
  int iVar3;
  short *psVar4;
  
  psVar4 = *(short **)(*(int *)(param_1 + 0x50) + 0x24);
  *(undefined2 *)(param_4 + 4) = 0;
  if (psVar4 != (short *)0x0) {
    iVar3 = 0;
    for (psVar2 = psVar4; *psVar2 != -1; psVar2 = psVar2 + 3) {
      if (param_5 == *psVar2) {
        sVar1 = psVar4[iVar3 + 1];
        *(short *)(param_4 + 4) = psVar4[iVar3 + 2];
        if (*(short *)(param_4 + 6) < *(short *)(param_4 + 4)) {
          *(short *)(param_4 + 4) = *(short *)(param_4 + 6);
        }
        if (param_6 == 0) {
          FUN_8001f71c(*(undefined4 *)(param_4 + 8),0x41,(int)sVar1,(int)*(short *)(param_4 + 4));
          return;
        }
        FUN_80048f48(0x41,*(undefined4 *)(param_4 + 8),(int)sVar1,(int)*(short *)(param_4 + 4));
        return;
      }
      iVar3 = iVar3 + 3;
    }
  }
  return;
}

