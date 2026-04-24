// Function: FUN_8002c60c
// Entry: 8002c60c
// Size: 188 bytes

void FUN_8002c60c(int param_1,undefined4 param_2,int *param_3,int param_4,char param_5)

{
  short sVar1;
  short *psVar2;
  int iVar3;
  short *psVar4;
  
  psVar4 = *(short **)(*(int *)(param_1 + 0x50) + 0x28);
  *param_3 = 0;
  if (psVar4 != (short *)0x0) {
    iVar3 = 0;
    for (psVar2 = psVar4; *psVar2 != -1; psVar2 = psVar2 + 3) {
      if (param_4 == *psVar2) {
        sVar1 = psVar4[iVar3 + 1];
        *param_3 = (int)psVar4[iVar3 + 2];
        if (0x800 < *param_3) {
          *param_3 = 0x800;
        }
        if (param_5 != '\0') {
          FUN_8001f71c(param_3[1],0x34,(int)sVar1,*param_3);
          return;
        }
        FUN_80048f48(0x34,param_3[1],(int)sVar1,*param_3);
        return;
      }
      iVar3 = iVar3 + 3;
    }
  }
  return;
}

