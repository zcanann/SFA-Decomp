// Function: FUN_8002c6e4
// Entry: 8002c6e4
// Size: 188 bytes

void FUN_8002c6e4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,uint *param_11,int param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  short *psVar2;
  int iVar3;
  short *psVar4;
  
  psVar4 = *(short **)(*(int *)(param_9 + 0x50) + 0x28);
  *param_11 = 0;
  if (psVar4 != (short *)0x0) {
    iVar3 = 0;
    for (psVar2 = psVar4; *psVar2 != -1; psVar2 = psVar2 + 3) {
      if (param_12 == *psVar2) {
        sVar1 = psVar4[iVar3 + 1];
        *param_11 = (int)psVar4[iVar3 + 2];
        if (0x800 < (int)*param_11) {
          *param_11 = 0x800;
        }
        if ((param_13 & 0xff) != 0) {
          FUN_8001f7e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_11[1],
                       0x34,(int)sVar1,*param_11,param_13,param_11,param_15,param_16);
          return;
        }
        FUN_800490c4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x34,
                     param_11[1],(int)sVar1,*param_11,param_13,param_11,param_15,param_16);
        return;
      }
      iVar3 = iVar3 + 3;
    }
  }
  return;
}

