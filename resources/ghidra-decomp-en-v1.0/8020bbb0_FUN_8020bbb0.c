// Function: FUN_8020bbb0
// Entry: 8020bbb0
// Size: 596 bytes

void FUN_8020bbb0(int param_1)

{
  short sVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  int local_38;
  int local_34;
  undefined auStack48 [4];
  undefined auStack44 [4];
  undefined auStack40 [8];
  undefined4 local_20;
  uint uStack28;
  
  piVar4 = *(int **)(param_1 + 0xb8);
  if (*piVar4 != 0) {
    iVar2 = FUN_800801a8(piVar4 + 4);
    iVar3 = FUN_80036770(param_1,&local_38,0,&local_34,auStack48,auStack44,auStack40);
    if (iVar3 == 0) {
      piVar4[2] = 0;
    }
    else if (((*(short *)(local_38 + 0x46) != 0x35f) && (piVar4[2] != local_38)) &&
            (iVar3 = FUN_8007fe74(piVar4[0x1b],2), iVar3 != -1)) {
      piVar4[2] = local_38;
      FUN_80221e94((double)FLOAT_803e6598,param_1,auStack48);
      *piVar4 = *piVar4 - local_34;
      if (*piVar4 < 1) {
        iVar2 = 1;
      }
      else {
        FUN_8000bb18(param_1,0x496);
      }
    }
    if (iVar2 != 0) {
      iVar2 = *(int *)(param_1 + 0x4c);
      *piVar4 = 0;
      sVar1 = *(short *)(param_1 + 0x46);
      if (sVar1 == 0x727) {
        uStack28 = (int)*(short *)(iVar2 + 0x1c) ^ 0x80000000;
        local_20 = 0x43300000;
        FUN_8009ab70((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e65a0),
                     param_1,1,0,0,0,0,1,1);
      }
      else if ((sVar1 < 0x727) && (sVar1 == 0x709)) {
        FUN_8000bb18(param_1,0x2f9);
        uStack28 = piVar4[0x1d] << 1 ^ 0x80000000;
        local_20 = 0x43300000;
        FUN_8009ab70((double)(float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e65a0),
                     param_1,1,1,1,1,0,1,0);
        FUN_80221978((double)FLOAT_803e6588,param_1,piVar4 + 5,3,piVar4 + 0x19);
      }
      if (*(short *)(iVar2 + 0x1a) == 0) {
        if (*(int *)(iVar2 + 0x14) == -1) {
          FUN_8002cbc4(param_1);
        }
        else {
          FUN_8002ce88(param_1);
          FUN_80035f00(param_1);
          *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
        }
      }
      else {
        FUN_80080178(piVar4 + 3);
        *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
        FUN_80035f00(param_1);
      }
    }
  }
  return;
}

