// Function: FUN_8019e568
// Entry: 8019e568
// Size: 352 bytes

void FUN_8019e568(short *param_1,undefined4 param_2,int param_3,int param_4)

{
  short sVar1;
  int iVar2;
  
  FUN_8003adc4(param_1,param_2,param_3 + 0x3c,0x28,0,3);
  iVar2 = FUN_800385e8(param_1,param_2,0);
  sVar1 = (short)(iVar2 >> 3);
  *param_1 = *param_1 + sVar1;
  if (param_4 != 0) {
    if ((sVar1 < -199) || (199 < sVar1)) {
      if (*(int *)(param_3 + 0xc0) == 0) {
        *(undefined4 *)(param_3 + 0xc0) = 1;
        FUN_80030334((double)FLOAT_803e4218,param_1,9,0);
      }
      else {
        iVar2 = (int)sVar1;
        if (iVar2 < 1) {
          sVar1 = (short)(-iVar2 >> 2);
        }
        else {
          sVar1 = (short)(iVar2 >> 2);
        }
        FUN_8002fa48((double)((float)((double)CONCAT44(0x43300000,(int)sVar1 ^ 0x80000000) -
                                     DOUBLE_803e4220) / FLOAT_803e4240),(double)FLOAT_803db414,
                     param_1,0);
      }
    }
    else if (*(int *)(param_3 + 0xc0) == 0) {
      FUN_8002fa48((double)FLOAT_803e423c,(double)FLOAT_803db414,param_1,0);
    }
    else {
      *(undefined4 *)(param_3 + 0xc0) = 0;
      FUN_80030334((double)FLOAT_803e4218,param_1,0,0);
    }
  }
  return;
}

