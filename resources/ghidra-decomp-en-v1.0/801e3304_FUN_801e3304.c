// Function: FUN_801e3304
// Entry: 801e3304
// Size: 268 bytes

void FUN_801e3304(int param_1)

{
  float fVar1;
  int iVar2;
  double dVar3;
  
  fVar1 = FLOAT_803e586c;
  if (*(int *)(param_1 + 0x30) != 0) {
    iVar2 = *(int *)(*(int *)(param_1 + 0x30) + 0xf4);
    *(float *)(param_1 + 0xc) = FLOAT_803e586c;
    *(float *)(param_1 + 0x10) = fVar1;
    *(float *)(param_1 + 0x14) = fVar1;
    if (*(short *)(*(int *)(param_1 + 0x30) + 0x46) == 0x139) {
      if ((iVar2 < 10) || (0xc < iVar2)) {
        if (*(short *)(param_1 + 0xa0) != 1) {
          FUN_80030334((double)FLOAT_803e586c,param_1,1,0);
        }
        dVar3 = (double)FLOAT_803e5878;
      }
      else {
        if (*(short *)(param_1 + 0xa0) != 0) {
          FUN_80030334(param_1,0,0);
        }
        if (iVar2 < 0xc) {
          dVar3 = (double)FLOAT_803e5874;
        }
        else {
          dVar3 = (double)FLOAT_803e5870;
        }
      }
    }
    else {
      if (*(short *)(param_1 + 0xa0) != 1) {
        FUN_80030334(param_1,1,0);
      }
      dVar3 = (double)FLOAT_803e5878;
    }
    FUN_8002fa48(dVar3,(double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803db410) -
                                      DOUBLE_803e5880),param_1,0);
  }
  return;
}

