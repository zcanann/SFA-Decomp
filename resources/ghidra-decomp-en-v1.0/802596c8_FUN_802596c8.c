// Function: FUN_802596c8
// Entry: 802596c8
// Size: 384 bytes

void FUN_802596c8(double param_1,int param_2,undefined4 param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  
  if ((param_1 <= (double)FLOAT_803e7680) || ((double)FLOAT_803e7684 < param_1)) {
    param_3 = 0;
  }
  dVar4 = (double)FUN_80294850((double)((float)((double)FLOAT_803e7688 * param_1) / FLOAT_803e768c))
  ;
  fVar2 = FLOAT_803e7680;
  fVar3 = FLOAT_803e7680;
  fVar1 = FLOAT_803e7698;
  switch(param_3) {
  case 1:
    fVar1 = (float)((double)FLOAT_803e7690 * dVar4);
    fVar2 = FLOAT_803e7694;
    break;
  case 2:
    dVar5 = (double)(float)((double)FLOAT_803e7698 - dVar4);
    fVar1 = (float)(-dVar4 / dVar5);
    fVar2 = (float)((double)FLOAT_803e7698 / dVar5);
    break;
  case 3:
    dVar5 = (double)(float)((double)FLOAT_803e7698 - dVar4);
    fVar2 = (float)(-dVar4 / dVar5);
    fVar3 = (float)((double)FLOAT_803e7698 / dVar5);
    fVar1 = FLOAT_803e7680;
    break;
  case 4:
    dVar5 = (double)((float)((double)FLOAT_803e7698 - dVar4) *
                    (float)((double)FLOAT_803e7698 - dVar4));
    fVar2 = (float)((double)FLOAT_803e769c / dVar5);
    fVar3 = (float)((double)FLOAT_803e76a0 / dVar5);
    fVar1 = (float)((double)(float)(dVar4 * (double)(float)(dVar4 - (double)FLOAT_803e769c)) / dVar5
                   );
    break;
  case 5:
    fVar1 = (float)((double)FLOAT_803e7698 - dVar4);
    dVar5 = (double)(fVar1 * fVar1);
    fVar2 = (float)((double)(FLOAT_803e76a8 * (float)((double)FLOAT_803e7698 + dVar4)) / dVar5);
    fVar3 = (float)((double)FLOAT_803e76a4 / dVar5);
    fVar1 = (float)((double)(float)((double)FLOAT_803e76a4 * dVar4) / dVar5);
    break;
  case 6:
    fVar1 = (float)((double)FLOAT_803e7698 - dVar4);
    fVar1 = fVar1 * fVar1;
    fVar2 = (float)((double)FLOAT_803e76a8 * dVar4) / fVar1;
    fVar3 = FLOAT_803e76ac / fVar1;
    fVar1 = (float)((double)FLOAT_803e7698 -
                   (double)((float)((double)(float)((double)FLOAT_803e769c * dVar4) * dVar4) / fVar1
                           ));
  }
  *(float *)(param_2 + 0x10) = fVar1;
  *(float *)(param_2 + 0x14) = fVar2;
  *(float *)(param_2 + 0x18) = fVar3;
  return;
}

