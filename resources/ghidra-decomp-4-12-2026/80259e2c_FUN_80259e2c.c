// Function: FUN_80259e2c
// Entry: 80259e2c
// Size: 384 bytes

void FUN_80259e2c(double param_1,int param_2,undefined4 param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  
  if ((param_1 <= (double)FLOAT_803e8318) || ((double)FLOAT_803e831c < param_1)) {
    param_3 = 0;
  }
  dVar4 = FUN_80294fb0((double)((float)((double)FLOAT_803e8320 * param_1) / FLOAT_803e8324));
  fVar2 = FLOAT_803e8318;
  switch(param_3) {
  default:
    fVar1 = FLOAT_803e8318;
    fVar3 = FLOAT_803e8330;
    break;
  case 1:
    fVar3 = (float)((double)FLOAT_803e8328 * dVar4);
    fVar1 = FLOAT_803e832c;
    break;
  case 2:
    dVar5 = (double)(float)((double)FLOAT_803e8330 - dVar4);
    fVar3 = (float)(-dVar4 / dVar5);
    fVar1 = (float)((double)FLOAT_803e8330 / dVar5);
    break;
  case 3:
    dVar5 = (double)(float)((double)FLOAT_803e8330 - dVar4);
    fVar1 = (float)(-dVar4 / dVar5);
    fVar2 = (float)((double)FLOAT_803e8330 / dVar5);
    fVar3 = FLOAT_803e8318;
    break;
  case 4:
    dVar5 = (double)((float)((double)FLOAT_803e8330 - dVar4) *
                    (float)((double)FLOAT_803e8330 - dVar4));
    fVar1 = (float)((double)FLOAT_803e8334 / dVar5);
    fVar3 = (float)((double)(float)(dVar4 * (double)(float)(dVar4 - (double)FLOAT_803e8334)) / dVar5
                   );
    fVar2 = (float)((double)FLOAT_803e8338 / dVar5);
    break;
  case 5:
    fVar2 = (float)((double)FLOAT_803e8330 - dVar4);
    dVar5 = (double)(fVar2 * fVar2);
    fVar3 = (float)((double)(float)((double)FLOAT_803e833c * dVar4) / dVar5);
    fVar1 = (float)((double)(FLOAT_803e8340 * (float)((double)FLOAT_803e8330 + dVar4)) / dVar5);
    fVar2 = (float)((double)FLOAT_803e833c / dVar5);
    break;
  case 6:
    fVar2 = (float)((double)FLOAT_803e8330 - dVar4);
    fVar2 = fVar2 * fVar2;
    fVar1 = (float)((double)FLOAT_803e8340 * dVar4) / fVar2;
    fVar3 = (float)((double)FLOAT_803e8330 -
                   (double)((float)((double)(float)((double)FLOAT_803e8334 * dVar4) * dVar4) / fVar2
                           ));
    fVar2 = FLOAT_803e8344 / fVar2;
  }
  *(float *)(param_2 + 0x10) = fVar3;
  *(float *)(param_2 + 0x14) = fVar1;
  *(float *)(param_2 + 0x18) = fVar2;
  return;
}

