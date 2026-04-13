// Function: FUN_802a8918
// Entry: 802a8918
// Size: 408 bytes

void FUN_802a8918(int param_1,int param_2,float *param_3)

{
  double dVar1;
  
  if (((*(byte *)(param_2 + 0x3f1) >> 5 & 1) == 0) && (*(int *)(param_2 + 0x2d0) == 0)) {
    dVar1 = (double)FUN_802945e0();
    *param_3 = (float)-dVar1;
    param_3[1] = FLOAT_803e8b3c;
    dVar1 = (double)FUN_80294964();
    param_3[2] = (float)-dVar1;
  }
  else {
    *param_3 = *(float *)(param_1 + 0x24);
    param_3[1] = FLOAT_803e8b3c;
    param_3[2] = *(float *)(param_1 + 0x2c);
    dVar1 = FUN_80247f54(param_3);
    if (dVar1 <= (double)FLOAT_803e8b3c) {
      dVar1 = (double)FUN_802945e0();
      *param_3 = (float)-dVar1;
      param_3[1] = FLOAT_803e8b3c;
      dVar1 = (double)FUN_80294964();
      param_3[2] = (float)-dVar1;
    }
    else {
      FUN_80247edc((double)(float)((double)FLOAT_803e8b78 / dVar1),param_3,param_3);
    }
  }
  return;
}

