// Function: FUN_80138ee8
// Entry: 80138ee8
// Size: 540 bytes

void FUN_80138ee8(int param_1,undefined4 *param_2)

{
  float fVar1;
  float fVar2;
  int *piVar3;
  
  FUN_8002b660(param_1);
  if (*(char *)((int)param_2 + 0x82e) < '\0') {
    piVar3 = (int *)FUN_8002b660(param_1);
    FUN_80027a90((double)FLOAT_803e306c,piVar3,1,-1,0x1a,0x21);
    param_2[0x20c] = FLOAT_803e3070;
    FUN_80027a44((double)FLOAT_803e306c,piVar3,0);
    *(byte *)((int)param_2 + 0x82e) = *(byte *)((int)param_2 + 0x82e) & 0x7f;
    *(byte *)((int)param_2 + 0x82e) = *(byte *)((int)param_2 + 0x82e) & 0xbf | 0x40;
  }
  if ((*(byte *)((int)param_2 + 0x82e) >> 6 & 1) != 0) {
    fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)*param_2) - DOUBLE_803e3090) /
            (float)((double)CONCAT44(0x43300000,(uint)((byte *)*param_2)[1]) - DOUBLE_803e3090);
    if (fVar1 <= (float)param_2[0x20c]) {
      if (fVar1 < (float)param_2[0x20c]) {
        param_2[0x20d] = -(FLOAT_803e3074 * FLOAT_803dc074 - (float)param_2[0x20d]);
        param_2[0x20c] = (float)param_2[0x20d] * FLOAT_803dc074 + (float)param_2[0x20c];
        fVar2 = FLOAT_803e306c;
        if ((float)param_2[0x20c] < FLOAT_803e306c) {
          param_2[0x20d] = FLOAT_803e306c;
          param_2[0x20c] = fVar2;
        }
        if ((float)param_2[0x20c] < fVar1) {
          if ((float)param_2[0x20d] <= FLOAT_803e3084) {
            param_2[0x20d] = (float)param_2[0x20d] * FLOAT_803e3080;
          }
          else {
            param_2[0x20d] = FLOAT_803e306c;
            param_2[0x20c] = fVar1;
          }
        }
      }
    }
    else {
      param_2[0x20d] = FLOAT_803e3074 * FLOAT_803dc074 + (float)param_2[0x20d];
      param_2[0x20c] = (float)param_2[0x20d] * FLOAT_803dc074 + (float)param_2[0x20c];
      fVar2 = FLOAT_803e3078;
      if ((float)param_2[0x20c] <= FLOAT_803e3078) {
        if (fVar1 < (float)param_2[0x20c]) {
          if (FLOAT_803e307c <= (float)param_2[0x20d]) {
            param_2[0x20d] = (float)param_2[0x20d] * FLOAT_803e3080;
          }
          else {
            param_2[0x20d] = FLOAT_803e306c;
            param_2[0x20c] = fVar1;
          }
        }
      }
      else {
        param_2[0x20d] = FLOAT_803e306c;
        param_2[0x20c] = fVar2;
      }
    }
    piVar3 = (int *)FUN_8002b660(param_1);
    FUN_80027a44((double)(FLOAT_803e3088 * (float)param_2[0x20c] - FLOAT_803e3078),piVar3,1);
  }
  return;
}

