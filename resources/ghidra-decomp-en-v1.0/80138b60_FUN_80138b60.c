// Function: FUN_80138b60
// Entry: 80138b60
// Size: 540 bytes

void FUN_80138b60(undefined4 param_1,byte **param_2)

{
  byte *pbVar1;
  float fVar2;
  undefined4 uVar3;
  
  FUN_8002b588();
  if (*(char *)((int)param_2 + 0x82e) < '\0') {
    uVar3 = FUN_8002b588(param_1);
    FUN_800279cc((double)FLOAT_803e23dc,uVar3,1,0xffffffff,0x1a,0x21);
    param_2[0x20c] = (byte *)FLOAT_803e23e0;
    FUN_80027980((double)FLOAT_803e23dc,uVar3,0);
    *(byte *)((int)param_2 + 0x82e) = *(byte *)((int)param_2 + 0x82e) & 0x7f;
    *(byte *)((int)param_2 + 0x82e) = *(byte *)((int)param_2 + 0x82e) & 0xbf | 0x40;
  }
  if ((*(byte *)((int)param_2 + 0x82e) >> 6 & 1) != 0) {
    pbVar1 = (byte *)((float)((double)CONCAT44(0x43300000,(uint)**param_2) - DOUBLE_803e2400) /
                     (float)((double)CONCAT44(0x43300000,(uint)(*param_2)[1]) - DOUBLE_803e2400));
    if ((float)pbVar1 <= (float)param_2[0x20c]) {
      if ((float)pbVar1 < (float)param_2[0x20c]) {
        param_2[0x20d] = (byte *)-(FLOAT_803e23e4 * FLOAT_803db414 - (float)param_2[0x20d]);
        param_2[0x20c] = (byte *)((float)param_2[0x20d] * FLOAT_803db414 + (float)param_2[0x20c]);
        fVar2 = FLOAT_803e23dc;
        if ((float)param_2[0x20c] < FLOAT_803e23dc) {
          param_2[0x20d] = (byte *)FLOAT_803e23dc;
          param_2[0x20c] = (byte *)fVar2;
        }
        if ((float)param_2[0x20c] < (float)pbVar1) {
          if ((float)param_2[0x20d] <= FLOAT_803e23f4) {
            param_2[0x20d] = (byte *)((float)param_2[0x20d] * FLOAT_803e23f0);
          }
          else {
            param_2[0x20d] = (byte *)FLOAT_803e23dc;
            param_2[0x20c] = pbVar1;
          }
        }
      }
    }
    else {
      param_2[0x20d] = (byte *)(FLOAT_803e23e4 * FLOAT_803db414 + (float)param_2[0x20d]);
      param_2[0x20c] = (byte *)((float)param_2[0x20d] * FLOAT_803db414 + (float)param_2[0x20c]);
      fVar2 = FLOAT_803e23e8;
      if ((float)param_2[0x20c] <= FLOAT_803e23e8) {
        if ((float)pbVar1 < (float)param_2[0x20c]) {
          if (FLOAT_803e23ec <= (float)param_2[0x20d]) {
            param_2[0x20d] = (byte *)((float)param_2[0x20d] * FLOAT_803e23f0);
          }
          else {
            param_2[0x20d] = (byte *)FLOAT_803e23dc;
            param_2[0x20c] = pbVar1;
          }
        }
      }
      else {
        param_2[0x20d] = (byte *)FLOAT_803e23dc;
        param_2[0x20c] = (byte *)fVar2;
      }
    }
    uVar3 = FUN_8002b588(param_1);
    FUN_80027980((double)(FLOAT_803e23f8 * (float)param_2[0x20c] - FLOAT_803e23e8),uVar3,1);
  }
  return;
}

