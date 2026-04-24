// Function: FUN_80022150
// Entry: 80022150
// Size: 276 bytes

uint FUN_80022150(double param_1,double param_2,float *param_3)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined8 local_28;
  
  fVar1 = FLOAT_803df474;
  *param_3 = *param_3 + FLOAT_803dc074 / FLOAT_803df474;
  if ((double)*param_3 <= param_1) {
    uVar3 = 0;
  }
  else {
    if ((double)*param_3 <= param_2) {
      uVar3 = (uint)(FLOAT_803dc078 * fVar1 * (float)(param_2 - param_1));
      if (uVar3 == 0) {
        iVar2 = 0;
      }
      else {
        uVar4 = FUN_80293520();
        local_28 = (double)CONCAT44(0x43300000,uVar4);
        iVar2 = (int)(((float)(local_28 - DOUBLE_803df480) / FLOAT_803df478) *
                      ((FLOAT_803df444 +
                       (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803df460)) -
                      FLOAT_803df440) + FLOAT_803df440);
      }
      uVar3 = countLeadingZeros(iVar2);
      uVar3 = uVar3 >> 5;
    }
    else {
      uVar3 = 1;
    }
    if (uVar3 != 0) {
      *param_3 = FLOAT_803df440;
    }
  }
  return uVar3;
}

