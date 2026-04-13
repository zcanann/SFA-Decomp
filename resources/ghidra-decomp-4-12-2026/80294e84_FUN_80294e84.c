// Function: FUN_80294e84
// Entry: 80294e84
// Size: 168 bytes

double FUN_80294e84(double param_1)

{
  uint uVar1;
  float fVar2;
  double dVar3;
  
  fVar2 = (float)param_1;
  dVar3 = (double)fVar2;
  uVar1 = (uint)param_1;
  if (((float)((double)(float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e8ac8) -
              dVar3) != 0.0) && (((uint)fVar2 & 0x7f800000) < 0x4b800000)) {
    if (((uint)fVar2 & 0x80000000) == 0) {
      dVar3 = (double)(float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e8ac8);
    }
    else {
      dVar3 = (double)(float)((double)CONCAT44(0x43300000,uVar1 - 1 ^ 0x80000000) - DOUBLE_803e8ac8)
      ;
    }
  }
  return dVar3;
}

