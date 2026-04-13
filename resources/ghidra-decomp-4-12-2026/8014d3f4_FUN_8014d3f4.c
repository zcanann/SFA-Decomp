// Function: FUN_8014d3f4
// Entry: 8014d3f4
// Size: 272 bytes

void FUN_8014d3f4(short *param_1,undefined4 param_2,uint param_3,short param_4)

{
  float fVar1;
  short sVar2;
  int iVar3;
  
  iVar3 = FUN_80021884();
  sVar2 = (short)iVar3 - *param_1;
  if (0x8000 < sVar2) {
    sVar2 = sVar2 + 1;
  }
  if (sVar2 < -0x8000) {
    sVar2 = sVar2 + -1;
  }
  fVar1 = FLOAT_803dc074 / (float)((double)CONCAT44(0x43300000,param_3 & 0xffff) - DOUBLE_803e3278);
  if (FLOAT_803e3200 < fVar1) {
    fVar1 = FLOAT_803e3200;
  }
  *param_1 = *param_1 +
             (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)(short)(sVar2 + param_4) ^ 0x80000000) -
                                 DOUBLE_803e3218) * fVar1);
  return;
}

