// Function: FUN_801542b8
// Entry: 801542b8
// Size: 660 bytes

void FUN_801542b8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 *param_10)

{
  float fVar1;
  int iVar2;
  char cVar4;
  uint uVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  float *pfVar5;
  double dVar6;
  double dVar7;
  
  pfVar5 = (float *)*param_10;
  *(undefined *)((int)param_10 + 0x33a) = 0;
  param_10[0xca] = FLOAT_803e35e4;
  if ((param_10[0xb7] & 0x2000) != 0) {
    iVar2 = FUN_80010340((double)(float)param_10[0xbf],pfVar5);
    if ((((iVar2 != 0) || (pfVar5[4] != 0.0)) &&
        (cVar4 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar5), cVar4 != '\0')) &&
       (cVar4 = (**(code **)(*DAT_803dd71c + 0x8c))
                          ((double)FLOAT_803e35e8,*param_10,param_9,&DAT_803dc930,0xffffffff),
       cVar4 != '\0')) {
      param_10[0xb7] = param_10[0xb7] & 0xffffdfff;
    }
    if (FLOAT_803e35e4 == (float)param_10[0xcb]) {
      if (param_9[0x50] == 0) {
        FUN_8014d3f4(param_9,param_10,0x3c,0);
      }
      fVar1 = FLOAT_803e35e4;
      if (FLOAT_803e35e4 < (float)param_10[0xc9]) {
        param_10[0xc9] = (float)param_10[0xc9] - FLOAT_803dc074;
        if ((float)param_10[0xc9] <= fVar1) {
          param_10[0xb9] = param_10[0xb9] & 0xfffeffff;
          param_10[0xc9] = fVar1;
        }
      }
    }
  }
  dVar7 = (double)(float)param_10[0xcb];
  dVar6 = (double)FLOAT_803e35e4;
  if (dVar7 <= dVar6) {
    if ((param_10[0xb7] & 0x40000000) != 0) {
      FUN_8014d504((double)FLOAT_803e35f0,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,(int)param_10,0,0,3,in_r8,in_r9,in_r10);
    }
  }
  else {
    param_10[0xcb] = (float)(dVar7 - (double)FLOAT_803dc074);
    if (dVar6 < (double)(float)param_10[0xcb]) {
      if ((param_10[0xb7] & 0x40000000) != 0) {
        FUN_8014d504((double)FLOAT_803e35ec,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)param_9,(int)param_10,5,0,3,in_r8,in_r9,in_r10);
      }
    }
    else {
      FUN_8014d504((double)FLOAT_803e35e0,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,(int)param_10,6,0,3,in_r8,in_r9,in_r10);
      param_10[0xcb] = FLOAT_803e35e4;
    }
  }
  param_9[1] = *(short *)(param_10 + 0x67);
  param_9[2] = *(short *)((int)param_10 + 0x19e);
  param_10[0xcc] = (float)param_10[0xcc] - FLOAT_803dc074;
  if ((float)param_10[0xcc] <= FLOAT_803e35e4) {
    uVar3 = FUN_80022264(0x3c,0x78);
    param_10[0xcc] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e35f8);
    FUN_8000bb38((uint)param_9,0x25e);
  }
  if (*(char *)((int)param_10 + 0x33b) != '\0') {
    *(char *)((int)param_10 + 0x33b) = *(char *)((int)param_10 + 0x33b) + -1;
  }
  return;
}

