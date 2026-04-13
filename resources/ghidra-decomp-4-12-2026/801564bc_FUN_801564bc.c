// Function: FUN_801564bc
// Entry: 801564bc
// Size: 376 bytes

void FUN_801564bc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)

{
  bool bVar1;
  short sVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar3;
  
  *(float *)(param_10 + 0x324) = *(float *)(param_10 + 0x324) - FLOAT_803dc074;
  dVar3 = (double)*(float *)(param_10 + 0x324);
  bVar1 = dVar3 <= (double)FLOAT_803e36f8;
  if (bVar1) {
    *(float *)(param_10 + 0x324) = FLOAT_803e36f8;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    sVar2 = *(short *)(param_9 + 0xa0);
    if (sVar2 == 4) {
      FUN_80155fbc(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
      *(float *)(param_10 + 0x324) = FLOAT_803e3718;
      dVar3 = (double)FUN_8014d504((double)FLOAT_803e36ec,param_2,param_3,param_4,param_5,param_6,
                                   param_7,param_8,param_9,param_10,5,0,0,in_r8,in_r9,in_r10);
    }
    else if ((sVar2 == 5) && (bVar1)) {
      FUN_8014d504((double)FLOAT_803e36ec,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,param_10,6,0,0,in_r8,in_r9,in_r10);
      dVar3 = (double)FUN_8000bb38(param_9,0x24c);
    }
    else if (sVar2 == 6) {
      dVar3 = (double)FUN_8014d504((double)FLOAT_803e36ec,param_2,param_3,param_4,param_5,param_6,
                                   param_7,param_8,param_9,param_10,2,0,0,in_r8,in_r9,in_r10);
      *(float *)(param_10 + 0x324) = FLOAT_803e3718;
    }
    else if (((sVar2 == 2) && (bVar1)) && ((*(uint *)(param_10 + 0x2dc) & 0x4000000) != 0)) {
      FUN_8014d504((double)FLOAT_803e36ec,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,param_10,4,0,0,in_r8,in_r9,in_r10);
      dVar3 = (double)FUN_8000bb38(param_9,0x24b);
    }
  }
  FUN_801561a4(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10);
  return;
}

