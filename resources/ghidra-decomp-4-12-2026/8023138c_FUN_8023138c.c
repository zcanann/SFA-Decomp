// Function: FUN_8023138c
// Entry: 8023138c
// Size: 348 bytes

void FUN_8023138c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  char cVar1;
  float fVar2;
  float *pfVar3;
  undefined8 uVar4;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  *(code **)(param_9 + 0xbc) = FUN_80230fc8;
  *(undefined2 *)(pfVar3 + 5) = 1;
  *(undefined2 *)((int)pfVar3 + 0x16) = 0x50;
  fVar2 = FLOAT_803e7d84;
  *pfVar3 = FLOAT_803e7d84;
  pfVar3[1] = fVar2;
  pfVar3[2] = FLOAT_803e7d88;
  pfVar3[3] = FLOAT_803e7d8c;
  if (*(int *)(param_10 + 0x14) == 0x48f7e) {
    *(undefined *)((int)pfVar3 + 0x1b) = 1;
  }
  if (*(char *)((int)pfVar3 + 0x19) == '\0') {
    FUN_800201ac(0x9d6,0);
    FUN_800201ac(0x9d8,0);
    FUN_800201ac(0x9d7,0);
    FUN_800201ac(0xe74,0);
  }
  uVar4 = FUN_8011f638(2);
  FUN_80126070(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  cVar1 = *(char *)(param_9 + 0xac);
  if (cVar1 == '<') {
    pfVar3[7] = 2.93236e-41;
    *(undefined2 *)(pfVar3 + 8) = 0x6e1;
    return;
  }
  if (cVar1 < '<') {
    if (cVar1 == ':') {
      pfVar3[7] = 2.93208e-41;
      *(undefined2 *)(pfVar3 + 8) = 0x6e3;
      return;
    }
    if ('9' < cVar1) {
      pfVar3[7] = 2.93222e-41;
      *(undefined2 *)(pfVar3 + 8) = 0x6df;
      return;
    }
  }
  else if ((cVar1 != '>') && (cVar1 < '>')) {
    pfVar3[7] = 2.9325e-41;
    *(undefined2 *)(pfVar3 + 8) = 0x6e2;
    return;
  }
  pfVar3[7] = 2.93264e-41;
  *(undefined2 *)(pfVar3 + 8) = 0x6e0;
  return;
}

