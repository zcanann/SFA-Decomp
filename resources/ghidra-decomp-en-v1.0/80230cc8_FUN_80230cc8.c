// Function: FUN_80230cc8
// Entry: 80230cc8
// Size: 348 bytes

void FUN_80230cc8(int param_1,int param_2)

{
  char cVar1;
  float fVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_80230904;
  *(undefined2 *)(pfVar3 + 5) = 1;
  *(undefined2 *)((int)pfVar3 + 0x16) = 0x50;
  fVar2 = FLOAT_803e70ec;
  *pfVar3 = FLOAT_803e70ec;
  pfVar3[1] = fVar2;
  pfVar3[2] = FLOAT_803e70f0;
  pfVar3[3] = FLOAT_803e70f4;
  if (*(int *)(param_2 + 0x14) == 0x48f7e) {
    *(undefined *)((int)pfVar3 + 0x1b) = 1;
  }
  if (*(char *)((int)pfVar3 + 0x19) == '\0') {
    FUN_800200e8(0x9d6,0);
    FUN_800200e8(0x9d8,0);
    FUN_800200e8(0x9d7,0);
    FUN_800200e8(0xe74,0);
  }
  FUN_8011f354(2);
  FUN_80125d8c();
  cVar1 = *(char *)(param_1 + 0xac);
  if (cVar1 == '<') {
    pfVar3[7] = 2.932357e-41;
    *(undefined2 *)(pfVar3 + 8) = 0x6e1;
    return;
  }
  if (cVar1 < '<') {
    if (cVar1 == ':') {
      pfVar3[7] = 2.932077e-41;
      *(undefined2 *)(pfVar3 + 8) = 0x6e3;
      return;
    }
    if ('9' < cVar1) {
      pfVar3[7] = 2.932217e-41;
      *(undefined2 *)(pfVar3 + 8) = 0x6df;
      return;
    }
  }
  else if ((cVar1 != '>') && (cVar1 < '>')) {
    pfVar3[7] = 2.932497e-41;
    *(undefined2 *)(pfVar3 + 8) = 0x6e2;
    return;
  }
  pfVar3[7] = 2.932637e-41;
  *(undefined2 *)(pfVar3 + 8) = 0x6e0;
  return;
}

