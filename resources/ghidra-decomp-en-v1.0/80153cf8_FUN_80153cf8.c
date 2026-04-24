// Function: FUN_80153cf8
// Entry: 80153cf8
// Size: 276 bytes

void FUN_80153cf8(int param_1,int param_2,undefined4 param_3,int param_4)

{
  short sVar1;
  bool bVar2;
  
  bVar2 = false;
  sVar1 = *(short *)(param_1 + 0xa0);
  if ((((sVar1 == 5) || (sVar1 == 4)) ||
      ((sVar1 == 6 && ((double)*(float *)(param_1 + 0x98) < DOUBLE_803e2938)))) && (param_4 != 0xe))
  {
    bVar2 = true;
  }
  if (param_4 == 0x10) {
    if (bVar2) {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x20;
    }
  }
  else if (bVar2) {
    if (*(char *)(param_2 + 0x33b) == '\0') {
      *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 8;
      *(undefined2 *)(param_2 + 0x2b0) = 0;
      FUN_8000bb18(param_1,0x25f);
    }
  }
  else if (param_4 == 0x11) {
    *(float *)(param_2 + 0x32c) = FLOAT_803e2940;
    *(float *)(param_2 + 0x324) = FLOAT_803e2944;
    FUN_8014d08c((double)FLOAT_803e2948,param_1,param_2,4,0,3);
    *(uint *)(param_2 + 0x2e4) = *(uint *)(param_2 + 0x2e4) | 0x10000;
    *(undefined *)(param_2 + 0x33b) = 0x3c;
  }
  else {
    *(uint *)(param_2 + 0x2e8) = *(uint *)(param_2 + 0x2e8) | 0x10;
  }
  return;
}

