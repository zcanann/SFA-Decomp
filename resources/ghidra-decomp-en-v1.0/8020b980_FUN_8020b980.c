// Function: FUN_8020b980
// Entry: 8020b980
// Size: 300 bytes

void FUN_8020b980(int param_1,int param_2)

{
  float fVar1;
  float *pfVar2;
  
  pfVar2 = *(float **)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x19) == '\0') {
    *(undefined *)(param_2 + 0x19) = 10;
  }
  if (*(short *)(param_2 + 0x1a) < 1) {
    *(undefined2 *)(param_2 + 0x1a) = 0x1e;
  }
  pfVar2[3] = 0.0;
  *(byte *)(pfVar2 + 0x66) = *(byte *)(pfVar2 + 0x66) & 0x7f;
  *pfVar2 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x19)) - DOUBLE_803e6580);
  pfVar2[0x5c] = (float)(int)*(short *)(param_2 + 0x1a);
  fVar1 = FLOAT_803e6510;
  pfVar2[5] = FLOAT_803e6510;
  pfVar2[0x5a] = 0.0;
  pfVar2[0x5b] = -NAN;
  pfVar2[0x5d] = 0.0;
  pfVar2[0x59] = FLOAT_803e657c;
  *(byte *)(pfVar2 + 0x66) = *(byte *)(pfVar2 + 0x66) & 0xbf | 0x40;
  pfVar2[0x5e] = fVar1;
  pfVar2[0x5f] = fVar1;
  pfVar2[0x65] = 0.0;
  pfVar2[99] = fVar1;
  *(byte *)(pfVar2 + 0x66) = *(byte *)(pfVar2 + 0x66) & 0xef | 0x10;
  FUN_8008016c(pfVar2 + 4);
  FUN_80037200(param_1,0x45);
  FUN_8008016c(pfVar2 + 6);
  *(code **)(param_1 + 0xbc) = FUN_8020a1c8;
  FUN_8000a518(0x26,1);
  FUN_8000a518(0x96,1);
  pfVar2[0x58] = 0.0;
  return;
}

