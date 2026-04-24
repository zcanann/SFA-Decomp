// Function: FUN_80140248
// Entry: 80140248
// Size: 248 bytes

void FUN_80140248(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int param_11,undefined4 param_12,byte param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = FUN_8013b6f0((double)FLOAT_803e310c,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,param_10,param_11,param_12,param_13,param_14,param_15,
                       param_16);
  if (iVar2 == 0) {
    if (FLOAT_803e306c == *(float *)(param_10 + 0x2ac)) {
      bVar1 = false;
    }
    else if (FLOAT_803e30a0 == *(float *)(param_10 + 0x2b0)) {
      bVar1 = true;
    }
    else if (*(float *)(param_10 + 0x2b4) - *(float *)(param_10 + 0x2b0) <= FLOAT_803e30a4) {
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
    if (bVar1) {
      FUN_8013a778((double)FLOAT_803e30cc,param_9,8,0);
      *(float *)(param_10 + 0x79c) = FLOAT_803e30d0;
      *(float *)(param_10 + 0x838) = FLOAT_803e306c;
      FUN_80148ff0();
    }
    else {
      FUN_8013a778((double)FLOAT_803e30d4,param_9,0,0);
      FUN_80148ff0();
    }
  }
  return;
}

