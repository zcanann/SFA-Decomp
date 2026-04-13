// Function: FUN_80235b90
// Entry: 80235b90
// Size: 284 bytes

void FUN_80235b90(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  double dVar3;
  float local_18;
  float local_14 [3];
  
  iVar2 = *(int *)(param_9 + 0x26);
  FUN_80235700(param_9,local_14,&local_18);
  dVar3 = (double)local_18;
  iVar1 = FUN_80021884();
  *param_9 = (short)iVar1 + 0x4000;
  if ((DAT_803dea28 == (short *)0x0) && (*(char *)(iVar2 + 0x1f) == '\0')) {
    DAT_803dea28 = param_9;
  }
  if (param_9 == DAT_803dea28) {
    dVar3 = (double)FLOAT_803dc074;
    for (FLOAT_803dea30 = (float)((double)FLOAT_803e7f84 * dVar3 + (double)FLOAT_803dea30);
        FLOAT_803e7f80 < FLOAT_803dea30; FLOAT_803dea30 = FLOAT_803dea30 - FLOAT_803e7f80) {
    }
    for (FLOAT_803dea2c = (float)((double)FLOAT_803e7f88 * dVar3 + (double)FLOAT_803dea2c);
        FLOAT_803e7f80 < FLOAT_803dea2c; FLOAT_803dea2c = FLOAT_803dea2c - FLOAT_803e7f80) {
    }
  }
  if ((FLOAT_803e7f48 == local_14[0]) && (FLOAT_803e7f48 == local_18)) {
    FUN_8003042c((double)FLOAT_803dea30,dVar3,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,1,0,param_12,param_13,param_14,param_15,param_16);
  }
  else {
    FUN_8003042c((double)FLOAT_803dea30,dVar3,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

