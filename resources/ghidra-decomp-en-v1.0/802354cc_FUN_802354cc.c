// Function: FUN_802354cc
// Entry: 802354cc
// Size: 284 bytes

void FUN_802354cc(short *param_1)

{
  short sVar1;
  int iVar2;
  float local_18;
  float local_14 [3];
  
  iVar2 = *(int *)(param_1 + 0x26);
  FUN_8023503c(param_1,local_14,&local_18);
  sVar1 = FUN_800217c0((double)local_14[0],(double)local_18);
  *param_1 = sVar1 + 0x4000;
  if ((DAT_803ddda8 == (short *)0x0) && (*(char *)(iVar2 + 0x1f) == '\0')) {
    DAT_803ddda8 = param_1;
  }
  if (param_1 == DAT_803ddda8) {
    for (FLOAT_803dddb0 = FLOAT_803e72ec * FLOAT_803db414 + FLOAT_803dddb0;
        FLOAT_803e72e8 < FLOAT_803dddb0; FLOAT_803dddb0 = FLOAT_803dddb0 - FLOAT_803e72e8) {
    }
    for (FLOAT_803dddac = FLOAT_803e72f0 * FLOAT_803db414 + FLOAT_803dddac;
        FLOAT_803e72e8 < FLOAT_803dddac; FLOAT_803dddac = FLOAT_803dddac - FLOAT_803e72e8) {
    }
  }
  if ((FLOAT_803e72b0 == local_14[0]) && (FLOAT_803e72b0 == local_18)) {
    FUN_80030334((double)FLOAT_803dddb0,param_1,1,0);
  }
  else {
    FUN_80030334((double)FLOAT_803dddb0,param_1,0,0);
  }
  return;
}

