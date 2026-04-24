// Function: FUN_80234e24
// Entry: 80234e24
// Size: 216 bytes

void FUN_80234e24(int param_1)

{
  if ((DAT_803ddd98 == 0) && (*(char *)(*(int *)(param_1 + 0x4c) + 0x1f) == '\0')) {
    DAT_803ddd98 = param_1;
  }
  if (param_1 == DAT_803ddd98) {
    for (FLOAT_803ddda0 = FLOAT_803e728c * FLOAT_803db414 + FLOAT_803ddda0;
        FLOAT_803e7288 < FLOAT_803ddda0; FLOAT_803ddda0 = FLOAT_803ddda0 - FLOAT_803e7288) {
    }
    for (FLOAT_803ddd9c = FLOAT_803e7290 * FLOAT_803db414 + FLOAT_803ddd9c;
        FLOAT_803e7288 < FLOAT_803ddd9c; FLOAT_803ddd9c = FLOAT_803ddd9c - FLOAT_803e7288) {
    }
  }
  if ((*(short *)(param_1 + 0x46) < 0x6b2) && (0x6ae < *(short *)(param_1 + 0x46))) {
    FUN_80030334((double)FLOAT_803ddda0,param_1,0,0);
  }
  else {
    FUN_80030334((double)FLOAT_803ddd9c,param_1,0,0);
  }
  return;
}

