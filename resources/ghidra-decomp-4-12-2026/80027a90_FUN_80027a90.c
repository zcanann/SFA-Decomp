// Function: FUN_80027a90
// Entry: 80027a90
// Size: 232 bytes

void FUN_80027a90(double param_1,int *param_2,int param_3,int param_4,int param_5,byte param_6)

{
  uint uVar1;
  float *pfVar2;
  
  if (2 < param_3) {
    return;
  }
  if (*(int *)(*param_2 + 0xdc) == 0) {
    return;
  }
  if (param_4 < -1) {
    return;
  }
  if (param_5 < -1) {
    return;
  }
  uVar1 = (uint)*(byte *)(*param_2 + 0xf9);
  if ((int)uVar1 <= param_4) {
    return;
  }
  if ((int)uVar1 <= param_5) {
    return;
  }
  pfVar2 = (float *)(param_2[10] + param_3 * 0x10);
  if ((param_4 == -1) && (param_5 == -1)) {
    if ((*(char *)(pfVar2 + 3) == -1) && (*(char *)((int)pfVar2 + 0xd) == -1)) {
      return;
    }
    param_6 = param_6 | 6;
  }
  if ((*(char *)(pfVar2 + 3) == param_4) && (*(char *)((int)pfVar2 + 0xd) == param_5)) {
    return;
  }
  *(char *)(pfVar2 + 3) = (char)param_4;
  *(char *)((int)pfVar2 + 0xd) = (char)param_5;
  if ((param_6 & 0x10) == 0) {
    *pfVar2 = FLOAT_803df4a8;
  }
  pfVar2[1] = FLOAT_803df4c0;
  pfVar2[2] = (float)param_1;
  *(byte *)((int)pfVar2 + 0xe) = param_6 | 4;
  return;
}

