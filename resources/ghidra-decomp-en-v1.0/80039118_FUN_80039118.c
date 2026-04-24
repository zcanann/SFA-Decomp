// Function: FUN_80039118
// Entry: 80039118
// Size: 332 bytes

void FUN_80039118(int param_1,int *param_2)

{
  float fVar1;
  int *piVar2;
  int iVar3;
  
  if (-1 < *param_2) {
    fVar1 = (float)param_2[2] - FLOAT_803db414;
    param_2[2] = (int)fVar1;
    if (fVar1 < FLOAT_803de9a4) {
      if (*param_2 < param_2[1]) {
        if (*param_2 == 1) {
          FUN_8000bab0(param_1,0x10,*(undefined2 *)(param_2 + 5));
        }
        iVar3 = *param_2;
        *param_2 = iVar3 + 1;
        piVar2 = *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
        if (*(char *)(*piVar2 + 0xf9) != '\0') {
          FUN_800279cc((double)(FLOAT_803de99c / FLOAT_803db464),piVar2,2,
                       (int)*(char *)(piVar2[10] + 0x2d),*(int *)(param_2[4] + iVar3 * 4) + -1,0);
        }
        param_2[2] = (int)((float)param_2[2] + (float)param_2[3]);
      }
      else {
        *param_2 = -1;
        piVar2 = *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
        if (*(char *)(*piVar2 + 0xf9) != '\0') {
          FUN_800279cc((double)(FLOAT_803de99c / FLOAT_803db464),piVar2,2,
                       (int)*(char *)(piVar2[10] + 0x2d),0xffffffff,0);
        }
      }
    }
  }
  return;
}

