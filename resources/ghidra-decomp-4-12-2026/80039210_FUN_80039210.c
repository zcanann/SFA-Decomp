// Function: FUN_80039210
// Entry: 80039210
// Size: 332 bytes

void FUN_80039210(uint param_1,int *param_2)

{
  float fVar1;
  int *piVar2;
  int iVar3;
  
  if ((-1 < *param_2) &&
     (fVar1 = (float)param_2[2] - FLOAT_803dc074, param_2[2] = (int)fVar1, fVar1 < FLOAT_803df624))
  {
    if (*param_2 < param_2[1]) {
      if (*param_2 == 1) {
        FUN_8000bad0(param_1,0x10,*(ushort *)(param_2 + 5));
      }
      iVar3 = *param_2;
      *param_2 = iVar3 + 1;
      piVar2 = *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
      if (*(char *)(*piVar2 + 0xf9) != '\0') {
        FUN_80027a90((double)(FLOAT_803df61c / FLOAT_803dc0c4),piVar2,2,
                     (int)*(char *)(piVar2[10] + 0x2d),*(int *)(param_2[4] + iVar3 * 4) + -1,0);
      }
      param_2[2] = (int)((float)param_2[2] + (float)param_2[3]);
    }
    else {
      *param_2 = -1;
      piVar2 = *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
      if (*(char *)(*piVar2 + 0xf9) != '\0') {
        FUN_80027a90((double)(FLOAT_803df61c / FLOAT_803dc0c4),piVar2,2,
                     (int)*(char *)(piVar2[10] + 0x2d),-1,0);
      }
    }
  }
  return;
}

