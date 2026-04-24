// Function: FUN_80027814
// Entry: 80027814
// Size: 208 bytes

void FUN_80027814(double param_1,int *param_2)

{
  int iVar1;
  float *pfVar2;
  int iVar3;
  
  if (*(int *)(*param_2 + 0xdc) == 0) {
    return;
  }
  iVar1 = 0;
  iVar3 = 3;
  do {
    pfVar2 = (float *)(param_2[10] + iVar1);
    if (((*(char *)(pfVar2 + 3) != -1) || (*(char *)((int)pfVar2 + 0xd) != -1)) &&
       ((*(byte *)((int)pfVar2 + 0xe) & 1) == 0)) {
      *pfVar2 = (float)((double)pfVar2[2] * param_1 + (double)*pfVar2);
      if (*pfVar2 < FLOAT_803de874) {
        if (*pfVar2 <= FLOAT_803de87c) {
          *pfVar2 = FLOAT_803de87c;
          pfVar2[2] = FLOAT_803de878;
          *(byte *)((int)pfVar2 + 0xe) = *(byte *)((int)pfVar2 + 0xe) & 0xfb;
        }
      }
      else {
        *pfVar2 = FLOAT_803de874;
        pfVar2[2] = FLOAT_803de878;
        *(byte *)((int)pfVar2 + 0xe) = *(byte *)((int)pfVar2 + 0xe) & 0xfb;
      }
    }
    iVar1 = iVar1 + 0x10;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  return;
}

