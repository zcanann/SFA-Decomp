// Function: FUN_80038f38
// Entry: 80038f38
// Size: 480 bytes

void FUN_80038f38(int param_1,char *param_2)

{
  float fVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  double local_18;
  
  fVar1 = *(float *)(param_2 + 0xc);
  psVar7 = (short *)0x0;
  iVar4 = *(int *)(param_1 + 0x50);
  if (iVar4 != 0) {
    iVar5 = 0;
    iVar6 = 0;
    for (uVar2 = (uint)*(byte *)(iVar4 + 0x5a); uVar2 != 0; uVar2 = uVar2 - 1) {
      if ((*(char *)(*(int *)(iVar4 + 0x10) + *(char *)(param_1 + 0xad) + iVar5 + 1) != -1) &&
         (*(char *)(*(int *)(iVar4 + 0x10) + iVar5) == '\x01')) {
        psVar7 = (short *)(*(int *)(param_1 + 0x6c) + iVar6);
      }
      iVar5 = *(char *)(iVar4 + 0x55) + iVar5 + 1;
      iVar6 = iVar6 + 0x12;
    }
  }
  if (*param_2 == '\0') {
    iVar4 = FUN_8000b578(param_1,0x10);
    if (iVar4 == 0) {
      *(float *)(param_2 + 0xc) = FLOAT_803de9c8;
      *(undefined2 *)(param_2 + 0x14) = 0;
      if (FLOAT_803de9a4 < *(float *)(param_2 + 4)) {
        *(float *)(param_2 + 4) = FLOAT_803de9a4;
        piVar3 = *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
        if (*(char *)(*piVar3 + 0xf9) != '\0') {
          FUN_800279cc((double)(FLOAT_803de99c / FLOAT_803db464),piVar3,2,
                       (int)*(char *)(piVar3[10] + 0x2d),0xffffffff,0);
        }
      }
    }
    else if ((int)fVar1 != -1) {
      uVar2 = (int)fVar1 - (uint)DAT_803db410;
      if ((int)uVar2 < 0) {
        FUN_8000b7bc(param_1,0x10);
        *(float *)(param_2 + 4) = FLOAT_803de9a4;
        *(undefined2 *)(param_2 + 0x14) = 0;
      }
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      *(float *)(param_2 + 0xc) = (float)(local_18 - DOUBLE_803de9d0);
    }
  }
  else {
    *param_2 = '\0';
  }
  if (psVar7 != (short *)0x0) {
    *psVar7 = (short)((int)*psVar7 + (int)*(short *)(param_2 + 0x14) >> 1);
  }
  return;
}

