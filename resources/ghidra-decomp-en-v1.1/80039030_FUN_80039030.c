// Function: FUN_80039030
// Entry: 80039030
// Size: 480 bytes

void FUN_80039030(int param_1,char *param_2)

{
  float fVar1;
  uint uVar2;
  bool bVar4;
  int *piVar3;
  int iVar5;
  int iVar6;
  int iVar7;
  short *psVar8;
  undefined8 local_18;
  
  fVar1 = *(float *)(param_2 + 0xc);
  psVar8 = (short *)0x0;
  iVar5 = *(int *)(param_1 + 0x50);
  if (iVar5 != 0) {
    iVar6 = 0;
    iVar7 = 0;
    for (uVar2 = (uint)*(byte *)(iVar5 + 0x5a); uVar2 != 0; uVar2 = uVar2 - 1) {
      if ((*(char *)(*(int *)(iVar5 + 0x10) + *(char *)(param_1 + 0xad) + iVar6 + 1) != -1) &&
         (*(char *)(*(int *)(iVar5 + 0x10) + iVar6) == '\x01')) {
        psVar8 = (short *)(*(int *)(param_1 + 0x6c) + iVar7);
      }
      iVar6 = *(char *)(iVar5 + 0x55) + iVar6 + 1;
      iVar7 = iVar7 + 0x12;
    }
  }
  if (*param_2 == '\0') {
    bVar4 = FUN_8000b598(param_1,0x10);
    if (bVar4) {
      if ((int)fVar1 != -1) {
        uVar2 = (int)fVar1 - (uint)DAT_803dc070;
        if ((int)uVar2 < 0) {
          FUN_8000b7dc(param_1,0x10);
          *(float *)(param_2 + 4) = FLOAT_803df624;
          param_2[0x14] = '\0';
          param_2[0x15] = '\0';
        }
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        *(float *)(param_2 + 0xc) = (float)(local_18 - DOUBLE_803df650);
      }
    }
    else {
      *(float *)(param_2 + 0xc) = FLOAT_803df648;
      param_2[0x14] = '\0';
      param_2[0x15] = '\0';
      if (FLOAT_803df624 < *(float *)(param_2 + 4)) {
        *(float *)(param_2 + 4) = FLOAT_803df624;
        piVar3 = *(int **)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4);
        if (*(char *)(*piVar3 + 0xf9) != '\0') {
          FUN_80027a90((double)(FLOAT_803df61c / FLOAT_803dc0c4),piVar3,2,
                       (int)*(char *)(piVar3[10] + 0x2d),-1,0);
        }
      }
    }
  }
  else {
    *param_2 = '\0';
  }
  if (psVar8 != (short *)0x0) {
    *psVar8 = (short)((int)*psVar8 + (int)*(short *)(param_2 + 0x14) >> 1);
  }
  return;
}

