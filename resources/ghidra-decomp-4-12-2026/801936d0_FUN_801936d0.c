// Function: FUN_801936d0
// Entry: 801936d0
// Size: 372 bytes

double FUN_801936d0(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  iVar6 = *(int *)(param_1 + 0x4c);
  fVar1 = *(float *)(param_2 + 0x10) - *(float *)(param_1 + 0x10);
  if ((fVar1 < FLOAT_803e4c40) || (FLOAT_803e4c44 < fVar1)) {
    dVar7 = (double)FLOAT_803e4c48;
  }
  else {
    fVar1 = *(float *)(param_2 + 0xc) - *(float *)(param_1 + 0xc);
    fVar2 = *(float *)(param_2 + 0x14) - *(float *)(param_1 + 0x14);
    fVar3 = FLOAT_803e4c4c + *(float *)(iVar5 + 0x14);
    if (fVar1 * fVar1 + fVar2 * fVar2 <= fVar3 * fVar3) {
      fVar1 = FLOAT_803e4c30 *
              (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x20)) - DOUBLE_803e4c38);
      if ((fVar1 <= *(float *)(iVar5 + 0xc)) && (*(int *)(iVar5 + 8) != 0)) {
        *(float *)(iVar5 + 0xc) = fVar1;
        iVar4 = *(int *)(iVar5 + 8);
        if (*(short *)(iVar4 + 0x46) == 0x519) {
          FUN_801a86a4(iVar4,'\0');
        }
        else {
          (**(code **)(**(int **)(iVar4 + 0x68) + 0x24))(iVar4,0);
        }
      }
      *(float *)(iVar5 + 0xc) = FLOAT_803e4c54 * FLOAT_803dc074 + *(float *)(iVar5 + 0xc);
      *(byte *)(iVar5 + 0x2d) = *(byte *)(iVar5 + 0x2d) | 4;
      dVar7 = (double)(*(float *)(iVar5 + 0x14) *
                      (*(float *)(iVar5 + 0xc) /
                      (FLOAT_803e4c30 *
                      (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x20)) -
                             DOUBLE_803e4c38))));
    }
    else {
      dVar7 = (double)FLOAT_803e4c50;
    }
  }
  return dVar7;
}

