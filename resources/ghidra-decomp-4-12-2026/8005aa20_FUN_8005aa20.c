// Function: FUN_8005aa20
// Entry: 8005aa20
// Size: 268 bytes

void FUN_8005aa20(float *param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int in_r8;
  
  for (iVar5 = 0; iVar5 < param_2; iVar5 = iVar5 + 1) {
    iVar3 = 0;
    fVar1 = FLOAT_803df84c;
    while (iVar4 = iVar3, iVar4 < 0x18) {
      fVar2 = param_1[2] * (float)(&DAT_8030f194)[iVar4 + 2] +
              param_1[1] * (float)(&DAT_8030f194)[iVar4 + 1] +
              *param_1 * (float)(&DAT_8030f194)[iVar4];
      iVar3 = iVar4 + 3;
      if (fVar1 < fVar2) {
        in_r8 = iVar4;
        fVar1 = fVar2;
      }
    }
    switch(in_r8) {
    case 0:
      *(undefined *)(param_1 + 4) = 0;
      break;
    case 3:
      *(undefined *)(param_1 + 4) = 2;
      break;
    case 6:
      *(undefined *)(param_1 + 4) = 5;
      break;
    case 9:
      *(undefined *)(param_1 + 4) = 7;
      break;
    case 0xc:
      *(undefined *)(param_1 + 4) = 1;
      break;
    case 0xf:
      *(undefined *)(param_1 + 4) = 3;
      break;
    case 0x12:
      *(undefined *)(param_1 + 4) = 4;
      break;
    case 0x15:
      *(undefined *)(param_1 + 4) = 6;
    }
    param_1 = param_1 + 5;
  }
  return;
}

