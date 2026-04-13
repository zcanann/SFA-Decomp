// Function: FUN_801f42b4
// Entry: 801f42b4
// Size: 524 bytes

void FUN_801f42b4(short *param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  short sVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_1 + 0x5c);
  iVar4 = FUN_8002bac4();
  if (iVar4 != 0) {
    dVar7 = (double)FUN_80021754((float *)(iVar4 + 0x18),(float *)(*(int *)(param_1 + 0x26) + 8));
    if (dVar7 <= (double)FLOAT_803e6af0) {
      fVar1 = *(float *)(iVar4 + 0x18) - *(float *)(param_1 + 6);
      fVar2 = *(float *)(iVar4 + 0x1c) - *(float *)(param_1 + 8);
      fVar3 = *(float *)(iVar4 + 0x20) - *(float *)(param_1 + 10);
      if ((FLOAT_803e6af4 < fVar1) || (fVar1 < FLOAT_803e6af4)) {
        *(float *)(param_1 + 6) = FLOAT_803e6af8 * fVar1 * FLOAT_803dc074 + *(float *)(param_1 + 6);
      }
      if ((FLOAT_803e6af4 < fVar2) || (fVar2 < FLOAT_803e6af4)) {
        *(float *)(param_1 + 8) = FLOAT_803e6af8 * fVar2 * FLOAT_803dc074 + *(float *)(param_1 + 8);
      }
      if ((FLOAT_803e6af4 < fVar3) || (fVar3 < FLOAT_803e6af4)) {
        *(float *)(param_1 + 10) =
             FLOAT_803e6af8 * fVar3 * FLOAT_803dc074 + *(float *)(param_1 + 10);
      }
      sVar6 = *(short *)(iVar5 + 8);
      if ((-1 < sVar6) || ((-1 >= sVar6 && (*(int *)(param_1 + 0x7a) < 1)))) {
        if (sVar6 == 0) {
          *(undefined2 *)(iVar5 + 0xc) = 1;
        }
        *param_1 = *param_1 + 300;
        if (*(short *)(iVar5 + 8) < 1) {
          (**(code **)(*DAT_803dd708 + 8))(param_1,(int)*(short *)(iVar5 + 4),0,4,0xffffffff,0);
        }
        else {
          for (sVar6 = 0; sVar6 < *(short *)(iVar5 + 8); sVar6 = sVar6 + 1) {
            (**(code **)(*DAT_803dd708 + 8))(param_1,(int)*(short *)(iVar5 + 4),0,4,0xffffffff,0);
          }
        }
        *(int *)(param_1 + 0x7a) = -(int)*(short *)(iVar5 + 8);
      }
      else if ((sVar6 < 0) && (0 < *(int *)(param_1 + 0x7a))) {
        *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803dc070;
      }
    }
    else {
      *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar5 + 0x10);
      *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar5 + 0x14);
      *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar5 + 0x18);
    }
  }
  return;
}

