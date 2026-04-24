// Function: FUN_8002caec
// Entry: 8002caec
// Size: 216 bytes

void FUN_8002caec(int param_1)

{
  short sVar1;
  float fVar2;
  int iVar3;
  code *pcVar4;
  
  sVar1 = *(short *)(param_1 + 0x46);
  if ((sVar1 == 0x1f) || ((sVar1 < 0x1f && (sVar1 == 0)))) {
    FUN_802b6ad4(param_1);
  }
  else if (((*(int **)(param_1 + 0x68) != (int *)0x0) &&
           (pcVar4 = *(code **)(**(int **)(param_1 + 0x68) + 4), pcVar4 != (code *)0xffffffff)) &&
          (pcVar4 != (code *)0x0)) {
    (*pcVar4)(param_1);
  }
  iVar3 = *(int *)(param_1 + 100);
  if (iVar3 != 0) {
    *(uint *)(iVar3 + 0x30) = *(uint *)(iVar3 + 0x30) | 8;
  }
  *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x84) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_1 + 0x88) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(param_1 + 0x8c) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x90) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_1 + 0x94) = *(undefined4 *)(param_1 + 0x14);
  fVar2 = FLOAT_803de88c;
  *(float *)(param_1 + 0xfc) = FLOAT_803de88c;
  *(float *)(param_1 + 0x100) = fVar2;
  *(float *)(param_1 + 0x104) = fVar2;
  return;
}

