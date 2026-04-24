// Function: FUN_8002cbc4
// Entry: 8002cbc4
// Size: 216 bytes

void FUN_8002cbc4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  short sVar1;
  float fVar2;
  int iVar3;
  code *pcVar4;
  
  sVar1 = *(short *)(param_9 + 0x46);
  if ((sVar1 == 0x1f) || ((sVar1 < 0x1f && (sVar1 == 0)))) {
    FUN_802b7234(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  else if (((*(int **)(param_9 + 0x68) != (int *)0x0) &&
           (pcVar4 = *(code **)(**(int **)(param_9 + 0x68) + 4), pcVar4 != (code *)0xffffffff)) &&
          (pcVar4 != (code *)0x0)) {
    (*pcVar4)(param_9);
  }
  iVar3 = *(int *)(param_9 + 100);
  if (iVar3 != 0) {
    *(uint *)(iVar3 + 0x30) = *(uint *)(iVar3 + 0x30) | 8;
  }
  *(undefined4 *)(param_9 + 0x80) = *(undefined4 *)(param_9 + 0xc);
  *(undefined4 *)(param_9 + 0x84) = *(undefined4 *)(param_9 + 0x10);
  *(undefined4 *)(param_9 + 0x88) = *(undefined4 *)(param_9 + 0x14);
  *(undefined4 *)(param_9 + 0x8c) = *(undefined4 *)(param_9 + 0xc);
  *(undefined4 *)(param_9 + 0x90) = *(undefined4 *)(param_9 + 0x10);
  *(undefined4 *)(param_9 + 0x94) = *(undefined4 *)(param_9 + 0x14);
  fVar2 = FLOAT_803df50c;
  *(float *)(param_9 + 0xfc) = FLOAT_803df50c;
  *(float *)(param_9 + 0x100) = fVar2;
  *(float *)(param_9 + 0x104) = fVar2;
  return;
}

