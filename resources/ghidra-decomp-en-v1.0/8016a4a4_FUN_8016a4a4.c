// Function: FUN_8016a4a4
// Entry: 8016a4a4
// Size: 444 bytes

void FUN_8016a4a4(int param_1)

{
  bool bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (*(short *)(iVar4 + 0x12) != 0) {
    *(short *)(iVar4 + 0x12) = *(short *)(iVar4 + 0x12) + -1;
    goto LAB_8016a624;
  }
  fVar2 = *(float *)(param_1 + 0x28);
  *(float *)(param_1 + 0x28) = -(FLOAT_803e3140 * FLOAT_803db414 - fVar2);
  if ((FLOAT_803e313c <= fVar2) && (*(float *)(param_1 + 0x28) <= FLOAT_803e313c)) {
    FUN_8016a660();
    FUN_8000bb18(param_1,0xb7);
    *(undefined *)(param_1 + 0x36) = 0;
  }
  FUN_8002b95c((double)(*(float *)(param_1 + 0x24) * FLOAT_803db414),
               (double)(*(float *)(param_1 + 0x28) * FLOAT_803db414),
               (double)(*(float *)(param_1 + 0x2c) * FLOAT_803db414),param_1);
  FUN_80035df4(param_1,0x16,1,0);
  FUN_80035974(param_1,7);
  FUN_80035f20(param_1);
  if (*(int *)(*(int *)(param_1 + 0x54) + 0x50) != 0) {
    iVar3 = FUN_8002b9ec();
    if (*(int *)(*(int *)(param_1 + 0x54) + 0x50) != iVar3) {
      iVar3 = FUN_8002b9ac();
      if (*(int *)(*(int *)(param_1 + 0x54) + 0x50) != iVar3) goto LAB_8016a5dc;
    }
    FUN_8000fad8();
    FUN_8000e67c((double)FLOAT_803e3138);
    FUN_8000bb18(param_1,0xb6);
    *(undefined *)(param_1 + 0x36) = 0;
    *(undefined2 *)(iVar4 + 0x12) = 0x3c;
    FUN_80035f00(param_1);
  }
LAB_8016a5dc:
  if (*(char *)(param_1 + 0x36) == -1) {
    iVar3 = 2;
    do {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x4ba,0,1,0xffffffff,0);
      bVar1 = iVar3 != 0;
      iVar3 = iVar3 + -1;
    } while (bVar1);
  }
LAB_8016a624:
  if ((*(char *)(param_1 + 0x36) == '\0') && (*(short *)(iVar4 + 0x12) == 0)) {
    FUN_8002cbc4(param_1);
  }
  return;
}

