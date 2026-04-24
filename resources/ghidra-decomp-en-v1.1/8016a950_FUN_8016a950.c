// Function: FUN_8016a950
// Entry: 8016a950
// Size: 444 bytes

void FUN_8016a950(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  if (*(short *)(iVar3 + 0x12) == 0) {
    dVar5 = (double)*(float *)(param_9 + 0x28);
    *(float *)(param_9 + 0x28) = -(float)((double)FLOAT_803e3dd8 * (double)FLOAT_803dc074 - dVar5);
    dVar4 = (double)FLOAT_803e3dd4;
    if ((dVar4 <= dVar5) && ((double)*(float *)(param_9 + 0x28) <= dVar4)) {
      FUN_8016ab0c(dVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      FUN_8000bb38(param_9,0xb7);
      *(undefined *)(param_9 + 0x36) = 0;
    }
    param_2 = (double)(*(float *)(param_9 + 0x28) * FLOAT_803dc074);
    param_3 = (double)(*(float *)(param_9 + 0x2c) * FLOAT_803dc074);
    FUN_8002ba34((double)(*(float *)(param_9 + 0x24) * FLOAT_803dc074),param_2,param_3,param_9);
    FUN_80035eec(param_9,0x16,1,0);
    FUN_80035a6c(param_9,7);
    param_1 = FUN_80036018(param_9);
    if ((*(int *)(*(int *)(param_9 + 0x54) + 0x50) != 0) &&
       ((iVar2 = FUN_8002bac4(), *(int *)(*(int *)(param_9 + 0x54) + 0x50) == iVar2 ||
        (iVar2 = FUN_8002ba84(), *(int *)(*(int *)(param_9 + 0x54) + 0x50) == iVar2)))) {
      FUN_8000faf8();
      FUN_8000e69c((double)FLOAT_803e3dd0);
      FUN_8000bb38(param_9,0xb6);
      *(undefined *)(param_9 + 0x36) = 0;
      *(undefined2 *)(iVar3 + 0x12) = 0x3c;
      param_1 = FUN_80035ff8(param_9);
    }
    if (*(char *)(param_9 + 0x36) == -1) {
      iVar2 = 2;
      do {
        param_1 = (**(code **)(*DAT_803dd708 + 8))(param_9,0x4ba,0,1,0xffffffff,0);
        bVar1 = iVar2 != 0;
        iVar2 = iVar2 + -1;
      } while (bVar1);
    }
  }
  else {
    *(short *)(iVar3 + 0x12) = *(short *)(iVar3 + 0x12) + -1;
  }
  if ((*(char *)(param_9 + 0x36) == '\0') && (*(short *)(iVar3 + 0x12) == 0)) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

