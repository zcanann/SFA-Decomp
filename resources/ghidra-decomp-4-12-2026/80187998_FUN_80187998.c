// Function: FUN_80187998
// Entry: 80187998
// Size: 228 bytes

void FUN_80187998(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  bool bVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  
  piVar3 = *(int **)(param_9 + 0xb8);
  bVar1 = false;
  if (*(char *)(*(int *)(param_9 + 0x4c) + 0x19) == '\x01') {
    if (*(char *)(piVar3 + 7) != '\0') {
      if (*piVar3 != 0) {
        param_1 = (**(code **)(**(int **)(*piVar3 + 0x68) + 0x24))();
      }
      FUN_8001ffac((int)*(short *)(piVar3 + 8));
    }
    bVar1 = true;
  }
  else if (*(char *)((int)piVar3 + 0x1e) < '\0') {
    piVar4 = piVar3;
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(piVar3 + 7); iVar2 = iVar2 + 1) {
      param_1 = FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar4
                            );
      piVar4 = piVar4 + 1;
    }
    bVar1 = true;
  }
  if (bVar1) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

