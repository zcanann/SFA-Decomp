// Function: FUN_8002ee64
// Entry: 8002ee64
// Size: 84 bytes

void FUN_8002ee64(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,uint param_10,undefined2 param_11)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(*(int *)(param_9 + 0x7c) + *(char *)(param_9 + 0xad) * 4);
  iVar1 = *piVar2;
  if (*(short *)(iVar1 + 0xec) != 0) {
    FUN_8002ec4c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar1,
                 piVar2[0xb],param_10,param_11);
  }
  return;
}

