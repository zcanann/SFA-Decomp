// Function: FUN_802207b4
// Entry: 802207b4
// Size: 124 bytes

void FUN_802207b4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  undefined8 uVar4;
  
  piVar1 = *(int **)(param_9 + 0xb8);
  uVar4 = FUN_8003709c(param_9,0x4a);
  piVar2 = piVar1;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(piVar1 + 8); iVar3 = iVar3 + 1) {
    uVar4 = FUN_8002cc9c(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar2);
    piVar2 = piVar2 + 1;
  }
  if (piVar1[0xb] != 0) {
    FUN_8001cc00((uint *)(piVar1 + 0xb));
  }
  return;
}

