// Function: FUN_8017fe70
// Entry: 8017fe70
// Size: 124 bytes

void FUN_8017fe70(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  int *piVar1;
  undefined8 uVar2;
  
  piVar1 = *(int **)(param_9 + 0xb8);
  FUN_8003709c(param_9,0x34);
  FUN_8003709c(param_9,0x3e);
  if ((*(char *)(param_9 + 0xeb) != '\0') && (uVar2 = FUN_80037da8(param_9,*piVar1), param_10 == 0))
  {
    FUN_8002cc9c(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar1);
  }
  return;
}

