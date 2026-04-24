// Function: FUN_8021ad3c
// Entry: 8021ad3c
// Size: 128 bytes

void FUN_8021ad3c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_9 + 0xb8);
  if (((*piVar1 != 0) && (param_10 == 0)) && (*(int *)(*piVar1 + 0x50) != 0)) {
    if (piVar1[1] != 0) {
      *(undefined4 *)(piVar1[1] + 0xf4) = 0;
    }
    *(undefined4 *)(*piVar1 + 0xf4) = 0;
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar1);
  }
  FUN_8003709c(param_9,0x18);
  return;
}

