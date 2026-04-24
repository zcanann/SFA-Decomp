// Function: FUN_802185b8
// Entry: 802185b8
// Size: 64 bytes

void FUN_802185b8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  
  iVar1 = *(int *)(param_9 + 0xb8);
  *(byte *)(iVar1 + 5) = *(byte *)(iVar1 + 5) | 1;
  if (*(char *)(iVar1 + 4) == '\x01') {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  return;
}

