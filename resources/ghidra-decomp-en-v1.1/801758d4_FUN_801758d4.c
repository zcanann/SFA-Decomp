// Function: FUN_801758d4
// Entry: 801758d4
// Size: 248 bytes

void FUN_801758d4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  int iVar2;
  undefined4 *local_28;
  uint local_24;
  uint local_20 [5];
  
  iVar2 = *(int *)(param_9 + 0xb8);
  local_28 = (undefined4 *)0x0;
  while (iVar1 = FUN_800375e4(param_9,&local_24,local_20,(uint *)&local_28), iVar1 != 0) {
    if (local_24 == 0x40001) {
      if (*(short *)(param_9 + 0x46) == 0x21e) {
        *(undefined4 *)(iVar2 + 0xf0) = *local_28;
      }
      if (*(short *)(param_9 + 0x46) == 0x411) {
        *(undefined4 *)(iVar2 + 0xf0) = *local_28;
      }
    }
    else if ((int)local_24 < 0x40001) {
      if (((local_24 == 0xe) && (*(short *)(param_9 + 0x46) != 0x21e)) &&
         (*(short *)(param_9 + 0x46) != 0x411)) {
        param_1 = FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               param_9);
      }
    }
    else if (local_24 == 0xf0003) {
      *(uint *)(iVar2 + 0xb8) = local_20[0];
    }
  }
  return;
}

