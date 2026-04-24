// Function: FUN_802208d8
// Entry: 802208d8
// Size: 48 bytes

void FUN_802208d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  FUN_8022013c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

