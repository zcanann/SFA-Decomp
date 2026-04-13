// Function: FUN_80163598
// Entry: 80163598
// Size: 188 bytes

void FUN_80163598(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  
  FUN_8002ba84();
  iVar1 = FUN_8002e1ac(0x1723);
  if (*(int *)(param_9 + 0xf4) == 0) {
    if (*(short *)(param_9 + 0xa0) != 0x208) {
      FUN_8003042c((double)FLOAT_803e3bcc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x208,0,param_12,param_13,param_14,param_15,param_16);
    }
    FUN_8002fb40((double)FLOAT_803e3bd0,(double)FLOAT_803dc074);
    if ((iVar1 != 0) &&
       (uVar2 = FUN_80020078((int)*(short *)(*(int *)(iVar1 + 0x4c) + 0x1a)), uVar2 != 0)) {
      *(undefined4 *)(param_9 + 0xf4) = 1;
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      FUN_80035ff8(param_9);
    }
  }
  return;
}

