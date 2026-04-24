// Function: FUN_80155d30
// Entry: 80155d30
// Size: 196 bytes

void FUN_80155d30(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int *param_9,int param_10)

{
  uint uVar1;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  if (*(char *)(param_10 + 0x33a) == '\0') {
    FUN_80155960(param_9,param_10);
  }
  else if ((*(short *)(*(int *)(param_10 + 0x29c) + 0x44) == 1) &&
          (uVar1 = FUN_8029641c(*(int *)(param_10 + 0x29c)), uVar1 != 0)) {
    FUN_80155460((double)FLOAT_803e36c8,(short *)param_9,param_10,0x19);
    if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
      FUN_8014d504((double)FLOAT_803e36c8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (int)param_9,param_10,0,0,0,in_r8,in_r9,in_r10);
      FUN_8000bb38((uint)param_9,0x252);
    }
  }
  else {
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) | 0x10000;
  }
  return;
}

