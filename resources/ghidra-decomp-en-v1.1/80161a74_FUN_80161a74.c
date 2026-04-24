// Function: FUN_80161a74
// Entry: 80161a74
// Size: 228 bytes

bool FUN_80161a74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  *(undefined *)(param_10 + 0x34d) = 0;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b78;
  fVar1 = FLOAT_803e3b50;
  *(float *)(param_10 + 0x280) = FLOAT_803e3b50;
  *(float *)(param_10 + 0x284) = fVar1;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8000bb38(param_9,0x27c);
    if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,2,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(float *)(param_10 + 0x2a0) = FLOAT_803e3b7c;
    *(undefined *)(param_10 + 0x346) = 0;
    *(undefined *)(param_9 + 0x36) = 0xff;
    *(ushort *)(iVar2 + 0x400) = *(ushort *)(iVar2 + 0x400) | 0x100;
  }
  return *(char *)(param_10 + 0x346) != '\0';
}

