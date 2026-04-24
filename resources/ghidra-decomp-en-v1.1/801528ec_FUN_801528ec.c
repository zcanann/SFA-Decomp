// Function: FUN_801528ec
// Entry: 801528ec
// Size: 212 bytes

void FUN_801528ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,int param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_9 + 0x4c);
  if ((param_12 != 0x10) && (param_12 != 0x11)) {
    FUN_8000bb38(param_9,0x23);
    FUN_8000bb38(param_9,0x31b);
    *(uint *)(param_10 + 0x2e8) = *(uint *)(param_10 + 0x2e8) | 8;
    *(float *)(param_10 + 0x32c) =
         (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar2 + 0x2c)) - DOUBLE_803e34b0);
    FUN_8014d504((double)FLOAT_803e34a8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,param_10,1,0,0,param_14,param_15,param_16);
    *(uint *)(param_10 + 0x2e4) = *(uint *)(param_10 + 0x2e4) & 0xffffffdf;
    fVar1 = FLOAT_803e34ac;
    *(float *)(param_9 + 0x2c) = FLOAT_803e34ac;
    *(float *)(param_9 + 0x28) = fVar1;
    *(float *)(param_9 + 0x24) = fVar1;
  }
  return;
}

