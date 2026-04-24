// Function: FUN_80162254
// Entry: 80162254
// Size: 356 bytes

bool FUN_80162254(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  double dVar3;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14 [2];
  
  iVar2 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e3b50,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,2,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(float *)(param_10 + 0x2a0) = FLOAT_803e3b7c;
  (**(code **)(**(int **)(*(int *)(iVar2 + 0x38) + 0x68) + 0x24))
            ((double)(*(float *)(iVar2 + 0x48) - FLOAT_803e3b94),*(int *)(iVar2 + 0x38),&local_28,
             &local_24,&local_20);
  (**(code **)(**(int **)(*(int *)(iVar2 + 0x38) + 0x68) + 0x24))
            ((double)(FLOAT_803e3b94 + *(float *)(iVar2 + 0x48)),*(int *)(iVar2 + 0x38),&local_1c,
             &local_18,local_14);
  local_28 = local_28 - local_1c;
  local_24 = local_24 - local_18;
  local_20 = local_20 - local_14[0];
  dVar3 = FUN_80293900((double)(local_28 * local_28 + local_20 * local_20));
  local_28 = (float)dVar3;
  iVar1 = FUN_80021884();
  *(short *)(param_9 + 2) = (short)iVar1 * ((short)((int)*(char *)(iVar2 + 0x45) << 1) + -1);
  return *(char *)(param_10 + 0x346) != '\0';
}

