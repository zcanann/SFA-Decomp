// Function: FUN_802242a8
// Entry: 802242a8
// Size: 332 bytes

undefined4 FUN_802242a8(int param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  float local_18;
  float local_14 [2];
  
  if (*(char *)(param_1 + 0xad) == '\x01') {
    (**(code **)(**(int **)(*(int *)(param_2 + 0x268) + 0x68) + 0x30))
              (*(undefined *)(param_2 + 0x283),param_2 + 0x27e,param_2 + 0x280);
    (**(code **)(**(int **)(*(int *)(param_2 + 0x268) + 0x68) + 0x20))
              (param_1,(int)*(short *)(param_2 + 0x27e),(int)*(short *)(param_2 + 0x280),local_14,
               &local_18);
  }
  else {
    (**(code **)(**(int **)(*(int *)(param_2 + 0x268) + 0x68) + 0x4c))
              (*(undefined *)(param_2 + 0x283),param_2 + 0x27e,param_2 + 0x280);
    (**(code **)(**(int **)(*(int *)(param_2 + 0x268) + 0x68) + 0x3c))
              (param_1,(int)*(short *)(param_2 + 0x27e),(int)*(short *)(param_2 + 0x280),local_14,
               &local_18);
  }
  if ((FLOAT_803e6d50 + local_14[0] < *(float *)(param_3 + 0xc)) ||
     (*(float *)(param_3 + 0xc) < local_14[0] - FLOAT_803e6d50)) {
    uVar1 = 1;
  }
  else if ((FLOAT_803e6d50 + local_18 < *(float *)(param_3 + 0x14)) ||
          (*(float *)(param_3 + 0x14) < local_18 - FLOAT_803e6d50)) {
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

