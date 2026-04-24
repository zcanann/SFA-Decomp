// Function: FUN_800a081c
// Entry: 800a081c
// Size: 424 bytes

void FUN_800a081c(int param_1,int param_2,int param_3)

{
  double dVar1;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  dVar1 = DOUBLE_803df448;
  if (param_3 == 1) {
    if (*(short *)(param_1 + *(short *)(param_1 + 0xfc) * 2 + 0xee) == 0) {
      if (((*(uint *)(param_1 + 0xa4) & 4) != 0) || ((*(uint *)(param_1 + 0xa4) & 0x80000) != 0)) {
        local_2c = FLOAT_803df430;
        local_28 = FLOAT_803df430;
        local_24 = FLOAT_803df430;
        local_30 = FLOAT_803df434;
        local_38 = **(undefined2 **)(param_1 + 4);
        local_36 = local_38;
        local_34 = local_38;
        FUN_80021ac8(&local_38,param_2 + 4);
      }
      *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(param_2 + 4);
      *(undefined4 *)(param_1 + 0x28) = *(undefined4 *)(param_2 + 8);
      *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(param_2 + 0xc);
    }
    else {
      *(float *)(param_1 + 0x24) =
           *(float *)(param_2 + 4) /
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) -
                  DOUBLE_803df448);
      *(float *)(param_1 + 0x28) =
           *(float *)(param_2 + 8) /
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) - dVar1
                  );
      *(float *)(param_1 + 0x2c) =
           *(float *)(param_2 + 0xc) /
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) - dVar1
                  );
    }
    *(float *)(param_1 + 0x60) = *(float *)(param_1 + 0x60) + *(float *)(param_1 + 0x24);
    *(float *)(param_1 + 100) = *(float *)(param_1 + 100) + *(float *)(param_1 + 0x28);
    *(float *)(param_1 + 0x68) = *(float *)(param_1 + 0x68) + *(float *)(param_1 + 0x2c);
  }
  else {
    *(float *)(param_1 + 0x60) =
         *(float *)(param_1 + 0x24) * FLOAT_803dd284 + *(float *)(param_1 + 0x60);
    *(float *)(param_1 + 100) =
         *(float *)(param_1 + 0x28) * FLOAT_803dd284 + *(float *)(param_1 + 100);
    *(float *)(param_1 + 0x68) =
         *(float *)(param_1 + 0x2c) * FLOAT_803dd284 + *(float *)(param_1 + 0x68);
  }
  return;
}

