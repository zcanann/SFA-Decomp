// Function: FUN_801a3190
// Entry: 801a3190
// Size: 676 bytes

undefined4
FUN_801a3190(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            undefined2 param_10,int param_11,undefined param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined2 *puVar4;
  double dVar5;
  
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) == 0) {
    uVar3 = 0;
  }
  else {
    puVar4 = FUN_8002becc(0x44,param_10);
    *puVar4 = param_10;
    *(undefined *)(puVar4 + 2) = 2;
    *(undefined *)(puVar4 + 3) = 0xff;
    *(undefined *)((int)puVar4 + 5) = 1;
    *(undefined *)((int)puVar4 + 7) = 0xff;
    *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_9 + 0x14);
    fVar1 = FLOAT_803e4fe8;
    puVar4[0x10] = (short)(int)(FLOAT_803e4fe8 * *(float *)(param_11 + 0x40));
    puVar4[0x11] = (short)(int)(fVar1 * *(float *)(param_11 + 0x44));
    puVar4[0x12] = (short)(int)(fVar1 * *(float *)(param_11 + 0x48));
    puVar4[0xd] = *(undefined2 *)(param_11 + 0x68);
    puVar4[0xe] = *(undefined2 *)(param_11 + 0x66);
    puVar4[0xf] = *(undefined2 *)(param_11 + 100);
    dVar5 = DOUBLE_803e4ff8;
    puVar4[0x16] = (short)(int)(*(float *)(param_11 + 0x1c) *
                               (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_11 + 0x6d))
                                      - DOUBLE_803e4ff8));
    puVar4[0x17] = (short)(int)(*(float *)(param_11 + 0x20) *
                               (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_11 + 0x6d))
                                      - dVar5));
    puVar4[0x18] = (short)(int)(*(float *)(param_11 + 0x24) *
                               (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_11 + 0x6d))
                                      - dVar5));
    fVar1 = FLOAT_803e4fec;
    puVar4[0x19] = (short)(int)(FLOAT_803e4fec * *(float *)(param_11 + 0x28));
    puVar4[0x1b] = (short)(int)(fVar1 * *(float *)(param_11 + 0x30));
    puVar4[0x1a] = (short)(int)(fVar1 * *(float *)(param_11 + 0x2c));
    fVar1 = FLOAT_803e4ff0;
    puVar4[0x13] = (short)(int)(FLOAT_803e4ff0 * *(float *)(param_11 + 0x34));
    puVar4[0x14] = (short)(int)(fVar1 * *(float *)(param_11 + 0x38));
    puVar4[0x15] = (short)(int)(fVar1 * *(float *)(param_11 + 0x3c));
    *(undefined *)(puVar4 + 0xc) = param_12;
    dVar5 = (double)FLOAT_803e4ff4;
    fVar1 = *(float *)(param_9 + 8);
    *(char *)((int)puVar4 + 0x3d) =
         (char)(int)(dVar5 * (double)(float)((double)fVar1 /
                                            (double)*(float *)(*(int *)(param_9 + 0x50) + 4)));
    puVar4[0x1c] = (short)*(undefined4 *)(param_11 + 0x5c);
    puVar4[0x1d] = (short)(int)*(float *)(param_11 + 0x58);
    uVar3 = FUN_8002e088((double)fVar1,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,puVar4,
                         5,*(undefined *)(param_9 + 0xac),0xffffffff,(uint *)0x0,param_14,param_15,
                         param_16);
  }
  return uVar3;
}

