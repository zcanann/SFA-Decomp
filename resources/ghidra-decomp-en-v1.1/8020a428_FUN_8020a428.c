// Function: FUN_8020a428
// Entry: 8020a428
// Size: 324 bytes

void FUN_8020a428(int param_1,int param_2)

{
  double dVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  undefined4 *puVar5;
  
  if (param_1 != 0) {
    puVar5 = *(undefined4 **)(param_1 + 0xb8);
    uVar4 = FUN_80022264(0,100);
    puVar5[1] = (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e7188);
    *puVar5 = 0;
    if (*(short *)(param_2 + 0x1a) < 1) {
      *(undefined2 *)(param_2 + 0x1a) = 1;
    }
    if (*(short *)(param_2 + 0x1c) < 1) {
      *(undefined2 *)(param_2 + 0x1c) = 1;
    }
    uVar4 = FUN_80022264(0,100);
    dVar1 = DOUBLE_803e7188;
    puVar5[2] = FLOAT_803e71a0 +
                (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e7188);
    fVar3 = FLOAT_803e71a4;
    fVar2 = FLOAT_803e719c;
    puVar5[3] = FLOAT_803e719c *
                ((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                        dVar1) / FLOAT_803e71a4);
    puVar5[4] = fVar2 * ((float)((double)CONCAT44(0x43300000,
                                                  (int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
                                dVar1) / fVar3);
    *(short *)(puVar5 + 5) = (short)*(char *)(param_2 + 0x18);
    *(short *)((int)puVar5 + 0x16) = *(char *)(param_2 + 0x19) * 10;
    puVar5[6] = (int)*(short *)(param_2 + 0x20);
  }
  return;
}

