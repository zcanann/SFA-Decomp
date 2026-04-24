// Function: FUN_801a2bdc
// Entry: 801a2bdc
// Size: 676 bytes

undefined4 FUN_801a2bdc(int param_1,undefined4 param_2,int param_3,undefined param_4)

{
  float fVar1;
  double dVar2;
  char cVar5;
  undefined4 uVar3;
  undefined2 *puVar4;
  
  cVar5 = FUN_8002e04c();
  if (cVar5 == '\0') {
    uVar3 = 0;
  }
  else {
    puVar4 = (undefined2 *)FUN_8002bdf4(0x44,param_2);
    *puVar4 = (short)param_2;
    *(undefined *)(puVar4 + 2) = 2;
    *(undefined *)(puVar4 + 3) = 0xff;
    *(undefined *)((int)puVar4 + 5) = 1;
    *(undefined *)((int)puVar4 + 7) = 0xff;
    *(undefined4 *)(puVar4 + 4) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(param_1 + 0x14);
    fVar1 = FLOAT_803e4350;
    puVar4[0x10] = (short)(int)(FLOAT_803e4350 * *(float *)(param_3 + 0x40));
    puVar4[0x11] = (short)(int)(fVar1 * *(float *)(param_3 + 0x44));
    puVar4[0x12] = (short)(int)(fVar1 * *(float *)(param_3 + 0x48));
    puVar4[0xd] = *(undefined2 *)(param_3 + 0x68);
    puVar4[0xe] = *(undefined2 *)(param_3 + 0x66);
    puVar4[0xf] = *(undefined2 *)(param_3 + 100);
    dVar2 = DOUBLE_803e4360;
    puVar4[0x16] = (short)(int)(*(float *)(param_3 + 0x1c) *
                               (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x6d))
                                      - DOUBLE_803e4360));
    puVar4[0x17] = (short)(int)(*(float *)(param_3 + 0x20) *
                               (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x6d))
                                      - dVar2));
    puVar4[0x18] = (short)(int)(*(float *)(param_3 + 0x24) *
                               (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_3 + 0x6d))
                                      - dVar2));
    fVar1 = FLOAT_803e4354;
    puVar4[0x19] = (short)(int)(FLOAT_803e4354 * *(float *)(param_3 + 0x28));
    puVar4[0x1b] = (short)(int)(fVar1 * *(float *)(param_3 + 0x30));
    puVar4[0x1a] = (short)(int)(fVar1 * *(float *)(param_3 + 0x2c));
    fVar1 = FLOAT_803e4358;
    puVar4[0x13] = (short)(int)(FLOAT_803e4358 * *(float *)(param_3 + 0x34));
    puVar4[0x14] = (short)(int)(fVar1 * *(float *)(param_3 + 0x38));
    puVar4[0x15] = (short)(int)(fVar1 * *(float *)(param_3 + 0x3c));
    *(undefined *)(puVar4 + 0xc) = param_4;
    *(char *)((int)puVar4 + 0x3d) =
         (char)(int)(FLOAT_803e435c *
                    (*(float *)(param_1 + 8) / *(float *)(*(int *)(param_1 + 0x50) + 4)));
    puVar4[0x1c] = (short)*(undefined4 *)(param_3 + 0x5c);
    puVar4[0x1d] = (short)(int)*(float *)(param_3 + 0x58);
    uVar3 = FUN_8002df90(puVar4,5,(int)*(char *)(param_1 + 0xac),0xffffffff,0);
  }
  return uVar3;
}

