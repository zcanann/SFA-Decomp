// Function: FUN_801f84e8
// Entry: 801f84e8
// Size: 316 bytes

void FUN_801f84e8(int param_1,short *param_2)

{
  double dVar1;
  uint uVar2;
  undefined2 *puVar3;
  
  dVar1 = DOUBLE_803e6c40;
  puVar3 = *(undefined2 **)(param_1 + 0xb8);
  *(float *)(param_1 + 8) =
       FLOAT_803e6c38 * *(float *)(*(int *)(param_1 + 0x50) + 4) *
       (FLOAT_803e6c30 +
       (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0xc) ^ 0x80000000) -
              DOUBLE_803e6c40));
  if (*param_2 == 0) {
    *(float *)(puVar3 + 6) = FLOAT_803e6c34;
  }
  else {
    *(float *)(puVar3 + 6) =
         -(float)((double)CONCAT44(0x43300000,(int)*(char *)((int)param_2 + 0x19) << 4 ^ 0x80000000)
                 - dVar1);
  }
  uVar2 = FUN_80022264(100,200);
  *puVar3 = (short)uVar2;
  uVar2 = FUN_80022264(200,400);
  puVar3[1] = (short)uVar2;
  puVar3[2] = 0;
  uVar2 = FUN_80022264(0,0x960);
  puVar3[4] = (short)uVar2;
  *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(puVar3 + 10) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(puVar3 + 0xc) = *(undefined4 *)(param_1 + 0x14);
  FUN_8002b95c(param_1,(int)param_2[0xd]);
  *(float *)(param_1 + 0x14) = *(float *)(param_2 + 8) + *(float *)(puVar3 + 6);
  return;
}

