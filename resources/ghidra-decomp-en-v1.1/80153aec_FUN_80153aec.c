// Function: FUN_80153aec
// Entry: 80153aec
// Size: 336 bytes

void FUN_80153aec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)

{
  float fVar1;
  uint uVar2;
  undefined2 *puVar3;
  int iVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  double dVar5;
  
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) != 0) {
    puVar3 = FUN_8002becc(0x24,0x51b);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar5 = (double)FLOAT_803e3588;
    *(float *)(puVar3 + 6) = (float)(dVar5 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 1;
    *(undefined *)(puVar3 + 3) = 0xff;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    iVar4 = FUN_8002e088(dVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,0xff
                         ,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar4 != 0) {
      *(float *)(iVar4 + 0x24) =
           FLOAT_803e358c * (*(float *)(*(int *)(param_10 + 0x29c) + 0xc) - *(float *)(puVar3 + 4));
      uVar2 = FUN_80022264(0xfffffff6,10);
      fVar1 = FLOAT_803e358c;
      *(float *)(iVar4 + 0x28) =
           FLOAT_803e358c *
           ((FLOAT_803e3588 + *(float *)(*(int *)(param_10 + 0x29c) + 0x10) +
            (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3590)) -
           *(float *)(puVar3 + 6));
      *(float *)(iVar4 + 0x2c) =
           fVar1 * (*(float *)(*(int *)(param_10 + 0x29c) + 0x14) - *(float *)(puVar3 + 8));
      *(uint *)(iVar4 + 0xc4) = param_9;
    }
    FUN_8000bb38(param_9,0x49a);
  }
  return;
}

