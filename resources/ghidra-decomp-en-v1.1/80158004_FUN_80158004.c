// Function: FUN_80158004
// Entry: 80158004
// Size: 388 bytes

/* WARNING: Removing unreachable block (ram,0x80158160) */
/* WARNING: Removing unreachable block (ram,0x80158014) */

void FUN_80158004(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)

{
  uint uVar1;
  undefined2 *puVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar5;
  double dVar6;
  
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_8002becc(0x24,0x869);
    uVar4 = 0;
    uVar5 = FUN_80038524(param_9,0,(float *)(puVar2 + 4),(undefined4 *)(puVar2 + 6),
                         (float *)(puVar2 + 8),0);
    *(undefined *)(puVar2 + 2) = 1;
    *(undefined *)((int)puVar2 + 5) = 4;
    *(undefined *)(puVar2 + 3) = 0xff;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    iVar3 = FUN_8002e088(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff
                         ,0xffffffff,(uint *)0x0,uVar4,in_r9,in_r10);
    if (iVar3 != 0) {
      dVar6 = (double)(FLOAT_803e381c *
                      ((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_10 + 0x2a4)) -
                              DOUBLE_803e3828) / *(float *)(param_10 + 0x2a8)));
      *(float *)(iVar3 + 0x24) =
           (float)((double)(*(float *)(*(int *)(param_10 + 0x29c) + 0xc) - *(float *)(puVar2 + 4)) /
                  dVar6);
      uVar1 = FUN_80022264(0xfffffff6,10);
      *(float *)(iVar3 + 0x28) =
           (float)((double)((FLOAT_803e3820 + *(float *)(*(int *)(param_10 + 0x29c) + 0x10) +
                            (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                   DOUBLE_803e3830)) - *(float *)(puVar2 + 6)) / dVar6);
      *(float *)(iVar3 + 0x2c) =
           (float)((double)(*(float *)(*(int *)(param_10 + 0x29c) + 0x14) - *(float *)(puVar2 + 8))
                  / dVar6);
    }
    FUN_8000bb38(param_9,0x4ae);
  }
  return;
}

