// Function: FUN_8016ab0c
// Entry: 8016ab0c
// Size: 408 bytes

void FUN_8016ab0c(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)

{
  bool bVar1;
  uint uVar2;
  undefined2 *puVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  int iVar5;
  double extraout_f1;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) != 0) {
    iVar5 = 5;
    do {
      puVar3 = FUN_8002becc(0x24,0x482);
      *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
      *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(param_9 + 0x10);
      *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
      *(undefined *)(puVar3 + 2) = 1;
      *(undefined *)((int)puVar3 + 5) = 1;
      *(undefined *)(puVar3 + 3) = 0xff;
      *(undefined *)((int)puVar3 + 7) = 0xff;
      puVar3 = (undefined2 *)
               FUN_8002e088(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5
                            ,0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
      param_1 = extraout_f1;
      if (puVar3 != (undefined2 *)0x0) {
        puVar3[1] = 0;
        uVar2 = FUN_80022264(0,0xffff);
        *puVar3 = (short)uVar2;
        uVar2 = FUN_80022264(0xffffffce,0x32);
        *(float *)(puVar3 + 0x12) =
             FLOAT_803e3ddc *
             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3de8) +
             *(float *)(param_9 + 0x24);
        uVar2 = FUN_80022264(0xffffffce,0x32);
        *(float *)(puVar3 + 0x14) =
             FLOAT_803e3de0 *
             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3de8) +
             *(float *)(param_9 + 0x28);
        uVar2 = FUN_80022264(0xffffffce,0x32);
        param_2 = (double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3de8)
        ;
        param_1 = (double)FLOAT_803e3ddc;
        *(float *)(puVar3 + 0x16) = (float)(param_1 * param_2 + (double)*(float *)(param_9 + 0x2c));
        *(int *)(puVar3 + 0x62) = param_9;
      }
      bVar1 = iVar5 != 0;
      iVar5 = iVar5 + -1;
    } while (bVar1);
    *(undefined2 *)(iVar4 + 0x12) = 0x3c;
  }
  return;
}

