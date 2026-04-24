// Function: FUN_801c5b9c
// Entry: 801c5b9c
// Size: 412 bytes

void FUN_801c5b9c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  uint uVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  double dVar6;
  double dVar7;
  
  iVar5 = *(int *)(param_9 + 0xb8);
  *(undefined2 *)(iVar5 + 0x6a) = *(undefined2 *)(param_10 + 0x1a);
  *(undefined2 *)(iVar5 + 0x6e) = 0xffff;
  dVar6 = DOUBLE_803e5c08;
  dVar7 = (double)FLOAT_803e5c00;
  *(float *)(iVar5 + 0x24) =
       (float)(dVar7 / (double)(float)(dVar7 + (double)(float)((double)CONCAT44(0x43300000,
                                                                                (uint)*(byte *)(
                                                  param_10 + 0x24)) - DOUBLE_803e5c08)));
  *(undefined4 *)(iVar5 + 0x28) = 0xffffffff;
  iVar4 = *(int *)(param_9 + 0xf4);
  if ((iVar4 == 0) && (*(short *)(param_10 + 0x18) != 1)) {
    dVar6 = (double)(**(code **)(*DAT_803dd6d4 + 0x1c))(iVar5);
    *(int *)(param_9 + 0xf4) = *(short *)(param_10 + 0x18) + 1;
  }
  else if ((iVar4 != 0) && ((int)*(short *)(param_10 + 0x18) != iVar4 + -1)) {
    dVar6 = (double)(**(code **)(*DAT_803dd6d4 + 0x24))(iVar5);
    if (*(short *)(param_10 + 0x18) != -1) {
      dVar6 = (double)(**(code **)(*DAT_803dd6d4 + 0x1c))(iVar5,param_10);
    }
    *(int *)(param_9 + 0xf4) = *(short *)(param_10 + 0x18) + 1;
  }
  uVar1 = FUN_8002e144();
  if ((uVar1 & 0xff) != 0) {
    puVar2 = FUN_8002becc(0x24,0x1b8);
    *(undefined4 *)(puVar2 + 4) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar2 + 2) = 0x20;
    *(undefined *)((int)puVar2 + 5) = 4;
    *(undefined *)((int)puVar2 + 7) = 0xff;
    uVar3 = FUN_8002e088(dVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,5,0xff,
                         0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    *(undefined4 *)(param_9 + 200) = uVar3;
    *(float *)(*(int *)(param_9 + 200) + 8) =
         *(float *)(*(int *)(param_9 + 200) + 8) * FLOAT_803e5c10;
  }
  return;
}

