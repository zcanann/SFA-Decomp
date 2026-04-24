// Function: FUN_8015fa5c
// Entry: 8015fa5c
// Size: 276 bytes

void FUN_8015fa5c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  float fVar1;
  uint uVar2;
  undefined2 *puVar3;
  int iVar4;
  int iVar5;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  double dVar7;
  
  iVar6 = *(int *)(param_9 + 0xb8);
  uVar2 = FUN_8002e144();
  if ((uVar2 & 0xff) != 0) {
    puVar3 = FUN_8002becc(0x24,0x51b);
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(param_9 + 0xc);
    dVar7 = (double)FLOAT_803e3ab8;
    *(float *)(puVar3 + 6) = (float)(dVar7 + (double)*(float *)(param_9 + 0x10));
    *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(param_9 + 0x14);
    *(undefined *)(puVar3 + 2) = 1;
    *(undefined *)((int)puVar3 + 5) = 4;
    *(undefined *)((int)puVar3 + 7) = 0xff;
    iVar4 = FUN_8002e088(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,0xff
                         ,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    if (iVar4 != 0) {
      iVar5 = FUN_8002bac4();
      fVar1 = FLOAT_803e3abc;
      *(float *)(iVar4 + 0x24) =
           (*(float *)(iVar5 + 0xc) - *(float *)(param_9 + 0xc)) / FLOAT_803e3abc;
      *(float *)(iVar4 + 0x28) =
           ((*(float *)(iVar5 + 0x10) +
            (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x15)) - DOUBLE_803e3ac0)) -
           *(float *)(param_9 + 0x10)) / fVar1;
      *(float *)(iVar4 + 0x2c) = (*(float *)(iVar5 + 0x14) - *(float *)(param_9 + 0x14)) / fVar1;
    }
  }
  return;
}

