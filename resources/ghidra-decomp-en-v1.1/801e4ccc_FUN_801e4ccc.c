// Function: FUN_801e4ccc
// Entry: 801e4ccc
// Size: 812 bytes

void FUN_801e4ccc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  double dVar4;
  double dVar5;
  float local_28;
  float local_24;
  float local_20;
  undefined4 local_18;
  uint uStack_14;
  
  pfVar3 = *(float **)(param_9 + 0x5c);
  iVar2 = FUN_8002bac4();
  fVar1 = FLOAT_803e6584;
  dVar5 = (double)pfVar3[8];
  dVar4 = (double)FLOAT_803e6584;
  if (dVar5 == dVar4) {
    *(undefined4 *)(param_9 + 0x40) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(param_9 + 0x42) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(param_9 + 0x44) = *(undefined4 *)(param_9 + 10);
    uStack_14 = FUN_80022264(0xffffff9c,100);
    uStack_14 = uStack_14 ^ 0x80000000;
    local_18 = 0x43300000;
    *(float *)(param_9 + 4) =
         FLOAT_803e6590 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e65a0) +
         FLOAT_803e658c;
    if (*(char *)(pfVar3 + 7) == '\0') {
      *pfVar3 = *(float *)(param_9 + 0x12);
      pfVar3[1] = *(float *)(param_9 + 0x14);
      pfVar3[2] = *(float *)(param_9 + 0x16);
      *(undefined *)(pfVar3 + 7) = 1;
      pfVar3[3] = *(float *)(param_9 + 6);
      pfVar3[4] = *(float *)(param_9 + 8);
      pfVar3[5] = *(float *)(param_9 + 10);
    }
    fVar1 = FLOAT_803e6594;
    pfVar3[3] = FLOAT_803e6594 * *pfVar3 * FLOAT_803dc074 + pfVar3[3];
    pfVar3[4] = fVar1 * pfVar3[1] * FLOAT_803dc074 + pfVar3[4];
    pfVar3[5] = fVar1 * pfVar3[2] * FLOAT_803dc074 + pfVar3[5];
    *(float *)(param_9 + 6) = pfVar3[3];
    *(float *)(param_9 + 8) = pfVar3[4];
    *(float *)(param_9 + 10) = pfVar3[5];
    *(uint *)(param_9 + 0x7a) = *(int *)(param_9 + 0x7a) - (uint)DAT_803dc070;
    if (((*(int *)(param_9 + 0x7a) < 0) ||
        ((iVar2 != 0 && ((*(ushort *)(iVar2 + 0xb0) & 0x1000) != 0)))) &&
       (pfVar3[8] == FLOAT_803e6584)) {
      *(undefined *)(param_9 + 0x1b) = 0;
      pfVar3[8] = FLOAT_803e6588;
    }
    iVar2 = FUN_80021884();
    *param_9 = (short)iVar2;
    *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6e) = 5;
    *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6f) = 1;
    *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x48) = 0x10;
    *(undefined4 *)(*(int *)(param_9 + 0x2a) + 0x4c) = 0x10;
    *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 1;
    if ((*(char *)(*(int *)(param_9 + 0x2a) + 0xad) != '\0') && (pfVar3[8] == FLOAT_803e6584)) {
      FUN_800998ec(param_9,2);
      pfVar3[8] = FLOAT_803e6588;
      *(undefined *)(param_9 + 0x1b) = 0;
    }
    local_28 = FLOAT_803e6598 * -*pfVar3;
    local_24 = FLOAT_803e6598 * -pfVar3[1];
    local_20 = FLOAT_803e6598 * -pfVar3[2];
    FUN_80098bb4((double)FLOAT_803e659c,param_9,2,0x156,0xf,&local_28);
    FUN_80098bb4((double)FLOAT_803e659c,param_9,2,0x156,0xf,&local_28);
    FUN_80098bb4((double)FLOAT_803e659c,param_9,2,0x156,0xf,&local_28);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0xa8,0,2,0xffffffff,0);
  }
  else {
    pfVar3[8] = (float)(dVar5 - (double)FLOAT_803dc074);
    if ((double)pfVar3[8] <= dVar4) {
      pfVar3[8] = fVar1;
      FUN_8002cc9c(dVar4,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
  }
  return;
}

