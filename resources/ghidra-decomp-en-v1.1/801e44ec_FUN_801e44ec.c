// Function: FUN_801e44ec
// Entry: 801e44ec
// Size: 676 bytes

void FUN_801e44ec(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  float fVar1;
  double dVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  if ((*(byte *)((int)pfVar3 + 0x1a) & 2) == 0) {
    FUN_80098bb4((double)FLOAT_803e6554,param_9,4,0x185,5,0);
    FUN_80098bb4((double)FLOAT_803e6554,param_9,4,0x185,5,0);
  }
  else {
    (**(code **)(*DAT_803dd708 + 8))(param_9,0xaa,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0xaa,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0xaa,0,1,0xffffffff,0);
    *(byte *)((int)pfVar3 + 0x1a) = *(byte *)((int)pfVar3 + 0x1a) & 0xfd;
  }
  (**(code **)(*DAT_803dd708 + 8))(param_9,0xa9,0,1,0xffffffff,0);
  *(short *)(param_9 + 2) = *(short *)(param_9 + 2) + 4000;
  if ((*(byte *)((int)pfVar3 + 0x1a) & 1) == 0) {
    *pfVar3 = *(float *)(param_9 + 0x24);
    pfVar3[1] = *(float *)(param_9 + 0x28);
    pfVar3[2] = *(float *)(param_9 + 0x2c);
    *(byte *)((int)pfVar3 + 0x1a) = *(byte *)((int)pfVar3 + 0x1a) | 1;
    pfVar3[3] = *(float *)(param_9 + 0xc);
    pfVar3[4] = *(float *)(param_9 + 0x10);
    pfVar3[5] = *(float *)(param_9 + 0x14);
  }
  dVar2 = DOUBLE_803e6558;
  pfVar3[3] = (float)(DOUBLE_803e6558 * (double)(*pfVar3 * FLOAT_803dc074) + (double)pfVar3[3]);
  pfVar3[4] = (float)(dVar2 * (double)(pfVar3[1] * FLOAT_803dc074) + (double)pfVar3[4]);
  fVar1 = pfVar3[2] * FLOAT_803dc074;
  pfVar3[5] = (float)(dVar2 * (double)fVar1 + (double)pfVar3[5]);
  *(float *)(param_9 + 0xc) = pfVar3[3];
  *(float *)(param_9 + 0x10) = pfVar3[4];
  *(float *)(param_9 + 0x14) = pfVar3[5];
  *(uint *)(param_9 + 0xf4) = *(int *)(param_9 + 0xf4) - (uint)DAT_803dc070;
  if (*(int *)(param_9 + 0xf4) < 0) {
    FUN_8002cc9c((double)fVar1,dVar2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  if (*(short *)(pfVar3 + 6) < 0x10) {
    *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) & 0xfffe;
  }
  else {
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x6e) = 5;
    *(undefined *)(*(int *)(param_9 + 0x54) + 0x6f) = 1;
    *(undefined4 *)(*(int *)(param_9 + 0x54) + 0x48) = 0x10;
    *(undefined4 *)(*(int *)(param_9 + 0x54) + 0x4c) = 0x10;
    *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) = *(ushort *)(*(int *)(param_9 + 0x54) + 0x60) | 1;
  }
  *(ushort *)(pfVar3 + 6) = *(short *)(pfVar3 + 6) + (ushort)DAT_803dc070;
  return;
}

