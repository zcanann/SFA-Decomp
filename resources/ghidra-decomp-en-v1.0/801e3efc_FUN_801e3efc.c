// Function: FUN_801e3efc
// Entry: 801e3efc
// Size: 676 bytes

void FUN_801e3efc(int param_1)

{
  double dVar1;
  float *pfVar2;
  
  pfVar2 = *(float **)(param_1 + 0xb8);
  if ((*(byte *)((int)pfVar2 + 0x1a) & 2) == 0) {
    FUN_80098928((double)FLOAT_803e58bc,param_1,4,0x185,5,0);
    FUN_80098928((double)FLOAT_803e58bc,param_1,4,0x185,5,0);
  }
  else {
    (**(code **)(*DAT_803dca88 + 8))(param_1,0xaa,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0xaa,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0xaa,0,1,0xffffffff,0);
    *(byte *)((int)pfVar2 + 0x1a) = *(byte *)((int)pfVar2 + 0x1a) & 0xfd;
  }
  (**(code **)(*DAT_803dca88 + 8))(param_1,0xa9,0,1,0xffffffff,0);
  *(short *)(param_1 + 2) = *(short *)(param_1 + 2) + 4000;
  if ((*(byte *)((int)pfVar2 + 0x1a) & 1) == 0) {
    *pfVar2 = *(float *)(param_1 + 0x24);
    pfVar2[1] = *(float *)(param_1 + 0x28);
    pfVar2[2] = *(float *)(param_1 + 0x2c);
    *(byte *)((int)pfVar2 + 0x1a) = *(byte *)((int)pfVar2 + 0x1a) | 1;
    pfVar2[3] = *(float *)(param_1 + 0xc);
    pfVar2[4] = *(float *)(param_1 + 0x10);
    pfVar2[5] = *(float *)(param_1 + 0x14);
  }
  dVar1 = DOUBLE_803e58c0;
  pfVar2[3] = (float)(DOUBLE_803e58c0 * (double)(*pfVar2 * FLOAT_803db414) + (double)pfVar2[3]);
  pfVar2[4] = (float)(dVar1 * (double)(pfVar2[1] * FLOAT_803db414) + (double)pfVar2[4]);
  pfVar2[5] = (float)(dVar1 * (double)(pfVar2[2] * FLOAT_803db414) + (double)pfVar2[5]);
  *(float *)(param_1 + 0xc) = pfVar2[3];
  *(float *)(param_1 + 0x10) = pfVar2[4];
  *(float *)(param_1 + 0x14) = pfVar2[5];
  *(uint *)(param_1 + 0xf4) = *(int *)(param_1 + 0xf4) - (uint)DAT_803db410;
  if (*(int *)(param_1 + 0xf4) < 0) {
    FUN_8002cbc4(param_1);
  }
  if (*(short *)(pfVar2 + 6) < 0x10) {
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
         *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
  }
  else {
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x6e) = 5;
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x6f) = 1;
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x48) = 0x10;
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x4c) = 0x10;
    *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) = *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) | 1;
  }
  *(ushort *)(pfVar2 + 6) = *(short *)(pfVar2 + 6) + (ushort)DAT_803db410;
  return;
}

