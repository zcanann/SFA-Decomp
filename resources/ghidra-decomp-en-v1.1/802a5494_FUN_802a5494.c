// Function: FUN_802a5494
// Entry: 802a5494
// Size: 600 bytes

undefined4
FUN_802a5494(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  ushort uVar1;
  int iVar2;
  double dVar3;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  *(float *)(param_10 + 0x284) = FLOAT_803e8b3c;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    if ((DAT_803df0cc != 0) && ((*(byte *)(iVar2 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar2 + 0x8b4) = 1;
      *(byte *)(iVar2 + 0x3f4) = *(byte *)(iVar2 + 0x3f4) & 0xf7 | 8;
    }
    *(undefined2 *)(param_10 + 0x278) = 1;
    *(code **)(iVar2 + 0x898) = FUN_802a58ac;
  }
  if (*(short *)(param_9 + 0xa0) == 5) {
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8bd8;
    *(float *)(param_10 + 0x280) = FLOAT_803e8b3c;
    if (*(int *)(iVar2 + 0x7f8) != 0) {
      if (FLOAT_803e8b30 < *(float *)(param_9 + 0x98)) {
        *(undefined4 *)(*(int *)(iVar2 + 0x7f8) + 0xf8) = 1;
      }
      param_3 = (double)FLOAT_803dc074;
      dVar3 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,
                                                            *(uint *)(iVar2 + 0x4a4) ^ 0x80000000) -
                                          DOUBLE_803e8b58),(double)FLOAT_803e8cf4,param_3);
      param_2 = DOUBLE_803e8b58;
      *(short *)(iVar2 + 0x478) =
           (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                         (int)*(short *)(iVar2 + 0x478) ^ 0x80000000
                                                        ) - DOUBLE_803e8b58) + dVar3);
      *(undefined2 *)(iVar2 + 0x484) = *(undefined2 *)(iVar2 + 0x478);
    }
    if (FLOAT_803e8bc4 < *(float *)(param_9 + 0x98)) {
      *(undefined2 **)(iVar2 + 0x3f8) = &DAT_80333d70;
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,(int)**(short **)(iVar2 + 0x3f8),0,param_12,param_13,param_14,param_15,
                   param_16);
      *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x800000;
      *(code **)(param_10 + 0x308) = FUN_802a58ac;
      return 2;
    }
  }
  else {
    if ((*(int *)(iVar2 + 0x7f8) != 0) && (*(short *)(*(int *)(iVar2 + 0x7f8) + 0x46) == 0x112)) {
      *(undefined2 **)(iVar2 + 0x3f8) = &DAT_80333d70;
      *(undefined4 *)(*(int *)(iVar2 + 0x7f8) + 0xf8) = 1;
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,(int)**(short **)(iVar2 + 0x3f8),0,param_12,param_13,param_14,param_15,
                   param_16);
      *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x800000;
      *(code **)(param_10 + 0x308) = FUN_802a58ac;
      return 2;
    }
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,5,0,param_12,param_13,param_14,param_15,param_16);
  }
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    if (*(short *)(iVar2 + 0x81a) == 0) {
      uVar1 = 800;
    }
    else {
      uVar1 = 0x3c1;
    }
    FUN_8000bb38(param_9,uVar1);
  }
  return 0;
}

