// Function: FUN_802a4d34
// Entry: 802a4d34
// Size: 600 bytes

undefined4 FUN_802a4d34(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  double dVar3;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(float *)(param_2 + 0x284) = FLOAT_803e7ea4;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    if ((DAT_803de44c != 0) && ((*(byte *)(iVar2 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar2 + 0x8b4) = 1;
      *(byte *)(iVar2 + 0x3f4) = *(byte *)(iVar2 + 0x3f4) & 0xf7 | 8;
    }
    *(undefined2 *)(param_2 + 0x278) = 1;
    *(code **)(iVar2 + 0x898) = FUN_802a514c;
  }
  if (*(short *)(param_1 + 0xa0) == 5) {
    *(float *)(param_2 + 0x2a0) = FLOAT_803e7f40;
    *(float *)(param_2 + 0x280) = FLOAT_803e7ea4;
    if (*(int *)(iVar2 + 0x7f8) != 0) {
      if (FLOAT_803e7e98 < *(float *)(param_1 + 0x98)) {
        *(undefined4 *)(*(int *)(iVar2 + 0x7f8) + 0xf8) = 1;
      }
      dVar3 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,
                                                                    *(uint *)(iVar2 + 0x4a4) ^
                                                                    0x80000000) - DOUBLE_803e7ec0),
                                   (double)FLOAT_803e805c,(double)FLOAT_803db414);
      *(short *)(iVar2 + 0x478) =
           (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                         (int)*(short *)(iVar2 + 0x478) ^ 0x80000000
                                                        ) - DOUBLE_803e7ec0) + dVar3);
      *(undefined2 *)(iVar2 + 0x484) = *(undefined2 *)(iVar2 + 0x478);
    }
    if (FLOAT_803e7f2c < *(float *)(param_1 + 0x98)) {
      *(undefined **)(iVar2 + 0x3f8) = &DAT_80333110;
      FUN_80030334((double)FLOAT_803e7ea4,param_1,(int)**(short **)(iVar2 + 0x3f8),0);
      *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x800000;
      *(code **)(param_2 + 0x308) = FUN_802a514c;
      return 2;
    }
  }
  else {
    if ((*(int *)(iVar2 + 0x7f8) != 0) && (*(short *)(*(int *)(iVar2 + 0x7f8) + 0x46) == 0x112)) {
      *(undefined **)(iVar2 + 0x3f8) = &DAT_80333110;
      *(undefined4 *)(*(int *)(iVar2 + 0x7f8) + 0xf8) = 1;
      FUN_80030334((double)FLOAT_803e7ea4,param_1,(int)**(short **)(iVar2 + 0x3f8),0);
      *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x800000;
      *(code **)(param_2 + 0x308) = FUN_802a514c;
      return 2;
    }
    FUN_80030334((double)FLOAT_803e7ea4,param_1,5,0);
  }
  if ((*(uint *)(param_2 + 0x314) & 1) != 0) {
    if (*(short *)(iVar2 + 0x81a) == 0) {
      uVar1 = 800;
    }
    else {
      uVar1 = 0x3c1;
    }
    FUN_8000bb18(param_1,uVar1);
  }
  return 0;
}

