// Function: FUN_8014e8c0
// Entry: 8014e8c0
// Size: 1168 bytes

void FUN_8014e8c0(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  double dVar5;
  undefined auStack88 [4];
  undefined auStack84 [4];
  undefined auStack80 [4];
  float local_4c;
  float local_48;
  float local_44;
  undefined auStack64 [12];
  float local_34;
  undefined auStack48 [4];
  float local_2c;
  double local_28;
  double local_20;
  
  piVar4 = *(int **)(param_1 + 0xb8);
  iVar3 = *piVar4;
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*(int *)(param_1 + 0xf4) == 0) {
    iVar1 = FUN_8002b9ec();
    dVar5 = (double)FUN_80021704(param_1 + 0x18,iVar1 + 0x18);
    if ((double)FLOAT_803e2658 <= dVar5) {
      if ((double)FLOAT_803e265c < dVar5) {
        FUN_8000b824(param_1,0x236);
      }
    }
    else {
      FUN_8000bb18(param_1,0x236);
    }
    if ((*(byte *)(param_1 + 0x36) == 0) || ((*(byte *)((int)piVar4 + 0x26) & 0x18) == 0)) {
      iVar1 = FUN_80036770(param_1,auStack80,auStack84,auStack88,&local_34,auStack48,&local_2c);
      if (iVar1 != 0) {
        FUN_8000b7bc(param_1,0x7f);
        *(byte *)((int)piVar4 + 0x26) = *(byte *)((int)piVar4 + 0x26) | 0x10;
        FUN_8000bb18(param_1,0x232);
        FUN_8000bb18(param_1,0x233);
        FUN_8000bb18(param_1,0x238);
        FUN_8000bb18(param_1,0x1f2);
        local_34 = local_34 + FLOAT_803dcdd8;
        local_2c = local_2c + FLOAT_803dcddc;
        FUN_8009a1dc((double)FLOAT_803e2660,param_1,auStack64,3,0);
        local_20 = (double)CONCAT44(0x43300000,*(short *)(iVar2 + 0x1c) * 0x3c ^ 0x80000000);
        (**(code **)(*DAT_803dcaac + 100))
                  ((double)(float)(local_20 - DOUBLE_803e2648),*(undefined4 *)(iVar2 + 0x14));
        if (*(short *)(iVar2 + 0x20) != -1) {
          FUN_800200e8((int)*(short *)(iVar2 + 0x20),1);
        }
      }
      FUN_80035df4(param_1,10,1,0);
      FUN_80035f20(param_1);
    }
    else {
      if ((*(byte *)((int)piVar4 + 0x26) & 0x10) != 0) {
        local_28 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36));
        iVar1 = (int)((float)(local_28 - DOUBLE_803e2640) - FLOAT_803db414);
        local_20 = (double)(longlong)iVar1;
        *(char *)(param_1 + 0x36) = (char)iVar1;
        if (*(byte *)(param_1 + 0x36) < 7) {
          *(undefined4 *)(param_1 + 0xf4) = 1;
          *(undefined *)(param_1 + 0x36) = 0;
          *(byte *)((int)piVar4 + 0x26) = *(byte *)((int)piVar4 + 0x26) & 0xef;
          FUN_8000b824(param_1,0x236);
        }
        FUN_80035f00(param_1);
      }
      if ((*(byte *)((int)piVar4 + 0x26) & 8) != 0) {
        local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x36));
        iVar1 = (int)((float)(local_20 - DOUBLE_803e2640) + FLOAT_803db414);
        local_28 = (double)(longlong)iVar1;
        *(char *)(param_1 + 0x36) = (char)iVar1;
        if (0xf8 < *(byte *)(param_1 + 0x36)) {
          *(undefined *)(param_1 + 0x36) = 0xff;
          *(byte *)((int)piVar4 + 0x26) = *(byte *)((int)piVar4 + 0x26) & 0xf7;
        }
      }
    }
    iVar1 = FUN_8002b9ec();
    piVar4[1] = iVar1;
    iVar1 = piVar4[1];
    if (iVar1 != 0) {
      local_4c = *(float *)(iVar1 + 0x18) - *(float *)(param_1 + 0x18);
      local_48 = *(float *)(iVar1 + 0x1c) - *(float *)(param_1 + 0x1c);
      local_44 = *(float *)(iVar1 + 0x20) - *(float *)(param_1 + 0x20);
      dVar5 = (double)FUN_802931a0((double)(local_44 * local_44 +
                                           local_4c * local_4c + local_48 * local_48));
      piVar4[4] = (int)(float)dVar5;
    }
    if (iVar3 != 0) {
      local_4c = *(float *)(iVar3 + 0x68) - *(float *)(param_1 + 0x18);
      local_48 = *(float *)(iVar3 + 0x6c) - *(float *)(param_1 + 0x1c);
      local_44 = *(float *)(iVar3 + 0x70) - *(float *)(param_1 + 0x20);
      dVar5 = (double)FUN_802931a0((double)(local_44 * local_44 +
                                           local_4c * local_4c + local_48 * local_48));
      piVar4[5] = (int)(float)dVar5;
    }
    if (((*(byte *)((int)piVar4 + 0x26) & 2) != 0) && (FLOAT_803e2664 < (float)piVar4[5])) {
      *(byte *)((int)piVar4 + 0x26) = *(byte *)((int)piVar4 + 0x26) & 0xfd;
      *(byte *)((int)piVar4 + 0x26) = *(byte *)((int)piVar4 + 0x26) | 4;
    }
    if (((*(byte *)((int)piVar4 + 0x26) & 4) != 0) && ((float)piVar4[5] < FLOAT_803e2668)) {
      *(byte *)((int)piVar4 + 0x26) = *(byte *)((int)piVar4 + 0x26) & 0xfb;
    }
    if (((((*(byte *)((int)piVar4 + 0x26) & 6) == 0) && (*(short *)(iVar2 + 0x1e) == 0)) &&
        (piVar4[1] != 0)) && ((float)piVar4[4] < (float)piVar4[6])) {
      *(byte *)((int)piVar4 + 0x26) = *(byte *)((int)piVar4 + 0x26) | 2;
    }
    FUN_8014e1dc(param_1,piVar4);
    return;
  }
  if ((*(short *)(iVar2 + 0x20) != -1) && (iVar3 = FUN_8001ffb4(), iVar3 != 0)) {
    return;
  }
  iVar2 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(iVar2 + 0x14));
  if (iVar2 == 0) {
    return;
  }
  *(undefined4 *)(param_1 + 0xf4) = 0;
  *(undefined *)(param_1 + 0x36) = 1;
  *(byte *)((int)piVar4 + 0x26) = *(byte *)((int)piVar4 + 0x26) | 8;
  FUN_8000bb18(param_1,0x237);
  return;
}

