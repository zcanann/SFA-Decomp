// Function: FUN_801bf8d8
// Entry: 801bf8d8
// Size: 648 bytes

void FUN_801bf8d8(short *param_1)

{
  uint uVar1;
  int iVar2;
  short *psVar3;
  int local_28 [2];
  undefined4 local_20;
  uint uStack28;
  double local_18;
  
  psVar3 = *(short **)(param_1 + 0x5c);
  *(float *)(param_1 + 4) = *(float *)(param_1 + 4) + FLOAT_803e4d38;
  *param_1 = *param_1 + 0xaaa;
  param_1[2] = param_1[2] + 0x38e;
  param_1[1] = param_1[1] + 0x38e;
  if (*psVar3 == 1) {
    iVar2 = 0;
    do {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x340,0,1,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x12);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x4bb,0,1,0xffffffff,0);
    FUN_8000bb18(param_1,0x17e);
    FUN_8000bb18(param_1,0x186);
    FUN_8000e67c((double)FLOAT_803e4d3c);
    FUN_80014aa0((double)FLOAT_803e4d40);
    if (*(int *)(psVar3 + 2) != 0) {
      FUN_8001db6c((double)FLOAT_803e4d44,*(int *)(psVar3 + 2),0);
    }
  }
  *psVar3 = *psVar3 + (ushort)DAT_803db410;
  uVar1 = (uint)*psVar3;
  if ((int)uVar1 < 0x201) {
    uStack28 = uVar1 ^ 0x80000000;
    local_20 = 0x43300000;
    iVar2 = (int)(FLOAT_803e4d48 *
                 (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e4d58) * FLOAT_803e4d4c);
    local_18 = (double)(longlong)iVar2;
    iVar2 = 0xff - iVar2;
    local_28[0] = 0x94 - ((int)uVar1 >> 2);
    if (iVar2 < 0) {
      if (*(int *)(psVar3 + 2) != 0) {
        FUN_8001f384();
        *(undefined4 *)(psVar3 + 2) = 0;
      }
      *(undefined *)(param_1 + 0x1b) = 0;
      local_18 = (double)CONCAT44(0x43300000,local_28[0] + -0x40 >> 1 ^ 0x80000000);
      if (FLOAT_803e4d50 < (float)(local_18 - DOUBLE_803e4d58)) {
        FUN_80035df4(param_1,9,1,0);
        FUN_80035974(param_1,(int)(short)(local_28[0] + -0x40 >> 1));
      }
    }
    else {
      FUN_80035df4(param_1,5,2,0);
      FUN_80035974(param_1,(int)(short)(local_28[0] + -0x40 >> 1));
      *(char *)(param_1 + 0x1b) = (char)iVar2;
    }
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x4bc,0,1,0xffffffff,local_28);
  }
  else if (0x22a < (int)uVar1) {
    FUN_8002cbc4(param_1);
  }
  return;
}

