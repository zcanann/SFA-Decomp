// Function: FUN_801bfe8c
// Entry: 801bfe8c
// Size: 648 bytes

void FUN_801bfe8c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)

{
  uint uVar1;
  int iVar2;
  short *psVar3;
  double dVar4;
  int local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  undefined8 local_18;
  
  psVar3 = *(short **)(param_9 + 0x5c);
  dVar4 = (double)*(float *)(param_9 + 4);
  *(float *)(param_9 + 4) = (float)(dVar4 + (double)FLOAT_803e59d0);
  *param_9 = *param_9 + 0xaaa;
  param_9[2] = param_9[2] + 0x38e;
  param_9[1] = param_9[1] + 0x38e;
  if (*psVar3 == 1) {
    iVar2 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(param_9,0x340,0,1,0xffffffff,0);
      iVar2 = iVar2 + 1;
    } while (iVar2 < 0x12);
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x4bb,0,1,0xffffffff,0);
    FUN_8000bb38((uint)param_9,0x17e);
    FUN_8000bb38((uint)param_9,0x186);
    FUN_8000e69c((double)FLOAT_803e59d4);
    dVar4 = (double)FUN_80014acc((double)FLOAT_803e59d8);
    if (*(int *)(psVar3 + 2) != 0) {
      dVar4 = (double)FUN_8001dc30((double)FLOAT_803e59dc,*(int *)(psVar3 + 2),'\0');
    }
  }
  *psVar3 = *psVar3 + (ushort)DAT_803dc070;
  uVar1 = (uint)*psVar3;
  if ((int)uVar1 < 0x201) {
    uStack_1c = uVar1 ^ 0x80000000;
    local_20 = 0x43300000;
    iVar2 = (int)(FLOAT_803e59e0 *
                 (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e59f0) * FLOAT_803e59e4)
    ;
    local_18 = (double)(longlong)iVar2;
    iVar2 = 0xff - iVar2;
    local_28[0] = 0x94 - ((int)uVar1 >> 2);
    if (iVar2 < 0) {
      if (*(uint *)(psVar3 + 2) != 0) {
        FUN_8001f448(*(uint *)(psVar3 + 2));
        psVar3[2] = 0;
        psVar3[3] = 0;
      }
      *(undefined *)(param_9 + 0x1b) = 0;
      local_18 = (double)CONCAT44(0x43300000,local_28[0] + -0x40 >> 1 ^ 0x80000000);
      if (FLOAT_803e59e8 < (float)(local_18 - DOUBLE_803e59f0)) {
        FUN_80035eec((int)param_9,9,1,0);
        FUN_80035a6c((int)param_9,(short)(local_28[0] + -0x40 >> 1));
      }
    }
    else {
      FUN_80035eec((int)param_9,5,2,0);
      FUN_80035a6c((int)param_9,(short)(local_28[0] + -0x40 >> 1));
      *(char *)(param_9 + 0x1b) = (char)iVar2;
    }
    (**(code **)(*DAT_803dd708 + 8))(param_9,0x4bc,0,1,0xffffffff,local_28);
  }
  else if (0x22a < (int)uVar1) {
    FUN_8002cc9c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
  }
  return;
}

