// Function: FUN_8016b2e0
// Entry: 8016b2e0
// Size: 780 bytes

void FUN_8016b2e0(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 local_28;
  undefined4 local_24;
  double local_20;
  double local_18;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  uVar3 = (uint)*(byte *)(param_1 + 0x36);
  if (uVar3 < 0xff) {
    local_20 = (double)CONCAT44(0x43300000,uVar3);
    if ((float)(local_20 - DOUBLE_803e31b8) - FLOAT_803e31c4 * FLOAT_803db414 <= FLOAT_803e31c8) {
      FUN_8000b7bc(param_1,0x7f);
      *(undefined *)(param_1 + 0x36) = 0;
      FUN_8002cbc4(param_1);
      return;
    }
    local_20 = (double)CONCAT44(0x43300000,uVar3);
    iVar1 = (int)((float)(local_20 - DOUBLE_803e31b8) - FLOAT_803e31c4 * FLOAT_803db414);
    local_18 = (double)(longlong)iVar1;
    *(char *)(param_1 + 0x36) = (char)iVar1;
  }
  else {
    *(float *)(param_1 + 0x28) = -(FLOAT_803e31cc * FLOAT_803db414 - *(float *)(param_1 + 0x28));
    if (*(float *)(param_1 + 0x28) < FLOAT_803e31d0) {
      *(float *)(param_1 + 0x28) = FLOAT_803e31d0;
    }
    FUN_8002b95c((double)(*(float *)(param_1 + 0x24) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x28) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x2c) * FLOAT_803db414),param_1);
  }
  if ((*(char *)(param_1 + 0x36) == -1) || (*(char *)(iVar4 + 0xc) != '\0')) {
    FUN_80035df4(param_1,5,1,0);
    FUN_80035f20(param_1);
    if ((*(int *)(*(int *)(param_1 + 0x54) + 0x50) != 0) &&
       (iVar1 = FUN_8002b9ec(), *(int *)(*(int *)(param_1 + 0x54) + 0x50) == iVar1)) {
      if (*(char *)(param_1 + 0x36) == -1) {
        puVar5 = *(undefined4 **)(param_1 + 0xb8);
        local_24 = DAT_803e31a0;
        FUN_8000bb18(param_1,0x4a);
        uVar2 = FUN_800221a0(0,2);
        (**(code **)(*(int *)puVar5[2] + 4))(param_1,uVar2,0,2,0xffffffff,&local_24);
        local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(param_1 + 0x50) + 0x62));
        iVar4 = (int)(FLOAT_803e31a4 * (float)(local_18 - DOUBLE_803e31b8));
        local_20 = (double)(longlong)iVar4;
        FUN_80035974(param_1,iVar4);
        FUN_8000e650((double)FLOAT_803e31a8,(double)FLOAT_803e31ac,(double)FLOAT_803e31b0);
        *(undefined *)(param_1 + 0x36) = 0xfe;
        FUN_8002cbc4(*puVar5);
        *puVar5 = 0;
      }
      FUN_80035f00(param_1);
      return;
    }
    if ((*(float *)(param_1 + 0x10) <= *(float *)(iVar4 + 4)) && (*(char *)(param_1 + 0x36) == -1))
    {
      puVar5 = *(undefined4 **)(param_1 + 0xb8);
      local_28 = DAT_803e31a0;
      FUN_8000bb18(param_1,0x4a);
      uVar2 = FUN_800221a0(0,2);
      (**(code **)(*(int *)puVar5[2] + 4))(param_1,uVar2,0,2,0xffffffff,&local_28);
      local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(param_1 + 0x50) + 0x62));
      iVar1 = (int)(FLOAT_803e31a4 * (float)(local_18 - DOUBLE_803e31b8));
      local_20 = (double)(longlong)iVar1;
      FUN_80035974(param_1,iVar1);
      FUN_8000e650((double)FLOAT_803e31a8,(double)FLOAT_803e31ac,(double)FLOAT_803e31b0);
      *(undefined *)(param_1 + 0x36) = 0xfe;
      FUN_8002cbc4(*puVar5);
      *puVar5 = 0;
      *(undefined *)(iVar4 + 0xc) = 1;
    }
  }
  return;
}

