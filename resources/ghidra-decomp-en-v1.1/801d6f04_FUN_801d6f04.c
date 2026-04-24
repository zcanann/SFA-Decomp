// Function: FUN_801d6f04
// Entry: 801d6f04
// Size: 752 bytes

void FUN_801d6f04(int param_1)

{
  float fVar1;
  undefined4 uVar2;
  char cVar3;
  int iVar4;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  
  uVar2 = FUN_8002bac4();
  iVar4 = *(int *)(param_1 + 0xb8);
  local_2c = FLOAT_803e60f8;
  local_28 = FLOAT_803e60fc;
  local_24 = FLOAT_803e60f8;
  local_34 = 0xc0e;
  local_36 = 1;
  if ((*(byte *)(iVar4 + 0xd4) & 4) != 0) {
    fVar1 = *(float *)(iVar4 + 4);
    if (FLOAT_803e6100 <= fVar1) {
      if (FLOAT_803e6108 <= fVar1) {
        if (FLOAT_803e6118 <= fVar1) {
          if (FLOAT_803e6120 <= fVar1) {
            *(float *)(iVar4 + 4) = FLOAT_803e60f8;
            *(byte *)(iVar4 + 0xd4) = *(byte *)(iVar4 + 0xd4) & 0xfb;
          }
        }
        else {
          uStack_1c = FUN_80022264(0,0x1e0);
          uStack_1c = uStack_1c ^ 0x80000000;
          local_20 = 0x43300000;
          if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6128) <
              *(float *)(iVar4 + 4) * FLOAT_803e6104) {
            (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7ca,&local_38,2,0xffffffff,0);
          }
          if ((*(byte *)(iVar4 + 0xd4) & 2) != 0) {
            *(byte *)(iVar4 + 0xd4) = *(byte *)(iVar4 + 0xd4) & 0xfd;
            local_32 = 0x46;
            local_30 = FLOAT_803e611c;
            for (cVar3 = '\x0f'; cVar3 != '\0'; cVar3 = cVar3 + -1) {
              (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7d2,&local_38,2,0xffffffff,0);
            }
          }
        }
      }
      else {
        uStack_1c = FUN_80022264(0,0x1e0);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6128) <
            *(float *)(iVar4 + 4) / FLOAT_803e610c) {
          (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7ca,&local_38,2,0xffffffff,0);
        }
        local_32 = 0x28;
        local_38 = 0;
        local_30 = FLOAT_803e6110 * ((*(float *)(iVar4 + 4) - FLOAT_803e6100) / FLOAT_803e6114);
        (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7d2,&local_38,2,0xffffffff,0);
        *(byte *)(iVar4 + 0xd4) = *(byte *)(iVar4 + 0xd4) | 2;
      }
    }
    else {
      uStack_1c = FUN_80022264(0,0x1e0);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6128) <
          *(float *)(iVar4 + 4) * FLOAT_803e6104) {
        (**(code **)(*DAT_803dd708 + 8))(uVar2,0x7ca,&local_38,2,0xffffffff,0);
      }
    }
    *(float *)(iVar4 + 4) = *(float *)(iVar4 + 4) + FLOAT_803dc074;
  }
  return;
}

