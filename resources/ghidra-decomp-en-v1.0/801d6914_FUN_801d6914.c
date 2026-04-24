// Function: FUN_801d6914
// Entry: 801d6914
// Size: 752 bytes

void FUN_801d6914(int param_1)

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
  uint uStack28;
  
  uVar2 = FUN_8002b9ec();
  iVar4 = *(int *)(param_1 + 0xb8);
  local_2c = FLOAT_803e5460;
  local_28 = FLOAT_803e5464;
  local_24 = FLOAT_803e5460;
  local_34 = 0xc0e;
  local_36 = 1;
  if ((*(byte *)(iVar4 + 0xd4) & 4) != 0) {
    fVar1 = *(float *)(iVar4 + 4);
    if (FLOAT_803e5468 <= fVar1) {
      if (FLOAT_803e5470 <= fVar1) {
        if (FLOAT_803e5480 <= fVar1) {
          if (FLOAT_803e5488 <= fVar1) {
            *(float *)(iVar4 + 4) = FLOAT_803e5460;
            *(byte *)(iVar4 + 0xd4) = *(byte *)(iVar4 + 0xd4) & 0xfb;
          }
        }
        else {
          uStack28 = FUN_800221a0(0,0x1e0);
          uStack28 = uStack28 ^ 0x80000000;
          local_20 = 0x43300000;
          if ((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5490) <
              *(float *)(iVar4 + 4) * FLOAT_803e546c) {
            (**(code **)(*DAT_803dca88 + 8))(uVar2,0x7ca,&local_38,2,0xffffffff,0);
          }
          if ((*(byte *)(iVar4 + 0xd4) & 2) != 0) {
            *(byte *)(iVar4 + 0xd4) = *(byte *)(iVar4 + 0xd4) & 0xfd;
            local_32 = 0x46;
            local_30 = FLOAT_803e5484;
            for (cVar3 = '\x0f'; cVar3 != '\0'; cVar3 = cVar3 + -1) {
              (**(code **)(*DAT_803dca88 + 8))(uVar2,0x7d2,&local_38,2,0xffffffff,0);
            }
          }
        }
      }
      else {
        uStack28 = FUN_800221a0(0,0x1e0);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        if ((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5490) <
            *(float *)(iVar4 + 4) / FLOAT_803e5474) {
          (**(code **)(*DAT_803dca88 + 8))(uVar2,0x7ca,&local_38,2,0xffffffff,0);
        }
        local_32 = 0x28;
        local_38 = 0;
        local_30 = FLOAT_803e5478 * ((*(float *)(iVar4 + 4) - FLOAT_803e5468) / FLOAT_803e547c);
        (**(code **)(*DAT_803dca88 + 8))(uVar2,0x7d2,&local_38,2,0xffffffff,0);
        *(byte *)(iVar4 + 0xd4) = *(byte *)(iVar4 + 0xd4) | 2;
      }
    }
    else {
      uStack28 = FUN_800221a0(0,0x1e0);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      if ((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e5490) <
          *(float *)(iVar4 + 4) * FLOAT_803e546c) {
        (**(code **)(*DAT_803dca88 + 8))(uVar2,0x7ca,&local_38,2,0xffffffff,0);
      }
    }
    *(float *)(iVar4 + 4) = *(float *)(iVar4 + 4) + FLOAT_803db414;
  }
  return;
}

