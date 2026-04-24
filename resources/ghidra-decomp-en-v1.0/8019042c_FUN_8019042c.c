// Function: FUN_8019042c
// Entry: 8019042c
// Size: 1376 bytes

void FUN_8019042c(int param_1)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  char cVar4;
  float *pfVar5;
  double dVar6;
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
  
  pfVar5 = *(float **)(param_1 + 0xb8);
  iVar3 = FUN_8002b9ec();
  local_2c = FLOAT_803e3e98;
  local_28 = FLOAT_803e3e9c;
  local_24 = FLOAT_803e3e98;
  bVar1 = *(byte *)((int)pfVar5 + 0xe);
  if ((bVar1 & 0x40) == 0) {
    if ((bVar1 & 8) == 0) {
      if ((bVar1 & 0x10) == 0) {
        dVar6 = (double)FUN_800216d0(param_1 + 0x18,iVar3 + 0x18);
        if (dVar6 < (double)FLOAT_803e3ea0) {
          if (((*(byte *)((int)pfVar5 + 0xe) & 0xa0) == 0) || (*(char *)(pfVar5 + 3) != '\0')) {
            FUN_80097734((double)FLOAT_803e3eb0,(double)FLOAT_803e3ea8,(double)FLOAT_803e3ea8,
                         (double)FLOAT_803e3eac,param_1,1,3,6,100,&local_38,0);
          }
          else {
            FUN_80097734((double)FLOAT_803e3ea4,(double)FLOAT_803e3ea8,(double)FLOAT_803e3ea8,
                         (double)FLOAT_803e3eac,param_1,1,2,7,100,&local_38,0);
          }
        }
        local_34 = 0xc13;
        local_36 = 0;
      }
      else {
        dVar6 = (double)FUN_800216d0(param_1 + 0x18,iVar3 + 0x18);
        if (dVar6 < (double)FLOAT_803e3ea0) {
          if (((*(byte *)((int)pfVar5 + 0xe) & 0xa0) == 0) || (*(char *)(pfVar5 + 3) != '\0')) {
            FUN_80097734((double)FLOAT_803e3eb0,(double)FLOAT_803e3ea8,(double)FLOAT_803e3ea8,
                         (double)FLOAT_803e3eac,param_1,1,5,6,100,&local_38,0);
          }
          else {
            FUN_80097734((double)FLOAT_803e3ea4,(double)FLOAT_803e3ea8,(double)FLOAT_803e3ea8,
                         (double)FLOAT_803e3eac,param_1,1,2,7,100,&local_38,0);
          }
        }
        local_34 = 0xc7e;
        local_36 = 2;
      }
    }
    else {
      dVar6 = (double)FUN_800216d0(param_1 + 0x18,iVar3 + 0x18);
      if (dVar6 < (double)FLOAT_803e3ea0) {
        if (((*(byte *)((int)pfVar5 + 0xe) & 0xa0) == 0) || (*(char *)(pfVar5 + 3) != '\0')) {
          FUN_80097734((double)FLOAT_803e3eb0,(double)FLOAT_803e3ea8,(double)FLOAT_803e3ea8,
                       (double)FLOAT_803e3eac,param_1,1,1,6,100,&local_38,0);
        }
        else {
          FUN_80097734((double)FLOAT_803e3ea4,(double)FLOAT_803e3ea8,(double)FLOAT_803e3ea8,
                       (double)FLOAT_803e3eac,param_1,1,2,7,100,&local_38,0);
        }
      }
      local_34 = 0xc0e;
      local_36 = 1;
    }
  }
  else if ((bVar1 & 8) == 0) {
    if ((bVar1 & 0x10) == 0) {
      local_34 = 0xc13;
      local_36 = 0;
    }
    else {
      local_34 = 0xc7e;
      local_36 = 2;
    }
  }
  else {
    local_34 = 0xc0e;
    local_36 = 1;
  }
  if ((*(byte *)((int)pfVar5 + 0xe) & 4) != 0) {
    fVar2 = *pfVar5;
    if (FLOAT_803e3eb4 <= fVar2) {
      if (FLOAT_803e3eb8 <= fVar2) {
        if (FLOAT_803e3ec8 <= fVar2) {
          if (FLOAT_803e3ed0 <= fVar2) {
            *pfVar5 = FLOAT_803e3e98;
            *(byte *)((int)pfVar5 + 0xe) = *(byte *)((int)pfVar5 + 0xe) & 0xfb;
          }
        }
        else {
          uStack28 = FUN_800221a0(0,0x1e0);
          uStack28 = uStack28 ^ 0x80000000;
          local_20 = 0x43300000;
          if ((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e3ed8) <
              *pfVar5 * FLOAT_803e3eb0) {
            (**(code **)(*DAT_803dca88 + 8))(param_1,0x7ca,&local_38,2,0xffffffff,0);
          }
          if ((*(byte *)((int)pfVar5 + 0xe) & 2) != 0) {
            *(byte *)((int)pfVar5 + 0xe) = *(byte *)((int)pfVar5 + 0xe) & 0xfd;
            local_32 = 0x46;
            local_30 = FLOAT_803e3ecc;
            for (cVar4 = '\x0f'; cVar4 != '\0'; cVar4 = cVar4 + -1) {
              (**(code **)(*DAT_803dca88 + 8))(param_1,0x7d2,&local_38,2,0xffffffff,0);
            }
          }
        }
      }
      else {
        uStack28 = FUN_800221a0(0,0x1e0);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        if ((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e3ed8) <
            *pfVar5 / FLOAT_803e3ebc) {
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x7ca,&local_38,2,0xffffffff,0);
        }
        local_32 = 0x28;
        local_38 = 0;
        local_30 = FLOAT_803e3ec0 * ((*pfVar5 - FLOAT_803e3eb4) / FLOAT_803e3ec4);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x7d2,&local_38,2,0xffffffff,0);
        *(byte *)((int)pfVar5 + 0xe) = *(byte *)((int)pfVar5 + 0xe) | 2;
      }
    }
    else {
      uStack28 = FUN_800221a0(0,0x1e0);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      if ((float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e3ed8) <
          *pfVar5 * FLOAT_803e3eb0) {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x7ca,&local_38,2,0xffffffff,0);
      }
    }
    *pfVar5 = *pfVar5 + FLOAT_803db414;
  }
  return;
}

