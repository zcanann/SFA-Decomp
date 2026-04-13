// Function: FUN_801909a8
// Entry: 801909a8
// Size: 1376 bytes

void FUN_801909a8(int param_1)

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
  uint uStack_1c;
  
  pfVar5 = *(float **)(param_1 + 0xb8);
  iVar3 = FUN_8002bac4();
  local_2c = FLOAT_803e4b30;
  local_28 = FLOAT_803e4b34;
  local_24 = FLOAT_803e4b30;
  bVar1 = *(byte *)((int)pfVar5 + 0xe);
  if ((bVar1 & 0x40) == 0) {
    if ((bVar1 & 8) == 0) {
      if ((bVar1 & 0x10) == 0) {
        dVar6 = FUN_80021794((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18));
        if (dVar6 < (double)FLOAT_803e4b38) {
          if (((*(byte *)((int)pfVar5 + 0xe) & 0xa0) == 0) || (*(char *)(pfVar5 + 3) != '\0')) {
            FUN_800979c0((double)FLOAT_803e4b48,(double)FLOAT_803e4b40,(double)FLOAT_803e4b40,
                         (double)FLOAT_803e4b44,param_1,1,3,6,100,(int)&local_38,0);
          }
          else {
            FUN_800979c0((double)FLOAT_803e4b3c,(double)FLOAT_803e4b40,(double)FLOAT_803e4b40,
                         (double)FLOAT_803e4b44,param_1,1,2,7,100,(int)&local_38,0);
          }
        }
        local_34 = 0xc13;
        local_36 = 0;
      }
      else {
        dVar6 = FUN_80021794((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18));
        if (dVar6 < (double)FLOAT_803e4b38) {
          if (((*(byte *)((int)pfVar5 + 0xe) & 0xa0) == 0) || (*(char *)(pfVar5 + 3) != '\0')) {
            FUN_800979c0((double)FLOAT_803e4b48,(double)FLOAT_803e4b40,(double)FLOAT_803e4b40,
                         (double)FLOAT_803e4b44,param_1,1,5,6,100,(int)&local_38,0);
          }
          else {
            FUN_800979c0((double)FLOAT_803e4b3c,(double)FLOAT_803e4b40,(double)FLOAT_803e4b40,
                         (double)FLOAT_803e4b44,param_1,1,2,7,100,(int)&local_38,0);
          }
        }
        local_34 = 0xc7e;
        local_36 = 2;
      }
    }
    else {
      dVar6 = FUN_80021794((float *)(param_1 + 0x18),(float *)(iVar3 + 0x18));
      if (dVar6 < (double)FLOAT_803e4b38) {
        if (((*(byte *)((int)pfVar5 + 0xe) & 0xa0) == 0) || (*(char *)(pfVar5 + 3) != '\0')) {
          FUN_800979c0((double)FLOAT_803e4b48,(double)FLOAT_803e4b40,(double)FLOAT_803e4b40,
                       (double)FLOAT_803e4b44,param_1,1,1,6,100,(int)&local_38,0);
        }
        else {
          FUN_800979c0((double)FLOAT_803e4b3c,(double)FLOAT_803e4b40,(double)FLOAT_803e4b40,
                       (double)FLOAT_803e4b44,param_1,1,2,7,100,(int)&local_38,0);
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
    if (FLOAT_803e4b4c <= fVar2) {
      if (FLOAT_803e4b50 <= fVar2) {
        if (FLOAT_803e4b60 <= fVar2) {
          if (FLOAT_803e4b68 <= fVar2) {
            *pfVar5 = FLOAT_803e4b30;
            *(byte *)((int)pfVar5 + 0xe) = *(byte *)((int)pfVar5 + 0xe) & 0xfb;
          }
        }
        else {
          uStack_1c = FUN_80022264(0,0x1e0);
          uStack_1c = uStack_1c ^ 0x80000000;
          local_20 = 0x43300000;
          if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4b70) <
              *pfVar5 * FLOAT_803e4b48) {
            (**(code **)(*DAT_803dd708 + 8))(param_1,0x7ca,&local_38,2,0xffffffff,0);
          }
          if ((*(byte *)((int)pfVar5 + 0xe) & 2) != 0) {
            *(byte *)((int)pfVar5 + 0xe) = *(byte *)((int)pfVar5 + 0xe) & 0xfd;
            local_32 = 0x46;
            local_30 = FLOAT_803e4b64;
            for (cVar4 = '\x0f'; cVar4 != '\0'; cVar4 = cVar4 + -1) {
              (**(code **)(*DAT_803dd708 + 8))(param_1,0x7d2,&local_38,2,0xffffffff,0);
            }
          }
        }
      }
      else {
        uStack_1c = FUN_80022264(0,0x1e0);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4b70) <
            *pfVar5 / FLOAT_803e4b54) {
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7ca,&local_38,2,0xffffffff,0);
        }
        local_32 = 0x28;
        local_38 = 0;
        local_30 = FLOAT_803e4b58 * ((*pfVar5 - FLOAT_803e4b4c) / FLOAT_803e4b5c);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7d2,&local_38,2,0xffffffff,0);
        *(byte *)((int)pfVar5 + 0xe) = *(byte *)((int)pfVar5 + 0xe) | 2;
      }
    }
    else {
      uStack_1c = FUN_80022264(0,0x1e0);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      if ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e4b70) <
          *pfVar5 * FLOAT_803e4b48) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7ca,&local_38,2,0xffffffff,0);
      }
    }
    *pfVar5 = *pfVar5 + FLOAT_803dc074;
  }
  return;
}

