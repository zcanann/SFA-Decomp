// Function: FUN_8016d394
// Entry: 8016d394
// Size: 2820 bytes

void FUN_8016d394(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  int local_58;
  float local_54;
  int local_50;
  undefined2 local_4c [3];
  short local_46;
  float local_44;
  undefined2 local_34;
  undefined2 local_32;
  undefined2 local_30;
  short local_2e;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  longlong local_18;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if ((param_1 != 0) && (param_2 != 0)) {
    if (*(char *)(iVar4 + 0xba) != '\0') {
      iVar2 = FUN_80296e60(param_2);
      if (iVar2 == 0) {
        local_54 = FLOAT_803e3f24;
        fVar1 = FLOAT_803e3f28;
      }
      else {
        local_54 = FLOAT_803e3f20;
        fVar1 = FLOAT_803e3f20;
      }
      if (*(byte *)(iVar4 + 0xbb) == 7) {
        dVar5 = (double)FLOAT_803e3f2c;
        local_18 = (longlong)(int)(FLOAT_803e3f30 * fVar1);
        FUN_800979c0(dVar5,dVar5,dVar5,(double)(FLOAT_803e3f34 * local_54),param_1,7,
                     (uint)*(byte *)(iVar4 + 0xba),1,(int)(FLOAT_803e3f30 * fVar1),0,0);
      }
      else {
        dVar5 = (double)FLOAT_803e3f20;
        local_18 = (longlong)(int)(FLOAT_803e3f30 * fVar1);
        FUN_800979c0(dVar5,dVar5,dVar5,(double)(FLOAT_803e3f34 * local_54),param_1,
                     (uint)*(byte *)(iVar4 + 0xbb),(uint)*(byte *)(iVar4 + 0xba),1,
                     (int)(FLOAT_803e3f30 * fVar1),0,0);
      }
    }
    FUN_80296904(param_2,&local_50,&local_54);
    local_34 = 0;
    local_32 = 0;
    local_30 = 0;
    local_2c = FLOAT_803e3f20;
    if (local_50 == 0x87) {
      iVar4 = (int)(FLOAT_803e3f38 * (local_54 / FLOAT_803e3f30));
      local_18 = (longlong)iVar4;
      local_2e = 0x15 - (short)iVar4;
      local_28 = FLOAT_803e3f3c * (local_54 / FLOAT_803e3f40 - FLOAT_803e3f2c);
      local_34 = 0xc94;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      local_2e = 9;
      local_2c = FLOAT_803e3f48 * (local_54 / FLOAT_803e3f40) + FLOAT_803e3f44;
      local_24 = FLOAT_803e3f4c;
      local_34 = 0xc0e;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
    }
    else if (local_50 < 0x87) {
      if (local_50 == 0x7f) {
        local_2c = FLOAT_803e3f58;
        local_2e = 10;
        local_24 = FLOAT_803e3f54;
        local_28 = FLOAT_803e3f50;
        local_34 = 0xc0e;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
      }
      else if (local_50 < 0x7f) {
        if ((local_50 == 0x43) && (FLOAT_803e3f4c < local_54)) {
          iVar4 = (int)(FLOAT_803e3f38 * (local_54 / FLOAT_803e3f30));
          local_18 = (longlong)iVar4;
          local_2e = (short)iVar4 + 6;
          local_28 = FLOAT_803e3f3c * (local_54 / FLOAT_803e3f40 - FLOAT_803e3f2c);
          local_34 = 0xc94;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b4,&local_34,2,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b4,&local_34,2,0xffffffff,0);
          local_2e = 9;
          local_2c = FLOAT_803e3f48 * (local_54 / FLOAT_803e3f40) + FLOAT_803e3f44;
          local_24 = FLOAT_803e3f4c;
          local_34 = 0xc0e;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
        }
      }
      else if (local_50 == 0x85) {
        if (FLOAT_803e3f4c < local_54) {
          uVar3 = FUN_80020078(0xc55);
          if (uVar3 == 0) {
            fVar1 = local_54 / FLOAT_803e3f40;
            iVar4 = (int)(FLOAT_803e3f38 * fVar1);
            local_2e = (short)iVar4;
            local_34 = 0xc94;
          }
          else {
            fVar1 = local_54 / FLOAT_803e3f50;
            iVar4 = (int)(FLOAT_803e3f38 * fVar1);
            local_2e = (short)iVar4;
            local_34 = 0xc75;
          }
          local_18 = (longlong)iVar4;
          local_28 = FLOAT_803e3f5c * (FLOAT_803e3f28 - fVar1);
          local_2e = 0x15 - local_2e;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
          local_2e = 9;
          uVar3 = FUN_80020078(0xc55);
          if (uVar3 == 0) {
            local_34 = 0xc0e;
            fVar1 = FLOAT_803e3f40;
          }
          else {
            local_34 = 0xc75;
            fVar1 = FLOAT_803e3f50;
          }
          local_2c = FLOAT_803e3f48 * (local_54 / fVar1) + FLOAT_803e3f44;
          local_24 = FLOAT_803e3f4c;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
        }
      }
      else if (0x84 < local_50) {
        uVar3 = FUN_80020078(0xc55);
        if (uVar3 == 0) {
          local_34 = 0xc0e;
        }
        else {
          local_34 = 0xc75;
        }
        fVar1 = *(float *)(param_2 + 0x98);
        if (FLOAT_803e3f68 <= fVar1) {
          if (fVar1 < FLOAT_803e3f70) {
            local_28 = FLOAT_803e3f5c * (FLOAT_803e3f74 * (fVar1 - FLOAT_803e3f68) - FLOAT_803e3f2c)
            ;
            local_2e = 9;
            local_2c = FLOAT_803e3f20;
            local_24 = FLOAT_803e3f4c;
            (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
          }
        }
        else {
          local_28 = FLOAT_803e3f6c;
          local_2e = 9;
          local_2c = FLOAT_803e3f20;
          local_24 = FLOAT_803e3f4c;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
        }
      }
    }
    else if (local_50 == 0x468) {
      if (FLOAT_803e3f4c < local_54) {
        iVar4 = (int)(FLOAT_803e3f38 * (local_54 / FLOAT_803e3f60));
        local_18 = (longlong)iVar4;
        local_46 = 0x15 - (short)iVar4;
        local_4c[0] = 0xc95;
        FUN_80296854(*(int *)(param_1 + 0xc4),&local_58);
        local_28 = *(float *)(local_58 + 0xc);
        local_24 = *(float *)(local_58 + 0x10);
        local_20 = *(undefined4 *)(local_58 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7b9,&local_34,0x200001,0xffffffff,local_4c);
        (**(code **)(*DAT_803dd708 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7b9,&local_34,0x200001,0xffffffff,local_4c);
        (**(code **)(*DAT_803dd708 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7b9,&local_34,0x200001,0xffffffff,local_4c);
        (**(code **)(*DAT_803dd708 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7b9,&local_34,0x200001,0xffffffff,local_4c);
        local_46 = 9;
        local_4c[0] = 0xc95;
        local_44 = FLOAT_803e3f64 * (local_54 / FLOAT_803e3f60) + FLOAT_803e3f44;
        local_28 = *(float *)(local_58 + 0xc);
        local_24 = *(float *)(local_58 + 0x10);
        local_20 = *(undefined4 *)(local_58 + 0x14);
        (**(code **)(*DAT_803dd708 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7ba,&local_34,0x200001,0xffffffff,local_4c);
      }
    }
    else if (local_50 < 0x468) {
      if (local_50 < 0x89) {
        local_2e = 0x23;
        local_24 = FLOAT_803e3f4c;
        local_28 = FLOAT_803e3f50;
        local_34 = 0xc0e;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
        local_2e = 0x12;
        local_24 = FLOAT_803e3f54;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
      }
    }
    else if ((local_50 == 0x46f) && (FLOAT_803e3f4c < local_54)) {
      iVar4 = (int)(FLOAT_803e3f38 * (local_54 / FLOAT_803e3f60));
      local_18 = (longlong)iVar4;
      local_2e = 0x15 - (short)iVar4;
      local_28 = FLOAT_803e3f5c * (FLOAT_803e3f28 - local_54 / FLOAT_803e3f60);
      local_34 = 0xc94;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      local_2e = 9;
      local_2c = FLOAT_803e3f48 * (local_54 / FLOAT_803e3f60) + FLOAT_803e3f44;
      local_24 = FLOAT_803e3f4c;
      local_34 = 0xc0e;
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
    }
  }
  return;
}

