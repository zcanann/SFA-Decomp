// Function: FUN_8016cee8
// Entry: 8016cee8
// Size: 2820 bytes

void FUN_8016cee8(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
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
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((param_1 != 0) && (param_2 != 0)) {
    if (*(char *)(iVar3 + 0xba) != '\0') {
      iVar2 = FUN_80296700(param_2);
      if (iVar2 == 0) {
        local_54 = FLOAT_803e328c;
        fVar1 = FLOAT_803e3290;
      }
      else {
        local_54 = FLOAT_803e3288;
        fVar1 = FLOAT_803e3288;
      }
      if (*(char *)(iVar3 + 0xbb) == '\a') {
        dVar4 = (double)FLOAT_803e3294;
        local_18 = (longlong)(int)(FLOAT_803e3298 * fVar1);
        FUN_80097734(dVar4,dVar4,dVar4,(double)(FLOAT_803e329c * local_54),param_1,7,
                     *(undefined *)(iVar3 + 0xba),1,(int)(FLOAT_803e3298 * fVar1),0,0);
      }
      else {
        dVar4 = (double)FLOAT_803e3288;
        local_18 = (longlong)(int)(FLOAT_803e3298 * fVar1);
        FUN_80097734(dVar4,dVar4,dVar4,(double)(FLOAT_803e329c * local_54),param_1,
                     *(char *)(iVar3 + 0xbb),*(undefined *)(iVar3 + 0xba),1,
                     (int)(FLOAT_803e3298 * fVar1),0,0);
      }
    }
    FUN_802961a4(param_2,&local_50,&local_54);
    local_34 = 0;
    local_32 = 0;
    local_30 = 0;
    local_2c = FLOAT_803e3288;
    if (local_50 == 0x87) {
      iVar3 = (int)(FLOAT_803e32a0 * (local_54 / FLOAT_803e3298));
      local_18 = (longlong)iVar3;
      local_2e = 0x15 - (short)iVar3;
      local_28 = FLOAT_803e32a4 * (local_54 / FLOAT_803e32a8 - FLOAT_803e3294);
      local_34 = 0xc94;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      local_2e = 9;
      local_2c = FLOAT_803e32b0 * (local_54 / FLOAT_803e32a8) + FLOAT_803e32ac;
      local_24 = FLOAT_803e32b4;
      local_34 = 0xc0e;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
    }
    else if (local_50 < 0x87) {
      if (local_50 == 0x7f) {
        local_2c = FLOAT_803e32c0;
        local_2e = 10;
        local_24 = FLOAT_803e32bc;
        local_28 = FLOAT_803e32b8;
        local_34 = 0xc0e;
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
      }
      else if (local_50 < 0x7f) {
        if ((local_50 == 0x43) && (FLOAT_803e32b4 < local_54)) {
          iVar3 = (int)(FLOAT_803e32a0 * (local_54 / FLOAT_803e3298));
          local_18 = (longlong)iVar3;
          local_2e = (short)iVar3 + 6;
          local_28 = FLOAT_803e32a4 * (local_54 / FLOAT_803e32a8 - FLOAT_803e3294);
          local_34 = 0xc94;
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b4,&local_34,2,0xffffffff,0);
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b4,&local_34,2,0xffffffff,0);
          local_2e = 9;
          local_2c = FLOAT_803e32b0 * (local_54 / FLOAT_803e32a8) + FLOAT_803e32ac;
          local_24 = FLOAT_803e32b4;
          local_34 = 0xc0e;
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
        }
      }
      else if (local_50 == 0x85) {
        if (FLOAT_803e32b4 < local_54) {
          iVar3 = FUN_8001ffb4(0xc55);
          if (iVar3 == 0) {
            fVar1 = local_54 / FLOAT_803e32a8;
            iVar3 = (int)(FLOAT_803e32a0 * fVar1);
            local_2e = (short)iVar3;
            local_34 = 0xc94;
          }
          else {
            fVar1 = local_54 / FLOAT_803e32b8;
            iVar3 = (int)(FLOAT_803e32a0 * fVar1);
            local_2e = (short)iVar3;
            local_34 = 0xc75;
          }
          local_18 = (longlong)iVar3;
          local_28 = FLOAT_803e32c4 * (FLOAT_803e3290 - fVar1);
          local_2e = 0x15 - local_2e;
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
          local_2e = 9;
          iVar3 = FUN_8001ffb4(0xc55);
          if (iVar3 == 0) {
            local_34 = 0xc0e;
            fVar1 = FLOAT_803e32a8;
          }
          else {
            local_34 = 0xc75;
            fVar1 = FLOAT_803e32b8;
          }
          local_2c = FLOAT_803e32b0 * (local_54 / fVar1) + FLOAT_803e32ac;
          local_24 = FLOAT_803e32b4;
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
        }
      }
      else if (0x84 < local_50) {
        iVar3 = FUN_8001ffb4(0xc55);
        if (iVar3 == 0) {
          local_34 = 0xc0e;
        }
        else {
          local_34 = 0xc75;
        }
        fVar1 = *(float *)(param_2 + 0x98);
        if (FLOAT_803e32d0 <= fVar1) {
          if (fVar1 < FLOAT_803e32d8) {
            local_28 = FLOAT_803e32c4 * (FLOAT_803e32dc * (fVar1 - FLOAT_803e32d0) - FLOAT_803e3294)
            ;
            local_2e = 9;
            local_2c = FLOAT_803e3288;
            local_24 = FLOAT_803e32b4;
            (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
          }
        }
        else {
          local_28 = FLOAT_803e32d4;
          local_2e = 9;
          local_2c = FLOAT_803e3288;
          local_24 = FLOAT_803e32b4;
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
        }
      }
    }
    else if (local_50 == 0x468) {
      if (FLOAT_803e32b4 < local_54) {
        iVar3 = (int)(FLOAT_803e32a0 * (local_54 / FLOAT_803e32c8));
        local_18 = (longlong)iVar3;
        local_46 = 0x15 - (short)iVar3;
        local_4c[0] = 0xc95;
        FUN_802960f4(*(undefined4 *)(param_1 + 0xc4),&local_58);
        local_28 = *(float *)(local_58 + 0xc);
        local_24 = *(float *)(local_58 + 0x10);
        local_20 = *(undefined4 *)(local_58 + 0x14);
        (**(code **)(*DAT_803dca88 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7b9,&local_34,0x200001,0xffffffff,local_4c);
        (**(code **)(*DAT_803dca88 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7b9,&local_34,0x200001,0xffffffff,local_4c);
        (**(code **)(*DAT_803dca88 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7b9,&local_34,0x200001,0xffffffff,local_4c);
        (**(code **)(*DAT_803dca88 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7b9,&local_34,0x200001,0xffffffff,local_4c);
        local_46 = 9;
        local_4c[0] = 0xc95;
        local_44 = FLOAT_803e32cc * (local_54 / FLOAT_803e32c8) + FLOAT_803e32ac;
        local_28 = *(float *)(local_58 + 0xc);
        local_24 = *(float *)(local_58 + 0x10);
        local_20 = *(undefined4 *)(local_58 + 0x14);
        (**(code **)(*DAT_803dca88 + 8))
                  (*(undefined4 *)(param_1 + 0xc4),0x7ba,&local_34,0x200001,0xffffffff,local_4c);
      }
    }
    else if (local_50 < 0x468) {
      if (local_50 < 0x89) {
        local_2e = 0x23;
        local_24 = FLOAT_803e32b4;
        local_28 = FLOAT_803e32b8;
        local_34 = 0xc0e;
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
        local_2e = 0x12;
        local_24 = FLOAT_803e32bc;
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
      }
    }
    else if ((local_50 == 0x46f) && (FLOAT_803e32b4 < local_54)) {
      iVar3 = (int)(FLOAT_803e32a0 * (local_54 / FLOAT_803e32c8));
      local_18 = (longlong)iVar3;
      local_2e = 0x15 - (short)iVar3;
      local_28 = FLOAT_803e32c4 * (FLOAT_803e3290 - local_54 / FLOAT_803e32c8);
      local_34 = 0xc94;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b2,&local_34,2,0xffffffff,0);
      local_2e = 9;
      local_2c = FLOAT_803e32b0 * (local_54 / FLOAT_803e32c8) + FLOAT_803e32ac;
      local_24 = FLOAT_803e32b4;
      local_34 = 0xc0e;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7b3,&local_34,2,0xffffffff,0);
    }
  }
  return;
}

