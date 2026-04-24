// Function: FUN_800c2ba8
// Entry: 800c2ba8
// Size: 7700 bytes

/* WARNING: Removing unreachable block (ram,0x800c4994) */
/* WARNING: Removing unreachable block (ram,0x800c2bb8) */

undefined4
FUN_800c2ba8(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5,
            float *param_6)

{
  float fVar1;
  undefined4 uVar2;
  uint uVar3;
  double dVar4;
  int local_c8 [3];
  undefined2 local_bc;
  undefined2 local_ba;
  undefined2 local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  undefined2 local_88;
  undefined2 local_86;
  uint local_84;
  undefined4 local_80;
  uint local_7c;
  uint local_78;
  uint local_74;
  undefined2 local_70;
  undefined2 local_6e;
  undefined2 local_6c;
  undefined local_6a;
  undefined local_68;
  undefined local_67;
  undefined local_66;
  undefined8 local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  FLOAT_803dc490 = FLOAT_803dc490 + FLOAT_803e0b38;
  if (FLOAT_803e0b40 < FLOAT_803dc490) {
    FLOAT_803dc490 = FLOAT_803e0b3c;
  }
  FLOAT_803dc494 = FLOAT_803dc494 + FLOAT_803e0b44;
  if (FLOAT_803e0b40 < FLOAT_803dc494) {
    FLOAT_803dc494 = FLOAT_803e0b48;
  }
  if (param_1 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        return 0xffffffff;
      }
      local_b0 = *(float *)(param_3 + 6);
      local_ac = *(float *)(param_3 + 8);
      local_a8 = *(float *)(param_3 + 10);
      local_b4 = *(float *)(param_3 + 4);
      local_b8 = param_3[2];
      local_ba = param_3[1];
      local_bc = *param_3;
      local_66 = param_5;
    }
    local_84 = 0;
    local_80 = 0;
    local_6a = (undefined)param_2;
    local_98 = FLOAT_803e0b4c;
    local_94 = FLOAT_803e0b4c;
    local_90 = FLOAT_803e0b4c;
    local_a4 = FLOAT_803e0b4c;
    local_a0 = FLOAT_803e0b4c;
    local_9c = FLOAT_803e0b4c;
    local_8c = FLOAT_803e0b4c;
    local_c8[2] = 0;
    local_c8[1] = 0xffffffff;
    local_68 = 0xff;
    local_67 = 0;
    local_86 = 0;
    local_70 = 0xffff;
    local_6e = 0xffff;
    local_6c = 0xffff;
    local_7c = 0xffff;
    local_78 = 0xffff;
    local_74 = 0xffff;
    local_88 = 0;
    if (param_3 == (undefined2 *)0x0) {
      DAT_8039d01c = FLOAT_803e0b4c;
      DAT_8039d020 = FLOAT_803e0b4c;
      DAT_8039d024 = FLOAT_803e0b4c;
      DAT_8039d018 = FLOAT_803e0b40;
      DAT_8039d010 = 0;
      DAT_8039d012 = 0;
      DAT_8039d014 = 0;
      param_3 = &DAT_8039d010;
    }
    local_c8[0] = param_1;
    switch(param_2) {
    case 0x32a:
      local_c8[2] = (int)(FLOAT_803e0b54 * *(float *)(param_3 + 4) + FLOAT_803e0b50);
      local_60 = (double)(longlong)local_c8[2];
      uStack_54 = local_c8[2] ^ 0x80000000;
      local_58 = 0x43300000;
      local_8c = FLOAT_803e0b58 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0ba8);
      local_84 = 0x8100200;
      local_86 = 0x57;
      local_b0 = *(float *)(param_3 + 6);
      local_ac = *(float *)(param_3 + 8);
      local_a8 = *(float *)(param_3 + 10);
      local_b4 = FLOAT_803e0b40;
      local_b8 = 0;
      local_ba = 0;
      local_bc = *param_3;
      local_68 = 0xff;
      break;
    case 0x32b:
      uStack_54 = FUN_80022264(0x96,200);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_c8[2] = (int)(*(float *)(param_3 + 4) *
                          (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0ba8) +
                         FLOAT_803e0b54);
      local_60 = (double)(longlong)local_c8[2];
      uStack_4c = local_c8[2] ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803e0b5c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0ba8);
      local_84 = 0x8100200;
      local_86 = 0x56;
      local_b0 = *(float *)(param_3 + 6);
      local_ac = *(float *)(param_3 + 8);
      local_a8 = *(float *)(param_3 + 10);
      local_b4 = FLOAT_803e0b40;
      local_b8 = 0;
      local_ba = 0;
      local_bc = 0;
      local_68 = 0xff;
      break;
    case 0x32c:
      uStack_4c = FUN_80022264(2,4);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0ba8);
      local_c8[2] = 200;
      local_84 = 0x8100200;
      local_86 = 0x56;
      local_b0 = *(float *)(param_3 + 6);
      local_ac = *(float *)(param_3 + 8);
      local_a8 = *(float *)(param_3 + 10);
      local_b4 = FLOAT_803e0b40;
      local_b8 = 0;
      local_ba = 0;
      local_bc = 0;
      local_68 = 0xff;
      break;
    case 0x32d:
      local_8c = FLOAT_803e0b64;
      local_c8[2] = 0x32;
      local_84 = 0x180200;
      local_80 = 0x1000000;
      local_86 = 0x60;
      local_68 = 0xff;
      break;
    case 0x32e:
      uStack_4c = FUN_80022264(0xffffffd8,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a4 = FLOAT_803e0b68 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0ba8);
      uStack_54 = FUN_80022264(10,0x50);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803e0b6c * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0ba8);
      uVar3 = FUN_80022264(0xffffffd8,0x28);
      local_60 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_9c = FLOAT_803e0b68 * (float)(local_60 - DOUBLE_803e0ba8);
      uStack_44 = FUN_80022264(5,0x19);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803e0b70 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0ba8);
      local_c8[2] = FUN_80022264(100,0x78);
      uVar3 = FUN_80022264(0,0xffff);
      local_bc = (undefined2)uVar3;
      uVar3 = FUN_80022264(0,0xffff);
      local_ba = (undefined2)uVar3;
      uVar3 = FUN_80022264(0,0xffff);
      local_bc = (undefined2)uVar3;
      uStack_3c = FUN_80022264(0xe6,800);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_b0 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
      uStack_34 = FUN_80022264(0xe6,800);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_ac = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
      uStack_2c = FUN_80022264(0xe6,800);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_a8 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
      local_80 = 0x1000020;
      local_84 = 0x86000008;
      uVar3 = FUN_80022264(0x8000,0xffff);
      local_7c = uVar3 & 0xffff;
      local_70 = (undefined2)uVar3;
      local_6e = 0xffff;
      local_78 = 0xffff;
      local_6c = 0xffff;
      local_74 = 0xffff;
      local_86 = 0x3a3;
      break;
    case 0x32f:
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      uStack_2c = FUN_80022264(0xffffff9c,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803e0b74 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
      uStack_34 = FUN_80022264(0xffffff9c,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0b74 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
      uStack_3c = FUN_80022264(0xffffff9c,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0b74 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
      uStack_44 = FUN_80022264(4,5);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = *(float *)(param_3 + 4) *
                 FLOAT_803e0b78 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0ba8);
      local_c8[2] = FUN_80022264(0xf,0x23);
      local_68 = 0xff;
      local_84 = 0x80110;
      local_80 = 0x8400c00;
      local_86 = 0xc79;
      break;
    case 0x330:
      uStack_2c = FUN_80022264(0xffffff9c,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803e0b38 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8)
                 + *(float *)(param_3 + 6);
      uStack_34 = FUN_80022264(0xffffff9c,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e0b38 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8)
                 + *(float *)(param_3 + 8);
      uStack_3c = FUN_80022264(0xffffff9c,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = FLOAT_803e0b38 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8)
                 + *(float *)(param_3 + 10);
      uStack_44 = FUN_80022264(0xffffff9c,100);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803e0b7c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0ba8);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803e0b7c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0ba8);
      uStack_54 = FUN_80022264(0xffffff9c,100);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = FLOAT_803e0b7c * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0ba8);
      local_8c = FLOAT_803e0b68 * *(float *)(param_3 + 4);
      local_c8[2] = FUN_80022264(0xf,0x23);
      local_68 = 0xff;
      local_84 = 0x80100;
      local_80 = 0x4400c00;
      local_86 = 0xc74;
      break;
    case 0x331:
    case 0x333:
    case 0x334:
    case 0x335:
    case 0x339:
      break;
    case 0x332:
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803e0b80 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
      local_a0 = FLOAT_803e0b80;
      uStack_34 = FUN_80022264(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = FLOAT_803e0b80 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
      local_8c = FLOAT_803e0b84;
      local_c8[2] = 0x96;
      local_84 = 0xa100100;
      local_86 = 0x62;
      break;
    case 0x336:
      fVar1 = FLOAT_803e0b40;
      if (param_6 != (float *)0x0) {
        fVar1 = *param_6;
      }
      dVar4 = (double)fVar1;
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = (float)(dVar4 * (double)(float)((double)CONCAT44(0x43300000,uStack_2c) -
                                                DOUBLE_803e0ba8));
      uStack_34 = FUN_80022264(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = (float)(dVar4 * (double)(float)((double)CONCAT44(0x43300000,uStack_34) -
                                                DOUBLE_803e0ba8));
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)(dVar4 * (double)(float)((double)CONCAT44(0x43300000,uStack_3c) -
                                                DOUBLE_803e0ba8));
      uStack_44 = FUN_80022264(0xfffffff1,0xf);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = (float)(dVar4 * (double)(FLOAT_803e0b60 *
                                         (float)((double)CONCAT44(0x43300000,uStack_44) -
                                                DOUBLE_803e0ba8)));
      uStack_4c = FUN_80022264(0xfffffff1,0xf);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = (float)(dVar4 * (double)(FLOAT_803e0b60 *
                                         (float)((double)CONCAT44(0x43300000,uStack_4c) -
                                                DOUBLE_803e0ba8)));
      uStack_54 = FUN_80022264(0xfffffff1,0xf);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = (float)(dVar4 * (double)(FLOAT_803e0b60 *
                                         (float)((double)CONCAT44(0x43300000,uStack_54) -
                                                DOUBLE_803e0ba8)));
      uVar3 = FUN_80022264(8,10);
      local_60 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_8c = FLOAT_803e0b88 * (float)(local_60 - DOUBLE_803e0ba8);
      local_c8[2] = 0x50;
      local_84 = 0x80480404;
      local_80 = 0x20;
      local_6c = 0;
      local_6e = 0;
      local_70 = 0;
      local_74 = 0;
      local_78 = 0;
      local_7c = 0;
      local_86 = 0xc9d;
      break;
    case 0x337:
      if (param_6 == (float *)0x0) {
        fVar1 = 0.0;
      }
      else {
        fVar1 = *param_6;
      }
      if (fVar1 == 0.0) {
        local_8c = FLOAT_803e0b60;
        local_c8[2] = 1;
        local_84 = 0x480000;
      }
      else if (fVar1 == 1.4013e-45) {
        local_8c = FLOAT_803e0b8c;
        local_c8[2] = 1;
        local_84 = 0x480000;
        local_68 = 0x32;
      }
      else if (fVar1 == 2.8026e-45) {
        uStack_2c = FUN_80022264(0xfffffff1,0xf);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_a4 = FLOAT_803e0b60 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
        uStack_34 = FUN_80022264(0xfffffff1,0xf);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_a0 = FLOAT_803e0b60 *
                   (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
        uStack_3c = FUN_80022264(0xfffffff6,10);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_9c = FLOAT_803e0b60 *
                   (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
        local_8c = FLOAT_803e0b7c;
        local_c8[2] = FUN_80022264(0x1e,0x28);
        local_84 = 0x3000000;
        local_80 = 0x600000;
      }
      else if (fVar1 == 4.2039e-45) {
        uStack_2c = FUN_80022264(0xfffffff6,10);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_98 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
        uStack_34 = FUN_80022264(0xfffffff6,10);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_94 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
        uStack_3c = FUN_80022264(0xfffffff6,10);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_90 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
        uStack_44 = FUN_80022264(0xfffffff1,0xf);
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_a4 = FLOAT_803e0b60 *
                   (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0ba8);
        uStack_4c = FUN_80022264(0xfffffff1,0xf);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_a0 = FLOAT_803e0b60 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0ba8);
        uStack_54 = FUN_80022264(0xfffffff1,0xf);
        uStack_54 = uStack_54 ^ 0x80000000;
        local_58 = 0x43300000;
        local_9c = FLOAT_803e0b60 *
                   (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0ba8);
        uVar3 = FUN_80022264(8,10);
        local_60 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        local_8c = FLOAT_803e0b88 * (float)(local_60 - DOUBLE_803e0ba8);
        local_c8[2] = 0x1e;
        local_68 = 0xb4;
        local_84 = 0x80480404;
      }
      else {
        uStack_2c = FUN_80022264(0xfffffffd,3);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_98 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
        uStack_34 = FUN_80022264(0xfffffffd,3);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_94 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
        uStack_3c = FUN_80022264(0xfffffffd,3);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_90 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
        local_8c = FLOAT_803e0b90;
        local_c8[2] = 100;
        local_84 = 0x80480000;
        local_80 = 0x400000;
        local_68 = 0x7f;
      }
      local_86 = 0xc7e;
      break;
    case 0x338:
      if (param_6 == (float *)0x0) {
        fVar1 = 0.0;
      }
      else {
        fVar1 = *param_6;
      }
      if (fVar1 == 0.0) {
        local_8c = FLOAT_803e0b60;
        local_c8[2] = 1;
        local_84 = 0x480000;
      }
      else if (fVar1 == 1.4013e-45) {
        local_8c = FLOAT_803e0b8c;
        local_c8[2] = 1;
        local_84 = 0x480000;
        local_68 = 0x32;
      }
      else if (fVar1 == 2.8026e-45) {
        uStack_2c = FUN_80022264(0xfffffff1,0xf);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_a4 = FLOAT_803e0b60 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
        uStack_34 = FUN_80022264(0xfffffff1,0xf);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_a0 = FLOAT_803e0b60 *
                   (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
        uStack_3c = FUN_80022264(0xfffffff6,10);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_9c = FLOAT_803e0b60 *
                   (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
        local_8c = FLOAT_803e0b7c;
        local_c8[2] = FUN_80022264(0x1e,0x28);
        local_84 = 0x3000000;
        local_80 = 0x600000;
      }
      else if (fVar1 == 4.2039e-45) {
        uStack_2c = FUN_80022264(0xfffffff6,10);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_98 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
        uStack_34 = FUN_80022264(0xfffffff6,10);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_94 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
        uStack_3c = FUN_80022264(0xfffffff6,10);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_90 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
        uStack_44 = FUN_80022264(0xfffffff1,0xf);
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_a4 = FLOAT_803e0b60 *
                   (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0ba8);
        uStack_4c = FUN_80022264(0xfffffff1,0xf);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_a0 = FLOAT_803e0b60 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0ba8);
        uStack_54 = FUN_80022264(0xfffffff1,0xf);
        uStack_54 = uStack_54 ^ 0x80000000;
        local_58 = 0x43300000;
        local_9c = FLOAT_803e0b60 *
                   (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0ba8);
        uVar3 = FUN_80022264(8,10);
        local_60 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        local_8c = FLOAT_803e0b88 * (float)(local_60 - DOUBLE_803e0ba8);
        local_c8[2] = 0x1e;
        local_68 = 0xb4;
        local_84 = 0x80480404;
      }
      else {
        uStack_2c = FUN_80022264(0xfffffffd,3);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_98 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
        uStack_34 = FUN_80022264(0xfffffffd,3);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_94 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
        uStack_3c = FUN_80022264(0xfffffffd,3);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_90 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
        local_8c = FLOAT_803e0b90;
        local_c8[2] = 100;
        local_84 = 0x80480000;
        local_80 = 0x400000;
        local_68 = 0x7f;
      }
      local_86 = 0x4f9;
      break;
    default:
      return 0xffffffff;
    case 0x340:
      uStack_2c = FUN_80022264(0xffffff9c,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
      uStack_34 = FUN_80022264(10,200);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
      uStack_3c = FUN_80022264(0xffffff9c,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
      uStack_44 = FUN_80022264(8,0xb);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803e0b70 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0ba8);
      local_c8[2] = 0x4b;
      local_84 = 0x1080000;
      local_86 = 0xc0f;
      break;
    case 0x342:
      uStack_2c = FUN_80022264(0xffffff9c,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
      uStack_34 = FUN_80022264(0x14,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0b94 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
      uStack_3c = FUN_80022264(0xffffff9c,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
      local_8c = FLOAT_803e0b98;
      local_c8[2] = 0x28;
      local_84 = 0x1080200;
      local_86 = 0xc0f;
      break;
    case 0x343:
      uStack_2c = FUN_80022264(0xffffff9c,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
      uStack_34 = FUN_80022264(10,200);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
      uStack_3c = FUN_80022264(0xffffff9c,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
      uStack_44 = FUN_80022264(8,0xb);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803e0b9c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0ba8);
      local_c8[2] = FUN_80022264(0x41,0x4b);
      local_84 = 0x1080000;
      local_80 = 0x5000000;
      local_86 = 0x77;
      uVar3 = FUN_80022264(0x46,100);
      local_68 = (undefined)uVar3;
      break;
    case 0x344:
      uStack_2c = FUN_80022264(0xffffff9c,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
      uStack_34 = FUN_80022264(0x14,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0b94 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
      uStack_3c = FUN_80022264(0xffffff9c,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
      uStack_44 = FUN_80022264(5,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803e0b9c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0ba8);
      local_c8[2] = 0x28;
      local_84 = 0x1080200;
      local_86 = 0x77;
      local_68 = 0x7f;
      break;
    case 0x345:
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
      uStack_34 = FUN_80022264(0x14,0x28);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
      uStack_44 = FUN_80022264(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0ba8);
      local_94 = FLOAT_803e0ba0;
      uStack_4c = FUN_80022264(0xfffffff6,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0ba8);
      local_8c = FLOAT_803e0ba4;
      local_c8[2] = FUN_80022264(0x14,0x23);
      local_84 = 0x1080200;
      local_80 = 0x5000000;
      local_86 = 0x60;
      uVar3 = FUN_80022264(0x96,200);
      local_68 = (undefined)uVar3;
      break;
    case 0x346:
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      uStack_2c = FUN_80022264(5,0x19);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0b38 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8)
                 + *(float *)(param_3 + 4);
      local_c8[2] = 0x1e0;
      local_67 = 0;
      local_84 = 0x480014;
      local_86 = 0xdf;
      break;
    case 0x347:
      uStack_2c = FUN_80022264(0xffffffe2,0x1e);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
      uStack_34 = FUN_80022264(0xfffffffb,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
      uStack_3c = FUN_80022264(0xffffffe2,0x1e);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0b60 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
      local_98 = FLOAT_803e0b4c;
      uStack_44 = FUN_80022264(10,0x1e);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0ba8);
      local_90 = FLOAT_803e0b4c;
      local_8c = FLOAT_803e0b80;
      local_c8[2] = 0x32;
      local_84 = 0x8a000208;
      local_86 = 0x60;
      local_70 = 0x7f00;
      local_6e = 0x6400;
      local_6c = 0;
      local_7c = 0x5a00;
      local_78 = 0;
      local_74 = 0;
      local_80 = 0x20;
      local_68 = 0x7f;
      break;
    case 0x34c:
      local_8c = FLOAT_803e0b64;
      local_c8[2] = 0x32;
      local_84 = 0x180200;
      local_80 = 0x1000000;
      local_86 = 0x2b;
      local_68 = 0x9d;
      break;
    case 0x34d:
      uStack_2c = FUN_80022264(0xffffffd8,0x28);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803e0b68 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
      uStack_34 = FUN_80022264(10,0x50);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0b6c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
      uStack_3c = FUN_80022264(0xffffffd8,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0b68 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
      uStack_44 = FUN_80022264(5,0x19);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803e0b70 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0ba8);
      local_c8[2] = FUN_80022264(100,0x78);
      uVar3 = FUN_80022264(0,0xffff);
      local_bc = (undefined2)uVar3;
      uVar3 = FUN_80022264(0,0xffff);
      local_ba = (undefined2)uVar3;
      uVar3 = FUN_80022264(0,0xffff);
      local_bc = (undefined2)uVar3;
      uStack_4c = FUN_80022264(0xe6,800);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0ba8);
      uStack_54 = FUN_80022264(0xe6,800);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_ac = (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0ba8);
      uVar3 = FUN_80022264(0xe6,800);
      local_60 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_a8 = (float)(local_60 - DOUBLE_803e0ba8);
      local_80 = 0x1000020;
      local_84 = 0x86000008;
      uVar3 = FUN_80022264(0,12000);
      local_7c = uVar3 + 0x3caf & 0xffff;
      local_70 = (undefined2)(uVar3 + 0x3caf);
      uVar3 = FUN_80022264(0,10000);
      local_78 = local_7c - uVar3 & 0xffff;
      local_6e = (undefined2)(local_7c - uVar3);
      uVar3 = FUN_80022264(10000,0x3caf);
      local_74 = local_7c - uVar3 & 0xffff;
      local_6c = (undefined2)(local_7c - uVar3);
      local_86 = 0x3a3;
      break;
    case 0x34e:
      uStack_2c = FUN_80022264(0xffffffd8,0x28);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803e0b68 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0ba8);
      uStack_34 = FUN_80022264(10,0x50);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0b6c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0ba8);
      uStack_3c = FUN_80022264(0xffffffd8,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0b68 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0ba8);
      uStack_44 = FUN_80022264(5,0x1e);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0ba8);
      uStack_4c = FUN_80022264(5,0x19);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803e0b70 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0ba8);
      local_c8[2] = FUN_80022264(100,0x78);
      uVar3 = FUN_80022264(0,0xffff);
      local_bc = (undefined2)uVar3;
      uVar3 = FUN_80022264(0,0xffff);
      local_ba = (undefined2)uVar3;
      uVar3 = FUN_80022264(0,0xffff);
      local_bc = (undefined2)uVar3;
      uStack_54 = FUN_80022264(0xe6,800);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_b0 = (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0ba8);
      uVar3 = FUN_80022264(0xe6,800);
      local_60 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_ac = (float)(local_60 - DOUBLE_803e0ba8);
      uStack_24 = FUN_80022264(0xe6,800);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_a8 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0ba8);
      local_80 = 0x1000020;
      local_84 = 0x86000008;
      uVar3 = FUN_80022264(0,12000);
      local_7c = uVar3 + 0x3caf & 0xffff;
      local_70 = (undefined2)(uVar3 + 0x3caf);
      local_6e = 30000;
      local_78 = 30000;
      uVar3 = FUN_80022264(10000,0x3caf);
      local_74 = local_7c - uVar3 & 0xffff;
      local_6c = (undefined2)(local_7c - uVar3);
      local_86 = 0x3a3;
    }
    local_84 = local_84 | param_4;
    if (((local_84 & 1) != 0) && ((local_84 & 2) != 0)) {
      local_84 = local_84 ^ 2;
    }
    if ((local_84 & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_c8[0] != 0) {
          local_98 = local_98 + *(float *)(local_c8[0] + 0x18);
          local_94 = local_94 + *(float *)(local_c8[0] + 0x1c);
          local_90 = local_90 + *(float *)(local_c8[0] + 0x20);
        }
      }
      else {
        local_98 = local_98 + local_b0;
        local_94 = local_94 + local_ac;
        local_90 = local_90 + local_a8;
      }
    }
    uVar2 = (**(code **)(*DAT_803dd6f8 + 8))(local_c8,0xffffffff,param_2,0);
  }
  return uVar2;
}

