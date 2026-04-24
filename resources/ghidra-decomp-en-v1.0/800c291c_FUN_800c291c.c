// Function: FUN_800c291c
// Entry: 800c291c
// Size: 7700 bytes

/* WARNING: Removing unreachable block (ram,0x800c4708) */

undefined4
FUN_800c291c(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5,
            float *param_6)

{
  float fVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  undefined8 in_f31;
  double dVar6;
  int local_c8;
  undefined4 local_c4;
  uint local_c0;
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
  double local_60;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  FLOAT_803db830 = FLOAT_803db830 + FLOAT_803dfeb8;
  if (FLOAT_803dfec0 < FLOAT_803db830) {
    FLOAT_803db830 = FLOAT_803dfebc;
  }
  FLOAT_803db834 = FLOAT_803db834 + FLOAT_803dfec4;
  if (FLOAT_803dfec0 < FLOAT_803db834) {
    FLOAT_803db834 = FLOAT_803dfec8;
  }
  if (param_1 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = 0xffffffff;
        goto LAB_800c4708;
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
    local_98 = FLOAT_803dfecc;
    local_94 = FLOAT_803dfecc;
    local_90 = FLOAT_803dfecc;
    local_a4 = FLOAT_803dfecc;
    local_a0 = FLOAT_803dfecc;
    local_9c = FLOAT_803dfecc;
    local_8c = FLOAT_803dfecc;
    local_c0 = 0;
    local_c4 = 0xffffffff;
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
      DAT_8039c3bc = FLOAT_803dfecc;
      DAT_8039c3c0 = FLOAT_803dfecc;
      DAT_8039c3c4 = FLOAT_803dfecc;
      DAT_8039c3b8 = FLOAT_803dfec0;
      DAT_8039c3b0 = 0;
      DAT_8039c3b2 = 0;
      DAT_8039c3b4 = 0;
      param_3 = &DAT_8039c3b0;
    }
    local_c8 = param_1;
    switch(param_2) {
    case 0x32a:
      local_c0 = (uint)(FLOAT_803dfed4 * *(float *)(param_3 + 4) + FLOAT_803dfed0);
      local_60 = (double)(longlong)(int)local_c0;
      uStack84 = local_c0 ^ 0x80000000;
      local_58 = 0x43300000;
      local_8c = FLOAT_803dfed8 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dff28);
      local_84 = 0x8100200;
      local_86 = 0x57;
      local_b0 = *(float *)(param_3 + 6);
      local_ac = *(float *)(param_3 + 8);
      local_a8 = *(float *)(param_3 + 10);
      local_b4 = FLOAT_803dfec0;
      local_b8 = 0;
      local_ba = 0;
      local_bc = *param_3;
      local_68 = 0xff;
      break;
    case 0x32b:
      uStack84 = FUN_800221a0(0x96,200);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_c0 = (uint)(*(float *)(param_3 + 4) *
                        (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dff28) +
                       FLOAT_803dfed4);
      local_60 = (double)(longlong)(int)local_c0;
      uStack76 = local_c0 ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803dfedc * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dff28);
      local_84 = 0x8100200;
      local_86 = 0x56;
      local_b0 = *(float *)(param_3 + 6);
      local_ac = *(float *)(param_3 + 8);
      local_a8 = *(float *)(param_3 + 10);
      local_b4 = FLOAT_803dfec0;
      local_b8 = 0;
      local_ba = 0;
      local_bc = 0;
      local_68 = 0xff;
      break;
    case 0x32c:
      uStack76 = FUN_800221a0(2,4);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dff28);
      local_c0 = 200;
      local_84 = 0x8100200;
      local_86 = 0x56;
      local_b0 = *(float *)(param_3 + 6);
      local_ac = *(float *)(param_3 + 8);
      local_a8 = *(float *)(param_3 + 10);
      local_b4 = FLOAT_803dfec0;
      local_b8 = 0;
      local_ba = 0;
      local_bc = 0;
      local_68 = 0xff;
      break;
    case 0x32d:
      local_8c = FLOAT_803dfee4;
      local_c0 = 0x32;
      local_84 = 0x180200;
      local_80 = 0x1000000;
      local_86 = 0x60;
      local_68 = 0xff;
      break;
    case 0x32e:
      uStack76 = FUN_800221a0(0xffffffd8,0x28);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a4 = FLOAT_803dfee8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dff28);
      uStack84 = FUN_800221a0(10,0x50);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803dfeec * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dff28);
      uVar3 = FUN_800221a0(0xffffffd8,0x28);
      local_60 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_9c = FLOAT_803dfee8 * (float)(local_60 - DOUBLE_803dff28);
      uStack68 = FUN_800221a0(5,0x19);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803dfef0 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dff28);
      local_c0 = FUN_800221a0(100,0x78);
      local_bc = FUN_800221a0(0,0xffff);
      local_ba = FUN_800221a0(0,0xffff);
      local_bc = FUN_800221a0(0,0xffff);
      uStack60 = FUN_800221a0(0xe6,800);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_b0 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
      uStack52 = FUN_800221a0(0xe6,800);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_ac = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
      uStack44 = FUN_800221a0(0xe6,800);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_a8 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
      local_80 = 0x1000020;
      local_84 = 0x86000008;
      local_7c = FUN_800221a0(0x8000,0xffff);
      local_7c = local_7c & 0xffff;
      local_70 = (undefined2)local_7c;
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
      uStack44 = FUN_800221a0(0xffffff9c,100);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803dfef4 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
      uStack52 = FUN_800221a0(0xffffff9c,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dfef4 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
      uStack60 = FUN_800221a0(0xffffff9c,100);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfef4 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
      uStack68 = FUN_800221a0(4,5);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = *(float *)(param_3 + 4) *
                 FLOAT_803dfef8 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dff28);
      local_c0 = FUN_800221a0(0xf,0x23);
      local_68 = 0xff;
      local_84 = 0x80110;
      local_80 = 0x8400c00;
      local_86 = 0xc79;
      break;
    case 0x330:
      uStack44 = FUN_800221a0(0xffffff9c,100);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803dfeb8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28) +
                 *(float *)(param_3 + 6);
      uStack52 = FUN_800221a0(0xffffff9c,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803dfeb8 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28) +
                 *(float *)(param_3 + 8);
      uStack60 = FUN_800221a0(0xffffff9c,100);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = FLOAT_803dfeb8 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28) +
                 *(float *)(param_3 + 10);
      uStack68 = FUN_800221a0(0xffffff9c,100);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803dfefc * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dff28);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803dfefc * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dff28);
      uStack84 = FUN_800221a0(0xffffff9c,100);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = FLOAT_803dfefc * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dff28);
      local_8c = FLOAT_803dfee8 * *(float *)(param_3 + 4);
      local_c0 = FUN_800221a0(0xf,0x23);
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
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803dff00 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
      local_a0 = FLOAT_803dff00;
      uStack52 = FUN_800221a0(0xffffffec,0x14);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = FLOAT_803dff00 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
      local_8c = FLOAT_803dff04;
      local_c0 = 0x96;
      local_84 = 0xa100100;
      local_86 = 0x62;
      break;
    case 0x336:
      fVar1 = FLOAT_803dfec0;
      if (param_6 != (float *)0x0) {
        fVar1 = *param_6;
      }
      dVar6 = (double)fVar1;
      uStack44 = FUN_800221a0(0xfffffff6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack44) -
                                                DOUBLE_803dff28));
      uStack52 = FUN_800221a0(0xfffffff6,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack52) -
                                                DOUBLE_803dff28));
      uStack60 = FUN_800221a0(0xfffffff6,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)(dVar6 * (double)(float)((double)CONCAT44(0x43300000,uStack60) -
                                                DOUBLE_803dff28));
      uStack68 = FUN_800221a0(0xfffffff1,0xf);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = (float)(dVar6 * (double)(FLOAT_803dfee0 *
                                         (float)((double)CONCAT44(0x43300000,uStack68) -
                                                DOUBLE_803dff28)));
      uStack76 = FUN_800221a0(0xfffffff1,0xf);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = (float)(dVar6 * (double)(FLOAT_803dfee0 *
                                         (float)((double)CONCAT44(0x43300000,uStack76) -
                                                DOUBLE_803dff28)));
      uStack84 = FUN_800221a0(0xfffffff1,0xf);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = (float)(dVar6 * (double)(FLOAT_803dfee0 *
                                         (float)((double)CONCAT44(0x43300000,uStack84) -
                                                DOUBLE_803dff28)));
      uVar3 = FUN_800221a0(8,10);
      local_60 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_8c = FLOAT_803dff08 * (float)(local_60 - DOUBLE_803dff28);
      local_c0 = 0x50;
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
        local_8c = FLOAT_803dfee0;
        local_c0 = 1;
        local_84 = 0x480000;
      }
      else if (fVar1 == 1.401298e-45) {
        local_8c = FLOAT_803dff0c;
        local_c0 = 1;
        local_84 = 0x480000;
        local_68 = 0x32;
      }
      else if (fVar1 == 2.802597e-45) {
        uStack44 = FUN_800221a0(0xfffffff1,0xf);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_a4 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28)
        ;
        uStack52 = FUN_800221a0(0xfffffff1,0xf);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_a0 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28)
        ;
        uStack60 = FUN_800221a0(0xfffffff6,10);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_9c = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28)
        ;
        local_8c = FLOAT_803dfefc;
        local_c0 = FUN_800221a0(0x1e,0x28);
        local_84 = 0x3000000;
        local_80 = 0x600000;
      }
      else if (fVar1 == 4.203895e-45) {
        uStack44 = FUN_800221a0(0xfffffff6,10);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_98 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
        uStack52 = FUN_800221a0(0xfffffff6,10);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_94 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
        uStack60 = FUN_800221a0(0xfffffff6,10);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_90 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
        uStack68 = FUN_800221a0(0xfffffff1,0xf);
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_a4 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dff28)
        ;
        uStack76 = FUN_800221a0(0xfffffff1,0xf);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_a0 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dff28)
        ;
        uStack84 = FUN_800221a0(0xfffffff1,0xf);
        uStack84 = uStack84 ^ 0x80000000;
        local_58 = 0x43300000;
        local_9c = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dff28)
        ;
        uVar3 = FUN_800221a0(8,10);
        local_60 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        local_8c = FLOAT_803dff08 * (float)(local_60 - DOUBLE_803dff28);
        local_c0 = 0x1e;
        local_68 = 0xb4;
        local_84 = 0x80480404;
      }
      else {
        uStack44 = FUN_800221a0(0xfffffffd,3);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_98 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
        uStack52 = FUN_800221a0(0xfffffffd,3);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_94 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
        uStack60 = FUN_800221a0(0xfffffffd,3);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_90 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
        local_8c = FLOAT_803dff10;
        local_c0 = 100;
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
        local_8c = FLOAT_803dfee0;
        local_c0 = 1;
        local_84 = 0x480000;
      }
      else if (fVar1 == 1.401298e-45) {
        local_8c = FLOAT_803dff0c;
        local_c0 = 1;
        local_84 = 0x480000;
        local_68 = 0x32;
      }
      else if (fVar1 == 2.802597e-45) {
        uStack44 = FUN_800221a0(0xfffffff1,0xf);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_a4 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28)
        ;
        uStack52 = FUN_800221a0(0xfffffff1,0xf);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_a0 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28)
        ;
        uStack60 = FUN_800221a0(0xfffffff6,10);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_9c = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28)
        ;
        local_8c = FLOAT_803dfefc;
        local_c0 = FUN_800221a0(0x1e,0x28);
        local_84 = 0x3000000;
        local_80 = 0x600000;
      }
      else if (fVar1 == 4.203895e-45) {
        uStack44 = FUN_800221a0(0xfffffff6,10);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_98 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
        uStack52 = FUN_800221a0(0xfffffff6,10);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_94 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
        uStack60 = FUN_800221a0(0xfffffff6,10);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_90 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
        uStack68 = FUN_800221a0(0xfffffff1,0xf);
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_a4 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dff28)
        ;
        uStack76 = FUN_800221a0(0xfffffff1,0xf);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_a0 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dff28)
        ;
        uStack84 = FUN_800221a0(0xfffffff1,0xf);
        uStack84 = uStack84 ^ 0x80000000;
        local_58 = 0x43300000;
        local_9c = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dff28)
        ;
        uVar3 = FUN_800221a0(8,10);
        local_60 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        local_8c = FLOAT_803dff08 * (float)(local_60 - DOUBLE_803dff28);
        local_c0 = 0x1e;
        local_68 = 0xb4;
        local_84 = 0x80480404;
      }
      else {
        uStack44 = FUN_800221a0(0xfffffffd,3);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_98 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
        uStack52 = FUN_800221a0(0xfffffffd,3);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_94 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
        uStack60 = FUN_800221a0(0xfffffffd,3);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_90 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
        local_8c = FLOAT_803dff10;
        local_c0 = 100;
        local_84 = 0x80480000;
        local_80 = 0x400000;
        local_68 = 0x7f;
      }
      local_86 = 0x4f9;
      break;
    default:
      uVar2 = 0xffffffff;
      goto LAB_800c4708;
    case 0x340:
      uStack44 = FUN_800221a0(0xffffff9c,100);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
      uStack52 = FUN_800221a0(10,200);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
      uStack60 = FUN_800221a0(0xffffff9c,100);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
      uStack68 = FUN_800221a0(8,0xb);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803dfef0 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dff28);
      local_c0 = 0x4b;
      local_84 = 0x1080000;
      local_86 = 0xc0f;
      break;
    case 0x342:
      uStack44 = FUN_800221a0(0xffffff9c,100);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
      uStack52 = FUN_800221a0(0x14,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dff14 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
      uStack60 = FUN_800221a0(0xffffff9c,100);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
      local_8c = FLOAT_803dff18;
      local_c0 = 0x28;
      local_84 = 0x1080200;
      local_86 = 0xc0f;
      break;
    case 0x343:
      uStack44 = FUN_800221a0(0xffffff9c,100);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
      uStack52 = FUN_800221a0(10,200);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
      uStack60 = FUN_800221a0(0xffffff9c,100);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
      uStack68 = FUN_800221a0(8,0xb);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803dff1c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dff28);
      local_c0 = FUN_800221a0(0x41,0x4b);
      local_84 = 0x1080000;
      local_80 = 0x5000000;
      local_86 = 0x77;
      local_68 = FUN_800221a0(0x46,100);
      break;
    case 0x344:
      uStack44 = FUN_800221a0(0xffffff9c,100);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
      uStack52 = FUN_800221a0(0x14,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dff14 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
      uStack60 = FUN_800221a0(0xffffff9c,100);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
      uStack68 = FUN_800221a0(5,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803dff1c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dff28);
      local_c0 = 0x28;
      local_84 = 0x1080200;
      local_86 = 0x77;
      local_68 = 0x7f;
      break;
    case 0x345:
      uStack44 = FUN_800221a0(0xfffffff6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
      uStack52 = FUN_800221a0(0x14,0x28);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
      uStack60 = FUN_800221a0(0xfffffff6,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
      uStack68 = FUN_800221a0(0xfffffff6,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dff28);
      local_94 = FLOAT_803dff20;
      uStack76 = FUN_800221a0(0xfffffff6,10);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dff28);
      local_8c = FLOAT_803dff24;
      local_c0 = FUN_800221a0(0x14,0x23);
      local_84 = 0x1080200;
      local_80 = 0x5000000;
      local_86 = 0x60;
      local_68 = FUN_800221a0(0x96,200);
      break;
    case 0x346:
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      uStack44 = FUN_800221a0(5,0x19);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfeb8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28) +
                 *(float *)(param_3 + 4);
      local_c0 = 0x1e0;
      local_67 = 0;
      local_84 = 0x480014;
      local_86 = 0xdf;
      break;
    case 0x347:
      uStack44 = FUN_800221a0(0xffffffe2,0x1e);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
      uStack52 = FUN_800221a0(0xfffffffb,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
      uStack60 = FUN_800221a0(0xffffffe2,0x1e);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfee0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
      local_98 = FLOAT_803dfecc;
      uStack68 = FUN_800221a0(10,0x1e);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dff28);
      local_90 = FLOAT_803dfecc;
      local_8c = FLOAT_803dff00;
      local_c0 = 0x32;
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
      local_8c = FLOAT_803dfee4;
      local_c0 = 0x32;
      local_84 = 0x180200;
      local_80 = 0x1000000;
      local_86 = 0x2b;
      local_68 = 0x9d;
      break;
    case 0x34d:
      uStack44 = FUN_800221a0(0xffffffd8,0x28);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803dfee8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
      uStack52 = FUN_800221a0(10,0x50);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dfeec * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
      uStack60 = FUN_800221a0(0xffffffd8,0x28);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfee8 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
      uStack68 = FUN_800221a0(5,0x19);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803dfef0 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dff28);
      local_c0 = FUN_800221a0(100,0x78);
      local_bc = FUN_800221a0(0,0xffff);
      local_ba = FUN_800221a0(0,0xffff);
      local_bc = FUN_800221a0(0,0xffff);
      uStack76 = FUN_800221a0(0xe6,800);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dff28);
      uStack84 = FUN_800221a0(0xe6,800);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_ac = (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dff28);
      uVar3 = FUN_800221a0(0xe6,800);
      local_60 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_a8 = (float)(local_60 - DOUBLE_803dff28);
      local_80 = 0x1000020;
      local_84 = 0x86000008;
      iVar4 = FUN_800221a0(0,12000);
      local_7c = iVar4 + 0x3cafU & 0xffff;
      local_70 = (undefined2)local_7c;
      iVar4 = FUN_800221a0(0,10000);
      local_78 = local_7c - iVar4 & 0xffff;
      local_6e = (undefined2)local_78;
      iVar4 = FUN_800221a0(10000,0x3caf);
      local_74 = local_7c - iVar4 & 0xffff;
      local_6c = (undefined2)local_74;
      local_86 = 0x3a3;
      break;
    case 0x34e:
      uStack44 = FUN_800221a0(0xffffffd8,0x28);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_a4 = FLOAT_803dfee8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dff28);
      uStack52 = FUN_800221a0(10,0x50);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dfeec * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dff28);
      uStack60 = FUN_800221a0(0xffffffd8,0x28);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfee8 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dff28);
      uStack68 = FUN_800221a0(5,0x1e);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dff28);
      uStack76 = FUN_800221a0(5,0x19);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803dfef0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dff28);
      local_c0 = FUN_800221a0(100,0x78);
      local_bc = FUN_800221a0(0,0xffff);
      local_ba = FUN_800221a0(0,0xffff);
      local_bc = FUN_800221a0(0,0xffff);
      uStack84 = FUN_800221a0(0xe6,800);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_b0 = (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dff28);
      uVar3 = FUN_800221a0(0xe6,800);
      local_60 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_ac = (float)(local_60 - DOUBLE_803dff28);
      uStack36 = FUN_800221a0(0xe6,800);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_a8 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dff28);
      local_80 = 0x1000020;
      local_84 = 0x86000008;
      iVar4 = FUN_800221a0(0,12000);
      local_7c = iVar4 + 0x3cafU & 0xffff;
      local_70 = (undefined2)local_7c;
      local_6e = 30000;
      local_78 = 30000;
      iVar4 = FUN_800221a0(10000,0x3caf);
      local_74 = local_7c - iVar4 & 0xffff;
      local_6c = (undefined2)local_74;
      local_86 = 0x3a3;
    }
    local_84 = local_84 | param_4;
    if (((local_84 & 1) != 0) && ((local_84 & 2) != 0)) {
      local_84 = local_84 ^ 2;
    }
    if ((local_84 & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_c8 != 0) {
          local_98 = local_98 + *(float *)(local_c8 + 0x18);
          local_94 = local_94 + *(float *)(local_c8 + 0x1c);
          local_90 = local_90 + *(float *)(local_c8 + 0x20);
        }
      }
      else {
        local_98 = local_98 + local_b0;
        local_94 = local_94 + local_ac;
        local_90 = local_90 + local_a8;
      }
    }
    uVar2 = (**(code **)(*DAT_803dca78 + 8))(&local_c8,0xffffffff,param_2,0);
  }
LAB_800c4708:
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return uVar2;
}

