// Function: FUN_800cb690
// Entry: 800cb690
// Size: 6040 bytes

/* WARNING: Removing unreachable block (ram,0x800cce08) */

void FUN_800cb690(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)

{
  float fVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f31;
  undefined8 uVar7;
  int local_c8;
  undefined4 local_c4;
  uint local_c0;
  undefined2 local_bc;
  undefined2 local_ba;
  undefined2 local_b8;
  undefined4 local_b4;
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
  undefined2 local_86;
  uint local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined2 local_70;
  undefined2 local_6e;
  undefined2 local_6c;
  undefined local_6a;
  undefined local_68;
  undefined local_67;
  undefined local_66;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  double local_48;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar7 = FUN_802860dc();
  iVar4 = (int)((ulonglong)uVar7 >> 0x20);
  FLOAT_803db860 = FLOAT_803db860 + FLOAT_803e0220;
  if (FLOAT_803e0228 < FLOAT_803db860) {
    FLOAT_803db860 = FLOAT_803e0224;
  }
  FLOAT_803db864 = FLOAT_803db864 + FLOAT_803e022c;
  if (FLOAT_803e0228 < FLOAT_803db864) {
    FLOAT_803db864 = FLOAT_803e0230;
  }
  if (iVar4 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = 0xffffffff;
        goto LAB_800cce08;
      }
      local_b0 = *(float *)(param_3 + 6);
      local_ac = *(float *)(param_3 + 8);
      local_a8 = *(float *)(param_3 + 10);
      local_b4 = *(undefined4 *)(param_3 + 4);
      local_b8 = param_3[2];
      local_ba = param_3[1];
      local_bc = *param_3;
      local_66 = param_5;
    }
    local_84 = 0;
    local_80 = 0;
    local_6a = (undefined)uVar7;
    local_98 = FLOAT_803e0234;
    local_94 = FLOAT_803e0234;
    local_90 = FLOAT_803e0234;
    local_a4 = FLOAT_803e0234;
    local_a0 = FLOAT_803e0234;
    local_9c = FLOAT_803e0234;
    local_8c = FLOAT_803e0234;
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
    local_c8 = iVar4;
    switch((int)uVar7) {
    case 0x708:
      uStack92 = FUN_800221a0(10,0x19);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a4 = FLOAT_803e0238 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e02c0);
      local_8c = FLOAT_803e0224;
      local_c0 = FUN_800221a0(0x15e,400);
      local_84 = 0xa100100;
      local_80 = 0x1000000;
      local_86 = 0x62;
      break;
    case 0x709:
      uStack92 = FUN_800221a0(10,0x14);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = FLOAT_803e023c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e02c0);
      iVar4 = FUN_800221a0(0,1);
      if (iVar4 != 0) {
        local_a0 = -local_a0;
      }
      local_8c = FLOAT_803e0220;
      local_c0 = 0x78;
      local_68 = FUN_800221a0(0x7f,0xff);
      local_84 = 0x80480000;
      local_80 = 0x440000;
      local_86 = FUN_800221a0(0x525,0x528);
      break;
    case 0x70a:
      uStack92 = FUN_800221a0(0xffffffec,0x14);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a4 = FLOAT_803e0240 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e02c0);
      uStack84 = FUN_800221a0(0xffffffec,0x14);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803e0240 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e02c0);
      uStack76 = FUN_800221a0(0xffffffec,0x14);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803e0240 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e02c0);
      local_8c = FLOAT_803e0244;
      local_c0 = 0x32;
      local_84 = 0x480100;
      local_86 = FUN_800221a0(0x525,0x528);
      break;
    case 0x70b:
      local_c0 = 100;
      local_8c = FLOAT_803e0248;
      local_84 = 0x180200;
      local_86 = 0x208;
      local_80 = 0x5000000;
      break;
    case 0x70c:
      local_c0 = FUN_800221a0(0x19,0x4b);
      uStack76 = FUN_800221a0(0xffffffd8,0x28);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a4 = FLOAT_803e023c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e02c0);
      uStack84 = local_c0 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803e024c * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e02c0);
      uStack92 = FUN_800221a0(0xffffffd8,0x28);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = FLOAT_803e023c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e02c0);
      uVar3 = FUN_800221a0(0x32,100);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_8c = FLOAT_803e0250 * (float)(local_48 - DOUBLE_803e02c0);
      local_84 = 0x1082000;
      local_86 = FUN_800221a0(0x208,0x20a);
      local_80 = 0x1400000;
      break;
    default:
      uVar2 = 0xffffffff;
      goto LAB_800cce08;
    case 0x70f:
      local_c0 = FUN_800221a0(0xf,0x2d);
      uVar3 = FUN_800221a0(0xfffffffb,5);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_98 = (float)(local_48 - DOUBLE_803e02c0);
      uStack76 = FUN_800221a0(0xfffffffb,5);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e02c0);
      uStack84 = FUN_800221a0(0xffffffd8,0x28);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a4 = FLOAT_803e023c * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e02c0);
      uStack92 = local_c0 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = FLOAT_803e024c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e02c0);
      uStack60 = FUN_800221a0(0xffffffd8,0x28);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e023c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0);
      uStack52 = FUN_800221a0(0x32,0x46);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e0254 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      local_68 = 0xa0;
      local_84 = 0x1082000;
      local_80 = 0x5400000;
      local_86 = FUN_800221a0(0x208,0x20a);
      break;
    case 0x710:
      fVar1 = FLOAT_803e0228;
      if (param_6 != (float *)0x0) {
        fVar1 = *param_6;
      }
      dVar6 = (double)fVar1;
      local_c0 = FUN_800221a0(0xf,0x4b);
      local_94 = (float)((double)FLOAT_803e0258 * dVar6);
      local_90 = (float)((double)FLOAT_803e025c * dVar6);
      uStack52 = FUN_800221a0(0xffffffe2,0x1e);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803e023c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      uStack60 = local_c0 ^ 0x80000000;
      local_40 = 0x43300000;
      local_a0 = FLOAT_803e024c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0);
      uVar3 = FUN_800221a0(0x14,0x46);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_9c = FLOAT_803e0260 * (float)(local_48 - DOUBLE_803e02c0);
      uStack76 = FUN_800221a0(0x28,0x3c);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803e0264 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e02c0);
      local_68 = FUN_800221a0(0x3c,0xa0);
      local_84 = 0x81080200;
      local_80 = 0x4000800;
      local_86 = 0xc0f;
      break;
    case 0x711:
      fVar1 = FLOAT_803e0228;
      if (param_6 != (float *)0x0) {
        fVar1 = *param_6;
      }
      dVar6 = (double)fVar1;
      local_c0 = FUN_800221a0(0x23,0x4b);
      local_94 = (float)((double)FLOAT_803e0268 * dVar6);
      local_90 = (float)((double)FLOAT_803e025c * dVar6);
      uStack52 = FUN_800221a0(0xffffffce,0x32);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803e023c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      uStack60 = local_c0 ^ 0x80000000;
      local_40 = 0x43300000;
      local_a0 = FLOAT_803e026c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0);
      uVar3 = FUN_800221a0(0x14,0x3c);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_9c = FLOAT_803e0260 * (float)(local_48 - DOUBLE_803e02c0);
      uStack76 = FUN_800221a0(0x28,0x3c);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803e0264 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e02c0);
      local_68 = FUN_800221a0(100,200);
      local_84 = 0x81080200;
      local_80 = 0x4000800;
      local_86 = 0xc0f;
      break;
    case 0x712:
      local_c0 = FUN_800221a0(0x32,100);
      uStack52 = FUN_800221a0(0xffffffec,0x14);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803e023c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      uStack60 = local_c0 ^ 0x80000000;
      local_40 = 0x43300000;
      local_a0 = FLOAT_803e0270 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0);
      uVar3 = FUN_800221a0(0xffffffec,0x14);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_9c = FLOAT_803e023c * (float)(local_48 - DOUBLE_803e02c0);
      local_8c = FLOAT_803e0274;
      iVar4 = FUN_800221a0(0,2);
      if (iVar4 == 0) {
        local_84 = 0x180008;
      }
      else {
        local_84 = 0xa100008;
      }
      local_80 = 0x1400000;
      local_86 = 0x5f;
      break;
    case 0x713:
      break;
    case 0x714:
      uVar3 = FUN_800221a0(0x1e,0x28);
      uVar3 = uVar3 & 0xff;
      local_68 = (undefined)uVar3;
      if (param_6 != (float *)0x0) {
        local_38 = 0x43300000;
        uStack60 = (uint)*param_6 ^ 0x80000000;
        local_40 = 0x43300000;
        iVar4 = (int)((float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e02c8) *
                     ((float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0) /
                     FLOAT_803e0278));
        local_48 = (double)(longlong)iVar4;
        local_68 = (undefined)iVar4;
        uStack52 = uVar3;
      }
      uStack52 = FUN_800221a0(0x12,0x14);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = FLOAT_803e027c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      uStack60 = FUN_800221a0(0x28,0x3c);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_8c = FLOAT_803e0280 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0);
      local_c0 = FUN_800221a0(8,0x14);
      local_84 = 0x80204;
      local_80 = 0x4002800;
      local_86 = 0xc0f;
      break;
    case 0x715:
      if (param_6 == (float *)0x0) {
        uStack52 = FUN_800221a0(0x32,100);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_8c = FLOAT_803e028c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0)
        ;
        local_c0 = 0x78;
        local_84 = 0x80580200;
        local_80 = 0x800;
      }
      else {
        uStack52 = FUN_800221a0(0xffffffe7,0x19);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_a4 = FLOAT_803e0284 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0)
        ;
        uStack60 = FUN_800221a0(5,0x32);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_a0 = FLOAT_803e0284 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0)
        ;
        uVar3 = FUN_800221a0(0xffffffe7,0x19);
        local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        local_9c = FLOAT_803e0284 * (float)(local_48 - DOUBLE_803e02c0);
        local_8c = FLOAT_803e0288;
        local_c0 = FUN_800221a0(0x28,0x78);
        local_84 = 0x80480000;
        local_80 = 0x400800;
      }
      local_68 = 0xff;
      local_86 = 0xc0f;
      break;
    case 0x716:
      uStack52 = FUN_800221a0(0xffffffec,0x14);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      uStack60 = FUN_800221a0(0xffffffec,0x14);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0);
      uVar3 = FUN_800221a0(0xffffffec,0x14);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = (float)(local_48 - DOUBLE_803e02c0);
      uStack76 = FUN_800221a0(0x5a,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803e0238 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e02c0);
      local_67 = 0xf;
      uStack84 = FUN_800221a0(0x5a,100);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_8c = FLOAT_803e0220 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e02c0);
      local_84 = 0x800c0100;
      local_80 = 0x4000800;
      local_68 = FUN_800221a0(0x96,200);
      local_c0 = FUN_800221a0(0x32,0x46);
      local_86 = 0x185;
      break;
    case 0x717:
      fVar1 = FLOAT_803e0228;
      if (param_6 != (float *)0x0) {
        fVar1 = *param_6;
      }
      dVar6 = (double)fVar1;
      uStack52 = FUN_800221a0(0xffffff6a,0x96);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)(dVar6 * (double)(FLOAT_803e0224 *
                                         (float)((double)CONCAT44(0x43300000,uStack52) -
                                                DOUBLE_803e02c0)));
      uStack60 = FUN_800221a0(100,300);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = (float)(dVar6 * (double)(FLOAT_803e0224 *
                                         (float)((double)CONCAT44(0x43300000,uStack60) -
                                                DOUBLE_803e02c0)));
      uVar3 = FUN_800221a0(0xffffff6a,0xffffffce);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = (float)(dVar6 * (double)(FLOAT_803e0224 * (float)(local_48 - DOUBLE_803e02c0)));
      local_8c = FLOAT_803e0244;
      local_c0 = FUN_800221a0(0x32,0x96);
      local_84 = 0x80480100;
      local_86 = FUN_800221a0(0x527,0x528);
      break;
    case 0x718:
      uStack52 = FUN_800221a0(8,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e027c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      if (param_6 != (float *)0x0) {
        local_a0 = local_a0 * (FLOAT_803e0228 + *param_6 / FLOAT_803e0290);
      }
      uStack52 = FUN_800221a0(6,0xc);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e0240 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      local_c0 = FUN_800221a0(0x3c,100);
      local_84 = 0x80180000;
      local_80 = 0x5440800;
      local_86 = 0xc0b;
      local_68 = 0x40;
      break;
    case 0x71a:
      local_90 = FLOAT_803e0294;
      uStack52 = FUN_800221a0(0x4b,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e0298 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      local_c0 = 1;
      local_84 = 0x80010;
      local_80 = 0x800;
      local_86 = 0xc7e;
      local_68 = 0x7f;
      break;
    case 0x71b:
      local_8c = FLOAT_803e029c;
      local_c0 = 100;
      local_84 = 0x180000;
      local_80 = 0x400800;
      local_86 = 0x73;
      local_68 = 0xff;
      break;
    case 0x71c:
      local_c0 = FUN_800221a0(0x28,0x78);
      uStack52 = FUN_800221a0(0xffffffce,0x32);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803e027c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      uStack60 = local_c0 ^ 0x80000000;
      local_40 = 0x43300000;
      local_a0 = FLOAT_803e02a0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0);
      uVar3 = FUN_800221a0(0xffffffce,0x32);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_9c = FLOAT_803e027c * (float)(local_48 - DOUBLE_803e02c0);
      local_8c = FLOAT_803e0284;
      local_84 = 0x3000000;
      local_80 = 0x600820;
      local_86 = 0x20d;
      local_68 = 0xff;
      local_6c = 0xffff;
      local_6e = 0xffff;
      local_70 = 0xffff;
      local_7c = 0xffff;
      local_74 = 0;
      local_78 = 0;
      break;
    case 0x71d:
      uStack52 = FUN_800221a0(0xffffffec,0x14);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      uStack60 = FUN_800221a0(0xffffffec,0x14);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0);
      uVar3 = FUN_800221a0(0xffffffec,0x14);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = (float)(local_48 - DOUBLE_803e02c0);
      local_67 = 0xf;
      uStack76 = FUN_800221a0(0x78,200);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803e0220 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e02c0);
      local_84 = 0x80180100;
      local_80 = 0x4000800;
      local_68 = FUN_800221a0(0x32,100);
      local_c0 = FUN_800221a0(100,0x8c);
      local_86 = 0x185;
      break;
    case 0x71e:
      uStack52 = FUN_800221a0(0xffffffdd,0x23);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      uStack60 = FUN_800221a0(0,0x1e);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0);
      uVar3 = FUN_800221a0(0xffffffdd,0x23);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = (float)(local_48 - DOUBLE_803e02c0);
      uStack76 = FUN_800221a0(8,10);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803e027c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e02c0);
      uStack84 = FUN_800221a0(6,0xc);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_8c = FLOAT_803e0240 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e02c0);
      local_c0 = FUN_800221a0(100,0x96);
      local_84 = 0x80180000;
      local_80 = 0x1440000;
      local_86 = 0x564;
      local_68 = 0x7f;
      break;
    case 0x71f:
      uStack52 = FUN_800221a0(8,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e027c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      uStack60 = FUN_800221a0(6,0xc);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_8c = FLOAT_803e0288 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0);
      local_c0 = FUN_800221a0(0x3c,0x50);
      local_84 = 0x80180000;
      local_80 = 0x5440800;
      local_86 = 0x564;
      local_68 = 0x40;
      break;
    case 0x720:
      uStack52 = FUN_800221a0(8,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e02a4 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      uStack60 = FUN_800221a0(6,0xc);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_8c = FLOAT_803e0288 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0);
      local_c0 = FUN_800221a0(0x3c,0x50);
      local_84 = 0x80180200;
      local_80 = 0x5000800;
      local_86 = 0x564;
      local_68 = 0x40;
      break;
    case 0x721:
      uStack52 = FUN_800221a0(6,0xc);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e02a8 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      local_c0 = FUN_800221a0(0xfa,0x15e);
      local_84 = 0x80480008;
      local_80 = 0x400000;
      local_86 = 0xc0d;
      break;
    case 0x722:
      local_94 = FLOAT_803e02ac;
      local_c0 = FUN_800221a0(0x1e,0x3c);
      uStack52 = FUN_800221a0(0xffffffc4,0x3c);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803e02a4 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      dVar6 = (double)FUN_802931a0((double)(local_a4 * local_a4 + local_9c * local_9c));
      local_a0 = (float)((double)FLOAT_803e02b0 * dVar6);
      uStack60 = FUN_800221a0(0xffffffc4,0x3c);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e02a4 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0);
      local_8c = FLOAT_803e02a4;
      local_84 = 0x80000;
      local_80 = 0x5400800;
      local_86 = 0x564;
      iVar4 = FUN_800221a0(0x46,0xbe);
      local_68 = (undefined)(iVar4 >> 1);
      break;
    case 0x723:
      local_c0 = FUN_800221a0(0x23,0x2d);
      if (param_6 == (float *)0x0) {
        uVar3 = 5;
      }
      else {
        uVar3 = (int)*param_6 + 5;
      }
      uStack52 = FUN_800221a0(8,0xc);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      uStack60 = uVar3 ^ 0x80000000;
      local_40 = 0x43300000;
      local_a0 = ((float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0) / FLOAT_803e02b4)
                 * FLOAT_803e02b8 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0)
      ;
      iVar4 = 0x41 - uVar3;
      uVar3 = FUN_800221a0(-iVar4,iVar4);
      local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_a4 = FLOAT_803e024c * (float)(local_48 - DOUBLE_803e02c0);
      uStack76 = FUN_800221a0(-iVar4,iVar4);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803e024c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e02c0);
      uStack84 = FUN_800221a0(6,0xc);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_8c = FLOAT_803e0240 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e02c0);
      iVar4 = FUN_800221a0(0x40,0x7f);
      local_68 = (undefined)(iVar4 >> 1);
      local_84 = 0x80080000;
      local_80 = 0x5400800;
      local_86 = 0x564;
      break;
    case 0x724:
      uStack52 = FUN_800221a0(8,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e027c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e02c0);
      uStack60 = FUN_800221a0(6,0xc);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_8c = FLOAT_803e0240 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e02c0);
      local_c0 = FUN_800221a0(0x1e,0x3c);
      local_84 = 0x80080000;
      local_80 = 0x5440800;
      local_86 = 0xc0b;
      local_68 = 0x40;
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
    uVar2 = (**(code **)(*DAT_803dca78 + 8))(&local_c8,0xffffffff,(int)uVar7,0);
  }
LAB_800cce08:
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  FUN_80286128(uVar2);
  return;
}

