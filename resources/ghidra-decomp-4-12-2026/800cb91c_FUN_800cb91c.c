// Function: FUN_800cb91c
// Entry: 800cb91c
// Size: 6040 bytes

/* WARNING: Removing unreachable block (ram,0x800cd094) */
/* WARNING: Removing unreachable block (ram,0x800cb92c) */

void FUN_800cb91c(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)

{
  int iVar1;
  uint uVar2;
  float fVar3;
  uint uVar4;
  double dVar5;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar6;
  int local_c8 [2];
  float local_c0;
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
  float fStack_5c;
  undefined4 local_58;
  float fStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined8 local_48;
  undefined4 local_40;
  float fStack_3c;
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar6 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  FLOAT_803dc4c0 = FLOAT_803dc4c0 + FLOAT_803e0ea0;
  if (FLOAT_803e0ea8 < FLOAT_803dc4c0) {
    FLOAT_803dc4c0 = FLOAT_803e0ea4;
  }
  FLOAT_803dc4c4 = FLOAT_803dc4c4 + FLOAT_803e0eac;
  if (FLOAT_803e0ea8 < FLOAT_803dc4c4) {
    FLOAT_803dc4c4 = FLOAT_803e0eb0;
  }
  if (iVar1 != 0) {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) goto LAB_800cd094;
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
    local_6a = (undefined)uVar6;
    local_98 = FLOAT_803e0eb4;
    local_94 = FLOAT_803e0eb4;
    local_90 = FLOAT_803e0eb4;
    local_a4 = FLOAT_803e0eb4;
    local_a0 = FLOAT_803e0eb4;
    local_9c = FLOAT_803e0eb4;
    local_8c = FLOAT_803e0eb4;
    local_c0 = 0.0;
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
    local_c8[0] = iVar1;
    switch((int)uVar6) {
    case 0x708:
      fStack_5c = (float)FUN_80022264(10,0x19);
      fStack_5c = -fStack_5c;
      local_60 = 0x43300000;
      local_a4 = FLOAT_803e0eb8 * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      local_8c = FLOAT_803e0ea4;
      local_c0 = (float)FUN_80022264(0x15e,400);
      local_84 = 0xa100100;
      local_80 = 0x1000000;
      local_86 = 0x62;
      break;
    case 0x709:
      fStack_5c = (float)FUN_80022264(10,0x14);
      fStack_5c = -fStack_5c;
      local_60 = 0x43300000;
      local_a0 = FLOAT_803e0ebc * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      uVar2 = FUN_80022264(0,1);
      if (uVar2 != 0) {
        local_a0 = -local_a0;
      }
      local_8c = FLOAT_803e0ea0;
      local_c0 = 1.68156e-43;
      uVar2 = FUN_80022264(0x7f,0xff);
      local_68 = (undefined)uVar2;
      local_84 = 0x80480000;
      local_80 = 0x440000;
      uVar2 = FUN_80022264(0x525,0x528);
      local_86 = (undefined2)uVar2;
      break;
    case 0x70a:
      fStack_5c = (float)FUN_80022264(0xffffffec,0x14);
      fStack_5c = -fStack_5c;
      local_60 = 0x43300000;
      local_a4 = FLOAT_803e0ec0 * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      fStack_54 = (float)FUN_80022264(0xffffffec,0x14);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803e0ec0 * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      uStack_4c = FUN_80022264(0xffffffec,0x14);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803e0ec0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      local_8c = FLOAT_803e0ec4;
      local_c0 = 7.00649e-44;
      local_84 = 0x480100;
      uVar2 = FUN_80022264(0x525,0x528);
      local_86 = (undefined2)uVar2;
      break;
    case 0x70b:
      local_c0 = 1.4013e-43;
      local_8c = FLOAT_803e0ec8;
      local_84 = 0x180200;
      local_86 = 0x208;
      local_80 = 0x5000000;
      break;
    case 0x70c:
      local_c0 = (float)FUN_80022264(0x19,0x4b);
      uStack_4c = FUN_80022264(0xffffffd8,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a4 = FLOAT_803e0ebc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      fStack_54 = -local_c0;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803e0ecc * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      fStack_5c = (float)FUN_80022264(0xffffffd8,0x28);
      fStack_5c = -fStack_5c;
      local_60 = 0x43300000;
      local_9c = FLOAT_803e0ebc * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      uVar2 = FUN_80022264(0x32,100);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_8c = FLOAT_803e0ed0 * (float)(local_48 - DOUBLE_803e0f40);
      local_84 = 0x1082000;
      uVar2 = FUN_80022264(0x208,0x20a);
      local_86 = (undefined2)uVar2;
      local_80 = 0x1400000;
      break;
    default:
      goto LAB_800cd094;
    case 0x70f:
      local_c0 = (float)FUN_80022264(0xf,0x2d);
      uVar2 = FUN_80022264(0xfffffffb,5);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_98 = (float)(local_48 - DOUBLE_803e0f40);
      uStack_4c = FUN_80022264(0xfffffffb,5);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      fStack_54 = (float)FUN_80022264(0xffffffd8,0x28);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_a4 = FLOAT_803e0ebc * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      fStack_5c = -local_c0;
      local_60 = 0x43300000;
      local_a0 = FLOAT_803e0ecc * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80022264(0xffffffd8,0x28);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0ebc * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uStack_34 = FUN_80022264(0x32,0x46);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e0ed4 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      local_68 = 0xa0;
      local_84 = 0x1082000;
      local_80 = 0x5400000;
      uVar2 = FUN_80022264(0x208,0x20a);
      local_86 = (undefined2)uVar2;
      break;
    case 0x710:
      fVar3 = FLOAT_803e0ea8;
      if (param_6 != (float *)0x0) {
        fVar3 = *param_6;
      }
      dVar5 = (double)fVar3;
      local_c0 = (float)FUN_80022264(0xf,0x4b);
      local_94 = (float)((double)FLOAT_803e0ed8 * dVar5);
      local_90 = (float)((double)FLOAT_803e0edc * dVar5);
      uStack_34 = FUN_80022264(0xffffffe2,0x1e);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803e0ebc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = -local_c0;
      local_40 = 0x43300000;
      local_a0 = FLOAT_803e0ecc * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80022264(0x14,0x46);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e0ee0 * (float)(local_48 - DOUBLE_803e0f40);
      uStack_4c = FUN_80022264(0x28,0x3c);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803e0ee4 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      uVar2 = FUN_80022264(0x3c,0xa0);
      local_68 = (undefined)uVar2;
      local_84 = 0x81080200;
      local_80 = 0x4000800;
      local_86 = 0xc0f;
      break;
    case 0x711:
      fVar3 = FLOAT_803e0ea8;
      if (param_6 != (float *)0x0) {
        fVar3 = *param_6;
      }
      dVar5 = (double)fVar3;
      local_c0 = (float)FUN_80022264(0x23,0x4b);
      local_94 = (float)((double)FLOAT_803e0ee8 * dVar5);
      local_90 = (float)((double)FLOAT_803e0edc * dVar5);
      uStack_34 = FUN_80022264(0xffffffce,0x32);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803e0ebc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = -local_c0;
      local_40 = 0x43300000;
      local_a0 = FLOAT_803e0eec * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80022264(0x14,0x3c);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e0ee0 * (float)(local_48 - DOUBLE_803e0f40);
      uStack_4c = FUN_80022264(0x28,0x3c);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803e0ee4 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      uVar2 = FUN_80022264(100,200);
      local_68 = (undefined)uVar2;
      local_84 = 0x81080200;
      local_80 = 0x4000800;
      local_86 = 0xc0f;
      break;
    case 0x712:
      local_c0 = (float)FUN_80022264(0x32,100);
      uStack_34 = FUN_80022264(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803e0ebc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = -local_c0;
      local_40 = 0x43300000;
      local_a0 = FLOAT_803e0ef0 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e0ebc * (float)(local_48 - DOUBLE_803e0f40);
      local_8c = FLOAT_803e0ef4;
      uVar2 = FUN_80022264(0,2);
      if (uVar2 == 0) {
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
      uVar2 = FUN_80022264(0x1e,0x28);
      local_68 = (undefined)uVar2;
      if (param_6 != (float *)0x0) {
        local_38 = 0x43300000;
        fStack_3c = -*param_6;
        local_40 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uVar2 & 0xff) - DOUBLE_803e0f48) *
                     ((float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40) /
                     FLOAT_803e0ef8));
        local_48 = (double)(longlong)iVar1;
        local_68 = (undefined)iVar1;
        uStack_34 = uVar2 & 0xff;
      }
      uStack_34 = FUN_80022264(0x12,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = FLOAT_803e0efc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80022264(0x28,0x3c);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_8c = FLOAT_803e0f00 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80022264(8,0x14);
      local_84 = 0x80204;
      local_80 = 0x4002800;
      local_86 = 0xc0f;
      break;
    case 0x715:
      if (param_6 == (float *)0x0) {
        uStack_34 = FUN_80022264(0x32,100);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_8c = FLOAT_803e0f0c *
                   (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
        local_c0 = 1.68156e-43;
        local_84 = 0x80580200;
        local_80 = 0x800;
      }
      else {
        uStack_34 = FUN_80022264(0xffffffe7,0x19);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_a4 = FLOAT_803e0f04 *
                   (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
        fStack_3c = (float)FUN_80022264(5,0x32);
        fStack_3c = -fStack_3c;
        local_40 = 0x43300000;
        local_a0 = FLOAT_803e0f04 *
                   (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
        uVar2 = FUN_80022264(0xffffffe7,0x19);
        local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_9c = FLOAT_803e0f04 * (float)(local_48 - DOUBLE_803e0f40);
        local_8c = FLOAT_803e0f08;
        local_c0 = (float)FUN_80022264(0x28,0x78);
        local_84 = 0x80480000;
        local_80 = 0x400800;
      }
      local_68 = 0xff;
      local_86 = 0xc0f;
      break;
    case 0x716:
      uStack_34 = FUN_80022264(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80022264(0xffffffec,0x14);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_90 = (float)(local_48 - DOUBLE_803e0f40);
      uStack_4c = FUN_80022264(0x5a,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803e0eb8 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      local_67 = 0xf;
      fStack_54 = (float)FUN_80022264(0x5a,100);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_8c = FLOAT_803e0ea0 * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      local_84 = 0x800c0100;
      local_80 = 0x4000800;
      uVar2 = FUN_80022264(0x96,200);
      local_68 = (undefined)uVar2;
      local_c0 = (float)FUN_80022264(0x32,0x46);
      local_86 = 0x185;
      break;
    case 0x717:
      fVar3 = FLOAT_803e0ea8;
      if (param_6 != (float *)0x0) {
        fVar3 = *param_6;
      }
      dVar5 = (double)fVar3;
      uStack_34 = FUN_80022264(0xffffff6a,0x96);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)(dVar5 * (double)(FLOAT_803e0ea4 *
                                         (float)((double)CONCAT44(0x43300000,uStack_34) -
                                                DOUBLE_803e0f40)));
      fStack_3c = (float)FUN_80022264(100,300);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_94 = (float)(dVar5 * (double)(FLOAT_803e0ea4 *
                                         (float)((double)CONCAT44(0x43300000,fStack_3c) -
                                                DOUBLE_803e0f40)));
      uVar2 = FUN_80022264(0xffffff6a,0xffffffce);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_90 = (float)(dVar5 * (double)(FLOAT_803e0ea4 * (float)(local_48 - DOUBLE_803e0f40)));
      local_8c = FLOAT_803e0ec4;
      local_c0 = (float)FUN_80022264(0x32,0x96);
      local_84 = 0x80480100;
      uVar2 = FUN_80022264(0x527,0x528);
      local_86 = (undefined2)uVar2;
      break;
    case 0x718:
      uStack_34 = FUN_80022264(8,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0efc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      if (param_6 != (float *)0x0) {
        local_a0 = local_a0 * (FLOAT_803e0ea8 + *param_6 / FLOAT_803e0f10);
      }
      uStack_34 = FUN_80022264(6,0xc);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e0ec0 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80022264(0x3c,100);
      local_84 = 0x80180000;
      local_80 = 0x5440800;
      local_86 = 0xc0b;
      local_68 = 0x40;
      break;
    case 0x71a:
      local_90 = FLOAT_803e0f14;
      uStack_34 = FUN_80022264(0x4b,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e0f18 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      local_c0 = 1.4013e-45;
      local_84 = 0x80010;
      local_80 = 0x800;
      local_86 = 0xc7e;
      local_68 = 0x7f;
      break;
    case 0x71b:
      local_8c = FLOAT_803e0f1c;
      local_c0 = 1.4013e-43;
      local_84 = 0x180000;
      local_80 = 0x400800;
      local_86 = 0x73;
      local_68 = 0xff;
      break;
    case 0x71c:
      local_c0 = (float)FUN_80022264(0x28,0x78);
      uStack_34 = FUN_80022264(0xffffffce,0x32);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803e0efc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = -local_c0;
      local_40 = 0x43300000;
      local_a0 = FLOAT_803e0f20 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80022264(0xffffffce,0x32);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e0efc * (float)(local_48 - DOUBLE_803e0f40);
      local_8c = FLOAT_803e0f04;
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
      uStack_34 = FUN_80022264(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80022264(0xffffffec,0x14);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_90 = (float)(local_48 - DOUBLE_803e0f40);
      local_67 = 0xf;
      uStack_4c = FUN_80022264(0x78,200);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803e0ea0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      local_84 = 0x80180100;
      local_80 = 0x4000800;
      uVar2 = FUN_80022264(0x32,100);
      local_68 = (undefined)uVar2;
      local_c0 = (float)FUN_80022264(100,0x8c);
      local_86 = 0x185;
      break;
    case 0x71e:
      uStack_34 = FUN_80022264(0xffffffdd,0x23);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80022264(0,0x1e);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80022264(0xffffffdd,0x23);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_90 = (float)(local_48 - DOUBLE_803e0f40);
      uStack_4c = FUN_80022264(8,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803e0efc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      fStack_54 = (float)FUN_80022264(6,0xc);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_8c = FLOAT_803e0ec0 * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80022264(100,0x96);
      local_84 = 0x80180000;
      local_80 = 0x1440000;
      local_86 = 0x564;
      local_68 = 0x7f;
      break;
    case 0x71f:
      uStack_34 = FUN_80022264(8,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0efc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80022264(6,0xc);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_8c = FLOAT_803e0f08 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80022264(0x3c,0x50);
      local_84 = 0x80180000;
      local_80 = 0x5440800;
      local_86 = 0x564;
      local_68 = 0x40;
      break;
    case 0x720:
      uStack_34 = FUN_80022264(8,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0f24 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80022264(6,0xc);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_8c = FLOAT_803e0f08 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80022264(0x3c,0x50);
      local_84 = 0x80180200;
      local_80 = 0x5000800;
      local_86 = 0x564;
      local_68 = 0x40;
      break;
    case 0x721:
      uStack_34 = FUN_80022264(6,0xc);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e0f28 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80022264(0xfa,0x15e);
      local_84 = 0x80480008;
      local_80 = 0x400000;
      local_86 = 0xc0d;
      break;
    case 0x722:
      local_94 = FLOAT_803e0f2c;
      local_c0 = (float)FUN_80022264(0x1e,0x3c);
      uStack_34 = FUN_80022264(0xffffffc4,0x3c);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803e0f24 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      dVar5 = FUN_80293900((double)(local_a4 * local_a4 + local_9c * local_9c));
      local_a0 = (float)((double)FLOAT_803e0f30 * dVar5);
      fStack_3c = (float)FUN_80022264(0xffffffc4,0x3c);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0f24 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_8c = FLOAT_803e0f24;
      local_84 = 0x80000;
      local_80 = 0x5400800;
      local_86 = 0x564;
      uVar2 = FUN_80022264(0x46,0xbe);
      local_68 = (undefined)((int)uVar2 >> 1);
      break;
    case 0x723:
      local_c0 = (float)FUN_80022264(0x23,0x2d);
      if (param_6 == (float *)0x0) {
        fVar3 = 7.00649e-45;
      }
      else {
        fVar3 = (float)((int)*param_6 + 5);
      }
      uStack_34 = FUN_80022264(8,0xc);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      fStack_3c = -fVar3;
      local_40 = 0x43300000;
      local_a0 = ((float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40) / FLOAT_803e0f34
                 ) * FLOAT_803e0f38 *
                     (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      uVar4 = 0x41 - (int)fVar3;
      uVar2 = FUN_80022264(-uVar4,uVar4);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a4 = FLOAT_803e0ecc * (float)(local_48 - DOUBLE_803e0f40);
      uStack_4c = FUN_80022264(-uVar4,uVar4);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803e0ecc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      fStack_54 = (float)FUN_80022264(6,0xc);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_8c = FLOAT_803e0ec0 * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      uVar2 = FUN_80022264(0x40,0x7f);
      local_68 = (undefined)((int)uVar2 >> 1);
      local_84 = 0x80080000;
      local_80 = 0x5400800;
      local_86 = 0x564;
      break;
    case 0x724:
      uStack_34 = FUN_80022264(8,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0efc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80022264(6,0xc);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_8c = FLOAT_803e0ec0 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80022264(0x1e,0x3c);
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
    (**(code **)(*DAT_803dd6f8 + 8))(local_c8,0xffffffff,(int)uVar6,0);
  }
LAB_800cd094:
  FUN_8028688c();
  return;
}

