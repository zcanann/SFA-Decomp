// Function: FUN_800cd6bc
// Entry: 800cd6bc
// Size: 32716 bytes

/* WARNING: Removing unreachable block (ram,0x800d5668) */
/* WARNING: Removing unreachable block (ram,0x800d5660) */
/* WARNING: Removing unreachable block (ram,0x800cd6d4) */
/* WARNING: Removing unreachable block (ram,0x800cd6cc) */

void FUN_800cd6bc(undefined4 param_1,undefined4 param_2,ushort *param_3,uint param_4,
                 undefined param_5,float *param_6)

{
  int iVar1;
  ushort uVar2;
  ushort *puVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double in_f30;
  double in_f31;
  double dVar8;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar9;
  ushort *local_d8;
  undefined4 local_d4;
  uint local_d0;
  ushort local_cc;
  ushort local_ca;
  ushort local_c8;
  undefined4 local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  ushort local_96;
  code *local_94;
  uint local_90;
  uint local_8c;
  uint local_88;
  uint local_84;
  ushort local_80;
  ushort local_7e;
  ushort local_7c;
  undefined local_7a;
  char local_78;
  undefined local_77;
  undefined local_76;
  undefined8 local_70;
  undefined8 local_68;
  undefined4 local_60;
  uint uStack_5c;
  undefined8 local_58;
  undefined4 local_50;
  uint uStack_4c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar9 = FUN_80286834();
  puVar3 = (ushort *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  uVar6 = 0;
  FLOAT_803dc4e0 = FLOAT_803dc4e0 + FLOAT_803e0f90;
  if (FLOAT_803e0f98 < FLOAT_803dc4e0) {
    FLOAT_803dc4e0 = FLOAT_803e0f94;
  }
  FLOAT_803dc4e4 = FLOAT_803dc4e4 + FLOAT_803e0f9c;
  if (FLOAT_803e0f98 < FLOAT_803dc4e4) {
    FLOAT_803dc4e4 = FLOAT_803e0fa0;
  }
  if (puVar3 == (ushort *)0x0) goto LAB_800d5660;
  if ((param_4 & 0x200000) != 0) {
    if (param_3 == (ushort *)0x0) goto LAB_800d5660;
    local_c0 = *(float *)(param_3 + 6);
    local_bc = *(float *)(param_3 + 8);
    local_b8 = *(float *)(param_3 + 10);
    local_c4 = *(undefined4 *)(param_3 + 4);
    local_c8 = param_3[2];
    local_ca = param_3[1];
    local_cc = *param_3;
    local_76 = param_5;
  }
  local_94 = (code *)0x0;
  local_90 = 0;
  local_7a = (undefined)uVar9;
  local_a8 = FLOAT_803e0fa4;
  local_a4 = FLOAT_803e0fa4;
  local_a0 = FLOAT_803e0fa4;
  local_b4 = FLOAT_803e0fa4;
  local_b0 = FLOAT_803e0fa4;
  local_ac = FLOAT_803e0fa4;
  local_9c = FLOAT_803e0fa4;
  local_d0 = 0;
  local_d4 = 0xffffffff;
  local_78 = -1;
  local_77 = 0;
  local_96 = 0;
  local_80 = 0xffff;
  local_7e = 0xffff;
  local_7c = 0xffff;
  local_8c = 0xffff;
  local_88 = 0xffff;
  local_84 = 0xffff;
  local_d8 = puVar3;
  switch(iVar5) {
  case 0x79e:
    if (param_6 != (float *)0x0) {
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b4 = FLOAT_803e0fa0 * *param_6 + FLOAT_803e0f90 * (float)(local_70 - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = FLOAT_803e0fa0 * param_6[1] + FLOAT_803e0f90 * (float)(local_68 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e0fa0 * param_6[2] +
                 FLOAT_803e0f90 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    }
    uStack_5c = FUN_80022264(0x32,100);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_9c = FLOAT_803e0fa8 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    local_d0 = 100;
    local_94 = (code *)0x80480200;
    local_90 = 0x8000800;
    local_78 = -1;
    local_96 = 0x84;
    break;
  case 0x79f:
    uStack_5c = FUN_80022264(0x32,100);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_9c = FLOAT_803e0f98;
    if (param_6 != (float *)0x0) {
      local_9c = *param_6;
    }
    local_9c = local_9c *
               FLOAT_803e0f90 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    local_d0 = 0x1e;
    local_94 = (code *)0x180010;
    local_90 = 0x8000;
    local_78 = -1;
    local_96 = 0xc80;
    local_80 = 0xffff;
    local_7e = 0xffff;
    local_7c = 0xffff;
    local_8c = 0xffff;
    local_88 = 0xffff;
    local_84 = 0xffff;
    break;
  case 0x7a0:
    if (param_3 == (ushort *)0x0) {
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_b4 = FLOAT_803e0fb0 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = FLOAT_803e0fb0 * (float)(local_68 - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_ac = FLOAT_803e0fb0 * (float)(local_70 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x14,0x28);
      local_94 = (code *)0x80010;
      local_90 = 0x8480800;
      uVar4 = FUN_80022264(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e0fac * (float)(local_58 - DOUBLE_803e1150);
    }
    else {
      local_d0 = (uint)(short)param_3[3];
      local_94 = (code *)0x80080210;
      local_90 = 0x8000800;
      uStack_5c = FUN_80022264(0x32,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e0fac * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    }
    local_78 = -1;
    local_96 = 0xdb;
    break;
  case 0x7a1:
    if (param_3 == (ushort *)0x0) {
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b4 = FLOAT_803e0fb4 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = FLOAT_803e0fb4 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_ac = FLOAT_803e0fb4 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x14,0x28);
      local_94 = (code *)0x80010;
      local_90 = 0x8480800;
      uVar4 = FUN_80022264(0x32,100);
      local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e0fac * (float)(local_70 - DOUBLE_803e1150);
    }
    else {
      local_d0 = (uint)(short)param_3[3];
      local_94 = (code *)0x80080210;
      local_90 = 0x8000800;
      uVar4 = FUN_80022264(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0fac * (float)(local_58 - DOUBLE_803e1150);
    }
    local_78 = -1;
    local_96 = 0x157;
    break;
  case 0x7a2:
    if (param_6 != (float *)0x0) {
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b4 = FLOAT_803e0fb8 * *param_6 + FLOAT_803e0f90 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = FLOAT_803e0fb8 * param_6[1] +
                 FLOAT_803e0f90 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_ac = FLOAT_803e0fb8 * param_6[2] + FLOAT_803e0f90 * (float)(local_68 - DOUBLE_803e1150);
    }
    local_d0 = FUN_80022264(10,0x1e);
    local_94 = (code *)0x480000;
    local_90 = 0x400800;
    uVar4 = FUN_80022264(0x32,100);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_9c = FLOAT_803e0fbc * (float)(local_58 - DOUBLE_803e1150);
    local_78 = -1;
    local_96 = 0xde;
    break;
  case 0x7a3:
    uVar4 = FUN_80022264(0xffff8001,0x7fff);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    dVar7 = (double)FUN_80294964();
    uStack_5c = FUN_80022264(100,0x96);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_b4 = (float)((double)(FLOAT_803e0fc0 *
                               (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150)) *
                      dVar7);
    dVar7 = (double)FUN_802945e0();
    uVar4 = FUN_80022264(100,0x96);
    local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_b0 = (float)((double)(FLOAT_803e0fc0 * (float)(local_68 - DOUBLE_803e1150)) * dVar7);
    local_ac = FLOAT_803e0fa4;
    local_d0 = FUN_80022264(0x14,0x1e);
    local_94 = (code *)0x480000;
    local_90 = 0x480800;
    uVar4 = FUN_80022264(0x32,100);
    local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_9c = FLOAT_803e0fbc * (float)(local_70 - DOUBLE_803e1150);
    local_78 = -1;
    local_96 = 0xde;
    break;
  case 0x7a4:
    if (param_6 != (float *)0x0) {
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b4 = FLOAT_803e0fb8 * *param_6 + FLOAT_803e0f90 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = FLOAT_803e0fb8 * param_6[1] +
                 FLOAT_803e0f90 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_ac = FLOAT_803e0fb8 * param_6[2] + FLOAT_803e0f90 * (float)(local_68 - DOUBLE_803e1150);
    }
    local_d0 = FUN_80022264(10,0x1e);
    local_94 = (code *)0x480000;
    local_90 = 0x400800;
    uVar4 = FUN_80022264(0x32,100);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_9c = FLOAT_803e0fbc * (float)(local_58 - DOUBLE_803e1150);
    local_78 = -1;
    local_96 = 0xc22;
    break;
  case 0x7a5:
    uVar4 = FUN_80022264(0xffff8001,0x7fff);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    dVar7 = (double)FUN_80294964();
    uStack_5c = FUN_80022264(100,0x96);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_b4 = (float)((double)(FLOAT_803e0fb0 *
                               (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150)) *
                      dVar7);
    dVar7 = (double)FUN_802945e0();
    uVar4 = FUN_80022264(100,0x96);
    local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_b0 = (float)((double)(FLOAT_803e0fb0 * (float)(local_68 - DOUBLE_803e1150)) * dVar7);
    local_ac = FLOAT_803e0fa4;
    local_d0 = FUN_80022264(0x1e,0x28);
    local_94 = (code *)0x480000;
    local_90 = 0x480800;
    uVar4 = FUN_80022264(0x32,100);
    local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_9c = FLOAT_803e0fbc * (float)(local_70 - DOUBLE_803e1150);
    local_78 = -1;
    local_96 = 0xc22;
    break;
  case 0x7a6:
    if (param_3 == (ushort *)0x0) {
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b4 = FLOAT_803e0fb4 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = FLOAT_803e0fb4 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_ac = FLOAT_803e0fb4 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x14,0x28);
      local_94 = (code *)0x80010;
      local_90 = 0x8480800;
      uVar4 = FUN_80022264(0x32,100);
      local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e0fac * (float)(local_70 - DOUBLE_803e1150);
    }
    else {
      local_d0 = (uint)(short)param_3[3];
      local_94 = (code *)0x80080210;
      local_90 = 0x8000800;
      uVar4 = FUN_80022264(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0fac * (float)(local_58 - DOUBLE_803e1150);
    }
    local_78 = -1;
    local_96 = 0xc7e;
    break;
  case 0x7a7:
    if (param_3 == (ushort *)0x0) {
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b4 = FLOAT_803e0fb4 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = FLOAT_803e0fb4 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_ac = FLOAT_803e0fb4 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x14,0x28);
      local_94 = (code *)0x80010;
      local_90 = 0x8480800;
      uVar4 = FUN_80022264(0x32,100);
      local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e0fac * (float)(local_70 - DOUBLE_803e1150);
    }
    else {
      local_d0 = (uint)(short)param_3[3];
      local_94 = (code *)0x80080210;
      local_90 = 0x8000800;
      uVar4 = FUN_80022264(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0fac * (float)(local_58 - DOUBLE_803e1150);
    }
    local_78 = -1;
    local_96 = 0xc13;
    break;
  case 0x7a8:
    if (param_3 != (ushort *)0x0) {
      uVar4 = FUN_80022264(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0fcc * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fd0 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150)
                 + *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a0 = *(float *)(param_3 + 4) * FLOAT_803e0fd0 * (float)(local_68 - DOUBLE_803e1150) +
                 *(float *)(param_3 + 10);
      uVar4 = FUN_80022264(0x50,100);
      local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0fd4 * (float)(local_70 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x14);
      local_d0 = local_d0 + 10;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)(param_4 | 0x80200);
      local_90 = 0x4040800;
    }
    break;
  case 0x7a9:
    if (param_3 != (ushort *)0x0) {
      uVar4 = FUN_80022264(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0fd8 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fb4 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150)
                 + *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a0 = *(float *)(param_3 + 4) * FLOAT_803e0fb4 * (float)(local_68 - DOUBLE_803e1150) +
                 *(float *)(param_3 + 10);
      uVar4 = FUN_80022264(0x50,100);
      local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0fd4 * (float)(local_70 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x14);
      local_d0 = local_d0 + 10;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)(param_4 | 0x80200);
      local_90 = 0x4040800;
    }
    break;
  case 0x7aa:
    if (param_3 != (ushort *)0x0) {
      uVar4 = FUN_80022264(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0fdc * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e0f94 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150)
                 + *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a0 = *(float *)(param_3 + 4) * FLOAT_803e0f94 * (float)(local_68 - DOUBLE_803e1150) +
                 *(float *)(param_3 + 10);
      uVar4 = FUN_80022264(0x50,100);
      local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0fe0 * (float)(local_70 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x23);
      local_d0 = local_d0 + 0x19;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)(param_4 | 0x80200);
      local_90 = 0x4040820;
      local_8c = 0xffff;
      local_88 = 0xffff;
      local_84 = FUN_80022264(0,0xffff);
      local_80 = 0xffff;
      uVar4 = FUN_80022264(0,0x7fff);
      local_7e = (ushort)uVar4;
      local_7c = (ushort)local_84;
    }
    break;
  case 0x7ab:
    if (param_3 != (ushort *)0x0) {
      uVar4 = FUN_80022264(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0fe4 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fe8 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150)
                 + *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a0 = *(float *)(param_3 + 4) * FLOAT_803e0fe8 * (float)(local_68 - DOUBLE_803e1150) +
                 *(float *)(param_3 + 10);
      uVar4 = FUN_80022264(0x23,100);
      local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0fd4 * (float)(local_70 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x12);
      local_d0 = local_d0 + 10;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)(param_4 | 0x80080200);
      local_90 = 0x4010800;
      uVar6 = 1;
    }
    break;
  case 0x7ac:
    if (param_3 != (ushort *)0x0) {
      uVar4 = FUN_80022264(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0fe4 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fec * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150)
                 + *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a0 = *(float *)(param_3 + 4) * FLOAT_803e0fec * (float)(local_68 - DOUBLE_803e1150) +
                 *(float *)(param_3 + 10);
      uVar4 = FUN_80022264(0x50,100);
      local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0fd4 * (float)(local_70 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x17);
      local_d0 = local_d0 + 5;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)(param_4 | 0x80080200);
      local_90 = 0x40800;
    }
    break;
  case 0x7ad:
    if (param_3 != (ushort *)0x0) {
      uVar4 = FUN_80022264(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0ff0 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xf,0x14);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a4 = *(float *)(param_3 + 4) *
                 (FLOAT_803e0ff4 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150)
                 + *(float *)(param_3 + 8));
      uVar4 = FUN_80022264(0x50,0x8c);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0ff8 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0,10);
      local_d0 = local_d0 + 0x32;
      local_96 = 0xc10;
      local_78 = -1;
      local_94 = (code *)0x80100;
      local_90 = 0x4010020;
      local_8c = (uint)(short)param_3[3];
      local_80 = (ushort)((int)local_8c >> 1);
      local_88 = local_8c;
      local_84 = local_8c;
      local_7e = local_80;
      local_7c = local_80;
    }
    break;
  case 0x7ae:
    if (param_3 != (ushort *)0x0) {
      uVar4 = FUN_80022264(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0ffc * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e1000 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xf,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a4 = *(float *)(param_3 + 4) *
                 (FLOAT_803e0ff4 * (float)(local_68 - DOUBLE_803e1150) + *(float *)(param_3 + 8));
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a0 = *(float *)(param_3 + 4) * FLOAT_803e1000 * (float)(local_70 - DOUBLE_803e1150);
      uStack_4c = FUN_80022264(0x50,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e1004 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0,10);
      local_d0 = local_d0 + 0x32;
      local_96 = 0xc0d;
      local_78 = -1;
      local_94 = (code *)0x80480000;
      local_90 = 0x410800;
    }
    break;
  case 0x7af:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(100,200);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4);
      local_b0 = local_9c *
                 FLOAT_803e1008 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      local_a4 = (FLOAT_803e100c + *(float *)(param_3 + 8)) * local_9c;
      local_9c = FLOAT_803e1010 * local_9c;
      local_d0 = 5;
      local_96 = 0x5e6;
      local_78 = (char)param_3[3];
      local_94 = (code *)0x80200;
      local_90 = 0x4088000;
      local_80 = 0xffff;
      local_7e = 0xffff;
      local_7c = 0xffff;
      local_8c = 0xffff;
      local_88 = 0xffff;
      local_84 = 0xffff;
    }
    break;
  case 0x7b0:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(100,200);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4);
      local_b0 = local_9c *
                 FLOAT_803e1008 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      local_a4 = (FLOAT_803e100c + *(float *)(param_3 + 8)) * local_9c;
      local_9c = FLOAT_803e1010 * local_9c;
      local_d0 = 0xf;
      local_96 = 0x5e6;
      local_78 = (char)param_3[3];
      local_94 = (code *)0x80100;
      local_90 = 0x4088000;
      local_80 = 0xffff;
      local_7e = 0xffff;
      local_7c = 0xffff;
      local_8c = 0xffff;
      local_88 = 0xffff;
      local_84 = 0xffff;
    }
    break;
  case 0x7b1:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xffffffe5,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 4) *
                 FLOAT_803e1014 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(10,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e1018 * (float)(local_58 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x23,100);
      local_78 = -1;
      local_96 = param_3[3];
      local_94 = (code *)0x80480100;
      local_90 = 0x8010800;
    }
    break;
  case 0x7b2:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e1010 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_ac = FLOAT_803e1010 * (float)(local_58 - DOUBLE_803e1150);
      local_a4 = *(float *)(param_3 + 6);
      uStack_5c = FUN_80022264(0x1c,0x20);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = FLOAT_803e101c * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_d0 = (uint)(short)param_3[3];
      local_96 = *param_3;
      local_94 = (code *)0x480204;
      local_90 = 0x808;
    }
    break;
  case 0x7b3:
    if (param_3 != (ushort *)0x0) {
      local_9c = FLOAT_803e1020 * *(float *)(param_3 + 4);
      local_d0 = (uint)(short)param_3[3];
      uStack_4c = FUN_80022264(0x154,0x2d5);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 8) *
                 (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      local_a4 = *(float *)(param_3 + 6);
      local_96 = *param_3;
      local_94 = (code *)0x80114;
      local_90 = 0x4000800;
    }
    break;
  case 0x7b4:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e1010 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_ac = FLOAT_803e1010 * (float)(local_58 - DOUBLE_803e1150);
      local_a4 = *(float *)(param_3 + 6);
      uStack_5c = FUN_80022264(0x1c,0x20);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = FLOAT_803e101c * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_d0 = (uint)(short)param_3[3];
      local_96 = *param_3;
      local_94 = (code *)0x480004;
      local_90 = 0x480800;
    }
    break;
  case 0x7b5:
    if (param_3 != (ushort *)0x0) {
      if (param_3[3] == 0) {
        local_9c = FLOAT_803e0fb0 * *(float *)(param_3 + 4);
        local_94 = (code *)0xc1180000;
        local_90 = 0x4400800;
        local_d0 = FUN_80022264(0x1c,0x22);
        local_d0 = local_d0 + 10;
      }
      else {
        uStack_4c = FUN_80022264(6,10);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e0f9c * *(float *)(param_3 + 4) *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        local_94 = (code *)0xc1080000;
        local_90 = 0x4400800;
        local_d0 = 10;
      }
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uStack_4c = FUN_80022264(100,0x96);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_ac = FLOAT_803e0f94 *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e1024 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      FUN_80021b8c(puVar3,&local_b4);
      local_96 = 0xc0a;
      local_90 = local_90 | 0x20;
      local_8c = 0xffff;
      local_88 = 0xffff;
      local_84 = FUN_80022264(0,0xffff);
      local_80 = 0xffff;
      uVar4 = FUN_80022264(0,0x7fff);
      local_7e = (ushort)uVar4;
      local_7c = (ushort)local_84;
    }
    break;
  case 0x7b6:
    if (param_3 != (ushort *)0x0) {
      if (param_3[3] == 0) {
        local_9c = FLOAT_803e0fb0 * *(float *)(param_3 + 4);
        local_94 = (code *)0x81180000;
        local_90 = 0x4400800;
        local_d0 = FUN_80022264(0x1c,0x22);
        local_d0 = local_d0 + 10;
      }
      else {
        uStack_4c = FUN_80022264(6,10);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e0f9c * *(float *)(param_3 + 4) *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        local_94 = (code *)0x81080000;
        local_90 = 0x4400800;
        local_d0 = 10;
      }
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(100,0x96);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_ac = FLOAT_803e0f94 *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e1024 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      FUN_80021b8c(puVar3,&local_b4);
      local_96 = 0x5f5;
    }
    break;
  case 0x7b7:
    if (param_3 != (ushort *)0x0) {
      if (param_6 == (float *)0x0) {
        uStack_4c = FUN_80022264(0x5a,100);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_b0 = *(float *)(param_3 + 4) *
                   FLOAT_803e1028 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      }
      else {
        uStack_4c = FUN_80022264(0xffffff9c,100);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_b4 = FLOAT_803e0fa0 * *param_6 +
                   FLOAT_803e0f90 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        if (FLOAT_803e0fa4 != local_b0) {
          uStack_4c = FUN_80022264(0xffffff9c,100);
          uStack_4c = uStack_4c ^ 0x80000000;
          local_b0 = FLOAT_803e0fa0 * param_6[1] +
                     FLOAT_803e0f90 *
                     (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        }
        local_50 = 0x43300000;
        uStack_4c = FUN_80022264(0xffffff9c,100);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_ac = FLOAT_803e0fa0 * param_6[2] +
                   FLOAT_803e0f90 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      }
      local_50 = 0x43300000;
      uStack_4c = FUN_80022264(0xffffffec,0x14);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffffec,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a4 = *(float *)(param_3 + 4) * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffffec,0x14);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0x5a,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0f90 * (float)(local_68 - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0x9b,0xff);
      local_78 = (char)uVar4;
      local_d0 = FUN_80022264(1,0x14);
      local_d0 = (int)(short)param_3[2] + local_d0;
      if (param_3[1] == 0) {
        local_94 = (code *)0x80480000;
      }
      else {
        local_94 = (code *)0x80080000;
      }
      if (*param_3 == 0) {
        local_90 = 0x4400000;
      }
      else {
        local_90 = 0x4400800;
      }
      local_96 = param_3[3];
      local_77 = 0xf;
    }
    break;
  case 0x7b8:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    uStack_4c = FUN_80022264(0x46,0x50);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e102c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    local_d0 = 5;
    local_96 = 0x2d;
    local_94 = (code *)0x180200;
    local_90 = 0;
    break;
  case 0x7b9:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e1010 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = FLOAT_803e1010 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e1010 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_d0 = (uint)*(short *)((int)param_6 + 6);
      local_96 = *(ushort *)param_6;
      uVar4 = FUN_80022264(0x1c,0x20);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e101c * (float)(local_68 - DOUBLE_803e1150);
      local_94 = (code *)0x480200;
      local_90 = 0x808;
    }
    break;
  case 0x7ba:
    if (param_3 != (ushort *)0x0) {
      local_d0 = (uint)*(short *)((int)param_6 + 6);
      local_96 = *(ushort *)param_6;
      local_9c = FLOAT_803e1020 * param_6[2];
      local_94 = (code *)0x80110;
      local_90 = 0x4000800;
    }
    break;
  case 0x7bb:
    if (param_3 != (ushort *)0x0) {
      if (param_3[3] == 0) {
        local_9c = FLOAT_803e0fb0 * *(float *)(param_3 + 4);
        local_94 = (code *)0xc0180200;
        local_90 = 0x4010000;
        local_d0 = FUN_80022264(0x1c,0x22);
        local_d0 = local_d0 + 10;
        uVar4 = FUN_80022264((int)(short)param_3[2],(int)(short)param_3[2] + 10);
        local_78 = (char)uVar4;
      }
      else {
        uStack_4c = FUN_80022264(7,10);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e1030 * *(float *)(param_3 + 4) *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        local_94 = (code *)0xc0080200;
        local_90 = 0x4010000;
        local_d0 = 10;
        local_78 = '\x7f';
      }
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uStack_4c = FUN_80022264(100,0x96);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_ac = FLOAT_803e1034 *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e1028 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      FUN_80021b8c(puVar3,&local_b4);
      local_96 = 0xc10;
    }
    break;
  case 0x7bc:
    if (param_3 != (ushort *)0x0) {
      if (param_3[3] == 0) {
        local_9c = FLOAT_803e0fb0 * *(float *)(param_3 + 4);
        local_94 = (code *)0xc1180200;
        local_90 = 0x5010000;
        local_d0 = FUN_80022264(0x1c,0x22);
        local_d0 = local_d0 + 10;
        uVar4 = FUN_80022264((int)(short)param_3[2],(int)(short)param_3[2] + 10);
        local_78 = (char)uVar4;
      }
      else {
        uStack_4c = FUN_80022264(7,10);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e1030 * *(float *)(param_3 + 4) *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        local_94 = (code *)0xc1080200;
        local_90 = 0x5010000;
        local_d0 = 10;
        local_78 = '\x7f';
      }
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uStack_4c = FUN_80022264(100,0x96);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_ac = FLOAT_803e1034 *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e1038 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      FUN_80021b8c(puVar3,&local_b4);
      local_96 = 0xc10;
    }
    break;
  case 0x7bd:
    if (param_3 != (ushort *)0x0) {
      local_9c = FLOAT_803e0f90 * *(float *)(param_3 + 4);
      local_94 = (code *)0x83000200;
      local_90 = 0x1200000;
      local_d0 = FUN_80022264(10,0x18);
      local_78 = -1;
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uStack_4c = FUN_80022264(0xffffff6a,0x96);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e103c *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e0fb0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff6a,0x96);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = FLOAT_803e103c *
                 *(float *)(param_3 + 4) * FLOAT_803e0fb0 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(100,0x96);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e0f94 *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e1040 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      FUN_80021b8c(puVar3,&local_b4);
      local_96 = 0xc10;
    }
    break;
  case 0x7be:
    if (param_3 != (ushort *)0x0) {
      if (param_6 == (float *)0x0) {
        uStack_4c = FUN_80022264(100,0x6b);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_ac = *(float *)(param_3 + 6) *
                   *(float *)(param_3 + 4) *
                   FLOAT_803e1038 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      }
      else {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
        if (param_6[2] <= FLOAT_803e0fa4) {
          if (FLOAT_803e0fa4 <= param_6[2]) {
            uStack_4c = FUN_80022264(100,0x6b);
            uStack_4c = uStack_4c ^ 0x80000000;
            local_ac = *(float *)(param_3 + 6) *
                       *(float *)(param_3 + 4) *
                       FLOAT_803e1038 *
                       (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
          }
          else {
            uStack_4c = FUN_80022264(100,0x6b);
            uStack_4c = uStack_4c ^ 0x80000000;
            local_ac = *(float *)(param_3 + 6) *
                       *(float *)(param_3 + 4) *
                       FLOAT_803e1044 *
                       (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
          }
        }
        else {
          uStack_4c = FUN_80022264(100,0x6b);
          uStack_4c = uStack_4c ^ 0x80000000;
          local_b0 = *(float *)(param_3 + 6) *
                     *(float *)(param_3 + 4) *
                     FLOAT_803e1044 *
                     (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        }
      }
      local_50 = 0x43300000;
      uStack_4c = FUN_80022264(0x1c,0x22);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e1048 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x14,0x1b);
      local_78 = -1;
      local_94 = (code *)0x80004;
      local_90 = 0x8002820;
      if (param_3[2] == 0) {
        local_80 = 0x69;
        local_7e = 0x863;
        local_7c = 0x7fff;
        local_8c = 0x7fff;
        local_88 = 0x2d1a;
        local_84 = 0x8000;
      }
      else {
        local_80 = 0xff2d;
        local_7e = 0xa8f;
        local_7c = 0x2c;
        local_8c = 0xf78f;
        local_88 = 0x9126;
        local_84 = 0x4828;
      }
      local_96 = param_3[3];
    }
    break;
  case 0x7bf:
    if (param_3 != (ushort *)0x0) {
      if (param_6 != (float *)0x0) {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
      }
      uStack_4c = FUN_80022264(10,0xd);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = (FLOAT_803e0ff4 + *(float *)(param_3 + 6)) *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e104c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,2);
      local_d0 = local_d0 + 2;
      local_94 = (code *)0x80014;
      local_90 = 0x4000820;
      local_58 = (double)(longlong)(int)(FLOAT_803e1050 * *(float *)(param_3 + 6));
      local_78 = (char)(int)(FLOAT_803e1050 * *(float *)(param_3 + 6)) + '@';
      local_96 = param_3[3];
      if (param_3[2] == 0) {
        local_80 = 0x7fff;
        local_7e = 0x1806;
        local_7c = 0x4cb3;
        local_8c = 0xf48c;
        local_88 = 0x9882;
        local_84 = 0xd97d;
      }
      else {
        local_80 = 0xff87;
        local_7e = 0x4817;
        local_7c = 0x23;
        local_8c = 0xf78f;
        local_88 = 0xffa9;
        local_84 = 0xb32b;
      }
    }
    break;
  case 0x7c0:
    if (param_3 != (ushort *)0x0) {
      if (param_6 != (float *)0x0) {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
      }
      uStack_4c = FUN_80022264(0x2d,0x3a);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e1054 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,7);
      local_d0 = local_d0 + 0x1e;
      local_78 = -1;
      local_94 = (code *)0x80004;
      local_90 = 0x8440820;
      local_80 = 0xfb54;
      local_7e = 0;
      local_7c = 0;
      local_8c = 0xffff;
      local_88 = 0x8347;
      local_84 = 0x9b49;
      uVar4 = FUN_80022264(100,0x6c);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_ac = *(float *)(param_3 + 6) *
                 *(float *)(param_3 + 4) * FLOAT_803e1058 * (float)(local_58 - DOUBLE_803e1150);
      local_b0 = FLOAT_803e0fa4;
      local_b4 = FLOAT_803e0fa4;
      if (param_6 != (float *)0x0) {
        FUN_80021b8c((ushort *)param_6,&local_b4);
      }
      local_96 = param_3[3];
    }
    break;
  case 0x7c1:
    if (param_3 != (ushort *)0x0) {
      if (param_6 != (float *)0x0) {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
      }
      uStack_4c = FUN_80022264(2,0xd);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = (FLOAT_803e0ff4 + *(float *)(param_3 + 6)) *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e105c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      local_d0 = 0x11;
      local_94 = (code *)0x80114;
      local_90 = 0x4000900;
      iVar1 = (int)(FLOAT_803e1050 * *(float *)(param_3 + 6));
      local_58 = (double)(longlong)iVar1;
      local_78 = (char)iVar1 + '@';
      local_96 = param_3[3];
    }
    break;
  case 0x7c2:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = FLOAT_803e0fd0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b4 = *(float *)(param_3 + 4) *
                 (FLOAT_803e1060 + local_b0) * FLOAT_803e1064 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 (FLOAT_803e1060 + local_b0) *
                 FLOAT_803e1064 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_b0 = -local_b0 * *(float *)(param_3 + 4);
      uVar4 = FUN_80022264(0x19,0x32);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e1030 * (float)(local_68 - DOUBLE_803e1150);
      local_a4 = FLOAT_803e1068 * *(float *)(param_3 + 4);
      local_d0 = FUN_80022264(0x28,0x50);
      local_96 = 0xc10;
      local_78 = '@';
      local_94 = (code *)0x80104;
      local_90 = 0x4800808;
    }
    break;
  case 0x7c3:
    if (param_3 != (ushort *)0x0) {
      uVar4 = FUN_80022264(0,0xffff);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_58 = (double)CONCAT44(0x43300000,(int)(short)param_3[3] ^ 0x80000000);
      dVar8 = (double)(FLOAT_803e0fb0 *
                       (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150) +
                      (float)(local_58 - DOUBLE_803e1150));
      uStack_5c = uVar4 ^ 0x80000000;
      local_60 = 0x43300000;
      dVar7 = (double)FUN_802945e0();
      local_a8 = (float)(dVar8 * dVar7 + (double)*(float *)(param_3 + 6));
      uVar4 = FUN_80022264(0,(int)(short)param_3[2]);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a4 = FLOAT_803e0f94 * (float)(local_68 - DOUBLE_803e1150) + *(float *)(param_3 + 8);
      dVar7 = (double)FUN_80294964();
      local_a0 = (float)(dVar8 * dVar7 + (double)*(float *)(param_3 + 10));
      local_d0 = FUN_80022264(10,0x28);
      local_96 = 0x156;
      local_94 = (code *)0x80480104;
      local_90 = 0x4000800;
      uVar4 = FUN_80022264(0x31,0x39);
      local_70 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e106c * (float)(local_70 - DOUBLE_803e1150);
      local_78 = -1;
    }
    break;
  case 0x7c4:
    if (param_3 != (ushort *)0x0) {
      if (param_6 != (float *)0x0) {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
      }
      uStack_4c = FUN_80022264(10,0xd);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = (FLOAT_803e0ff4 + *(float *)(param_3 + 6)) *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e104c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,2);
      local_d0 = local_d0 + 2;
      local_94 = (code *)0x80004;
      local_90 = 0x4000820;
      local_58 = (double)(longlong)(int)(FLOAT_803e1050 * *(float *)(param_3 + 6));
      local_78 = (char)(int)(FLOAT_803e1050 * *(float *)(param_3 + 6)) + '@';
      local_96 = param_3[3];
      if (param_3[2] == 0) {
        local_80 = 0x7fff;
        local_7e = 0x1806;
        local_7c = 0x4cb3;
        local_8c = 0xf48c;
        local_88 = 0x9882;
        local_84 = 0xd97d;
      }
      else {
        local_80 = 0xff87;
        local_7e = 0x4817;
        local_7c = 0x23;
        local_8c = 0xf78f;
        local_88 = 0xffa9;
        local_84 = 0xb32b;
      }
    }
    break;
  case 0x7c5:
    if (param_3 != (ushort *)0x0) {
      if (param_6 != (float *)0x0) {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
      }
      uStack_4c = FUN_80022264(2,0xd);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = (FLOAT_803e0ff4 + *(float *)(param_3 + 6)) *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e105c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      local_d0 = 0x11;
      local_94 = (code *)0x80104;
      local_90 = 0x4000900;
      iVar1 = (int)(FLOAT_803e1050 * *(float *)(param_3 + 6));
      local_58 = (double)(longlong)iVar1;
      local_78 = (char)iVar1 + '@';
      local_96 = param_3[3];
    }
    break;
  case 0x7c6:
    local_9c = FLOAT_803e1028;
    local_d0 = FUN_80022264(0x27,0x31);
    local_94 = (code *)0x180000;
    local_90 = 0x408000;
    local_96 = 0x5ff;
    break;
  case 0x7c7:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(100,200);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fcc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a8 = *(float *)(param_3 + 4) * FLOAT_803e0fd0 * (float)(local_58 - DOUBLE_803e1150) +
                 *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fd0 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150)
                 + *(float *)(param_3 + 10);
      uVar4 = FUN_80022264(0x50,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0fd4 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x14);
      local_d0 = local_d0 + 10;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x80200;
      local_90 = 0x4040800;
    }
    break;
  case 0x7c8:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xfffffed4,300);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e0fcc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = FLOAT_803e0fcc * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xfffffed4,300);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e0fcc * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_a4 = FLOAT_803e1070;
      local_9c = FLOAT_803e1074;
      local_d0 = FUN_80022264(0x19,0x20);
      local_96 = param_3[3];
      local_94 = (code *)0x80100;
      local_90 = 0x40808;
    }
    break;
  case 0x7c9:
    uStack_4c = FUN_80022264(0xffffff9c,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e1078 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0,100);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_b0 = FLOAT_803e107c * (float)(local_58 - DOUBLE_803e1150);
    uStack_5c = FUN_80022264(0xffffff9c,100);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e1080 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0xf,0x14);
    local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_9c = FLOAT_803e1084 * (float)(local_68 - DOUBLE_803e1150);
    local_d0 = FUN_80022264(300,0x1c2);
    local_96 = 0xc10;
    local_94 = (code *)0x8000100;
    local_90 = 0x1000000;
    local_78 = '\x7f';
    break;
  case 0x7ca:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e0fdc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = FLOAT_803e1088 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e0fdc * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(1,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e1064 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(100,0x78);
      local_96 = 0x605;
      if (param_3[1] == 1) {
        local_80 = 0x2234;
        local_7e = 0x8a54;
        local_7c = 0xfff6;
        local_8c = 0x2234;
        local_88 = 0x8a54;
        local_84 = 0xfff6;
      }
      else if (param_3[1] == 2) {
        local_80 = 0xfff6;
        local_7e = 0x1524;
        local_7c = 0x1524;
        local_8c = 0xfff6;
        local_88 = 0x1524;
        local_84 = 0x1524;
      }
      else {
        local_80 = 0xfff6;
        local_7e = 0x8a54;
        local_7c = 0x2234;
        local_8c = 0xfff6;
        local_88 = 0x8a54;
        local_84 = 0x2234;
      }
      local_94 = (code *)0x80110;
      local_90 = 0x8002828;
      local_78 = -0x40;
    }
    break;
  case 0x7cb:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fcc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0fcc * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e0fcc * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_9c = FLOAT_803e108c;
      uVar4 = FUN_80022264(0x32,0x3c);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_d0 = (uint)(*(float *)(param_3 + 4) * (float)(local_68 - DOUBLE_803e1150));
      local_70 = (double)(longlong)(int)local_d0;
      local_96 = 0x88;
      local_94 = (code *)0x480400;
      local_90 = 0x80800;
    }
    break;
  case 0x7cc:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e1000 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a4 = *(float *)(param_3 + 4) * FLOAT_803e1000 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = *(float *)(param_3 + 4) *
                 FLOAT_803e1000 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(5,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e0f9c * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x2a,0x32);
      local_96 = param_3[3];
      local_94 = (code *)0x580000;
      local_90 = 0x800;
    }
    break;
  case 0x7cd:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(100,200);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fd8 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a8 = *(float *)(param_3 + 4) * FLOAT_803e0fb4 * (float)(local_58 - DOUBLE_803e1150) +
                 *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fb4 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150)
                 + *(float *)(param_3 + 10);
      uVar4 = FUN_80022264(0x50,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0fd4 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x14);
      local_d0 = local_d0 + 10;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x280201;
      local_90 = 0x4040800;
    }
    break;
  case 0x7ce:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(100,200);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fd8 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a8 = *(float *)(param_3 + 4) * FLOAT_803e0fb4 * (float)(local_58 - DOUBLE_803e1150) +
                 *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fb4 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150)
                 + *(float *)(param_3 + 10);
      uVar4 = FUN_80022264(0x50,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0fd4 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(5,0xf);
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x280201;
      local_90 = 0x4040800;
    }
    break;
  case 1999:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      local_9c = FLOAT_803e1090 * *(float *)(param_3 + 4);
      local_d0 = 10;
      local_96 = param_3[3];
      local_78 = '\x7f';
      local_94 = (code *)0x280101;
      local_90 = 0x822;
      local_80 = 0x75b;
      local_7e = 0x1642;
      local_7c = 0xffff;
      local_8c = 0x656a;
      local_88 = 0x9f8;
      local_84 = 0xffff;
      if (param_3[2] != 0) {
        local_94 = (code *)0x20280101;
      }
    }
    break;
  case 2000:
    if (param_3 != (ushort *)0x0) {
      if (param_6 == (float *)0x0) {
        uStack_4c = FUN_80022264(100,200);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_b0 = *(float *)(param_3 + 4) *
                   FLOAT_803e0ff0 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        uVar4 = FUN_80022264(100,200);
        local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        local_ac = FLOAT_803e1094 *
                   *(float *)(param_3 + 4) * FLOAT_803e1098 * (float)(local_58 - DOUBLE_803e1150);
      }
      else {
        uStack_4c = FUN_80022264(100,200);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_b0 = FLOAT_803e0fa8 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        uVar4 = FUN_80022264(0x32,100);
        local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        local_ac = FLOAT_803e109c *
                   *(float *)(param_3 + 4) * FLOAT_803e10a0 * (float)(local_58 - DOUBLE_803e1150);
      }
      uStack_4c = FUN_80022264(0xffffffec,0x14);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a8 = FLOAT_803e1060 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150)
                 + *(float *)(param_3 + 6);
      uVar4 = FUN_80022264(0xf,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a4 = FLOAT_803e0ff4 * (float)(local_58 - DOUBLE_803e1150) + *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_5c = FUN_80022264(0x50,0x8c);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e0ff8 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0,10);
      local_d0 = local_d0 + 0xf;
      local_96 = 0xc10;
      local_78 = -1;
      local_94 = (code *)0x20080100;
      local_90 = 0x4010020;
      local_8c = (uint)(short)param_3[3];
      local_80 = (ushort)((int)local_8c >> 1);
      local_88 = local_8c;
      local_84 = local_8c;
      local_7e = local_80;
      local_7c = local_80;
    }
    break;
  case 0x7d1:
    if (param_3 != (ushort *)0x0) {
      if (param_6 == (float *)0x0) {
        uStack_4c = FUN_80022264(100,200);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_b0 = *(float *)(param_3 + 4) *
                   FLOAT_803e0fa8 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        uVar4 = FUN_80022264(100,200);
        local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        local_ac = FLOAT_803e10a4 *
                   *(float *)(param_3 + 4) * FLOAT_803e1098 * (float)(local_58 - DOUBLE_803e1150);
      }
      else {
        uStack_4c = FUN_80022264(100,200);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_b0 = FLOAT_803e0fa8 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        uVar4 = FUN_80022264(100,200);
        local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        local_ac = FLOAT_803e10a4 *
                   *(float *)(param_3 + 4) * FLOAT_803e0ff0 * (float)(local_58 - DOUBLE_803e1150);
      }
      uStack_4c = FUN_80022264(0xffffffec,0x14);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a4 = FLOAT_803e1000 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150)
                 + *(float *)(param_3 + 8);
      uVar4 = FUN_80022264(0xffffffec,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a8 = FLOAT_803e1000 * (float)(local_58 - DOUBLE_803e1150) + *(float *)(param_3 + 6);
      local_a0 = *(float *)(param_3 + 10);
      uStack_5c = FUN_80022264(0x50,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e0fd4 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x14);
      local_d0 = local_d0 + 10;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x20080200;
      local_90 = 0x4040800;
    }
    break;
  case 0x7d2:
    if (param_3 != (ushort *)0x0) {
      if (*param_3 == 0) {
        uStack_4c = FUN_80022264(0xffffff9c,100);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_b4 = FLOAT_803e0fd8 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        uVar4 = FUN_80022264(0xffffff9c,100);
        local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        local_b0 = FLOAT_803e0fec * (float)(local_58 - DOUBLE_803e1150);
        uStack_5c = FUN_80022264(0xffffff9c,100);
        uStack_5c = uStack_5c ^ 0x80000000;
        local_60 = 0x43300000;
        local_ac = FLOAT_803e0fd8 *
                   (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
        uVar4 = FUN_80022264(100,200);
        local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        local_a4 = FLOAT_803e0f94 * (float)(local_68 - DOUBLE_803e1150);
      }
      else {
        local_a4 = FLOAT_803e10a8;
        uStack_4c = FUN_80022264(0xffffff9c,100);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_b4 = FLOAT_803e0fa8 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        uVar4 = FUN_80022264(0xffffff9c,100);
        local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        local_b0 = FLOAT_803e1030 * (float)(local_58 - DOUBLE_803e1150);
        uStack_5c = FUN_80022264(0xffffff9c,100);
        uStack_5c = uStack_5c ^ 0x80000000;
        local_60 = 0x43300000;
        local_ac = FLOAT_803e0fa8 *
                   (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      }
      uStack_4c = FUN_80022264(5,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      local_d0 = (uint)(short)param_3[3];
      local_96 = param_3[2];
      local_78 = -1;
      local_94 = (code *)0x80110;
      local_90 = 0x20900;
    }
    break;
  case 0x7d3:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e10ac * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e10ac * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e10ac * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(10,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e10b0 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x28);
      local_d0 = (int)(short)param_3[1] + local_d0;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x480104;
      local_90 = 0x8000080;
    }
    break;
  case 0x7d4:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e10ac * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e10ac * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e10ac * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(10,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e10b0 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x28);
      local_d0 = (int)(short)param_3[1] + local_d0;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x1480104;
      local_90 = 0x8000080;
    }
    break;
  case 0x7d5:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e10ac * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e10ac * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e10ac * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(10,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e10b0 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x28);
      local_d0 = (int)(short)param_3[1] + local_d0;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x48010c;
      local_90 = 0x8000080;
    }
    break;
  case 0x7d6:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e10ac * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e10ac * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e10ac * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(10,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e10b0 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x28);
      local_d0 = (int)(short)param_3[1] + local_d0;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x40480104;
      local_90 = 0x8000080;
    }
    break;
  case 0x7d7:
    local_9c = FLOAT_803e1064;
    local_d0 = (uint)DAT_803dc070 * 3;
    local_78 = '2';
    local_96 = 0x605;
    local_94 = (code *)0x80200;
    local_90 = 0x820;
    local_80 = 0;
    local_7e = 0;
    local_7c = 0xffff;
    local_8c = 0x656a;
    local_88 = 0;
    local_84 = 0xffff;
    break;
  case 0x7d8:
    local_a4 = FLOAT_803e10b4;
    local_a0 = FLOAT_803e10b8;
    local_ac = FLOAT_803e10bc;
    uStack_4c = FUN_80022264(0x50,0x58);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e1030 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    local_d0 = FUN_80022264(0xd2,0xe6);
    local_96 = 0x7b;
    local_80 = 0xfaab;
    local_7e = 0xa9f;
    local_7c = 0x1d3;
    local_8c = 0x7fff;
    local_88 = 0x7fff;
    local_84 = 0xff4b;
    local_78 = ',';
    local_94 = (code *)0x80004;
    local_90 = 0x420820;
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a8 = FLOAT_803e1028 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150)
                 + local_a8;
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a4 = FLOAT_803e1028 * (float)(local_58 - DOUBLE_803e1150) + local_a4;
      uStack_5c = FUN_80022264(0x5a,0x6e);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e10c0 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_9c = FLOAT_803e0fdc;
      local_94 = (code *)((uint)local_94 | 0x400000);
    }
    break;
  case 0x7d9:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    local_9c = FLOAT_803e0fb0 * *(float *)(param_3 + 4);
    local_d0 = 10;
    local_96 = param_3[3];
    local_78 = '@';
    local_94 = (code *)0x80104;
    local_90 = 0x880;
    break;
  case 0x7da:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    local_9c = FLOAT_803e0fb0 * *(float *)(param_3 + 4);
    local_d0 = 0x14;
    local_96 = param_3[3];
    local_78 = '0';
    local_94 = (code *)0x80104;
    local_90 = 0x880;
    break;
  case 0x7db:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    local_9c = FLOAT_803e0fb0 * *(float *)(param_3 + 4);
    local_d0 = 0x14;
    local_96 = param_3[3];
    local_78 = '0';
    local_94 = (code *)0x80104;
    local_90 = 0x4000880;
    break;
  case 0x7dc:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e10ac * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e10ac * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e10ac * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(5,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_70 = (double)CONCAT44(0x43300000,(int)(short)param_3[2] ^ 0x80000000);
      local_9c = ((float)(local_70 - DOUBLE_803e1150) / FLOAT_803e10c4) *
                 FLOAT_803e0fbc * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x28);
      local_d0 = (int)(short)param_3[1] + local_d0;
      uVar4 = FUN_80022264(0x20,0x40);
      local_78 = (char)*param_3 + (char)uVar4;
      local_96 = 0x605;
      local_94 = (code *)0x80104;
      local_90 = 0x8a0;
      uVar2 = param_3[3];
      if (uVar2 == 0xe0) {
        local_80 = 0;
        local_7e = 0;
        local_7c = 0xffff;
        local_8c = 0x656a;
        local_88 = 0;
        local_84 = 0xffff;
      }
      else if ((short)uVar2 < 0xe0) {
        if (uVar2 == 0xdd) {
          local_80 = 40000;
          local_7e = 0;
          local_7c = 0;
          local_8c = 0xffff;
          local_88 = 0x7ffd;
          local_84 = 0x4000;
        }
        else if ((short)uVar2 < 0xdd) {
          if (uVar2 != 0x7b) goto LAB_800d2360;
          local_80 = 0;
          local_7e = 0x7fff;
          local_7c = 0xffff;
          local_8c = FUN_80022264(0x4b0,32000);
          local_88 = 0xffff;
          local_84 = 0xffff;
        }
        else if ((short)uVar2 < 0xdf) {
          local_80 = 0xffff;
          local_7e = 0x7fff;
          local_7c = 0;
          local_8c = 0xffff;
          local_88 = 0xffff;
          local_84 = 5000;
        }
        else {
          local_80 = 0;
          local_7e = 0;
          local_7c = 0xffff;
          local_8c = 12000;
          local_88 = FUN_80022264(0x4b0,32000);
          local_84 = 0xffff;
        }
      }
      else if (uVar2 == 0x160) {
        local_80 = 0;
        local_7e = 0xffff;
        local_7c = 0;
        local_8c = 0x656a;
        local_88 = 0xffff;
        local_84 = 5000;
      }
      else if ((short)uVar2 < 0x160) {
        if (uVar2 == 0xe4) {
          local_80 = 40000;
          local_7e = 40000;
          local_7c = 0xffff;
          local_8c = 0xffff;
          local_88 = 0xffff;
          local_84 = 0xffff;
        }
        else {
LAB_800d2360:
          local_80 = 0;
          local_7e = 0;
          local_7c = 0xffff;
          local_8c = 0x656a;
          local_88 = 0;
          local_84 = 0xffff;
        }
      }
      else {
        if (uVar2 != 0x200) goto LAB_800d2360;
        local_80 = 0xffff;
        local_7e = 0;
        local_7c = 0;
        local_8c = 0xffff;
        local_88 = 0x7fff;
        local_84 = 5000;
      }
    }
    break;
  case 0x7dd:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e1028 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e1028 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e1028 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      local_9c = FLOAT_803e0fcc * *(float *)(param_3 + 4);
      local_d0 = FUN_80022264(0x1e,0x6e);
      local_78 = -1;
      local_94 = (code *)0x3000000;
      local_90 = 0x780880;
      local_96 = param_3[3];
    }
    break;
  case 0x7de:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fc0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0fb4 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e0fc0 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      local_9c = FLOAT_803e10c8 * *(float *)(param_3 + 4);
      uVar4 = FUN_80022264(0x19,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_d0 = (uint)(local_b0 * (float)(local_68 - DOUBLE_803e1150));
      local_70 = (double)(longlong)(int)local_d0;
      local_94 = (code *)0x1482000;
      local_90 = 0x8400880;
      local_96 = param_3[3];
    }
    break;
  case 0x7df:
    if (param_3 != (ushort *)0x0) {
      local_ac = *(float *)(param_3 + 4);
      FUN_80021b8c(param_3,&local_b4);
      local_a8 = local_a8 + local_b4;
      local_a0 = local_a0 + local_ac;
      local_b4 = FLOAT_803e0fa4;
      uStack_4c = FUN_80022264(0x32,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 4) *
                 FLOAT_803e10cc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0x4b,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_ac = *(float *)(param_3 + 4) * FLOAT_803e0f90 * (float)(local_58 - DOUBLE_803e1150);
      FUN_80021b8c(param_3,&local_b4);
      local_9c = FLOAT_803e0fcc;
      uStack_5c = FUN_80022264(0x32,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_d0 = (uint)(local_b0 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150)
                       );
      local_68 = (double)(longlong)(int)local_d0;
      local_78 = '\x7f';
      local_94 = (code *)0x3000000;
      local_90 = 0x1600080;
      local_96 = 0xc10;
    }
    break;
  case 0x7e0:
    uStack_4c = FUN_80022264(0xffffff9c,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e10d0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0xffffff9c,100);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_ac = FLOAT_803e10d4 * (float)(local_58 - DOUBLE_803e1150);
    local_9c = FLOAT_803e1088;
    local_d0 = FUN_80022264(0x28,0x32);
    local_96 = 0xc10;
    local_78 = 'Z';
    local_94 = (code *)0xa100000;
    local_90 = 0x400000;
    break;
  case 0x7e1:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e1030 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0fcc * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e1030 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_9c = FLOAT_803e10ac;
      uVar4 = FUN_80022264(0x32,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_d0 = (uint)(local_b0 * (float)(local_68 - DOUBLE_803e1150));
      local_70 = (double)(longlong)(int)local_d0;
      local_78 = '\x7f';
      local_94 = (code *)0x1080000;
      local_90 = 0x5400080;
      local_96 = 0xc10;
    }
    break;
  case 0x7e2:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffffd8,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e1064 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(10,0x50);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = FLOAT_803e0fec * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffffd8,0x28);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e1064 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xf,0x1e);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e0fbc * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x122,0x15e);
      local_78 = -1;
      local_94 = (code *)0x86000008;
      local_90 = 0x1000000;
      local_96 = param_3[3];
      if (param_3[1] == 1) {
        uVar4 = FUN_80022264(0x63bf,0xffff);
        local_8c = uVar4 & 0xffff;
        local_80 = (ushort)uVar4;
        uVar4 = FUN_80022264(0x3caf,0xd8ef);
        local_88 = uVar4 & 0xffff;
        local_7e = (ushort)uVar4;
        uVar4 = FUN_80022264(0x159f,0x3caf);
        local_84 = uVar4 & 0xffff;
        local_7c = (ushort)uVar4;
        local_90 = local_90 | 0x20;
      }
      else if (param_3[1] == 2) {
        uVar4 = FUN_80022264(0x3caf,0x7fff);
        local_8c = uVar4 & 0xffff;
        local_80 = (ushort)uVar4;
        uVar4 = FUN_80022264(0x7fff,0xffff);
        local_88 = uVar4 & 0xffff;
        local_7e = (ushort)uVar4;
        uVar4 = FUN_80022264(0x159f,0x3caf);
        local_84 = uVar4 & 0xffff;
        local_7c = (ushort)uVar4;
        local_90 = local_90 | 0x20;
      }
      if (param_3[2] != 0) {
        local_94 = (code *)((uint)local_94 | 0x800000);
        local_78 = 'A';
      }
      uVar4 = FUN_80022264(0,0xffff);
      local_cc = (ushort)uVar4;
      uVar4 = FUN_80022264(0,0xffff);
      local_ca = (ushort)uVar4;
      uVar4 = FUN_80022264(0,0xffff);
      local_cc = (ushort)uVar4;
      uStack_4c = FUN_80022264(0xe6,800);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_c0 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xe6,800);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_bc = (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xe6,800);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_b8 = (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    }
    break;
  case 0x7e3:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffffd8,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e1064 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(10,0x50);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = FLOAT_803e10d8 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffffd8,0x28);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e1064 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(10,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e0fbc * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x122,0x15e);
      local_78 = -1;
      local_94 = (code *)0x80008;
      local_90 = 0x5000000;
      local_96 = 0xc10;
    }
    break;
  case 0x7e4:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffffd8,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e1064 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(10,0x50);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = FLOAT_803e0fec * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffffd8,0x28);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e1064 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(5,10);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e10dc * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x122,0x15e);
      local_78 = -1;
      local_94 = (code *)0x80008;
      local_90 = 0x5000100;
      local_96 = param_3[3];
    }
    break;
  case 0x7e5:
    if (param_6 != (float *)0x0) {
      local_b4 = *param_6;
      local_b0 = param_6[1];
      local_ac = param_6[2];
    }
    uStack_4c = FUN_80022264(0x44,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e0fbc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    local_d0 = FUN_80022264(100,0x82);
    local_96 = 0xc10;
    uVar4 = FUN_80022264(0x28,0x2c);
    local_78 = (char)uVar4;
    local_94 = (code *)0x180100;
    local_90 = 0x5080800;
    break;
  case 0x7e6:
    if (param_3 != (ushort *)0x0) {
      if (param_6 == (float *)0x0) {
      }
      else {
        local_b4 = *param_6;
        local_b0 = param_6[1];
        local_ac = param_6[2];
      }
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fcc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150)
                 + local_b4;
      uVar4 = FUN_80022264(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0fec * (float)(local_58 - DOUBLE_803e1150) +
                 local_b0;
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e0fcc * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150)
                 + local_ac;
      uVar4 = FUN_80022264(0x44,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = (float)((double)*(float *)(param_3 + 4) *
                        DOUBLE_803e10e0 * (double)(float)(local_68 - DOUBLE_803e1150));
      local_d0 = FUN_80022264(0x2d,0x5f);
      local_96 = 0xc10;
      local_94 = (code *)0x180100;
      local_90 = 0x5080000;
      if (*param_3 == 3) {
        uVar4 = FUN_80022264(0x26,0x2b);
        local_78 = (char)uVar4;
        local_90 = local_90 | 0x800;
      }
      else {
        uVar4 = FUN_80022264(0x26,0x2b);
        local_78 = (char)uVar4;
      }
    }
    break;
  case 0x7e7:
    uStack_4c = FUN_80022264(0xffffff9c,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e1078 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0,100);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_b0 = FLOAT_803e107c * (float)(local_58 - DOUBLE_803e1150);
    uStack_5c = FUN_80022264(0xffffff9c,100);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e1080 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0xf,0x14);
    local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_9c = FLOAT_803e1084 * (float)(local_68 - DOUBLE_803e1150);
    local_d0 = FUN_80022264(0x96,300);
    local_96 = 0xc10;
    local_94 = (code *)0x8000100;
    local_90 = 0x820;
    local_80 = 0;
    local_7e = 0xffff;
    local_7c = 0;
    local_8c = 0;
    local_88 = 0xffff;
    local_84 = 0x4000;
    local_78 = '@';
    break;
  case 0x7e8:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    local_9c = FLOAT_803e0fb0 * *(float *)(param_3 + 4);
    local_d0 = 10;
    local_96 = param_3[3];
    local_78 = '@';
    local_94 = (code *)0x80100;
    local_90 = 0x800;
    break;
  case 0x7e9:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    local_9c = FLOAT_803e0fb0 * *(float *)(param_3 + 4);
    local_d0 = 0x14;
    local_96 = param_3[3];
    local_78 = '0';
    local_94 = (code *)0x80100;
    local_90 = 0x800;
    break;
  case 0x7ea:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    local_9c = FLOAT_803e0fb0 * *(float *)(param_3 + 4);
    local_d0 = 0x14;
    local_96 = param_3[3];
    local_78 = '0';
    local_94 = (code *)0x80100;
    local_90 = 0x4000800;
    break;
  case 0x7eb:
    if (param_3 != (ushort *)0x0) {
      if (param_6 != (float *)0x0) {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
      }
      uVar4 = FUN_80022264(0,4);
      if (uVar4 == 0) {
        uStack_4c = FUN_80022264(0x1c,0x22);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = *(float *)(param_3 + 4) *
                   FLOAT_803e10ac *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        local_94 = (code *)0x80000;
        local_90 = 0x8000820;
      }
      else {
        uStack_4c = FUN_80022264(100,0x6b);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_b0 = *(float *)(param_3 + 6) *
                   *(float *)(param_3 + 4) *
                   FLOAT_803e1044 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        uVar4 = FUN_80022264(0x1c,0x22);
        local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        local_9c = *(float *)(param_3 + 4) * FLOAT_803e1048 * (float)(local_58 - DOUBLE_803e1150);
        local_94 = (code *)0x80080000;
        local_90 = 0x8002820;
      }
      local_78 = -1;
      local_d0 = FUN_80022264(0x14,0x1b);
      local_80 = 2000;
      local_7e = 2000;
      local_7c = 0x7fff;
      local_8c = 7000;
      local_88 = 0x7fff;
      local_84 = 0xffff;
      local_96 = param_3[3];
    }
    break;
  case 0x7ec:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0x1e,0x46);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e0fbc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x1e,0x28);
      uVar4 = FUN_80022264(0x40,0x7f);
      local_78 = (char)uVar4;
      local_96 = 0x605;
      local_94 = FUN_80080100;
      local_90 = 0x28a0;
      local_80 = 0;
      local_7e = 0x7fff;
      local_7c = 0xffff;
      local_8c = FUN_80022264(40000,0xffff);
      local_88 = FUN_80022264(0x4b0,32000);
      local_84 = 0xffff;
    }
    break;
  case 0x7ed:
    local_a4 = FLOAT_803e10e8;
    local_b0 = FLOAT_803e10a4;
    uStack_4c = FUN_80022264(0x50,0x58);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e1030 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    local_d0 = FUN_80022264(0x50,0x5a);
    local_96 = 0x7b;
    local_80 = 0xfaab;
    local_7e = 0xa9f;
    local_7c = 0x1d3;
    local_8c = 0x7fff;
    local_88 = 0x7fff;
    local_84 = 0xff4b;
    local_78 = ',';
    local_94 = (code *)0x200c0004;
    local_90 = 0x420820;
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a8 = FLOAT_803e1028 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150)
                 + local_a8;
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a4 = FLOAT_803e1028 * (float)(local_58 - DOUBLE_803e1150) + local_a4;
      uStack_5c = FUN_80022264(0x5a,0x6e);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = FLOAT_803e0fd8 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_9c = FLOAT_803e0fdc;
      local_94 = (code *)((uint)local_94 | 0x400000);
    }
    break;
  case 0x7ee:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0x1e,0x46);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803e1030 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      local_94 = FUN_80080100;
      local_90 = 0x8a0;
      uVar4 = FUN_80022264(40000,0xffff);
      local_80 = (ushort)uVar4;
      uVar4 = FUN_80022264(0x4b0,32000);
      local_7e = (ushort)uVar4;
      local_7c = 0xffff;
      local_8c = 0;
      local_88 = 0x7fff;
      local_84 = 0xffff;
      local_d0 = FUN_80022264(0x1c,0x22);
      local_d0 = local_d0 + 0x14;
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      local_ac = FLOAT_803e0fa4;
      local_b0 = *(float *)(param_3 + 4);
      if (param_3[3] == 0) {
        local_b4 = FLOAT_803e10ec;
      }
      else {
        local_b4 = FLOAT_803e0ff4;
      }
      local_96 = 0x605;
    }
    break;
  case 0x7ef:
  case 0x801:
  case 0x808:
    local_a8 = *(float *)(param_3 + 6);
    local_a4 = *(float *)(param_3 + 8);
    local_a0 = *(float *)(param_3 + 10);
    uStack_4c = FUN_80022264(0xffffff9c,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e10f0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0x32,100);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_b0 = FLOAT_803e10f4 * (float)(local_58 - DOUBLE_803e1150);
    uStack_5c = FUN_80022264(0xffffff9c,100);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e10f8 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0x14,100);
    local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_9c = FLOAT_803e10fc * (float)(local_68 - DOUBLE_803e1150);
    if (iVar5 == 0x808) {
      local_9c = local_9c * FLOAT_803e0f94;
    }
    local_d0 = FUN_80022264(0x14,100);
    local_96 = 0xc10;
    local_80 = 0xffe4;
    local_7e = 0x15;
    local_7c = 0xc67b;
    local_8c = 0x1378;
    local_88 = 0xfec0;
    local_84 = 0x2d55;
    local_78 = -1;
    local_94 = (code *)0x80080200;
    if ((iVar5 == 0x7ef) || (iVar5 == 0x808)) {
      local_94 = (code *)0x80280201;
    }
    local_90 = 0x4080820;
    break;
  case 0x7f0:
    uStack_4c = FUN_80022264(0x32,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e1100 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    local_b0 = FLOAT_803e108c;
    local_9c = FLOAT_803e1104;
    local_d0 = 0x73;
    local_96 = 0x632;
    local_80 = 0;
    local_7e = 0;
    local_7c = 0xffff;
    local_8c = 0xffff;
    local_88 = 0xffff;
    local_84 = 0xffff;
    local_78 = -1;
    local_94 = (code *)0x40180140;
    local_90 = 0x820;
    break;
  case 0x7f1:
    uStack_4c = FUN_80022264(8,10);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_b0 = FLOAT_803e1000 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    local_a4 = FLOAT_803e1108;
    uVar4 = FUN_80022264(6,0xc);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_9c = FLOAT_803e10a0 * (float)(local_58 - DOUBLE_803e1150);
    local_d0 = FUN_80022264(0x3c,0x5a);
    local_94 = (code *)0x80180000;
    local_90 = 0x5440820;
    local_96 = 0xc0b;
    local_78 = '@';
    local_80 = 0;
    local_7e = 0xffff;
    local_7c = 0xffff;
    local_8c = 0xffff;
    local_88 = 0;
    local_84 = 0xffff;
    break;
  case 0x7f2:
    local_a4 = FLOAT_803e110c;
    uStack_4c = FUN_80022264(0xffffff9c,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e0fc0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0xffffff9c,100);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_b0 = FLOAT_803e0fe8 * (float)(local_58 - DOUBLE_803e1150);
    uStack_5c = FUN_80022264(0xffffff9c,100);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e0fc0 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    local_9c = FLOAT_803e1110;
    local_d0 = FUN_80022264(0xc,0x3d);
    local_96 = 0x605;
    local_80 = 0xffcc;
    local_7e = 0x23a8;
    local_7c = 0x325f;
    local_8c = 0xfec1;
    local_88 = 0x130c;
    local_84 = 0xacf;
    local_78 = -0x80;
    local_94 = (code *)0x80100;
    local_90 = 0x80820;
    break;
  case 0x7f3:
    if (param_3 != (ushort *)0x0) {
      local_d0 = 0x37;
      local_96 = 0xc86;
      local_78 = -0xd;
      local_94 = (code *)0x80100;
      local_90 = 0x828;
      if (param_3[3] == 0) {
        uStack_4c = FUN_80022264(10,0x14);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e0fe8 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        local_a4 = FLOAT_803e110c;
        local_80 = 0xffcc;
        local_7e = 0x23a8;
        local_7c = 0x325f;
        local_8c = 0xfec1;
        local_88 = 0x130c;
        local_84 = 0xacf;
      }
      if (param_3[3] == 1) {
        uStack_4c = FUN_80022264(10,0x14);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e108c *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        local_a4 = FLOAT_803e1114;
        local_80 = 0x23a8;
        local_7e = 0xffcc;
        local_7c = 0x325f;
        local_8c = 0x130c;
        local_88 = 0xfec1;
        local_84 = 0xacf;
      }
      if (param_3[3] == 2) {
        uStack_4c = FUN_80022264(10,0x14);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e1118 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
        local_a4 = FLOAT_803e1114;
        local_80 = 0xffcc;
        local_7e = 0xffcc;
        local_7c = 0x325f;
        local_8c = 0xfec1;
        local_88 = 0xffcc;
        local_84 = 0xacf;
      }
    }
    break;
  case 0x7f4:
    local_a8 = *(float *)(param_3 + 6);
    local_a4 = *(float *)(param_3 + 8);
    local_a0 = *(float *)(param_3 + 10);
    local_b4 = *param_6;
    local_b0 = param_6[1];
    local_ac = param_6[2];
    uStack_4c = FUN_80022264(0x50,0x58);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e0fbc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    local_96 = 0x7b;
    local_d0 = 0x50;
    uVar2 = param_3[3];
    if ((uVar2 == 0) || (uVar2 == 3)) {
      local_80 = 65000;
      local_7e = 10000;
      local_7c = 10000;
      local_d0 = 0x55;
    }
    else if ((uVar2 == 1) || (uVar2 == 4)) {
      local_80 = 0;
      local_7e = 65000;
      local_7c = 0;
    }
    else if ((uVar2 == 2) || (uVar2 == 5)) {
      local_80 = 0;
      local_7e = 0;
      local_7c = 65000;
    }
    if ((short)param_3[3] < 3) {
      local_8c = (uint)local_80;
      local_88 = (uint)local_7e;
      local_84 = (uint)local_7c;
    }
    else {
      local_8c = 65000;
      local_88 = 65000;
      local_84 = 0;
      local_d0 = 0x5a;
    }
    local_78 = ',';
    local_94 = (code *)0x80002;
    local_90 = 0x420820;
    break;
  case 0x7f5:
    if (param_3 != (ushort *)0x0) {
      if (param_3[3] == 0) {
        local_9c = FLOAT_803e0fb0 * *(float *)(param_3 + 4);
        local_94 = (code *)0x81180000;
        local_90 = 0x8400800;
        local_d0 = FUN_80022264(0x14,0x1a);
        local_d0 = local_d0 + 10;
      }
      else {
        local_9c = FLOAT_803e111c * FLOAT_803e0f9c * *(float *)(param_3 + 4);
        local_94 = (code *)0x81080000;
        local_90 = 0x4400800;
        local_d0 = 10;
      }
      uStack_4c = FUN_80022264(100,0x96);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = FLOAT_803e0f94 *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e1120 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      FUN_80021b8c(puVar3,&local_b4);
      local_96 = 0x5f5;
      local_78 = -0x80;
    }
    break;
  default:
    goto LAB_800d5660;
  case 0x7f7:
    if (param_3 != (ushort *)0x0) {
      local_a4 = *(float *)(param_3 + 8);
      uStack_4c = FUN_80022264(200,300);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fd0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0x37,0x41);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e10ac * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0x1e,0x28);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_d0 = (uint)(*(float *)(param_3 + 4) *
                       (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150));
      local_68 = (double)(longlong)(int)local_d0;
      local_96 = 0xc10;
      local_78 = ' ';
      local_94 = (code *)0xc0080100;
      local_90 = 0x4000800;
    }
    break;
  case 0x7f9:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fcc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e1064 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e1124 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_9c = FLOAT_803e0fb0 * *(float *)(param_3 + 4);
      local_d0 = FUN_80022264(0x3c,0x4b);
      local_96 = 0xc73;
      local_80 = 5000;
      uVar4 = FUN_80022264(0,10000);
      local_7e = (short)uVar4 + 10000;
      uVar4 = FUN_80022264(0,10000);
      local_7c = (short)uVar4 + 20000;
      local_8c = 0;
      local_88 = FUN_80022264(0,10000);
      local_84 = FUN_80022264(0,10000);
      local_84 = local_84 + 20000;
      local_78 = -1;
      local_94 = (code *)0x1080004;
      local_90 = 0x800a020;
    }
    break;
  case 0x7fa:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fcc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e1064 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e1128 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(10,0x1e);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e108c * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x32,0x50);
      local_96 = 0xc10;
      local_80 = 0xffcf;
      local_7e = 0xf987;
      local_7c = 0xfff8;
      local_8c = 0x7a;
      local_88 = 0x57d2;
      local_84 = 0xffee;
      uVar4 = FUN_80022264(0x7b,0xff);
      local_78 = (char)uVar4;
      local_94 = (code *)0x40080204;
      local_90 = 0x4080820;
    }
    break;
  case 0x7fb:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e112c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0x32,0x96);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e112c * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e112c * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      local_9c = FLOAT_803e0fb0 * *(float *)(param_3 + 4);
      local_d0 = FUN_80022264(0x28,0x41);
      local_96 = 0xc73;
      local_80 = 5000;
      uVar4 = FUN_80022264(0,10000);
      local_7e = (short)uVar4 + 10000;
      uVar4 = FUN_80022264(0,10000);
      local_7c = (short)uVar4 + 20000;
      local_8c = 0;
      local_88 = FUN_80022264(0,10000);
      local_84 = FUN_80022264(0,10000);
      local_84 = local_84 + 20000;
      local_78 = -1;
      local_94 = (code *)0x1080000;
      local_90 = 0x800a020;
    }
    break;
  case 0x7fc:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fcc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e1064 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e0fcc * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(10,0x1e);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0f90 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x32,0x50);
      local_96 = 0xc10;
      local_80 = 0xffcf;
      local_7e = 0xf987;
      local_7c = 0xfff8;
      local_8c = 0x7a;
      local_88 = 0x57d2;
      local_84 = 0xffee;
      uVar4 = FUN_80022264(0x40,0x7f);
      local_78 = (char)uVar4;
      local_94 = (code *)0x40080200;
      local_90 = 0x4000820;
    }
    break;
  case 0x7fd:
    uStack_4c = FUN_80022264(0,4);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_a8 = FLOAT_803e1068 - (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0,4);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_a4 = FLOAT_803e1068 - (float)(local_58 - DOUBLE_803e1150);
    uStack_5c = FUN_80022264(0,4);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_a0 = FLOAT_803e1068 - (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    local_9c = FLOAT_803e112c;
    local_d0 = FUN_80022264(8,0xe);
    local_94 = (code *)0x110100;
    local_90 = 0x4000000;
    local_96 = 0xdf;
    break;
  case 0x7fe:
    uStack_4c = FUN_80022264(100,200);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e1130 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    local_d0 = FUN_80022264(0x43,100);
    local_96 = 0xc10;
    local_80 = 0x7fff;
    local_7e = 0x7fff;
    local_7c = 0x7fff;
    local_8c = 0x65a7;
    local_88 = 0x433a;
    local_84 = 0x1855;
    local_78 = -1;
    local_94 = (code *)0x80180200;
    local_90 = 0x5000020;
    break;
  case 0x7ff:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e1038 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0fb0 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e1038 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0x19,100);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e1134 * *(float *)(param_3 + 4) * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(0x28,0xa5);
      local_96 = 0xc73;
      local_80 = 15000;
      uVar4 = FUN_80022264(0,10000);
      local_7e = (short)uVar4 + 20000;
      uVar4 = FUN_80022264(0,10000);
      local_7c = (short)uVar4 + 30000;
      local_8c = 10000;
      local_88 = FUN_80022264(10000,20000);
      local_84 = FUN_80022264(0,10000);
      local_84 = local_84 + 30000;
      local_78 = -1;
      local_94 = (code *)0x1080000;
      local_90 = 0x800a020;
    }
    break;
  case 0x800:
    if (param_3 != (ushort *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e0fcc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e1064 * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e0fcc * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(10,0x1e);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e1138 * (float)(local_68 - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0,1);
      local_d0 = FUN_80022264(0x32,0xb4);
      local_d0 = local_d0 + uVar4 * 100;
      local_96 = 0xc10;
      local_80 = 0xffcf;
      local_7e = 0xf987;
      local_7c = 0xfff8;
      local_8c = 0x7a;
      local_88 = 0x57d2;
      local_84 = 0xffee;
      uVar4 = FUN_80022264(0x40,0x7f);
      local_78 = (char)uVar4;
      local_94 = (code *)0x40080200;
      local_90 = 0x4000820;
    }
    break;
  case 0x802:
    uStack_4c = FUN_80022264(0xffffff9c,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e112c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0x28,100);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_b0 = FLOAT_803e0fd0 * (float)(local_58 - DOUBLE_803e1150);
    uStack_5c = FUN_80022264(0xffffff9c,100);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e112c * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(4,10);
    local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_9c = FLOAT_803e1138 * (float)(local_68 - DOUBLE_803e1150);
    local_d0 = FUN_80022264(0x19,0x23);
    local_96 = 0xc10;
    local_80 = 0xffff;
    local_7e = 0xffff;
    local_7c = 50000;
    local_8c = 0xffff;
    local_88 = 54000;
    local_84 = 0x7fff;
    uVar4 = FUN_80022264(0x54,0x7a);
    local_78 = (char)uVar4;
    local_94 = (code *)0x1080200;
    local_90 = 0x5000020;
    break;
  case 0x803:
    uStack_4c = FUN_80022264(0xffffff9c,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e113c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0xffffffb5,100);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_b0 = FLOAT_803e113c * (float)(local_58 - DOUBLE_803e1150);
    local_9c = FLOAT_803e0fec;
    local_d0 = 0x32;
    local_80 = 2000;
    local_7e = 2000;
    uVar4 = FUN_80022264(0xffffec78,5000);
    local_7c = (short)uVar4 + 10000;
    local_8c = 8000;
    local_88 = 8000;
    local_84 = FUN_80022264(0xffffec78,5000);
    local_84 = local_84 + 12000;
    local_96 = 0x639;
    local_78 = -1;
    local_94 = (code *)0x1080004;
    local_90 = 0x408028;
    break;
  case 0x804:
    if (param_3 != (ushort *)0x0) {
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e10ac * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e10ac * (float)(local_58 - DOUBLE_803e1150);
      uStack_5c = FUN_80022264(0xffffff9c,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e10ac * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
      uVar4 = FUN_80022264(10,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803e10b0 * (float)(local_68 - DOUBLE_803e1150);
      local_d0 = FUN_80022264(1,0x28);
      local_d0 = (int)(short)param_3[1] + local_d0;
      local_96 = 0xdf;
      local_78 = -1;
      local_94 = (code *)0x480100;
      local_90 = 0x8000000;
    }
    break;
  case 0x805:
    uStack_4c = FUN_80022264(0x50,0x58);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e1134 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    local_d0 = FUN_80022264(100,0x6e);
    local_96 = 0x7b;
    if (param_3[1] == 0) {
      local_80 = 20000;
      local_7e = 20000;
      local_7c = 0xffff;
      local_8c = 20000;
      local_88 = 10000;
      local_84 = 0xffff;
    }
    else {
      local_80 = 0xffff;
      local_7e = 50000;
      local_7c = 0;
      local_8c = 0xffff;
      local_88 = 50000;
      local_84 = 0;
    }
    local_78 = ',';
    local_94 = (code *)0x80004;
    local_90 = 0x420820;
    local_b4 = *param_6;
    local_b0 = param_6[1];
    local_ac = param_6[2];
    break;
  case 0x806:
    local_a0 = FLOAT_803e1108;
    FUN_80021b8c(puVar3,&local_a8);
    local_b0 = FLOAT_803e1140;
    uStack_4c = FUN_80022264(0x50,0x5f);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e0fa8 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    local_d0 = 0xfa;
    local_96 = 0x7b;
    local_80 = 0xfaab;
    local_7e = 0xa9f;
    local_7c = 0x1d3;
    local_8c = 0x7fff;
    local_88 = 0x7fff;
    local_84 = 0xff4b;
    uVar4 = FUN_80022264(0x32,0x36);
    local_78 = (char)uVar4;
    local_94 = (code *)0x80000;
    local_90 = 0x4000820;
    break;
  case 0x807:
    local_a0 = FLOAT_803e1108;
    FUN_80021b8c(puVar3,&local_a8);
    local_b0 = FLOAT_803e1144;
    uStack_4c = FUN_80022264(0x50,0x5f);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e0fa8 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    local_d0 = 0xfa;
    local_96 = 0x7b;
    local_80 = 2000;
    local_7e = 2000;
    local_7c = 0xfaab;
    local_8c = 0x7fff;
    local_88 = 0x7fff;
    local_84 = 0xff4b;
    uVar4 = FUN_80022264(0x32,0x36);
    local_78 = (char)uVar4;
    local_94 = (code *)0x80000;
    local_90 = 0x4000820;
    break;
  case 0x809:
    uStack_4c = FUN_80022264(0xffffff9c,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e112c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0x28,100);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_b0 = FLOAT_803e0fb0 * (float)(local_58 - DOUBLE_803e1150);
    uStack_5c = FUN_80022264(0xffffff9c,100);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e112c * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(4,10);
    local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_9c = FLOAT_803e0fec * (float)(local_68 - DOUBLE_803e1150);
    local_d0 = FUN_80022264(0x19,0x23);
    local_96 = 0xc10;
    local_80 = 0xffff;
    local_7e = 0xffff;
    local_7c = 50000;
    local_8c = 0xffff;
    local_88 = 58000;
    local_84 = 38000;
    uVar4 = FUN_80022264(0xb8,0xde);
    local_78 = (char)uVar4;
    local_94 = (code *)0x1080200;
    local_90 = 0x5000020;
    break;
  case 0x80a:
    uStack_4c = FUN_80022264(0xffffff9c,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e112c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0x28,100);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_b0 = FLOAT_803e112c * (float)(local_58 - DOUBLE_803e1150);
    uStack_5c = FUN_80022264(0xffffff9c,100);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e112c * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(4,10);
    local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_9c = FLOAT_803e0fec * (float)(local_68 - DOUBLE_803e1150);
    local_d0 = FUN_80022264(0x19,0x23);
    local_96 = 0xc10;
    uVar4 = FUN_80022264(0x40,0x7f);
    local_78 = (char)uVar4;
    local_94 = (code *)0x80010;
    local_90 = 0x4400800;
    break;
  case 0x80b:
    uStack_4c = FUN_80022264(0xffffff9c,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e0fb0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(0x28,100);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_b0 = FLOAT_803e0fb0 * (float)(local_58 - DOUBLE_803e1150);
    uStack_5c = FUN_80022264(0xffffff9c,100);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e0fb0 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e1150);
    uVar4 = FUN_80022264(4,10);
    local_68 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_9c = FLOAT_803e1030 * (float)(local_68 - DOUBLE_803e1150);
    local_d0 = FUN_80022264(0x19,0x23);
    local_96 = 0xc10;
    local_78 = -1;
    local_94 = (code *)0x3000000;
    local_90 = 0x600820;
    local_80 = 0xffff;
    uVar4 = FUN_80022264(0x7fff,0xffff);
    local_88 = uVar4 & 0xffff;
    local_7e = (ushort)uVar4;
    local_7c = 0xffff;
    local_8c = (uint)local_80;
    local_84 = 0xffff;
    break;
  case 0x80c:
    if (param_3 != (ushort *)0x0) {
      local_b4 = *(float *)(param_3 + 6);
      local_b0 = *(float *)(param_3 + 8);
      local_ac = *(float *)(param_3 + 10);
    }
    uStack_4c = FUN_80022264(0xfffffff0,0x10);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_a0 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1150);
    local_a4 = FLOAT_803e1148;
    uVar4 = FUN_80022264(4,8);
    local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
    local_9c = FLOAT_803e0f90 * (float)(local_58 - DOUBLE_803e1150);
    local_d0 = FUN_80022264(0xf,0x14);
    local_96 = 0xc10;
    uVar4 = FUN_80022264(0x20,0x40);
    local_78 = (char)uVar4;
    local_94 = (code *)0x1080010;
    local_90 = 0x4400800;
  }
  local_94 = (code *)((uint)local_94 | param_4);
  if ((((uint)local_94 & 1) != 0) && (((uint)local_94 & 2) != 0)) {
    local_94 = (code *)((uint)local_94 ^ 2);
  }
  if (((uint)local_94 & 1) != 0) {
    if ((param_4 & 0x200000) == 0) {
      if (local_d8 != (ushort *)0x0) {
        local_a8 = local_a8 + *(float *)(local_d8 + 0xc);
        local_a4 = local_a4 + *(float *)(local_d8 + 0xe);
        local_a0 = local_a0 + *(float *)(local_d8 + 0x10);
      }
    }
    else {
      local_a8 = local_a8 + local_c0;
      local_a4 = local_a4 + local_bc;
      local_a0 = local_a0 + local_b8;
    }
  }
  (**(code **)(*DAT_803dd6f8 + 8))(&local_d8,0xffffffff,iVar5,uVar6);
LAB_800d5660:
  FUN_80286880();
  return;
}

