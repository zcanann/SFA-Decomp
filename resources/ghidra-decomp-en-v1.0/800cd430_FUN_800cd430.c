// Function: FUN_800cd430
// Entry: 800cd430
// Size: 32716 bytes

/* WARNING: Removing unreachable block (ram,0x800d53d4) */
/* WARNING: Removing unreachable block (ram,0x800d53dc) */

void FUN_800cd430(undefined4 param_1,undefined4 param_2,short *param_3,uint param_4,
                 undefined param_5,float *param_6)

{
  short sVar3;
  int iVar1;
  uint uVar2;
  int iVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  double dVar7;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined8 uVar10;
  int local_d8;
  undefined4 local_d4;
  int local_d0;
  short local_cc;
  short local_ca;
  short local_c8;
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
  short local_96;
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
  double local_70;
  double local_68;
  undefined4 local_60;
  uint uStack92;
  double local_58;
  undefined4 local_50;
  uint uStack76;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar10 = FUN_802860d0();
  iVar1 = (int)((ulonglong)uVar10 >> 0x20);
  iVar4 = (int)uVar10;
  uVar5 = 0;
  FLOAT_803db880 = FLOAT_803db880 + FLOAT_803e0310;
  if (FLOAT_803e0318 < FLOAT_803db880) {
    FLOAT_803db880 = FLOAT_803e0314;
  }
  FLOAT_803db884 = FLOAT_803db884 + FLOAT_803e031c;
  if (FLOAT_803e0318 < FLOAT_803db884) {
    FLOAT_803db884 = FLOAT_803e0320;
  }
  if (iVar1 == 0) {
    uVar5 = 0xffffffff;
    goto LAB_800d53d4;
  }
  if ((param_4 & 0x200000) != 0) {
    if (param_3 == (short *)0x0) {
      uVar5 = 0xffffffff;
      goto LAB_800d53d4;
    }
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
  local_7a = (undefined)uVar10;
  local_a8 = FLOAT_803e0324;
  local_a4 = FLOAT_803e0324;
  local_a0 = FLOAT_803e0324;
  local_b4 = FLOAT_803e0324;
  local_b0 = FLOAT_803e0324;
  local_ac = FLOAT_803e0324;
  local_9c = FLOAT_803e0324;
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
  local_d8 = iVar1;
  switch(iVar4) {
  case 0x79e:
    if (param_6 != (float *)0x0) {
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b4 = FLOAT_803e0320 * *param_6 + FLOAT_803e0310 * (float)(local_70 - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = FLOAT_803e0320 * param_6[1] + FLOAT_803e0310 * (float)(local_68 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e0320 * param_6[2] +
                 FLOAT_803e0310 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
    }
    uStack92 = FUN_800221a0(0x32,100);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_9c = FLOAT_803e0328 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
    local_d0 = 100;
    local_94 = (code *)0x80480200;
    local_90 = 0x8000800;
    local_78 = -1;
    local_96 = 0x84;
    break;
  case 0x79f:
    uStack92 = FUN_800221a0(0x32,100);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_9c = FLOAT_803e0318;
    if (param_6 != (float *)0x0) {
      local_9c = *param_6;
    }
    local_9c = local_9c *
               FLOAT_803e0310 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
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
    if (param_3 == (short *)0x0) {
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_b4 = FLOAT_803e0330 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = FLOAT_803e0330 * (float)(local_68 - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_ac = FLOAT_803e0330 * (float)(local_70 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x14,0x28);
      local_94 = (code *)0x80010;
      local_90 = 0x8480800;
      uVar2 = FUN_800221a0(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e032c * (float)(local_58 - DOUBLE_803e04d0);
    }
    else {
      local_d0 = (int)param_3[3];
      local_94 = (code *)0x80080210;
      local_90 = 0x8000800;
      uStack92 = FUN_800221a0(0x32,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e032c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
    }
    local_78 = -1;
    local_96 = 0xdb;
    break;
  case 0x7a1:
    if (param_3 == (short *)0x0) {
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b4 = FLOAT_803e0334 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = FLOAT_803e0334 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_ac = FLOAT_803e0334 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x14,0x28);
      local_94 = (code *)0x80010;
      local_90 = 0x8480800;
      uVar2 = FUN_800221a0(0x32,100);
      local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e032c * (float)(local_70 - DOUBLE_803e04d0);
    }
    else {
      local_d0 = (int)param_3[3];
      local_94 = (code *)0x80080210;
      local_90 = 0x8000800;
      uVar2 = FUN_800221a0(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e032c * (float)(local_58 - DOUBLE_803e04d0);
    }
    local_78 = -1;
    local_96 = 0x157;
    break;
  case 0x7a2:
    if (param_6 != (float *)0x0) {
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b4 = FLOAT_803e0338 * *param_6 + FLOAT_803e0310 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = FLOAT_803e0338 * param_6[1] +
                 FLOAT_803e0310 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_ac = FLOAT_803e0338 * param_6[2] + FLOAT_803e0310 * (float)(local_68 - DOUBLE_803e04d0);
    }
    local_d0 = FUN_800221a0(10,0x1e);
    local_94 = (code *)0x480000;
    local_90 = 0x400800;
    uVar2 = FUN_800221a0(0x32,100);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_9c = FLOAT_803e033c * (float)(local_58 - DOUBLE_803e04d0);
    local_78 = -1;
    local_96 = 0xde;
    break;
  case 0x7a3:
    uVar2 = FUN_800221a0(0xffff8001,0x7fff);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    dVar8 = (double)((FLOAT_803e0344 * (float)(local_58 - DOUBLE_803e04d0)) / FLOAT_803e0348);
    dVar7 = (double)FUN_80294204(dVar8);
    uStack92 = FUN_800221a0(100,0x96);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_b4 = (float)((double)(FLOAT_803e0340 *
                               (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0)) *
                      dVar7);
    dVar7 = (double)FUN_80293e80(dVar8);
    uVar2 = FUN_800221a0(100,0x96);
    local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_b0 = (float)((double)(FLOAT_803e0340 * (float)(local_68 - DOUBLE_803e04d0)) * dVar7);
    local_ac = FLOAT_803e0324;
    local_d0 = FUN_800221a0(0x14,0x1e);
    local_94 = (code *)0x480000;
    local_90 = 0x480800;
    uVar2 = FUN_800221a0(0x32,100);
    local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_9c = FLOAT_803e033c * (float)(local_70 - DOUBLE_803e04d0);
    local_78 = -1;
    local_96 = 0xde;
    break;
  case 0x7a4:
    if (param_6 != (float *)0x0) {
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b4 = FLOAT_803e0338 * *param_6 + FLOAT_803e0310 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = FLOAT_803e0338 * param_6[1] +
                 FLOAT_803e0310 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_ac = FLOAT_803e0338 * param_6[2] + FLOAT_803e0310 * (float)(local_68 - DOUBLE_803e04d0);
    }
    local_d0 = FUN_800221a0(10,0x1e);
    local_94 = (code *)0x480000;
    local_90 = 0x400800;
    uVar2 = FUN_800221a0(0x32,100);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_9c = FLOAT_803e033c * (float)(local_58 - DOUBLE_803e04d0);
    local_78 = -1;
    local_96 = 0xc22;
    break;
  case 0x7a5:
    uVar2 = FUN_800221a0(0xffff8001,0x7fff);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    dVar8 = (double)((FLOAT_803e0344 * (float)(local_58 - DOUBLE_803e04d0)) / FLOAT_803e0348);
    dVar7 = (double)FUN_80294204(dVar8);
    uStack92 = FUN_800221a0(100,0x96);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_b4 = (float)((double)(FLOAT_803e0330 *
                               (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0)) *
                      dVar7);
    dVar7 = (double)FUN_80293e80(dVar8);
    uVar2 = FUN_800221a0(100,0x96);
    local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_b0 = (float)((double)(FLOAT_803e0330 * (float)(local_68 - DOUBLE_803e04d0)) * dVar7);
    local_ac = FLOAT_803e0324;
    local_d0 = FUN_800221a0(0x1e,0x28);
    local_94 = (code *)0x480000;
    local_90 = 0x480800;
    uVar2 = FUN_800221a0(0x32,100);
    local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_9c = FLOAT_803e033c * (float)(local_70 - DOUBLE_803e04d0);
    local_78 = -1;
    local_96 = 0xc22;
    break;
  case 0x7a6:
    if (param_3 == (short *)0x0) {
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b4 = FLOAT_803e0334 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = FLOAT_803e0334 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_ac = FLOAT_803e0334 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x14,0x28);
      local_94 = (code *)0x80010;
      local_90 = 0x8480800;
      uVar2 = FUN_800221a0(0x32,100);
      local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e032c * (float)(local_70 - DOUBLE_803e04d0);
    }
    else {
      local_d0 = (int)param_3[3];
      local_94 = (code *)0x80080210;
      local_90 = 0x8000800;
      uVar2 = FUN_800221a0(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e032c * (float)(local_58 - DOUBLE_803e04d0);
    }
    local_78 = -1;
    local_96 = 0xc7e;
    break;
  case 0x7a7:
    if (param_3 == (short *)0x0) {
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b4 = FLOAT_803e0334 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = FLOAT_803e0334 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_ac = FLOAT_803e0334 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x14,0x28);
      local_94 = (code *)0x80010;
      local_90 = 0x8480800;
      uVar2 = FUN_800221a0(0x32,100);
      local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e032c * (float)(local_70 - DOUBLE_803e04d0);
    }
    else {
      local_d0 = (int)param_3[3];
      local_94 = (code *)0x80080210;
      local_90 = 0x8000800;
      uVar2 = FUN_800221a0(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e032c * (float)(local_58 - DOUBLE_803e04d0);
    }
    local_78 = -1;
    local_96 = 0xc13;
    break;
  case 0x7a8:
    if (param_3 != (short *)0x0) {
      uVar2 = FUN_800221a0(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e034c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e0350 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a0 = *(float *)(param_3 + 4) * FLOAT_803e0350 * (float)(local_68 - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 10);
      uVar2 = FUN_800221a0(0x50,100);
      local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0354 * (float)(local_70 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x14);
      local_d0 = local_d0 + 10;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)(param_4 | 0x80200);
      local_90 = 0x4040800;
    }
    break;
  case 0x7a9:
    if (param_3 != (short *)0x0) {
      uVar2 = FUN_800221a0(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0358 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e0334 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a0 = *(float *)(param_3 + 4) * FLOAT_803e0334 * (float)(local_68 - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 10);
      uVar2 = FUN_800221a0(0x50,100);
      local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0354 * (float)(local_70 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x14);
      local_d0 = local_d0 + 10;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)(param_4 | 0x80200);
      local_90 = 0x4040800;
    }
    break;
  case 0x7aa:
    if (param_3 != (short *)0x0) {
      uVar2 = FUN_800221a0(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e035c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e0314 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a0 = *(float *)(param_3 + 4) * FLOAT_803e0314 * (float)(local_68 - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 10);
      uVar2 = FUN_800221a0(0x50,100);
      local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0360 * (float)(local_70 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x23);
      local_d0 = local_d0 + 0x19;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)(param_4 | 0x80200);
      local_90 = 0x4040820;
      local_8c = 0xffff;
      local_88 = 0xffff;
      local_84 = FUN_800221a0(0);
      local_80 = 0xffff;
      local_7e = FUN_800221a0(0,0x7fff);
      local_7c = (ushort)local_84;
    }
    break;
  case 0x7ab:
    if (param_3 != (short *)0x0) {
      uVar2 = FUN_800221a0(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0364 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e0368 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a0 = *(float *)(param_3 + 4) * FLOAT_803e0368 * (float)(local_68 - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 10);
      uVar2 = FUN_800221a0(0x23,100);
      local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0354 * (float)(local_70 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x12);
      local_d0 = local_d0 + 10;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)(param_4 | 0x80080200);
      local_90 = 0x4010800;
      uVar5 = 1;
    }
    break;
  case 0x7ac:
    if (param_3 != (short *)0x0) {
      uVar2 = FUN_800221a0(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0364 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e036c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a0 = *(float *)(param_3 + 4) * FLOAT_803e036c * (float)(local_68 - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 10);
      uVar2 = FUN_800221a0(0x50,100);
      local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0354 * (float)(local_70 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x17);
      local_d0 = local_d0 + 5;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)(param_4 | 0x80080200);
      local_90 = 0x40800;
    }
    break;
  case 0x7ad:
    if (param_3 != (short *)0x0) {
      uVar2 = FUN_800221a0(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0370 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xf,0x14);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a4 = *(float *)(param_3 + 4) *
                 (FLOAT_803e0374 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0)
                 + *(float *)(param_3 + 8));
      uVar2 = FUN_800221a0(0x50,0x8c);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0378 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0,10);
      local_d0 = local_d0 + 0x32;
      local_96 = 0xc10;
      local_78 = -1;
      local_94 = (code *)0x80100;
      local_90 = 0x4010020;
      local_8c = (uint)param_3[3];
      local_80 = (ushort)((int)local_8c >> 1);
      local_88 = local_8c;
      local_84 = local_8c;
      local_7e = local_80;
      local_7c = local_80;
    }
    break;
  case 0x7ae:
    if (param_3 != (short *)0x0) {
      uVar2 = FUN_800221a0(100,200);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e037c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e0380 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xf,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a4 = *(float *)(param_3 + 4) *
                 (FLOAT_803e0374 * (float)(local_68 - DOUBLE_803e04d0) + *(float *)(param_3 + 8));
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a0 = *(float *)(param_3 + 4) * FLOAT_803e0380 * (float)(local_70 - DOUBLE_803e04d0);
      uStack76 = FUN_800221a0(0x50,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e0384 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0,10);
      local_d0 = local_d0 + 0x32;
      local_96 = 0xc0d;
      local_78 = -1;
      local_94 = (code *)0x80480000;
      local_90 = 0x410800;
    }
    break;
  case 0x7af:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(100,200);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4);
      local_b0 = local_9c *
                 FLOAT_803e0388 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      local_a4 = (FLOAT_803e038c + *(float *)(param_3 + 8)) * local_9c;
      local_9c = FLOAT_803e0390 * local_9c;
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
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(100,200);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4);
      local_b0 = local_9c *
                 FLOAT_803e0388 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      local_a4 = (FLOAT_803e038c + *(float *)(param_3 + 8)) * local_9c;
      local_9c = FLOAT_803e0390 * local_9c;
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
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xffffffe5,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0394 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(10,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0398 * (float)(local_58 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x23,100);
      local_78 = -1;
      local_96 = param_3[3];
      local_94 = (code *)0x80480100;
      local_90 = 0x8010800;
    }
    break;
  case 0x7b2:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e0390 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_ac = FLOAT_803e0390 * (float)(local_58 - DOUBLE_803e04d0);
      local_a4 = *(float *)(param_3 + 6);
      uStack92 = FUN_800221a0(0x1c,0x20);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = FLOAT_803e039c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_d0 = (int)param_3[3];
      local_96 = *param_3;
      local_94 = (code *)0x480204;
      local_90 = 0x808;
    }
    break;
  case 0x7b3:
    if (param_3 != (short *)0x0) {
      local_9c = FLOAT_803e03a0 * *(float *)(param_3 + 4);
      local_d0 = (int)param_3[3];
      uStack76 = FUN_800221a0(0x154,0x2d5);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 8) *
                 (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      local_a4 = *(float *)(param_3 + 6);
      local_96 = *param_3;
      local_94 = (code *)0x80114;
      local_90 = 0x4000800;
    }
    break;
  case 0x7b4:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e0390 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_ac = FLOAT_803e0390 * (float)(local_58 - DOUBLE_803e04d0);
      local_a4 = *(float *)(param_3 + 6);
      uStack92 = FUN_800221a0(0x1c,0x20);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = FLOAT_803e039c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_d0 = (int)param_3[3];
      local_96 = *param_3;
      local_94 = (code *)0x480004;
      local_90 = 0x480800;
    }
    break;
  case 0x7b5:
    if (param_3 != (short *)0x0) {
      if (param_3[3] == 0) {
        local_9c = FLOAT_803e0330 * *(float *)(param_3 + 4);
        local_94 = (code *)0xc1180000;
        local_90 = 0x4400800;
        local_d0 = FUN_800221a0(0x1c,0x22);
        local_d0 = local_d0 + 10;
      }
      else {
        uStack76 = FUN_800221a0(6,10);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e031c * *(float *)(param_3 + 4) *
                   (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
        local_94 = (code *)0xc1080000;
        local_90 = 0x4400800;
        local_d0 = 10;
      }
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uStack76 = FUN_800221a0(100,0x96);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_ac = FLOAT_803e0314 *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e03a4 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      FUN_80021ac8(iVar1,&local_b4);
      local_96 = 0xc0a;
      local_90 = local_90 | 0x20;
      local_8c = 0xffff;
      local_88 = 0xffff;
      local_84 = FUN_800221a0(0);
      local_80 = 0xffff;
      local_7e = FUN_800221a0(0,0x7fff);
      local_7c = (ushort)local_84;
    }
    break;
  case 0x7b6:
    if (param_3 != (short *)0x0) {
      if (param_3[3] == 0) {
        local_9c = FLOAT_803e0330 * *(float *)(param_3 + 4);
        local_94 = (code *)0x81180000;
        local_90 = 0x4400800;
        local_d0 = FUN_800221a0(0x1c,0x22);
        local_d0 = local_d0 + 10;
      }
      else {
        uStack76 = FUN_800221a0(6,10);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e031c * *(float *)(param_3 + 4) *
                   (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
        local_94 = (code *)0x81080000;
        local_90 = 0x4400800;
        local_d0 = 10;
      }
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(100,0x96);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_ac = FLOAT_803e0314 *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e03a4 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      FUN_80021ac8(iVar1,&local_b4);
      local_96 = 0x5f5;
    }
    break;
  case 0x7b7:
    if (param_3 != (short *)0x0) {
      if (param_6 == (float *)0x0) {
        uStack76 = FUN_800221a0(0x5a,100);
        uStack76 = uStack76 ^ 0x80000000;
        local_b0 = *(float *)(param_3 + 4) *
                   FLOAT_803e03a8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
      }
      else {
        uStack76 = FUN_800221a0(0xffffff9c,100);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_b4 = FLOAT_803e0320 * *param_6 +
                   FLOAT_803e0310 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
        if (FLOAT_803e0324 != local_b0) {
          uStack76 = FUN_800221a0(0xffffff9c,100);
          uStack76 = uStack76 ^ 0x80000000;
          local_b0 = FLOAT_803e0320 * param_6[1] +
                     FLOAT_803e0310 *
                     (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
        }
        local_50 = 0x43300000;
        uStack76 = FUN_800221a0(0xffffff9c,100);
        uStack76 = uStack76 ^ 0x80000000;
        local_ac = FLOAT_803e0320 * param_6[2] +
                   FLOAT_803e0310 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
      }
      local_50 = 0x43300000;
      uStack76 = FUN_800221a0(0xffffffec,0x14);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffffec,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a4 = *(float *)(param_3 + 4) * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffffec,0x14);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0x5a,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0310 * (float)(local_68 - DOUBLE_803e04d0);
      local_78 = FUN_800221a0(0x9b,0xff);
      local_d0 = FUN_800221a0(1,0x14);
      local_d0 = param_3[2] + local_d0;
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
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    uStack76 = FUN_800221a0(0x46,0x50);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e03ac * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    local_d0 = 5;
    local_96 = 0x2d;
    local_94 = (code *)0x180200;
    local_90 = 0;
    break;
  case 0x7b9:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e0390 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = FLOAT_803e0390 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e0390 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_d0 = (int)*(short *)((int)param_6 + 6);
      local_96 = *(short *)param_6;
      uVar2 = FUN_800221a0(0x1c,0x20);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e039c * (float)(local_68 - DOUBLE_803e04d0);
      local_94 = (code *)0x480200;
      local_90 = 0x808;
    }
    break;
  case 0x7ba:
    if (param_3 != (short *)0x0) {
      local_d0 = (int)*(short *)((int)param_6 + 6);
      local_96 = *(short *)param_6;
      local_9c = FLOAT_803e03a0 * param_6[2];
      local_94 = (code *)0x80110;
      local_90 = 0x4000800;
    }
    break;
  case 0x7bb:
    if (param_3 != (short *)0x0) {
      if (param_3[3] == 0) {
        local_9c = FLOAT_803e0330 * *(float *)(param_3 + 4);
        local_94 = (code *)0xc0180200;
        local_90 = 0x4010000;
        local_d0 = FUN_800221a0(0x1c,0x22);
        local_d0 = local_d0 + 10;
        local_78 = FUN_800221a0((int)param_3[2],param_3[2] + 10);
      }
      else {
        uStack76 = FUN_800221a0(7,10);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e03b0 * *(float *)(param_3 + 4) *
                   (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
        local_94 = (code *)0xc0080200;
        local_90 = 0x4010000;
        local_d0 = 10;
        local_78 = '\x7f';
      }
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uStack76 = FUN_800221a0(100,0x96);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_ac = FLOAT_803e03b4 *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e03a8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      FUN_80021ac8(iVar1,&local_b4);
      local_96 = 0xc10;
    }
    break;
  case 0x7bc:
    if (param_3 != (short *)0x0) {
      if (param_3[3] == 0) {
        local_9c = FLOAT_803e0330 * *(float *)(param_3 + 4);
        local_94 = (code *)0xc1180200;
        local_90 = 0x5010000;
        local_d0 = FUN_800221a0(0x1c,0x22);
        local_d0 = local_d0 + 10;
        local_78 = FUN_800221a0((int)param_3[2],param_3[2] + 10);
      }
      else {
        uStack76 = FUN_800221a0(7,10);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e03b0 * *(float *)(param_3 + 4) *
                   (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
        local_94 = (code *)0xc1080200;
        local_90 = 0x5010000;
        local_d0 = 10;
        local_78 = '\x7f';
      }
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uStack76 = FUN_800221a0(100,0x96);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_ac = FLOAT_803e03b4 *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e03b8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      FUN_80021ac8(iVar1,&local_b4);
      local_96 = 0xc10;
    }
    break;
  case 0x7bd:
    if (param_3 != (short *)0x0) {
      local_9c = FLOAT_803e0310 * *(float *)(param_3 + 4);
      local_94 = (code *)0x83000200;
      local_90 = 0x1200000;
      local_d0 = FUN_800221a0(10,0x18);
      local_78 = -1;
      local_a4 = *(float *)(param_3 + 8) * *(float *)(param_3 + 4);
      uStack76 = FUN_800221a0(0xffffff6a,0x96);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e03bc *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e0330 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff6a,0x96);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = FLOAT_803e03bc *
                 *(float *)(param_3 + 4) * FLOAT_803e0330 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(100,0x96);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e0314 *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e03c0 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      FUN_80021ac8(iVar1,&local_b4);
      local_96 = 0xc10;
    }
    break;
  case 0x7be:
    if (param_3 != (short *)0x0) {
      if (param_6 == (float *)0x0) {
        uStack76 = FUN_800221a0(100,0x6b);
        uStack76 = uStack76 ^ 0x80000000;
        local_ac = *(float *)(param_3 + 6) *
                   *(float *)(param_3 + 4) *
                   FLOAT_803e03b8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
      }
      else {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
        if (param_6[2] <= FLOAT_803e0324) {
          if (FLOAT_803e0324 <= param_6[2]) {
            uStack76 = FUN_800221a0(100,0x6b);
            uStack76 = uStack76 ^ 0x80000000;
            local_ac = *(float *)(param_3 + 6) *
                       *(float *)(param_3 + 4) *
                       FLOAT_803e03b8 *
                       (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
          }
          else {
            uStack76 = FUN_800221a0(100,0x6b);
            uStack76 = uStack76 ^ 0x80000000;
            local_ac = *(float *)(param_3 + 6) *
                       *(float *)(param_3 + 4) *
                       FLOAT_803e03c4 *
                       (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
          }
        }
        else {
          uStack76 = FUN_800221a0(100,0x6b);
          uStack76 = uStack76 ^ 0x80000000;
          local_b0 = *(float *)(param_3 + 6) *
                     *(float *)(param_3 + 4) *
                     FLOAT_803e03c4 *
                     (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
        }
      }
      local_50 = 0x43300000;
      uStack76 = FUN_800221a0(0x1c,0x22);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e03c8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x14,0x1b);
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
    if (param_3 != (short *)0x0) {
      if (param_6 != (float *)0x0) {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
      }
      uStack76 = FUN_800221a0(10,0xd);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = (FLOAT_803e0374 + *(float *)(param_3 + 6)) *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e03cc * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,2);
      local_d0 = local_d0 + 2;
      local_94 = (code *)0x80014;
      local_90 = 0x4000820;
      local_58 = (double)(longlong)(int)(FLOAT_803e03d0 * *(float *)(param_3 + 6));
      local_78 = (char)(int)(FLOAT_803e03d0 * *(float *)(param_3 + 6)) + '@';
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
    if (param_3 != (short *)0x0) {
      if (param_6 != (float *)0x0) {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
      }
      uStack76 = FUN_800221a0(0x2d,0x3a);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e03d4 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,7);
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
      uVar2 = FUN_800221a0(100,0x6c);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_ac = *(float *)(param_3 + 6) *
                 *(float *)(param_3 + 4) * FLOAT_803e03d8 * (float)(local_58 - DOUBLE_803e04d0);
      local_b0 = FLOAT_803e0324;
      local_b4 = FLOAT_803e0324;
      if (param_6 != (float *)0x0) {
        FUN_80021ac8(param_6,&local_b4);
      }
      local_96 = param_3[3];
    }
    break;
  case 0x7c1:
    if (param_3 != (short *)0x0) {
      if (param_6 != (float *)0x0) {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
      }
      uStack76 = FUN_800221a0(2,0xd);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = (FLOAT_803e0374 + *(float *)(param_3 + 6)) *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e03dc * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      local_d0 = 0x11;
      local_94 = (code *)0x80114;
      local_90 = 0x4000900;
      iVar1 = (int)(FLOAT_803e03d0 * *(float *)(param_3 + 6));
      local_58 = (double)(longlong)iVar1;
      local_78 = (char)iVar1 + '@';
      local_96 = param_3[3];
    }
    break;
  case 0x7c2:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = FLOAT_803e0350 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b4 = *(float *)(param_3 + 4) *
                 (FLOAT_803e03e0 + local_b0) * FLOAT_803e03e4 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 (FLOAT_803e03e0 + local_b0) *
                 FLOAT_803e03e4 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_b0 = -local_b0 * *(float *)(param_3 + 4);
      uVar2 = FUN_800221a0(0x19,0x32);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e03b0 * (float)(local_68 - DOUBLE_803e04d0);
      local_a4 = FLOAT_803e03e8 * *(float *)(param_3 + 4);
      local_d0 = FUN_800221a0(0x28,0x50);
      local_96 = 0xc10;
      local_78 = '@';
      local_94 = (code *)0x80104;
      local_90 = 0x4800808;
    }
    break;
  case 0x7c3:
    if (param_3 != (short *)0x0) {
      uStack92 = FUN_800221a0(0);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_58 = (double)CONCAT44(0x43300000,(int)param_3[3] ^ 0x80000000);
      dVar9 = (double)(FLOAT_803e0330 *
                       (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0) +
                      (float)(local_58 - DOUBLE_803e04d0));
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      dVar8 = (double)((FLOAT_803e0344 *
                       (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0)) /
                      FLOAT_803e0348);
      dVar7 = (double)FUN_80293e80(dVar8);
      local_a8 = (float)(dVar9 * dVar7 + (double)*(float *)(param_3 + 6));
      uVar2 = FUN_800221a0(0,(int)param_3[2]);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a4 = FLOAT_803e0314 * (float)(local_68 - DOUBLE_803e04d0) + *(float *)(param_3 + 8);
      dVar7 = (double)FUN_80294204(dVar8);
      local_a0 = (float)(dVar9 * dVar7 + (double)*(float *)(param_3 + 10));
      local_d0 = FUN_800221a0(10,0x28);
      local_96 = 0x156;
      local_94 = (code *)0x80480104;
      local_90 = 0x4000800;
      uVar2 = FUN_800221a0(0x31,0x39);
      local_70 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e03ec * (float)(local_70 - DOUBLE_803e04d0);
      local_78 = -1;
    }
    break;
  case 0x7c4:
    if (param_3 != (short *)0x0) {
      if (param_6 != (float *)0x0) {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
      }
      uStack76 = FUN_800221a0(10,0xd);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = (FLOAT_803e0374 + *(float *)(param_3 + 6)) *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e03cc * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,2);
      local_d0 = local_d0 + 2;
      local_94 = (code *)0x80004;
      local_90 = 0x4000820;
      local_58 = (double)(longlong)(int)(FLOAT_803e03d0 * *(float *)(param_3 + 6));
      local_78 = (char)(int)(FLOAT_803e03d0 * *(float *)(param_3 + 6)) + '@';
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
    if (param_3 != (short *)0x0) {
      if (param_6 != (float *)0x0) {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
      }
      uStack76 = FUN_800221a0(2,0xd);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = (FLOAT_803e0374 + *(float *)(param_3 + 6)) *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e03dc * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      local_d0 = 0x11;
      local_94 = (code *)0x80104;
      local_90 = 0x4000900;
      iVar1 = (int)(FLOAT_803e03d0 * *(float *)(param_3 + 6));
      local_58 = (double)(longlong)iVar1;
      local_78 = (char)iVar1 + '@';
      local_96 = param_3[3];
    }
    break;
  case 0x7c6:
    local_9c = FLOAT_803e03a8;
    local_d0 = FUN_800221a0(0x27,0x31);
    local_94 = (code *)0x180000;
    local_90 = 0x408000;
    local_96 = 0x5ff;
    break;
  case 0x7c7:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(100,200);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 4) *
                 FLOAT_803e034c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a8 = *(float *)(param_3 + 4) * FLOAT_803e0350 * (float)(local_58 - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0350 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 10);
      uVar2 = FUN_800221a0(0x50,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0354 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x14);
      local_d0 = local_d0 + 10;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x80200;
      local_90 = 0x4040800;
    }
    break;
  case 0x7c8:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xfffffed4,300);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e034c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = FLOAT_803e034c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xfffffed4,300);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e034c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_a4 = FLOAT_803e03f0;
      local_9c = FLOAT_803e03f4;
      local_d0 = FUN_800221a0(0x19,0x20);
      local_96 = param_3[3];
      local_94 = (code *)0x80100;
      local_90 = 0x40808;
    }
    break;
  case 0x7c9:
    uStack76 = FUN_800221a0(0xffffff9c,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e03f8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0,100);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_b0 = FLOAT_803e03fc * (float)(local_58 - DOUBLE_803e04d0);
    uStack92 = FUN_800221a0(0xffffff9c,100);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e0400 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0xf,0x14);
    local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_9c = FLOAT_803e0404 * (float)(local_68 - DOUBLE_803e04d0);
    local_d0 = FUN_800221a0(300,0x1c2);
    local_96 = 0xc10;
    local_94 = (code *)0x8000100;
    local_90 = 0x1000000;
    local_78 = '\x7f';
    break;
  case 0x7ca:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e035c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = FLOAT_803e0408 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e035c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(1,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e03e4 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(100,0x78);
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
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e034c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e034c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e034c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_9c = FLOAT_803e040c;
      uVar2 = FUN_800221a0(0x32,0x3c);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_d0 = (int)(*(float *)(param_3 + 4) * (float)(local_68 - DOUBLE_803e04d0));
      local_70 = (double)(longlong)local_d0;
      local_96 = 0x88;
      local_94 = (code *)0x480400;
      local_90 = 0x80800;
    }
    break;
  case 0x7cc:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a8 = *(float *)(param_3 + 4) *
                 FLOAT_803e0380 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a4 = *(float *)(param_3 + 4) * FLOAT_803e0380 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0380 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(5,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e031c * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x2a,0x32);
      local_96 = param_3[3];
      local_94 = (code *)0x580000;
      local_90 = 0x800;
    }
    break;
  case 0x7cd:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(100,200);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0358 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a8 = *(float *)(param_3 + 4) * FLOAT_803e0334 * (float)(local_58 - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0334 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 10);
      uVar2 = FUN_800221a0(0x50,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0354 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x14);
      local_d0 = local_d0 + 10;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x280201;
      local_90 = 0x4040800;
    }
    break;
  case 0x7ce:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(100,200);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0358 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a8 = *(float *)(param_3 + 4) * FLOAT_803e0334 * (float)(local_58 - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0334 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 10);
      uVar2 = FUN_800221a0(0x50,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0354 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(5,0xf);
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x280201;
      local_90 = 0x4040800;
    }
    break;
  case 1999:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      local_9c = FLOAT_803e0410 * *(float *)(param_3 + 4);
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
    if (param_3 != (short *)0x0) {
      if (param_6 == (float *)0x0) {
        uStack76 = FUN_800221a0(100,200);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_b0 = *(float *)(param_3 + 4) *
                   FLOAT_803e0370 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
        uVar2 = FUN_800221a0(100,200);
        local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_ac = FLOAT_803e0414 *
                   *(float *)(param_3 + 4) * FLOAT_803e0418 * (float)(local_58 - DOUBLE_803e04d0);
      }
      else {
        uStack76 = FUN_800221a0(100,200);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_b0 = FLOAT_803e0328 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
        uVar2 = FUN_800221a0(0x32,100);
        local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_ac = FLOAT_803e041c *
                   *(float *)(param_3 + 4) * FLOAT_803e0420 * (float)(local_58 - DOUBLE_803e04d0);
      }
      uStack76 = FUN_800221a0(0xffffffec,0x14);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a8 = FLOAT_803e03e0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 6);
      uVar2 = FUN_800221a0(0xf,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a4 = FLOAT_803e0374 * (float)(local_58 - DOUBLE_803e04d0) + *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack92 = FUN_800221a0(0x50,0x8c);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e0378 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0,10);
      local_d0 = local_d0 + 0xf;
      local_96 = 0xc10;
      local_78 = -1;
      local_94 = (code *)0x20080100;
      local_90 = 0x4010020;
      local_8c = (uint)param_3[3];
      local_80 = (ushort)((int)local_8c >> 1);
      local_88 = local_8c;
      local_84 = local_8c;
      local_7e = local_80;
      local_7c = local_80;
    }
    break;
  case 0x7d1:
    if (param_3 != (short *)0x0) {
      if (param_6 == (float *)0x0) {
        uStack76 = FUN_800221a0(100,200);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_b0 = *(float *)(param_3 + 4) *
                   FLOAT_803e0328 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
        uVar2 = FUN_800221a0(100,200);
        local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_ac = FLOAT_803e0424 *
                   *(float *)(param_3 + 4) * FLOAT_803e0418 * (float)(local_58 - DOUBLE_803e04d0);
      }
      else {
        uStack76 = FUN_800221a0(100,200);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_b0 = FLOAT_803e0328 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
        uVar2 = FUN_800221a0(100,200);
        local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_ac = FLOAT_803e0424 *
                   *(float *)(param_3 + 4) * FLOAT_803e0370 * (float)(local_58 - DOUBLE_803e04d0);
      }
      uStack76 = FUN_800221a0(0xffffffec,0x14);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a4 = FLOAT_803e0380 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0) +
                 *(float *)(param_3 + 8);
      uVar2 = FUN_800221a0(0xffffffec,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a8 = FLOAT_803e0380 * (float)(local_58 - DOUBLE_803e04d0) + *(float *)(param_3 + 6);
      local_a0 = *(float *)(param_3 + 10);
      uStack92 = FUN_800221a0(0x50,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e0354 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x14);
      local_d0 = local_d0 + 10;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x20080200;
      local_90 = 0x4040800;
    }
    break;
  case 0x7d2:
    if (param_3 != (short *)0x0) {
      if (*param_3 == 0) {
        uStack76 = FUN_800221a0(0xffffff9c,100);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_b4 = FLOAT_803e0358 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
        uVar2 = FUN_800221a0(0xffffff9c,100);
        local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_b0 = FLOAT_803e036c * (float)(local_58 - DOUBLE_803e04d0);
        uStack92 = FUN_800221a0(0xffffff9c,100);
        uStack92 = uStack92 ^ 0x80000000;
        local_60 = 0x43300000;
        local_ac = FLOAT_803e0358 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0)
        ;
        uVar2 = FUN_800221a0(100,200);
        local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_a4 = FLOAT_803e0314 * (float)(local_68 - DOUBLE_803e04d0);
      }
      else {
        local_a4 = FLOAT_803e0428;
        uStack76 = FUN_800221a0(0xffffff9c,100);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_b4 = FLOAT_803e0328 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
        uVar2 = FUN_800221a0(0xffffff9c,100);
        local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_b0 = FLOAT_803e03b0 * (float)(local_58 - DOUBLE_803e04d0);
        uStack92 = FUN_800221a0(0xffffff9c,100);
        uStack92 = uStack92 ^ 0x80000000;
        local_60 = 0x43300000;
        local_ac = FLOAT_803e0328 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0)
        ;
      }
      uStack76 = FUN_800221a0(5,10);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      local_d0 = (int)param_3[3];
      local_96 = param_3[2];
      local_78 = -1;
      local_94 = (code *)0x80110;
      local_90 = 0x20900;
    }
    break;
  case 0x7d3:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e042c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e042c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e042c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(10,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e0430 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x28);
      local_d0 = param_3[1] + local_d0;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x480104;
      local_90 = 0x8000080;
    }
    break;
  case 0x7d4:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e042c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e042c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e042c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(10,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e0430 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x28);
      local_d0 = param_3[1] + local_d0;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x1480104;
      local_90 = 0x8000080;
    }
    break;
  case 0x7d5:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e042c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e042c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e042c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(10,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e0430 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x28);
      local_d0 = param_3[1] + local_d0;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x48010c;
      local_90 = 0x8000080;
    }
    break;
  case 0x7d6:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e042c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e042c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e042c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(10,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e0430 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x28);
      local_d0 = param_3[1] + local_d0;
      local_96 = param_3[3];
      local_78 = -1;
      local_94 = (code *)0x40480104;
      local_90 = 0x8000080;
    }
    break;
  case 0x7d7:
    local_9c = FLOAT_803e03e4;
    local_d0 = (uint)DAT_803db410 * 3;
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
    local_a4 = FLOAT_803e0434;
    local_a0 = FLOAT_803e0438;
    local_ac = FLOAT_803e043c;
    uStack76 = FUN_800221a0(0x50,0x58);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e03b0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    local_d0 = FUN_800221a0(0xd2,0xe6);
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
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a8 = FLOAT_803e03a8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0) +
                 local_a8;
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a4 = FLOAT_803e03a8 * (float)(local_58 - DOUBLE_803e04d0) + local_a4;
      uStack92 = FUN_800221a0(0x5a,0x6e);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e0440 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_9c = FLOAT_803e035c;
      local_94 = (code *)((uint)local_94 | 0x400000);
    }
    break;
  case 0x7d9:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    local_9c = FLOAT_803e0330 * *(float *)(param_3 + 4);
    local_d0 = 10;
    local_96 = param_3[3];
    local_78 = '@';
    local_94 = (code *)0x80104;
    local_90 = 0x880;
    break;
  case 0x7da:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    local_9c = FLOAT_803e0330 * *(float *)(param_3 + 4);
    local_d0 = 0x14;
    local_96 = param_3[3];
    local_78 = '0';
    local_94 = (code *)0x80104;
    local_90 = 0x880;
    break;
  case 0x7db:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    local_9c = FLOAT_803e0330 * *(float *)(param_3 + 4);
    local_d0 = 0x14;
    local_96 = param_3[3];
    local_78 = '0';
    local_94 = (code *)0x80104;
    local_90 = 0x4000880;
    break;
  case 0x7dc:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e042c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e042c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e042c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(5,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_70 = (double)CONCAT44(0x43300000,(int)param_3[2] ^ 0x80000000);
      local_9c = ((float)(local_70 - DOUBLE_803e04d0) / FLOAT_803e0444) *
                 FLOAT_803e033c * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x28);
      local_d0 = param_3[1] + local_d0;
      local_78 = FUN_800221a0(0x20,0x40);
      local_78 = (char)*param_3 + local_78;
      local_96 = 0x605;
      local_94 = (code *)0x80104;
      local_90 = 0x8a0;
      sVar3 = param_3[3];
      if (sVar3 == 0xe0) {
        local_80 = 0;
        local_7e = 0;
        local_7c = 0xffff;
        local_8c = 0x656a;
        local_88 = 0;
        local_84 = 0xffff;
      }
      else if (sVar3 < 0xe0) {
        if (sVar3 == 0xdd) {
          local_80 = 40000;
          local_7e = 0;
          local_7c = 0;
          local_8c = 0xffff;
          local_88 = 0x7ffd;
          local_84 = 0x4000;
        }
        else if (sVar3 < 0xdd) {
          if (sVar3 != 0x7b) goto LAB_800d20d4;
          local_80 = 0;
          local_7e = 0x7fff;
          local_7c = 0xffff;
          local_8c = FUN_800221a0(0x4b0,32000);
          local_88 = 0xffff;
          local_84 = 0xffff;
        }
        else if (sVar3 < 0xdf) {
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
          local_88 = FUN_800221a0(0x4b0,32000);
          local_84 = 0xffff;
        }
      }
      else if (sVar3 == 0x160) {
        local_80 = 0;
        local_7e = 0xffff;
        local_7c = 0;
        local_8c = 0x656a;
        local_88 = 0xffff;
        local_84 = 5000;
      }
      else if (sVar3 < 0x160) {
        if (sVar3 == 0xe4) {
          local_80 = 40000;
          local_7e = 40000;
          local_7c = 0xffff;
          local_8c = 0xffff;
          local_88 = 0xffff;
          local_84 = 0xffff;
        }
        else {
LAB_800d20d4:
          local_80 = 0;
          local_7e = 0;
          local_7c = 0xffff;
          local_8c = 0x656a;
          local_88 = 0;
          local_84 = 0xffff;
        }
      }
      else {
        if (sVar3 != 0x200) goto LAB_800d20d4;
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
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e03a8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e03a8 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e03a8 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      local_9c = FLOAT_803e034c * *(float *)(param_3 + 4);
      local_d0 = FUN_800221a0(0x1e,0x6e);
      local_78 = -1;
      local_94 = (code *)0x3000000;
      local_90 = 0x780880;
      local_96 = param_3[3];
    }
    break;
  case 0x7de:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e0340 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0334 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e0340 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      local_9c = FLOAT_803e0448 * *(float *)(param_3 + 4);
      uVar2 = FUN_800221a0(0x19,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_d0 = (int)(local_b0 * (float)(local_68 - DOUBLE_803e04d0));
      local_70 = (double)(longlong)local_d0;
      local_94 = (code *)0x1482000;
      local_90 = 0x8400880;
      local_96 = param_3[3];
    }
    break;
  case 0x7df:
    if (param_3 != (short *)0x0) {
      local_ac = *(float *)(param_3 + 4);
      FUN_80021ac8(param_3,&local_b4);
      local_a8 = local_a8 + local_b4;
      local_a0 = local_a0 + local_ac;
      local_b4 = FLOAT_803e0324;
      uStack76 = FUN_800221a0(0x32,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 4) *
                 FLOAT_803e044c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0x4b,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_ac = *(float *)(param_3 + 4) * FLOAT_803e0310 * (float)(local_58 - DOUBLE_803e04d0);
      FUN_80021ac8(param_3,&local_b4);
      local_9c = FLOAT_803e034c;
      uStack92 = FUN_800221a0(0x32,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_d0 = (int)(local_b0 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0));
      local_68 = (double)(longlong)local_d0;
      local_78 = '\x7f';
      local_94 = (code *)0x3000000;
      local_90 = 0x1600080;
      local_96 = 0xc10;
    }
    break;
  case 0x7e0:
    uStack76 = FUN_800221a0(0xffffff9c,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e0450 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0xffffff9c,100);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_ac = FLOAT_803e0454 * (float)(local_58 - DOUBLE_803e04d0);
    local_9c = FLOAT_803e0408;
    local_d0 = FUN_800221a0(0x28,0x32);
    local_96 = 0xc10;
    local_78 = 'Z';
    local_94 = (code *)0xa100000;
    local_90 = 0x400000;
    break;
  case 0x7e1:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e03b0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e034c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e03b0 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_9c = FLOAT_803e042c;
      uVar2 = FUN_800221a0(0x32,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_d0 = (int)(local_b0 * (float)(local_68 - DOUBLE_803e04d0));
      local_70 = (double)(longlong)local_d0;
      local_78 = '\x7f';
      local_94 = (code *)0x1080000;
      local_90 = 0x5400080;
      local_96 = 0xc10;
    }
    break;
  case 0x7e2:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffffd8,0x28);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e03e4 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(10,0x50);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = FLOAT_803e036c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffffd8,0x28);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e03e4 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xf,0x1e);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e033c * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x122,0x15e);
      local_78 = -1;
      local_94 = (code *)0x86000008;
      local_90 = 0x1000000;
      local_96 = param_3[3];
      if (param_3[1] == 1) {
        local_8c = FUN_800221a0(0x63bf,0xffff);
        local_8c = local_8c & 0xffff;
        local_80 = (ushort)local_8c;
        local_88 = FUN_800221a0(0x3caf,0xd8ef);
        local_88 = local_88 & 0xffff;
        local_7e = (ushort)local_88;
        local_84 = FUN_800221a0(0x159f,0x3caf);
        local_84 = local_84 & 0xffff;
        local_7c = (ushort)local_84;
        local_90 = local_90 | 0x20;
      }
      else if (param_3[1] == 2) {
        local_8c = FUN_800221a0(0x3caf,0x7fff);
        local_8c = local_8c & 0xffff;
        local_80 = (ushort)local_8c;
        local_88 = FUN_800221a0(0x7fff,0xffff);
        local_88 = local_88 & 0xffff;
        local_7e = (ushort)local_88;
        local_84 = FUN_800221a0(0x159f,0x3caf);
        local_84 = local_84 & 0xffff;
        local_7c = (ushort)local_84;
        local_90 = local_90 | 0x20;
      }
      if (param_3[2] != 0) {
        local_94 = (code *)((uint)local_94 | 0x800000);
        local_78 = 'A';
      }
      local_cc = FUN_800221a0(0,0xffff);
      local_ca = FUN_800221a0(0,0xffff);
      local_cc = FUN_800221a0(0,0xffff);
      uStack76 = FUN_800221a0(0xe6,800);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_c0 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xe6,800);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_bc = (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xe6,800);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_b8 = (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
    }
    break;
  case 0x7e3:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffffd8,0x28);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e03e4 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(10,0x50);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = FLOAT_803e0458 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffffd8,0x28);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e03e4 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(10,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e033c * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x122,0x15e);
      local_78 = -1;
      local_94 = (code *)0x80008;
      local_90 = 0x5000000;
      local_96 = 0xc10;
    }
    break;
  case 0x7e4:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffffd8,0x28);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = FLOAT_803e03e4 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(10,0x50);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = FLOAT_803e036c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffffd8,0x28);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = FLOAT_803e03e4 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(5,10);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e045c * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x122,0x15e);
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
    uStack76 = FUN_800221a0(0x44,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e033c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    local_d0 = FUN_800221a0(100,0x82);
    local_96 = 0xc10;
    local_78 = FUN_800221a0(0x28,0x2c);
    local_94 = (code *)0x180100;
    local_90 = 0x5080800;
    break;
  case 0x7e6:
    if (param_3 != (short *)0x0) {
      if (param_6 == (float *)0x0) {
      }
      else {
        local_b4 = *param_6;
        local_b0 = param_6[1];
        local_ac = param_6[2];
      }
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e034c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0) +
                 local_b4;
      uVar2 = FUN_800221a0(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e036c * (float)(local_58 - DOUBLE_803e04d0) +
                 local_b0;
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e034c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0) +
                 local_ac;
      uVar2 = FUN_800221a0(0x44,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = (float)((double)*(float *)(param_3 + 4) *
                        DOUBLE_803e0460 * (double)(float)(local_68 - DOUBLE_803e04d0));
      local_d0 = FUN_800221a0(0x2d,0x5f);
      local_96 = 0xc10;
      local_94 = (code *)0x180100;
      local_90 = 0x5080000;
      if (*param_3 == 3) {
        local_78 = FUN_800221a0(0x26,0x2b);
        local_90 = local_90 | 0x800;
      }
      else {
        local_78 = FUN_800221a0(0x26,0x2b);
      }
    }
    break;
  case 0x7e7:
    uStack76 = FUN_800221a0(0xffffff9c,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e03f8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0,100);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_b0 = FLOAT_803e03fc * (float)(local_58 - DOUBLE_803e04d0);
    uStack92 = FUN_800221a0(0xffffff9c,100);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e0400 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0xf,0x14);
    local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_9c = FLOAT_803e0404 * (float)(local_68 - DOUBLE_803e04d0);
    local_d0 = FUN_800221a0(0x96,300);
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
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    local_9c = FLOAT_803e0330 * *(float *)(param_3 + 4);
    local_d0 = 10;
    local_96 = param_3[3];
    local_78 = '@';
    local_94 = (code *)0x80100;
    local_90 = 0x800;
    break;
  case 0x7e9:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    local_9c = FLOAT_803e0330 * *(float *)(param_3 + 4);
    local_d0 = 0x14;
    local_96 = param_3[3];
    local_78 = '0';
    local_94 = (code *)0x80100;
    local_90 = 0x800;
    break;
  case 0x7ea:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
    }
    local_9c = FLOAT_803e0330 * *(float *)(param_3 + 4);
    local_d0 = 0x14;
    local_96 = param_3[3];
    local_78 = '0';
    local_94 = (code *)0x80100;
    local_90 = 0x4000800;
    break;
  case 0x7eb:
    if (param_3 != (short *)0x0) {
      if (param_6 != (float *)0x0) {
        local_a8 = param_6[3];
        local_a4 = param_6[4];
        local_a0 = param_6[5];
      }
      iVar1 = FUN_800221a0(0,4);
      if (iVar1 == 0) {
        uStack76 = FUN_800221a0(0x1c,0x22);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = *(float *)(param_3 + 4) *
                   FLOAT_803e042c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
        local_94 = (code *)0x80000;
        local_90 = 0x8000820;
      }
      else {
        uStack76 = FUN_800221a0(100,0x6b);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_b0 = *(float *)(param_3 + 6) *
                   *(float *)(param_3 + 4) *
                   FLOAT_803e03c4 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
        uVar2 = FUN_800221a0(0x1c,0x22);
        local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_9c = *(float *)(param_3 + 4) * FLOAT_803e03c8 * (float)(local_58 - DOUBLE_803e04d0);
        local_94 = (code *)0x80080000;
        local_90 = 0x8002820;
      }
      local_78 = -1;
      local_d0 = FUN_800221a0(0x14,0x1b);
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
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0x1e,0x46);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = *(float *)(param_3 + 4) *
                 FLOAT_803e033c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x1e,0x28);
      local_78 = FUN_800221a0(0x40,0x7f);
      local_96 = 0x605;
      local_94 = FUN_80080100;
      local_90 = 0x28a0;
      local_80 = 0;
      local_7e = 0x7fff;
      local_7c = 0xffff;
      local_8c = FUN_800221a0(40000);
      local_88 = FUN_800221a0(0x4b0,32000);
      local_84 = 0xffff;
    }
    break;
  case 0x7ed:
    local_a4 = FLOAT_803e0468;
    local_b0 = FLOAT_803e0424;
    uStack76 = FUN_800221a0(0x50,0x58);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e03b0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    local_d0 = FUN_800221a0(0x50,0x5a);
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
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a8 = FLOAT_803e03a8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0) +
                 local_a8;
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a4 = FLOAT_803e03a8 * (float)(local_58 - DOUBLE_803e04d0) + local_a4;
      uStack92 = FUN_800221a0(0x5a,0x6e);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = FLOAT_803e0358 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_9c = FLOAT_803e035c;
      local_94 = (code *)((uint)local_94 | 0x400000);
    }
    break;
  case 0x7ee:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0x1e,0x46);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803e03b0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      local_94 = FUN_80080100;
      local_90 = 0x8a0;
      local_80 = FUN_800221a0(40000,0xffff);
      local_7e = FUN_800221a0(0x4b0,32000);
      local_7c = 0xffff;
      local_8c = 0;
      local_88 = 0x7fff;
      local_84 = 0xffff;
      local_d0 = FUN_800221a0(0x1c,0x22);
      local_d0 = local_d0 + 0x14;
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      local_ac = FLOAT_803e0324;
      local_b0 = *(float *)(param_3 + 4);
      if (param_3[3] == 0) {
        local_b4 = FLOAT_803e046c;
      }
      else {
        local_b4 = FLOAT_803e0374;
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
    uStack76 = FUN_800221a0(0xffffff9c,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e0470 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0x32,100);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_b0 = FLOAT_803e0474 * (float)(local_58 - DOUBLE_803e04d0);
    uStack92 = FUN_800221a0(0xffffff9c,100);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e0478 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0x14,100);
    local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_9c = FLOAT_803e047c * (float)(local_68 - DOUBLE_803e04d0);
    if (iVar4 == 0x808) {
      local_9c = local_9c * FLOAT_803e0314;
    }
    local_d0 = FUN_800221a0(0x14,100);
    local_96 = 0xc10;
    local_80 = 0xffe4;
    local_7e = 0x15;
    local_7c = 0xc67b;
    local_8c = 0x1378;
    local_88 = 0xfec0;
    local_84 = 0x2d55;
    local_78 = -1;
    local_94 = (code *)0x80080200;
    if ((iVar4 == 0x7ef) || (iVar4 == 0x808)) {
      local_94 = (code *)0x80280201;
    }
    local_90 = 0x4080820;
    break;
  case 0x7f0:
    uStack76 = FUN_800221a0(0x32,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e0480 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    local_b0 = FLOAT_803e040c;
    local_9c = FLOAT_803e0484;
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
    uStack76 = FUN_800221a0(8,10);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_b0 = FLOAT_803e0380 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    local_a4 = FLOAT_803e0488;
    uVar2 = FUN_800221a0(6,0xc);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_9c = FLOAT_803e0420 * (float)(local_58 - DOUBLE_803e04d0);
    local_d0 = FUN_800221a0(0x3c,0x5a);
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
    local_a4 = FLOAT_803e048c;
    uStack76 = FUN_800221a0(0xffffff9c,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e0340 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0xffffff9c,100);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_b0 = FLOAT_803e0368 * (float)(local_58 - DOUBLE_803e04d0);
    uStack92 = FUN_800221a0(0xffffff9c,100);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e0340 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
    local_9c = FLOAT_803e0490;
    local_d0 = FUN_800221a0(0xc,0x3d);
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
    if (param_3 != (short *)0x0) {
      local_d0 = 0x37;
      local_96 = 0xc86;
      local_78 = -0xd;
      local_94 = (code *)0x80100;
      local_90 = 0x828;
      if (param_3[3] == 0) {
        uStack76 = FUN_800221a0(10,0x14);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e0368 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
        local_a4 = FLOAT_803e048c;
        local_80 = 0xffcc;
        local_7e = 0x23a8;
        local_7c = 0x325f;
        local_8c = 0xfec1;
        local_88 = 0x130c;
        local_84 = 0xacf;
      }
      if (param_3[3] == 1) {
        uStack76 = FUN_800221a0(10,0x14);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e040c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
        local_a4 = FLOAT_803e0494;
        local_80 = 0x23a8;
        local_7e = 0xffcc;
        local_7c = 0x325f;
        local_8c = 0x130c;
        local_88 = 0xfec1;
        local_84 = 0xacf;
      }
      if (param_3[3] == 2) {
        uStack76 = FUN_800221a0(10,0x14);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_9c = FLOAT_803e0498 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0)
        ;
        local_a4 = FLOAT_803e0494;
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
    uStack76 = FUN_800221a0(0x50,0x58);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e033c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    local_96 = 0x7b;
    local_d0 = 0x50;
    sVar3 = param_3[3];
    if ((sVar3 == 0) || (sVar3 == 3)) {
      local_80 = 65000;
      local_7e = 10000;
      local_7c = 10000;
      local_d0 = 0x55;
    }
    else if ((sVar3 == 1) || (sVar3 == 4)) {
      local_80 = 0;
      local_7e = 65000;
      local_7c = 0;
    }
    else if ((sVar3 == 2) || (sVar3 == 5)) {
      local_80 = 0;
      local_7e = 0;
      local_7c = 65000;
    }
    if (param_3[3] < 3) {
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
    if (param_3 != (short *)0x0) {
      if (param_3[3] == 0) {
        local_9c = FLOAT_803e0330 * *(float *)(param_3 + 4);
        local_94 = (code *)0x81180000;
        local_90 = 0x8400800;
        local_d0 = FUN_800221a0(0x14,0x1a);
        local_d0 = local_d0 + 10;
      }
      else {
        local_9c = FLOAT_803e049c * FLOAT_803e031c * *(float *)(param_3 + 4);
        local_94 = (code *)0x81080000;
        local_90 = 0x4400800;
        local_d0 = 10;
      }
      uStack76 = FUN_800221a0(100,0x96);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = FLOAT_803e0314 *
                 *(float *)(param_3 + 4) *
                 FLOAT_803e04a0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      FUN_80021ac8(iVar1,&local_b4);
      local_96 = 0x5f5;
      local_78 = -0x80;
    }
    break;
  default:
    uVar5 = 0xffffffff;
    goto LAB_800d53d4;
  case 0x7f7:
    if (param_3 != (short *)0x0) {
      local_a4 = *(float *)(param_3 + 8);
      uStack76 = FUN_800221a0(200,300);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b0 = *(float *)(param_3 + 4) *
                 FLOAT_803e0350 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0x37,0x41);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e042c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0x1e,0x28);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_d0 = (int)(*(float *)(param_3 + 4) *
                      (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0));
      local_68 = (double)(longlong)local_d0;
      local_96 = 0xc10;
      local_78 = ' ';
      local_94 = (code *)0xc0080100;
      local_90 = 0x4000800;
    }
    break;
  case 0x7f9:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e034c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e03e4 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e04a4 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_9c = FLOAT_803e0330 * *(float *)(param_3 + 4);
      local_d0 = FUN_800221a0(0x3c,0x4b);
      local_96 = 0xc73;
      local_80 = 5000;
      sVar3 = FUN_800221a0(0,10000);
      local_7e = sVar3 + 10000;
      sVar3 = FUN_800221a0(0,10000);
      local_7c = sVar3 + 20000;
      local_8c = 0;
      local_88 = FUN_800221a0(0,10000);
      iVar1 = FUN_800221a0(0,10000);
      local_84 = iVar1 + 20000;
      local_78 = -1;
      local_94 = (code *)0x1080004;
      local_90 = 0x800a020;
    }
    break;
  case 0x7fa:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e034c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e03e4 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e04a8 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(10,0x1e);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e040c * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x32,0x50);
      local_96 = 0xc10;
      local_80 = 0xffcf;
      local_7e = 0xf987;
      local_7c = 0xfff8;
      local_8c = 0x7a;
      local_88 = 0x57d2;
      local_84 = 0xffee;
      local_78 = FUN_800221a0(0x7b,0xff);
      local_94 = (code *)0x40080204;
      local_90 = 0x4080820;
    }
    break;
  case 0x7fb:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e04ac * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0x32,0x96);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e04ac * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e04ac * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      local_9c = FLOAT_803e0330 * *(float *)(param_3 + 4);
      local_d0 = FUN_800221a0(0x28,0x41);
      local_96 = 0xc73;
      local_80 = 5000;
      sVar3 = FUN_800221a0(0,10000);
      local_7e = sVar3 + 10000;
      sVar3 = FUN_800221a0(0,10000);
      local_7c = sVar3 + 20000;
      local_8c = 0;
      local_88 = FUN_800221a0(0,10000);
      iVar1 = FUN_800221a0(0,10000);
      local_84 = iVar1 + 20000;
      local_78 = -1;
      local_94 = (code *)0x1080000;
      local_90 = 0x800a020;
    }
    break;
  case 0x7fc:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e034c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e03e4 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e034c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(10,0x1e);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e0310 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x32,0x50);
      local_96 = 0xc10;
      local_80 = 0xffcf;
      local_7e = 0xf987;
      local_7c = 0xfff8;
      local_8c = 0x7a;
      local_88 = 0x57d2;
      local_84 = 0xffee;
      local_78 = FUN_800221a0(0x40,0x7f);
      local_94 = (code *)0x40080200;
      local_90 = 0x4000820;
    }
    break;
  case 0x7fd:
    uStack76 = FUN_800221a0(0,4);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_a8 = FLOAT_803e03e8 - (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0,4);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_a4 = FLOAT_803e03e8 - (float)(local_58 - DOUBLE_803e04d0);
    uStack92 = FUN_800221a0(0,4);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_a0 = FLOAT_803e03e8 - (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
    local_9c = FLOAT_803e04ac;
    local_d0 = FUN_800221a0(8,0xe);
    local_94 = (code *)0x110100;
    local_90 = 0x4000000;
    local_96 = 0xdf;
    break;
  case 0x7fe:
    uStack76 = FUN_800221a0(100,200);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e04b0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    local_d0 = FUN_800221a0(0x43,100);
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
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e03b8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e0330 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e03b8 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0x19,100);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e04b4 * *(float *)(param_3 + 4) * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(0x28,0xa5);
      local_96 = 0xc73;
      local_80 = 15000;
      sVar3 = FUN_800221a0(0,10000);
      local_7e = sVar3 + 20000;
      sVar3 = FUN_800221a0(0,10000);
      local_7c = sVar3 + 30000;
      local_8c = 10000;
      local_88 = FUN_800221a0(10000,20000);
      iVar1 = FUN_800221a0(0,10000);
      local_84 = iVar1 + 30000;
      local_78 = -1;
      local_94 = (code *)0x1080000;
      local_90 = 0x800a020;
    }
    break;
  case 0x800:
    if (param_3 != (short *)0x0) {
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e034c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e03e4 * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e034c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(10,0x1e);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = *(float *)(param_3 + 4) * FLOAT_803e04b8 * (float)(local_68 - DOUBLE_803e04d0);
      iVar1 = FUN_800221a0(0,1);
      local_d0 = FUN_800221a0(0x32,0xb4);
      local_d0 = local_d0 + iVar1 * 100;
      local_96 = 0xc10;
      local_80 = 0xffcf;
      local_7e = 0xf987;
      local_7c = 0xfff8;
      local_8c = 0x7a;
      local_88 = 0x57d2;
      local_84 = 0xffee;
      local_78 = FUN_800221a0(0x40,0x7f);
      local_94 = (code *)0x40080200;
      local_90 = 0x4000820;
    }
    break;
  case 0x802:
    uStack76 = FUN_800221a0(0xffffff9c,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e04ac * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0x28,100);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_b0 = FLOAT_803e0350 * (float)(local_58 - DOUBLE_803e04d0);
    uStack92 = FUN_800221a0(0xffffff9c,100);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e04ac * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(4,10);
    local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_9c = FLOAT_803e04b8 * (float)(local_68 - DOUBLE_803e04d0);
    local_d0 = FUN_800221a0(0x19,0x23);
    local_96 = 0xc10;
    local_80 = 0xffff;
    local_7e = 0xffff;
    local_7c = 50000;
    local_8c = 0xffff;
    local_88 = 54000;
    local_84 = 0x7fff;
    local_78 = FUN_800221a0(0x54,0x7a);
    local_94 = (code *)0x1080200;
    local_90 = 0x5000020;
    break;
  case 0x803:
    uStack76 = FUN_800221a0(0xffffff9c,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e04bc * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0xffffffb5,100);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_b0 = FLOAT_803e04bc * (float)(local_58 - DOUBLE_803e04d0);
    local_9c = FLOAT_803e036c;
    local_d0 = 0x32;
    local_80 = 2000;
    local_7e = 2000;
    sVar3 = FUN_800221a0(0xffffec78,5000);
    local_7c = sVar3 + 10000;
    local_8c = 8000;
    local_88 = 8000;
    iVar1 = FUN_800221a0(0xffffec78,5000);
    local_84 = iVar1 + 12000;
    local_96 = 0x639;
    local_78 = -1;
    local_94 = (code *)0x1080004;
    local_90 = 0x408028;
    break;
  case 0x804:
    if (param_3 != (short *)0x0) {
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b4 = *(float *)(param_3 + 4) *
                 FLOAT_803e042c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_b0 = *(float *)(param_3 + 4) * FLOAT_803e042c * (float)(local_58 - DOUBLE_803e04d0);
      uStack92 = FUN_800221a0(0xffffff9c,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_ac = *(float *)(param_3 + 4) *
                 FLOAT_803e042c * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
      uVar2 = FUN_800221a0(10,0x14);
      local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = FLOAT_803e0430 * (float)(local_68 - DOUBLE_803e04d0);
      local_d0 = FUN_800221a0(1,0x28);
      local_d0 = param_3[1] + local_d0;
      local_96 = 0xdf;
      local_78 = -1;
      local_94 = (code *)0x480100;
      local_90 = 0x8000000;
    }
    break;
  case 0x805:
    uStack76 = FUN_800221a0(0x50,0x58);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e04b4 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    local_d0 = FUN_800221a0(100,0x6e);
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
    local_a0 = FLOAT_803e0488;
    FUN_80021ac8(iVar1,&local_a8);
    local_b0 = FLOAT_803e04c0;
    uStack76 = FUN_800221a0(0x50,0x5f);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e0328 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    local_d0 = 0xfa;
    local_96 = 0x7b;
    local_80 = 0xfaab;
    local_7e = 0xa9f;
    local_7c = 0x1d3;
    local_8c = 0x7fff;
    local_88 = 0x7fff;
    local_84 = 0xff4b;
    local_78 = FUN_800221a0(0x32,0x36);
    local_94 = (code *)0x80000;
    local_90 = 0x4000820;
    break;
  case 0x807:
    local_a0 = FLOAT_803e0488;
    FUN_80021ac8(iVar1,&local_a8);
    local_b0 = FLOAT_803e04c4;
    uStack76 = FUN_800221a0(0x50,0x5f);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_9c = FLOAT_803e0328 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    local_d0 = 0xfa;
    local_96 = 0x7b;
    local_80 = 2000;
    local_7e = 2000;
    local_7c = 0xfaab;
    local_8c = 0x7fff;
    local_88 = 0x7fff;
    local_84 = 0xff4b;
    local_78 = FUN_800221a0(0x32,0x36);
    local_94 = (code *)0x80000;
    local_90 = 0x4000820;
    break;
  case 0x809:
    uStack76 = FUN_800221a0(0xffffff9c,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e04ac * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0x28,100);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_b0 = FLOAT_803e0330 * (float)(local_58 - DOUBLE_803e04d0);
    uStack92 = FUN_800221a0(0xffffff9c,100);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e04ac * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(4,10);
    local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_9c = FLOAT_803e036c * (float)(local_68 - DOUBLE_803e04d0);
    local_d0 = FUN_800221a0(0x19,0x23);
    local_96 = 0xc10;
    local_80 = 0xffff;
    local_7e = 0xffff;
    local_7c = 50000;
    local_8c = 0xffff;
    local_88 = 58000;
    local_84 = 38000;
    local_78 = FUN_800221a0(0xb8,0xde);
    local_94 = (code *)0x1080200;
    local_90 = 0x5000020;
    break;
  case 0x80a:
    uStack76 = FUN_800221a0(0xffffff9c,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e04ac * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0x28,100);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_b0 = FLOAT_803e04ac * (float)(local_58 - DOUBLE_803e04d0);
    uStack92 = FUN_800221a0(0xffffff9c,100);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e04ac * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(4,10);
    local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_9c = FLOAT_803e036c * (float)(local_68 - DOUBLE_803e04d0);
    local_d0 = FUN_800221a0(0x19,0x23);
    local_96 = 0xc10;
    local_78 = FUN_800221a0(0x40,0x7f);
    local_94 = (code *)0x80010;
    local_90 = 0x4400800;
    break;
  case 0x80b:
    uStack76 = FUN_800221a0(0xffffff9c,100);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_b4 = FLOAT_803e0330 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(0x28,100);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_b0 = FLOAT_803e0330 * (float)(local_58 - DOUBLE_803e04d0);
    uStack92 = FUN_800221a0(0xffffff9c,100);
    uStack92 = uStack92 ^ 0x80000000;
    local_60 = 0x43300000;
    local_ac = FLOAT_803e0330 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e04d0);
    uVar2 = FUN_800221a0(4,10);
    local_68 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_9c = FLOAT_803e03b0 * (float)(local_68 - DOUBLE_803e04d0);
    local_d0 = FUN_800221a0(0x19,0x23);
    local_96 = 0xc10;
    local_78 = -1;
    local_94 = (code *)0x3000000;
    local_90 = 0x600820;
    local_80 = 0xffff;
    local_88 = FUN_800221a0(0x7fff);
    local_88 = local_88 & 0xffff;
    local_7e = (ushort)local_88;
    local_7c = 0xffff;
    local_8c = (uint)local_80;
    local_84 = 0xffff;
    break;
  case 0x80c:
    if (param_3 != (short *)0x0) {
      local_b4 = *(float *)(param_3 + 6);
      local_b0 = *(float *)(param_3 + 8);
      local_ac = *(float *)(param_3 + 10);
    }
    uStack76 = FUN_800221a0(0xfffffff0,0x10);
    uStack76 = uStack76 ^ 0x80000000;
    local_50 = 0x43300000;
    local_a0 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e04d0);
    local_a4 = FLOAT_803e04c8;
    uVar2 = FUN_800221a0(4,8);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    local_9c = FLOAT_803e0310 * (float)(local_58 - DOUBLE_803e04d0);
    local_d0 = FUN_800221a0(0xf,0x14);
    local_96 = 0xc10;
    local_78 = FUN_800221a0(0x20,0x40);
    local_94 = (code *)0x1080010;
    local_90 = 0x4400800;
  }
  local_94 = (code *)((uint)local_94 | param_4);
  if ((((uint)local_94 & 1) != 0) && (((uint)local_94 & 2) != 0)) {
    local_94 = (code *)((uint)local_94 ^ 2);
  }
  if (((uint)local_94 & 1) != 0) {
    if ((param_4 & 0x200000) == 0) {
      if (local_d8 != 0) {
        local_a8 = local_a8 + *(float *)(local_d8 + 0x18);
        local_a4 = local_a4 + *(float *)(local_d8 + 0x1c);
        local_a0 = local_a0 + *(float *)(local_d8 + 0x20);
      }
    }
    else {
      local_a8 = local_a8 + local_c0;
      local_a4 = local_a4 + local_bc;
      local_a0 = local_a0 + local_b8;
    }
  }
  uVar5 = (**(code **)(*DAT_803dca78 + 8))(&local_d8,0xffffffff,iVar4,uVar5);
LAB_800d53d4:
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  FUN_8028611c(uVar5);
  return;
}

