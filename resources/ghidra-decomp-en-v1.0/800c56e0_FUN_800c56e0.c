// Function: FUN_800c56e0
// Entry: 800c56e0
// Size: 3780 bytes

void FUN_800c56e0(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)

{
  undefined2 *puVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  undefined2 local_c8;
  undefined2 local_c6;
  undefined2 local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  undefined2 *local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined2 local_a4;
  undefined2 local_a2;
  undefined2 local_a0;
  undefined4 local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  short local_6e;
  uint local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined2 local_58;
  undefined2 local_56;
  undefined2 local_54;
  undefined local_52;
  undefined local_50;
  undefined local_4f;
  undefined local_4e;
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
  undefined4 local_20;
  uint uStack28;
  
  uVar3 = FUN_802860d8();
  puVar1 = (undefined2 *)((ulonglong)uVar3 >> 0x20);
  if (puVar1 == (undefined2 *)0x0) {
    uVar2 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = 0xffffffff;
        goto LAB_800c658c;
      }
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      local_9c = *(undefined4 *)(param_3 + 4);
      local_a0 = param_3[2];
      local_a2 = param_3[1];
      local_a4 = *param_3;
      local_4e = param_5;
    }
    local_6c = 0;
    local_68 = 0;
    local_52 = (undefined)uVar3;
    local_80 = FLOAT_803dffa8;
    local_7c = FLOAT_803dffa8;
    local_78 = FLOAT_803dffa8;
    local_8c = FLOAT_803dffa8;
    local_88 = FLOAT_803dffa8;
    local_84 = FLOAT_803dffa8;
    local_74 = FLOAT_803dffa8;
    local_a8 = 0;
    local_ac = 0xffffffff;
    local_50 = 0xff;
    local_4f = 0;
    local_6e = 0;
    local_58 = 0xffff;
    local_56 = 0xffff;
    local_54 = 0xffff;
    local_64 = 0xffff;
    local_60 = 0xffff;
    local_5c = 0xffff;
    local_b0 = puVar1;
    switch((int)uVar3) {
    case 0x47e:
      local_74 = FLOAT_803dffac;
      local_a8 = FUN_800221a0(0x32,0x3c);
      local_50 = 0x4b;
      local_6c = 0x180110;
      local_68 = 0x4000800;
      local_6e = 0x159;
      break;
    default:
      uVar2 = 0xffffffff;
      goto LAB_800c658c;
    case 0x483:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3ec = FLOAT_803dffa8;
        DAT_8039c3f0 = FLOAT_803dffa8;
        DAT_8039c3f4 = FLOAT_803dffa8;
        DAT_8039c3e8 = FLOAT_803dffb0;
        DAT_8039c3e0 = 0;
        DAT_8039c3e2 = 0;
        DAT_8039c3e4 = 0;
        param_3 = &DAT_8039c3e0;
      }
      uStack68 = FUN_800221a0(0xfffffff6,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfff8);
      uStack60 = FUN_800221a0(0xfffffff6,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfff8);
      uStack52 = FUN_800221a0(0xffffff9c,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803dffb4 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfff8);
      uStack44 = FUN_800221a0(0x28,0x50);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803dffb4 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfff8);
      uStack36 = FUN_800221a0(0xffffff9c,100);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_84 = FLOAT_803dffb4 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfff8);
      local_74 = FLOAT_803dffb8;
      local_a8 = 0x3c;
      local_6c = 0x81080200;
      local_68 = 0x8000000;
      local_6e = 0x2b;
      local_50 = 0x3c;
      break;
    case 0x484:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3ec = FLOAT_803dffa8;
        DAT_8039c3f0 = FLOAT_803dffa8;
        DAT_8039c3f4 = FLOAT_803dffa8;
        DAT_8039c3e8 = FLOAT_803dffb0;
        DAT_8039c3e0 = 0;
        DAT_8039c3e2 = 0;
        DAT_8039c3e4 = 0;
        param_3 = &DAT_8039c3e0;
      }
      uStack36 = FUN_800221a0(0xffffff9c,100);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803dffb8 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfff8);
      uStack44 = FUN_800221a0(0x14,0x50);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803dffb8 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfff8);
      uStack52 = FUN_800221a0(0xffffff9c,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803dffb8 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfff8);
      local_74 = FLOAT_803dffbc;
      local_a8 = 0x3c;
      local_68 = 0x200000;
      local_6c = 0x3000200;
      local_6e = 0x185;
      local_50 = 0x7f;
      break;
    case 0x485:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3ec = FLOAT_803dffa8;
        DAT_8039c3f0 = FLOAT_803dffa8;
        DAT_8039c3f4 = FLOAT_803dffa8;
        DAT_8039c3e8 = FLOAT_803dffb0;
        DAT_8039c3e0 = 0;
        DAT_8039c3e2 = 0;
        DAT_8039c3e4 = 0;
        param_3 = &DAT_8039c3e0;
      }
      uStack36 = FUN_800221a0(0xfffffff6,10);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfff8);
      uStack44 = FUN_800221a0(0xfffffff6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfff8);
      uStack52 = FUN_800221a0(0xffffff9c,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803dffb4 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfff8);
      uStack60 = FUN_800221a0(0x28,0x50);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803dffb4 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfff8);
      uStack68 = FUN_800221a0(0xffffff9c,100);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803dffb4 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfff8);
      local_74 = FLOAT_803dffb8;
      local_a8 = 0x3c;
      local_6c = 0x81080200;
      local_68 = 0x8000000;
      local_6e = 0x2b;
      local_50 = 0x3c;
      break;
    case 0x486:
      local_80 = FLOAT_803dffc0;
      local_7c = FLOAT_803dffc4;
      local_78 = FLOAT_803dffc0;
      uStack36 = FUN_800221a0(0xffffff9c,100);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803dffc8 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfff8);
      uStack44 = FUN_800221a0(0xffffffd8,0x140);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803dffcc * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfff8);
      uStack52 = FUN_800221a0(0xffffff9c,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803dffc8 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfff8);
      uStack60 = FUN_800221a0(10,0xf);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_74 = FLOAT_803dffd0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfff8);
      local_a8 = FUN_800221a0(0x2c,0x2f);
      local_6e = 0x156;
      local_50 = 0x7f;
      local_6c = 0xc80000;
      local_68 = 0x908;
      break;
    case 0x487:
      if (param_6 == (float *)0x0) {
        uVar2 = 0;
        goto LAB_800c658c;
      }
      local_8c = *param_6;
      local_88 = param_6[1];
      local_84 = param_6[2];
      local_74 = FLOAT_803dffd4;
      local_50 = 0x40;
      local_a8 = 100;
      local_6c = 0x3000200;
      local_6e = 0x62;
      local_68 = 0x200000;
      break;
    case 0x488:
      uStack36 = FUN_800221a0(0xffffffe8,0x18);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_80 = FLOAT_803dffc0 + (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfff8);
      local_7c = FLOAT_803dffa8;
      uStack44 = FUN_800221a0(0xffffffe8,0x18);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = FLOAT_803dffc0 + (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfff8);
      uStack52 = FUN_800221a0(0xfffffffb,5);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803dffbc * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfff8);
      uStack60 = FUN_800221a0(2,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803dffbc * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfff8);
      uStack68 = FUN_800221a0(0xfffffffb,5);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803dffbc * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfff8);
      local_74 = FLOAT_803dffb4;
      local_a8 = 0x6e;
      local_6c = 0x80180200;
      local_68 = 0x8000000;
      local_6e = 0x2b;
      local_50 = 0xff;
      break;
    case 0x489:
      local_74 = FLOAT_803dffd8;
      local_a8 = FUN_800221a0(0x32,100);
      local_50 = 0x7f;
      local_6c = 0x1180100;
      local_6e = 0x2b;
      local_68 = 0x4000000;
      break;
    case 0x48a:
      uStack36 = FUN_800221a0(0xffffffce,0x32);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803dffb4 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfff8);
      uStack44 = FUN_800221a0(0x1e,0x32);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803dffb4 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfff8);
      uStack52 = FUN_800221a0(0xffffffce,0x32);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803dffb4 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfff8);
      local_74 = FLOAT_803dffdc;
      local_a8 = FUN_800221a0(0x32,0x46);
      local_50 = 0x7f;
      local_6c = 0x1180100;
      local_68 = 0x8000000;
      local_6e = 0x2b;
      break;
    case 0x48b:
      uStack36 = FUN_800221a0(0xffffffce,0x32);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfff8);
      local_7c = FLOAT_803dffe0;
      uStack44 = FUN_800221a0(0xffffffce,0x32);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfff8);
      uStack52 = FUN_800221a0(0xffffffec,0x14);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803dffbc * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfff8);
      uStack60 = FUN_800221a0(0xffffffec,0);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803dffb8 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfff8);
      uStack68 = FUN_800221a0(0xffffffec,0x14);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803dffbc * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfff8);
      uStack28 = FUN_800221a0(0,10);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803dffe8 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfff8) +
                 FLOAT_803dffe4;
      local_a8 = FUN_800221a0(0xbe,0xfa);
      local_6c = 0x81088000;
      local_6e = FUN_800221a0(0,2);
      local_6e = local_6e + 0x208;
      local_58 = 0xb400;
      local_56 = 0x8000;
      local_54 = 0;
      local_64 = 0xb400;
      local_60 = 0xa000;
      local_5c = 0;
      local_68 = 0x20;
      local_50 = 0xd2;
      break;
    case 0x48c:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3ec = FLOAT_803dffa8;
        DAT_8039c3f0 = FLOAT_803dffa8;
        DAT_8039c3f4 = FLOAT_803dffa8;
        DAT_8039c3e8 = FLOAT_803dffb0;
        DAT_8039c3e0 = 0;
        DAT_8039c3e2 = 0;
        DAT_8039c3e4 = 0;
      }
      if (param_6 == (float *)0x0) {
        uVar2 = 0xffffffff;
        goto LAB_800c658c;
      }
      if (*param_6 == 0.0) {
        uStack28 = FUN_800221a0(8,0x11);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_74 = FLOAT_803dffec * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfff8)
        ;
        local_a8 = FUN_800221a0(5,10);
        local_50 = 100;
        local_6c = 0x80110;
        local_68 = 0x4000800;
      }
      else if (*param_6 == 1.401298e-45) {
        uStack28 = FUN_800221a0(0xffffffce,0x32);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_8c = FLOAT_803dffb4 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfff8)
        ;
        uStack36 = FUN_800221a0(0xffffffce,0x32);
        uStack36 = uStack36 ^ 0x80000000;
        local_28 = 0x43300000;
        local_88 = FLOAT_803dffb4 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfff8)
        ;
        uStack44 = FUN_800221a0(0,0x32);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_84 = FLOAT_803dffb4 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfff8)
        ;
        uStack52 = FUN_800221a0(10,0x14);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_74 = FLOAT_803dfff0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfff8)
        ;
        local_a8 = 0x2d;
        local_50 = 0;
        local_6c = 0x880014;
        local_68 = 0x4010808;
      }
      else {
        uStack28 = FUN_800221a0(0xffffffd8,0x28);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_8c = FLOAT_803dffb4 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfff8)
        ;
        uStack36 = FUN_800221a0(0xfffffff6,0x1e);
        uStack36 = uStack36 ^ 0x80000000;
        local_28 = 0x43300000;
        local_88 = FLOAT_803dffd8 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfff8)
        ;
        uStack44 = FUN_800221a0(0,0x28);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_84 = FLOAT_803dffd8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfff8)
        ;
        local_bc = FLOAT_803dffa8;
        local_b8 = FLOAT_803dffa8;
        local_b4 = FLOAT_803dffa8;
        local_c0 = FLOAT_803dffb0;
        local_c4 = 0;
        local_c6 = 0;
        local_c8 = *puVar1;
        FUN_80021ac8(&local_c8,&local_8c);
        local_74 = FLOAT_803dffb4;
        local_a8 = 100;
        local_50 = 0xff;
        local_68 = 0x300800;
        local_6c = 0x3000210;
      }
      local_6e = FUN_800221a0(0x156,0x157);
    }
    local_6c = local_6c | param_4;
    if (((local_6c & 1) != 0) && ((local_6c & 2) != 0)) {
      local_6c = local_6c ^ 2;
    }
    if ((local_6c & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_b0 != (undefined2 *)0x0) {
          local_80 = local_80 + *(float *)(local_b0 + 0xc);
          local_7c = local_7c + *(float *)(local_b0 + 0xe);
          local_78 = local_78 + *(float *)(local_b0 + 0x10);
        }
      }
      else {
        local_80 = local_80 + local_98;
        local_7c = local_7c + local_94;
        local_78 = local_78 + local_90;
      }
    }
    uVar2 = (**(code **)(*DAT_803dca78 + 8))(&local_b0,0xffffffff,(int)uVar3,0);
  }
LAB_800c658c:
  FUN_80286124(uVar2);
  return;
}

