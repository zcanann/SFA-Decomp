// Function: FUN_800c4864
// Entry: 800c4864
// Size: 3692 bytes

void FUN_800c4864(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  int local_b8;
  undefined4 local_b4;
  int local_b0;
  undefined2 local_ac;
  undefined2 local_aa;
  undefined2 local_a8;
  undefined4 local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  undefined2 local_78;
  undefined2 local_76;
  uint local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined2 local_60;
  undefined2 local_5e;
  undefined2 local_5c;
  undefined local_5a;
  undefined local_58;
  undefined local_57;
  undefined local_56;
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
  undefined4 local_20;
  uint uStack28;
  
  uVar3 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  if (iVar1 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = 0xffffffff;
        goto LAB_800c56b8;
      }
      local_a0 = *(float *)(param_3 + 6);
      local_9c = *(float *)(param_3 + 8);
      local_98 = *(float *)(param_3 + 10);
      local_a4 = *(undefined4 *)(param_3 + 4);
      local_a8 = param_3[2];
      local_aa = param_3[1];
      local_ac = *param_3;
      local_56 = param_5;
    }
    local_74 = 0;
    local_70 = 0;
    local_5a = (undefined)uVar3;
    local_88 = FLOAT_803dff38;
    local_84 = FLOAT_803dff38;
    local_80 = FLOAT_803dff38;
    local_94 = FLOAT_803dff38;
    local_90 = FLOAT_803dff38;
    local_8c = FLOAT_803dff38;
    local_7c = FLOAT_803dff38;
    local_b0 = 0;
    local_b4 = 0xffffffff;
    local_58 = 0xff;
    local_57 = 0;
    local_76 = 0;
    local_60 = 0xffff;
    local_5e = 0xffff;
    local_5c = 0xffff;
    local_6c = 0xffff;
    local_68 = 0xffff;
    local_64 = 0xffff;
    local_78 = 0;
    local_b8 = iVar1;
    switch((int)uVar3) {
    case 300:
      local_7c = FLOAT_803dff3c;
      local_b0 = 10;
      local_58 = 0xff;
      local_74 = 0x40200;
      local_76 = 0xdb;
      break;
    case 0x12d:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3d4 = FLOAT_803dff38;
        DAT_8039c3d8 = FLOAT_803dff38;
        DAT_8039c3dc = FLOAT_803dff38;
        DAT_8039c3d0 = FLOAT_803dff40;
        DAT_8039c3c8 = 0;
        DAT_8039c3ca = 0;
        DAT_8039c3cc = 0;
        param_3 = &DAT_8039c3c8;
      }
      local_7c = FLOAT_803dff44;
      local_b0 = FUN_800221a0(0,0x1e);
      local_b0 = local_b0 + 0x46;
      if (*(float *)(param_3 + 4) <= FLOAT_803dff38) {
        local_58 = 0x41;
      }
      else {
        local_58 = 0x50;
      }
      local_74 = 0x80110;
      if (*(float *)(param_3 + 4) <= FLOAT_803dff38) {
        local_76 = 0xdb;
      }
      else {
        local_76 = 0x7b;
      }
      break;
    case 0x12e:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3d4 = FLOAT_803dff38;
        DAT_8039c3d8 = FLOAT_803dff38;
        DAT_8039c3dc = FLOAT_803dff38;
        DAT_8039c3d0 = FLOAT_803dff40;
        DAT_8039c3c8 = 0;
        DAT_8039c3ca = 0;
        DAT_8039c3cc = 0;
        param_3 = &DAT_8039c3c8;
      }
      uStack76 = FUN_800221a0(0xfffffff6,10);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = FLOAT_803dff48 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dffa0);
      local_84 = FLOAT_803dff38;
      local_80 = FLOAT_803dff4c;
      uStack68 = FUN_800221a0(1,3);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = FLOAT_803dff50 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dffa0);
      local_94 = FLOAT_803dff48 * *(float *)(param_3 + 6);
      local_8c = FLOAT_803dff48 * -*(float *)(param_3 + 10);
      uStack60 = FUN_800221a0(1,3);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_7c = FLOAT_803dff3c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dffa0);
      local_b0 = 0x19;
      local_58 = 0x55;
      local_74 = 0x80118;
      local_76 = 0x5f;
      break;
    case 0x12f:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3d4 = FLOAT_803dff38;
        DAT_8039c3d8 = FLOAT_803dff38;
        DAT_8039c3dc = FLOAT_803dff38;
        DAT_8039c3d0 = FLOAT_803dff40;
        DAT_8039c3c8 = 0;
        DAT_8039c3ca = 0;
        DAT_8039c3cc = 0;
        param_3 = &DAT_8039c3c8;
      }
      uStack60 = FUN_800221a0(0xfffffff6,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803dff48 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dffa0);
      local_84 = FLOAT_803dff38;
      local_80 = FLOAT_803dff4c;
      uStack68 = FUN_800221a0(1,3);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = FLOAT_803dff50 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dffa0);
      local_94 = FLOAT_803dff54 * *(float *)(param_3 + 6);
      local_8c = FLOAT_803dff54 * -*(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(1,3);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_7c = FLOAT_803dff58 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dffa0);
      local_b0 = 0x19;
      local_58 = 0x55;
      local_74 = 0x80118;
      local_76 = 0x5f;
      break;
    case 0x130:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3d4 = FLOAT_803dff38;
        DAT_8039c3d8 = FLOAT_803dff38;
        DAT_8039c3dc = FLOAT_803dff38;
        DAT_8039c3d0 = FLOAT_803dff40;
        DAT_8039c3c8 = 0;
        DAT_8039c3ca = 0;
        DAT_8039c3cc = 0;
        param_3 = &DAT_8039c3c8;
      }
      uStack60 = FUN_800221a0(0xfffffff6,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803dff48 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dffa0);
      local_84 = FLOAT_803dff38;
      local_80 = FLOAT_803dff4c;
      uStack68 = FUN_800221a0(1,3);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = FLOAT_803dff50 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dffa0);
      local_94 = FLOAT_803dff5c * *(float *)(param_3 + 6);
      local_8c = FLOAT_803dff5c * -*(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(1,3);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_7c = FLOAT_803dff60 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dffa0);
      local_b0 = 0x19;
      local_58 = 0x55;
      local_74 = 0x80118;
      local_76 = 0x5f;
      break;
    case 0x131:
      uStack60 = FUN_800221a0(0xfffffff4,0xc);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803dff50 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dffa0);
      uStack68 = FUN_800221a0(0xfffffff4,0xc);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803dff50 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dffa0) +
                 FLOAT_803dff64;
      local_80 = FLOAT_803dff4c;
      uStack76 = FUN_800221a0(5,10);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803dff68 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dffa0);
      local_7c = FLOAT_803dff6c;
      local_b0 = 100;
      local_58 = 0xff;
      local_74 = 0x100;
      local_76 = 0x33;
      break;
    case 0x132:
      uStack60 = FUN_800221a0(0xfffffff6,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803dff70 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dffa0);
      uStack68 = FUN_800221a0(0xfffffff6,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803dff70 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dffa0);
      uStack76 = FUN_800221a0(0xfffffff6,10);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_80 = FLOAT_803dff70 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dffa0);
      local_7c = FLOAT_803dff74;
      local_b0 = FUN_800221a0(0x78,0x96);
      local_57 = 0x1e;
      local_58 = 0xff;
      local_74 = 0x11;
      local_76 = 0x5f;
      break;
    case 0x133:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3d4 = FLOAT_803dff38;
        DAT_8039c3d8 = FLOAT_803dff38;
        DAT_8039c3dc = FLOAT_803dff38;
        DAT_8039c3d0 = FLOAT_803dff40;
        DAT_8039c3c8 = 0;
        DAT_8039c3ca = 0;
        DAT_8039c3cc = 0;
        param_3 = &DAT_8039c3c8;
      }
      local_88 = *(float *)(param_3 + 6);
      local_84 = *(float *)(param_3 + 8);
      local_80 = *(float *)(param_3 + 10);
      local_7c = FLOAT_803dff74;
      local_b0 = 5;
      local_58 = 0x80;
      local_74 = 0x80210;
      local_76 = 0x26d;
      break;
    case 0x134:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3d4 = FLOAT_803dff38;
        DAT_8039c3d8 = FLOAT_803dff38;
        DAT_8039c3dc = FLOAT_803dff38;
        DAT_8039c3d0 = FLOAT_803dff40;
        DAT_8039c3c8 = 0;
        DAT_8039c3ca = 0;
        DAT_8039c3cc = 0;
        param_3 = &DAT_8039c3c8;
      }
      uStack60 = FUN_800221a0(0xffffff38,200);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803dff78 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dffa0) +
                 *(float *)(param_3 + 6);
      local_84 = *(float *)(param_3 + 8);
      uStack68 = FUN_800221a0(0xffffff38,200);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = FLOAT_803dff78 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dffa0) +
                 *(float *)(param_3 + 10);
      uStack76 = FUN_800221a0(5,0xc);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_7c = FLOAT_803dff7c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dffa0);
      local_b0 = 0xc;
      local_58 = FUN_800221a0(0x96,0xfa);
      local_74 = local_74 | 0x80210;
      local_76 = 0xe0;
      break;
    case 0x135:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3d4 = FLOAT_803dff38;
        DAT_8039c3d8 = FLOAT_803dff38;
        DAT_8039c3dc = FLOAT_803dff38;
        DAT_8039c3d0 = FLOAT_803dff40;
        DAT_8039c3c8 = 0;
        DAT_8039c3ca = 0;
        DAT_8039c3cc = 0;
        param_3 = &DAT_8039c3c8;
      }
      uStack60 = FUN_800221a0(0xfffffff6,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803dff70 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dffa0);
      uStack68 = FUN_800221a0(0xffffffe2,0);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803dff70 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dffa0);
      uStack76 = FUN_800221a0(0xfffffff6,10);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_80 = FLOAT_803dff70 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dffa0);
      uStack52 = FUN_800221a0(0xfffffff1,0xf);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803dff74 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dffa0);
      uStack44 = FUN_800221a0(0xf,0x23);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = FLOAT_803dff80 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dffa0);
      uStack36 = FUN_800221a0(0xfffffff1,0xf);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803dff74 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dffa0);
      uStack28 = FUN_800221a0(100,0x96);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_7c = FLOAT_803dff84 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dffa0);
      local_b0 = FUN_800221a0(0x32,0x50);
      local_57 = FUN_800221a0(10,0x1e);
      local_74 = 0x218;
      local_76 = param_3[2];
      break;
    case 0x136:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3d4 = FLOAT_803dff38;
        DAT_8039c3d8 = FLOAT_803dff38;
        DAT_8039c3dc = FLOAT_803dff38;
        DAT_8039c3d0 = FLOAT_803dff40;
        DAT_8039c3c8 = 0;
        DAT_8039c3ca = 0;
        DAT_8039c3cc = 0;
        param_3 = &DAT_8039c3c8;
      }
      uStack28 = FUN_800221a0(-(int)(short)param_3[1]);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dffa0) / FLOAT_803dff88;
      uStack36 = FUN_800221a0(-(int)(short)param_3[1]);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_84 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dffa0) / FLOAT_803dff88;
      uStack44 = FUN_800221a0(-(int)(short)param_3[1]);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dffa0) / FLOAT_803dff88;
      local_7c = FLOAT_803dff8c;
      local_b0 = FUN_800221a0(0x14,0x1e);
      local_74 = 0x100200;
      local_76 = param_3[2];
      break;
    case 0x137:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3d4 = FLOAT_803dff38;
        DAT_8039c3d8 = FLOAT_803dff38;
        DAT_8039c3dc = FLOAT_803dff38;
        DAT_8039c3d0 = FLOAT_803dff40;
        DAT_8039c3c8 = 0;
        DAT_8039c3ca = 0;
        DAT_8039c3cc = 0;
        param_3 = &DAT_8039c3c8;
      }
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = 0xffffffff;
        goto LAB_800c56b8;
      }
      uStack28 = FUN_800221a0(0,100);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = FLOAT_803dff94 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dffa0) +
                 FLOAT_803dff90;
      uStack36 = FUN_800221a0(0,100);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803dff98 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dffa0) +
                 FLOAT_803dff74;
      uStack44 = FUN_800221a0(0,100);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dff98 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dffa0) +
                 FLOAT_803dff74;
      FUN_80021ac8(param_3,&local_94);
      uStack52 = FUN_800221a0(0x14,0x1e);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_7c = FLOAT_803dff9c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dffa0);
      local_58 = 0xff;
      local_b0 = 0xf0;
      local_57 = 0x10;
      local_b4 = 0x138;
      local_74 = 0x480200;
      local_70 = 0x100000;
      local_76 = 0x167;
      break;
    case 0x138:
      uStack28 = FUN_800221a0(0x14,0x1e);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_7c = FLOAT_803dff7c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dffa0);
      local_58 = 0x37;
      local_b0 = 4;
      local_57 = 0x10;
      local_74 = 0x80201;
      local_70 = 2;
      local_76 = 0x167;
      break;
    default:
      uVar2 = 0xffffffff;
      goto LAB_800c56b8;
    }
    local_74 = local_74 | param_4;
    if (((local_74 & 1) != 0) && ((local_74 & 2) != 0)) {
      local_74 = local_74 ^ 2;
    }
    if ((local_74 & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_b8 != 0) {
          local_88 = local_88 + *(float *)(local_b8 + 0x18);
          local_84 = local_84 + *(float *)(local_b8 + 0x1c);
          local_80 = local_80 + *(float *)(local_b8 + 0x20);
        }
      }
      else {
        local_88 = local_88 + local_a0;
        local_84 = local_84 + local_9c;
        local_80 = local_80 + local_98;
      }
    }
    uVar2 = (**(code **)(*DAT_803dca78 + 8))(&local_b8,0xffffffff,(int)uVar3,0);
  }
LAB_800c56b8:
  FUN_80286128(uVar2);
  return;
}

