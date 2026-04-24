// Function: FUN_800af688
// Entry: 800af688
// Size: 14816 bytes

void FUN_800af688(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5)

{
  undefined2 *puVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  undefined2 local_d8;
  undefined2 local_d6;
  undefined2 local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  undefined2 *local_c0;
  undefined4 local_bc;
  int local_b8;
  undefined2 local_b4;
  undefined2 local_b2;
  undefined2 local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  undefined2 local_80;
  undefined2 local_7e;
  uint local_7c;
  undefined4 local_78;
  uint local_74;
  uint local_70;
  int local_6c;
  ushort local_68;
  undefined2 local_66;
  short local_64;
  undefined local_62;
  undefined local_60;
  char local_5f;
  undefined local_5e;
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
  
  uVar5 = FUN_802860d8();
  puVar1 = (undefined2 *)((ulonglong)uVar5 >> 0x20);
  iVar4 = (int)uVar5;
  FLOAT_803db7b0 = FLOAT_803db7b0 + FLOAT_803df720;
  if (FLOAT_803df728 < FLOAT_803db7b0) {
    FLOAT_803db7b0 = FLOAT_803df724;
  }
  FLOAT_803db7b4 = FLOAT_803db7b4 + FLOAT_803df72c;
  if (FLOAT_803df728 < FLOAT_803db7b4) {
    FLOAT_803db7b4 = FLOAT_803df730;
  }
  if (puVar1 == (undefined2 *)0x0) {
    uVar2 = 0xffffffff;
    goto LAB_800b3050;
  }
  if ((param_4 & 0x200000) != 0) {
    if (param_3 == (undefined2 *)0x0) {
      uVar2 = 0xffffffff;
      goto LAB_800b3050;
    }
    local_a8 = *(float *)(param_3 + 6);
    local_a4 = *(float *)(param_3 + 8);
    local_a0 = *(float *)(param_3 + 10);
    local_ac = *(float *)(param_3 + 4);
    local_b0 = param_3[2];
    local_b2 = param_3[1];
    local_b4 = *param_3;
    local_5e = param_5;
  }
  local_7c = 0;
  local_78 = 0;
  local_62 = (undefined)uVar5;
  local_90 = FLOAT_803df734;
  local_8c = FLOAT_803df734;
  local_88 = FLOAT_803df734;
  local_9c = FLOAT_803df734;
  local_98 = FLOAT_803df734;
  local_94 = FLOAT_803df734;
  local_84 = FLOAT_803df734;
  local_b8 = 0;
  local_bc = 0xffffffff;
  local_60 = 0xff;
  local_5f = '\0';
  local_7e = 0;
  local_68 = 0xffff;
  local_66 = 0xffff;
  local_64 = -1;
  local_74 = 0xffff;
  local_70 = 0xffff;
  local_6c = 0xffff;
  local_80 = 0;
  local_c0 = puVar1;
  if (iVar4 == 0x3a7) {
    local_84 = FLOAT_803df754;
    local_b8 = 0x50;
    local_60 = 0xff;
    local_7c = 0x1c0100;
    local_7e = 0x73;
  }
  else if (iVar4 < 0x3a7) {
    if (iVar4 == 0x395) {
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c32c = FLOAT_803df734;
        DAT_8039c330 = FLOAT_803df734;
        DAT_8039c334 = FLOAT_803df734;
        DAT_8039c328 = FLOAT_803df728;
        DAT_8039c320 = 0;
        DAT_8039c322 = 0;
        DAT_8039c324 = 0;
        param_3 = &DAT_8039c320;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_88 = *(float *)(param_3 + 6);
        local_8c = *(float *)(param_3 + 8);
        local_90 = *(float *)(param_3 + 10);
      }
      local_b4 = FUN_800221a0(0,0xffff);
      local_b2 = FUN_800221a0(0,0xffff);
      local_b4 = FUN_800221a0(0,0xffff);
      local_a8 = FLOAT_803df734;
      local_a4 = FLOAT_803df734;
      local_a0 = FLOAT_803df734;
      uStack44 = FUN_800221a0(0x1e,0x28);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803df740 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
      local_b8 = FUN_800221a0(0x50,100);
      local_60 = 0xff;
      local_7c = 0x6100110;
      local_7e = 0xc79;
    }
    else if (iVar4 < 0x395) {
      if (iVar4 == 0x38c) {
        local_8c = FLOAT_803df830;
        local_84 = FLOAT_803df834;
        local_b8 = 400;
        local_78 = 0x100;
        local_7e = 0x167;
        local_60 = 0x9b;
      }
      else if (iVar4 < 0x38c) {
        if (iVar4 == 0x387) {
          uStack36 = FUN_800221a0(0xffffffe7,0x19);
          uStack36 = uStack36 ^ 0x80000000;
          local_28 = 0x43300000;
          local_90 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803df860);
          uStack44 = FUN_800221a0(1,5);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_8c = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          uStack52 = FUN_800221a0(0xffffffe7,0x19);
          uStack52 = uStack52 ^ 0x80000000;
          local_38 = 0x43300000;
          local_88 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
          uStack60 = FUN_800221a0(0xfffffff8,8);
          uStack60 = uStack60 ^ 0x80000000;
          local_40 = 0x43300000;
          local_9c = FLOAT_803df738 *
                     (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
          uStack68 = FUN_800221a0(10,0x14);
          uStack68 = uStack68 ^ 0x80000000;
          local_48 = 0x43300000;
          local_98 = FLOAT_803df724 *
                     (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
          uStack76 = FUN_800221a0(0xfffffff8,8);
          uStack76 = uStack76 ^ 0x80000000;
          local_50 = 0x43300000;
          local_94 = FLOAT_803df738 *
                     (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803df860);
          uStack84 = FUN_800221a0(0,10);
          uStack84 = uStack84 ^ 0x80000000;
          local_58 = 0x43300000;
          local_84 = FLOAT_803df768 *
                     (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803df860) +
                     FLOAT_803df850;
          local_b8 = FUN_800221a0(0x78,0x8c);
          local_60 = 0xff;
          local_bc = 0x385;
          local_78 = 0x200000;
          local_7c = 0x81000120;
          local_7e = 0xc0a;
        }
        else if (iVar4 < 0x387) {
          if (iVar4 == 0x385) {
            uStack36 = FUN_800221a0(2,0x14);
            uStack36 = uStack36 ^ 0x80000000;
            local_28 = 0x43300000;
            local_98 = FLOAT_803df764 *
                       (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803df860);
            local_84 = FLOAT_803df854;
            local_b8 = 0x1e;
            local_60 = 0x9b;
            local_7c = 0x180100;
            local_7e = 0x5f;
            local_68 = 0xffff;
            iVar3 = FUN_800221a0(0,50000);
            local_70 = iVar3 + 0x3cafU & 0xffff;
            local_66 = (undefined2)local_70;
            local_64 = 0;
            local_74 = (uint)local_68;
            local_6c = 0;
            local_78 = 0x20;
          }
          else if (iVar4 < 0x385) {
            if (iVar4 < 900) goto LAB_800b2f6c;
            uStack36 = FUN_800221a0(0xffffffc9,0x37);
            uStack36 = uStack36 ^ 0x80000000;
            local_28 = 0x43300000;
            local_90 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803df860);
            uStack44 = FUN_800221a0(10,0xf);
            uStack44 = uStack44 ^ 0x80000000;
            local_30 = 0x43300000;
            local_8c = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
            uStack52 = FUN_800221a0(0xffffffc9,0x37);
            uStack52 = uStack52 ^ 0x80000000;
            local_38 = 0x43300000;
            local_88 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
            uStack60 = FUN_800221a0(0xfffffff8,8);
            uStack60 = uStack60 ^ 0x80000000;
            local_40 = 0x43300000;
            local_9c = FLOAT_803df738 *
                       (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
            uStack68 = FUN_800221a0(10,0x14);
            uStack68 = uStack68 ^ 0x80000000;
            local_48 = 0x43300000;
            local_98 = FLOAT_803df724 *
                       (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
            uStack76 = FUN_800221a0(0xfffffff8,8);
            uStack76 = uStack76 ^ 0x80000000;
            local_50 = 0x43300000;
            local_94 = FLOAT_803df738 *
                       (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803df860);
            uStack84 = FUN_800221a0(0,10);
            uStack84 = uStack84 ^ 0x80000000;
            local_58 = 0x43300000;
            local_84 = FLOAT_803df768 *
                       (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803df860) +
                       FLOAT_803df850;
            local_b8 = FUN_800221a0(0x78,0x8c);
            local_60 = 0xff;
            local_bc = 0x385;
            local_78 = 0x200000;
            local_7c = 0x1001100;
            local_7e = 0xc0a;
          }
          else {
            uStack36 = FUN_800221a0(1,5);
            uStack36 = uStack36 ^ 0x80000000;
            local_28 = 0x43300000;
            local_8c = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803df860);
            uStack44 = FUN_800221a0(10,0x14);
            uStack44 = uStack44 ^ 0x80000000;
            local_30 = 0x43300000;
            local_98 = FLOAT_803df7a8 *
                       (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
            uStack52 = FUN_800221a0(0,10);
            uStack52 = uStack52 ^ 0x80000000;
            local_38 = 0x43300000;
            local_84 = FLOAT_803df768 *
                       (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860) +
                       FLOAT_803df858;
            local_b8 = FUN_800221a0(0xe6,0x118);
            local_60 = 0x9b;
            local_7c = 0x80480200;
            local_7e = 0xc0d;
          }
        }
        else if (iVar4 == 0x38a) {
          if (param_3 == (undefined2 *)0x0) {
            DAT_8039c32c = FLOAT_803df734;
            DAT_8039c330 = FLOAT_803df734;
            DAT_8039c334 = FLOAT_803df734;
            DAT_8039c328 = FLOAT_803df728;
            DAT_8039c320 = 0;
            DAT_8039c322 = 0;
            DAT_8039c324 = 0;
            param_3 = &DAT_8039c320;
          }
          uStack44 = FUN_800221a0(0xfffffff6,0xfffffff6);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_90 = FLOAT_803df724 *
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          uStack52 = FUN_800221a0(0xffffffec,0xfffffff6);
          uStack52 = uStack52 ^ 0x80000000;
          local_38 = 0x43300000;
          local_8c = FLOAT_803df724 *
                     (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
          uStack60 = FUN_800221a0(0xfffffff6,10);
          uStack60 = uStack60 ^ 0x80000000;
          local_40 = 0x43300000;
          local_88 = FLOAT_803df724 *
                     (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
          uStack68 = FUN_800221a0(0xfffffff6,10);
          uStack68 = uStack68 ^ 0x80000000;
          local_48 = 0x43300000;
          local_9c = FLOAT_803df7dc *
                     (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
          uStack76 = FUN_800221a0(0xfffffff6,10);
          uStack76 = uStack76 ^ 0x80000000;
          local_50 = 0x43300000;
          local_94 = FLOAT_803df7dc *
                     (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803df860);
          local_60 = 0xff;
          if (param_3 != (undefined2 *)0x0) {
            local_90 = local_90 + *(float *)(param_3 + 6);
            local_8c = local_8c + *(float *)(param_3 + 8);
            local_88 = local_88 + *(float *)(param_3 + 10);
          }
          uStack44 = FUN_800221a0(10,0x14);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_84 = FLOAT_803df828 *
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          local_b8 = 0x55;
          local_7c = 0x100200;
          local_7e = 0x125;
          local_5f = FUN_800221a0(0,0x14);
          local_5f = local_5f + '\x04';
          local_68 = 0xffff;
          iVar3 = FUN_800221a0(0,10000);
          local_70 = iVar3 + 0xd8efU & 0xffff;
          local_66 = (undefined2)local_70;
          local_64 = 0;
          local_74 = local_68 / 10;
          local_70 = local_70 / 10;
          local_6c = 0;
          local_78 = 0xa0;
        }
        else if (iVar4 < 0x38a) {
          if (iVar4 < 0x389) {
            uStack36 = FUN_800221a0(0,0x10);
            uStack36 = uStack36 ^ 0x80000000;
            local_28 = 0x43300000;
            local_90 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803df860);
            uStack44 = FUN_800221a0(0xffffffd2,0x2e);
            uStack44 = uStack44 ^ 0x80000000;
            local_30 = 0x43300000;
            local_88 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
            uStack52 = FUN_800221a0(0x10,0x1e);
            uStack52 = uStack52 ^ 0x80000000;
            local_38 = 0x43300000;
            local_98 = FLOAT_803df748 *
                       (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
            local_84 = FLOAT_803df7ec;
            local_b8 = 100;
            local_60 = 0x37;
            local_5f = '\x10';
            local_7c = 0x100;
            local_78 = 0x100;
            local_7e = 0x1fb;
          }
          else {
            if (param_3 == (undefined2 *)0x0) {
              DAT_8039c32c = FLOAT_803df734;
              DAT_8039c330 = FLOAT_803df734;
              DAT_8039c334 = FLOAT_803df734;
              DAT_8039c328 = FLOAT_803df728;
              DAT_8039c320 = 0;
              DAT_8039c322 = 0;
              DAT_8039c324 = 0;
            }
            uStack44 = FUN_800221a0(0xfffffffb,5);
            uStack44 = uStack44 ^ 0x80000000;
            local_30 = 0x43300000;
            local_90 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
            uStack52 = FUN_800221a0(1,5);
            uStack52 = uStack52 ^ 0x80000000;
            local_38 = 0x43300000;
            local_8c = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
            uStack60 = FUN_800221a0(0xfffffffb,5);
            uStack60 = uStack60 ^ 0x80000000;
            local_40 = 0x43300000;
            local_88 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
            uStack68 = FUN_800221a0(0,600);
            uStack68 = uStack68 ^ 0x80000000;
            local_48 = 0x43300000;
            local_d0 = FLOAT_803df7dc *
                       (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860) +
                       FLOAT_803df844;
            uStack76 = FUN_800221a0(0,200);
            uStack76 = uStack76 ^ 0x80000000;
            local_50 = 0x43300000;
            local_98 = FLOAT_803df720 *
                       (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803df860) +
                       FLOAT_803df728;
            uStack84 = FUN_800221a0(0,0x14);
            uStack84 = uStack84 ^ 0x80000000;
            local_58 = 0x43300000;
            local_98 = local_98 * local_d0;
            local_9c = (FLOAT_803df7b0 *
                        (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803df860) +
                       FLOAT_803df724) * local_d0;
            uStack36 = FUN_800221a0(0,10);
            uStack36 = uStack36 ^ 0x80000000;
            local_28 = 0x43300000;
            local_84 = FLOAT_803df84c *
                       (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803df860) +
                       FLOAT_803df848;
            local_b8 = FUN_800221a0(0xb4,200);
            local_60 = 0xff;
            local_7c = 0x3000120;
            local_78 = 0x200800;
            local_7e = 0xc0a;
            local_bc = 0x385;
          }
        }
        else {
          local_84 = FLOAT_803df82c;
          local_b8 = 0x4b;
          local_7c = 0x82000108;
          local_78 = 0x80;
          local_7e = 0xc0a;
          local_60 = 0xff;
        }
      }
      else if (iVar4 == 0x391) {
        if (param_3 == (undefined2 *)0x0) {
          DAT_8039c32c = FLOAT_803df734;
          DAT_8039c330 = FLOAT_803df734;
          DAT_8039c334 = FLOAT_803df734;
          DAT_8039c328 = FLOAT_803df728;
          DAT_8039c320 = 0;
          DAT_8039c322 = 0;
          DAT_8039c324 = 0;
          param_3 = &DAT_8039c320;
        }
        if (param_3 == (undefined2 *)0x0) {
          local_88 = FLOAT_803df758;
          local_8c = FLOAT_803df75c;
        }
        else {
          local_88 = *(float *)(param_3 + 6);
          local_8c = *(float *)(param_3 + 8);
        }
        uStack44 = FUN_800221a0(0x1e,0x28);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_94 = FLOAT_803df76c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860)
        ;
        uStack52 = FUN_800221a0(0xfffffff6,10);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_9c = FLOAT_803df738 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860)
        ;
        uStack60 = FUN_800221a0(0xfffffffc,4);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_98 = FLOAT_803df764 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860)
        ;
        uStack68 = FUN_800221a0(0x28,0x32);
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_84 = FLOAT_803df770 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860)
        ;
        local_b8 = FUN_800221a0(0,0x3c);
        local_b8 = local_b8 + 0x50;
        local_60 = 0xff;
        local_7e = 0xc0a;
        local_78 = 0x200000;
        local_7c = 0x42000100;
      }
      else if (iVar4 < 0x391) {
        if (iVar4 == 0x38f) {
          uStack44 = FUN_800221a0(0xffffff74,0x8c);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_90 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          uStack52 = FUN_800221a0(0xffffffd8,0x8c);
          uStack52 = uStack52 ^ 0x80000000;
          local_38 = 0x43300000;
          local_8c = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
          uStack60 = FUN_800221a0(0xffffff74,0x8c);
          uStack60 = uStack60 ^ 0x80000000;
          local_40 = 0x43300000;
          local_88 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
          uStack68 = FUN_800221a0(0xffffffd8,0x28);
          uStack68 = uStack68 ^ 0x80000000;
          local_48 = 0x43300000;
          local_9c = FLOAT_803df73c *
                     (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
          uStack76 = FUN_800221a0(0xffffffd8,0x28);
          uStack76 = uStack76 ^ 0x80000000;
          local_50 = 0x43300000;
          local_98 = FLOAT_803df824 *
                     (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803df860);
          uStack84 = FUN_800221a0(0xffffffd8,0x28);
          uStack84 = uStack84 ^ 0x80000000;
          local_58 = 0x43300000;
          local_94 = FLOAT_803df73c *
                     (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803df860);
          local_84 = FLOAT_803df7e4;
          local_b8 = 0x96;
          local_60 = 0xff;
          local_7e = 0x167;
          local_78 = 0x300000;
          local_7c = 0x2000110;
        }
        else if (iVar4 < 0x38f) {
          if (iVar4 < 0x38e) {
            if (param_3 == (undefined2 *)0x0) {
              DAT_8039c32c = FLOAT_803df734;
              DAT_8039c330 = FLOAT_803df734;
              DAT_8039c334 = FLOAT_803df734;
              DAT_8039c328 = FLOAT_803df728;
              DAT_8039c320 = 0;
              DAT_8039c322 = 0;
              DAT_8039c324 = 0;
              param_3 = &DAT_8039c320;
            }
            if (param_3 != (undefined2 *)0x0) {
              local_90 = *(float *)(param_3 + 6);
              local_88 = *(float *)(param_3 + 10);
            }
            local_8c = FLOAT_803df838;
            uStack44 = FUN_800221a0(0xfffffff6,10);
            uStack44 = uStack44 ^ 0x80000000;
            local_30 = 0x43300000;
            local_9c = FLOAT_803df7b0 *
                       (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860) +
                       FLOAT_803df738;
            uStack52 = FUN_800221a0(0x32,100);
            uStack52 = uStack52 ^ 0x80000000;
            local_38 = 0x43300000;
            local_98 = FLOAT_803df738 *
                       (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
            uStack60 = FUN_800221a0(0xfffffff6,1);
            uStack60 = uStack60 ^ 0x80000000;
            local_40 = 0x43300000;
            local_94 = FLOAT_803df7b0 *
                       (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860) +
                       FLOAT_803df738;
            local_84 = FLOAT_803df83c;
            local_b8 = 200;
            local_7c = 0x3008000;
            local_78 = 0x200000;
            local_7e = 0x167;
            local_60 = 0xff;
          }
          else {
            uStack44 = FUN_800221a0(0xfffffff6,10);
            uStack44 = uStack44 ^ 0x80000000;
            local_30 = 0x43300000;
            local_9c = FLOAT_803df840 *
                       (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860) +
                       FLOAT_803df738;
            uStack52 = FUN_800221a0(0x32,100);
            uStack52 = uStack52 ^ 0x80000000;
            local_38 = 0x43300000;
            local_98 = FLOAT_803df7a8 *
                       (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
            uStack60 = FUN_800221a0(0xfffffff6,1);
            uStack60 = uStack60 ^ 0x80000000;
            local_40 = 0x43300000;
            local_94 = FLOAT_803df840 *
                       (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860) +
                       FLOAT_803df738;
            local_84 = FLOAT_803df83c;
            local_b8 = 0x50;
            local_7c = 0x3000000;
            local_78 = 0x200000;
            local_7e = 0x167;
            local_60 = 0xff;
          }
        }
        else {
          if (param_3 == (undefined2 *)0x0) {
            DAT_8039c32c = FLOAT_803df734;
            DAT_8039c330 = FLOAT_803df734;
            DAT_8039c334 = FLOAT_803df734;
            DAT_8039c328 = FLOAT_803df728;
            DAT_8039c320 = 0;
            DAT_8039c322 = 0;
            DAT_8039c324 = 0;
            param_3 = &DAT_8039c320;
          }
          if (param_3 == (undefined2 *)0x0) {
            local_88 = FLOAT_803df758;
            local_8c = FLOAT_803df75c;
          }
          else {
            local_88 = *(float *)(param_3 + 6);
            local_8c = *(float *)(param_3 + 8);
          }
          uStack44 = FUN_800221a0(0x1e,0x28);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_94 = FLOAT_803df760 *
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          uStack52 = FUN_800221a0(0xfffffff6,10);
          uStack52 = uStack52 ^ 0x80000000;
          local_38 = 0x43300000;
          local_9c = FLOAT_803df738 *
                     (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
          uStack60 = FUN_800221a0(0xfffffffc,4);
          uStack60 = uStack60 ^ 0x80000000;
          local_40 = 0x43300000;
          local_98 = FLOAT_803df764 *
                     (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
          uStack68 = FUN_800221a0(10,0x32);
          uStack68 = uStack68 ^ 0x80000000;
          local_48 = 0x43300000;
          local_84 = FLOAT_803df768 *
                     (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
          local_b8 = FUN_800221a0(0,10);
          local_b8 = local_b8 + 0x50;
          local_60 = 0xff;
          local_7e = 0x8e;
          local_7c = 0x40180100;
        }
      }
      else if (iVar4 == 0x393) {
        uStack44 = FUN_800221a0(0xffffff38,200);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_88 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
        uStack52 = FUN_800221a0(0,0x14);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_8c = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
        uStack60 = FUN_800221a0(0xfffffe70,400);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_90 = FLOAT_803df730 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860)
        ;
        uStack68 = FUN_800221a0(10,0x14);
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_98 = FLOAT_803df7b4 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860)
        ;
        local_84 = FLOAT_803df81c;
        local_b8 = FUN_800221a0(0x212,0x2a8);
        local_60 = 0xff;
        local_7c = 0x80480208;
        local_7e = 0xc0d;
      }
      else if (iVar4 < 0x393) {
        uStack44 = FUN_800221a0(0xffffffec,0x14);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_90 = FLOAT_803df724 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860)
        ;
        uStack52 = FUN_800221a0(0xffffffec,0x14);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_88 = FLOAT_803df724 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860)
        ;
        uStack60 = FUN_800221a0(0xffffffe2,0x1e);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_9c = FLOAT_803df7a8 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860)
        ;
        uStack68 = FUN_800221a0(0xffffffe2,0x1e);
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_98 = FLOAT_803df7a8 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860)
        ;
        uStack76 = FUN_800221a0(0xffffffe2,0x1e);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_94 = FLOAT_803df7a8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803df860)
        ;
        uStack84 = FUN_800221a0(10,0xf);
        uStack84 = uStack84 ^ 0x80000000;
        local_58 = 0x43300000;
        local_84 = FLOAT_803df820 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803df860)
        ;
        local_b8 = FUN_800221a0(0x5a,0x8c);
        local_7c = 0x80400201;
        local_5f = '\0';
        local_7e = 0x23b;
      }
      else {
        if (param_3 == (undefined2 *)0x0) {
          DAT_8039c32c = FLOAT_803df734;
          DAT_8039c330 = FLOAT_803df734;
          DAT_8039c334 = FLOAT_803df734;
          DAT_8039c328 = FLOAT_803df728;
          DAT_8039c320 = 0;
          DAT_8039c322 = 0;
          DAT_8039c324 = 0;
          param_3 = &DAT_8039c320;
        }
        if (param_3 != (undefined2 *)0x0) {
          local_88 = *(float *)(param_3 + 6);
          local_8c = *(float *)(param_3 + 8);
          local_90 = *(float *)(param_3 + 10);
        }
        local_b4 = FUN_800221a0(0,0xffff);
        local_b2 = FUN_800221a0(0,0xffff);
        local_b4 = FUN_800221a0(0,0xffff);
        local_a8 = FLOAT_803df734;
        local_a4 = FLOAT_803df734;
        local_a0 = FLOAT_803df734;
        uStack44 = FUN_800221a0(0x1e,0x28);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_84 = FLOAT_803df818 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860)
        ;
        local_b8 = FUN_800221a0(0x1e,0x2f);
        local_60 = 0xff;
        local_7c = 0x6100100;
        local_7e = 0xc79;
      }
    }
    else if (iVar4 == 0x39e) {
      uStack44 = FUN_800221a0(0xffffffd8,0x28);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_94 = FLOAT_803df764 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
      uStack52 = FUN_800221a0(0xffffffd8,0x28);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = FLOAT_803df764 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
      uStack60 = FUN_800221a0(0xffffffd8,0x28);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803df764 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
      local_60 = 0x87;
      uStack68 = FUN_800221a0(800,0x4b0);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803df7c0 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
      local_b8 = 100;
      local_7c = 0x1480200;
      local_78 = 0x100000;
      local_7e = 0x17c;
    }
    else if (iVar4 < 0x39e) {
      if (iVar4 == 0x39a) {
        local_60 = 0xff;
        local_84 = FLOAT_803df7bc;
        local_b8 = 300;
        local_7c = 0x480000;
        local_78 = 0x200;
        local_7e = 0x17c;
      }
      else if (iVar4 < 0x39a) {
        if (iVar4 == 0x398) {
          local_84 = FLOAT_803df7d0;
          local_b8 = 0x1e;
          local_60 = 0xff;
          local_7c = 0x80210;
          local_78 = 0x2000000;
          local_7e = 0xc0d;
        }
        else if (iVar4 < 0x398) {
          if (iVar4 < 0x397) {
            local_84 = FLOAT_803df754;
            local_b8 = 0x50;
            local_60 = 0xff;
            local_7c = 0x1c0100;
            local_7e = 0x159;
          }
          else {
            uStack44 = FUN_800221a0(0xfffffda8,600);
            uStack44 = uStack44 ^ 0x80000000;
            local_30 = 0x43300000;
            local_90 = FLOAT_803df738 *
                       (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
            uStack52 = FUN_800221a0(0xfffffda8,600);
            uStack52 = uStack52 ^ 0x80000000;
            local_38 = 0x43300000;
            local_88 = FLOAT_803df738 *
                       (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
            uStack60 = FUN_800221a0(800,0x4b0);
            uStack60 = uStack60 ^ 0x80000000;
            local_40 = 0x43300000;
            local_98 = FLOAT_803df7cc *
                       (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
            local_84 = FLOAT_803df7d0;
            local_b8 = 0xb4;
            local_60 = 0xff;
            local_7c = 0x80080110;
            local_bc = 0x398;
            local_7e = 0xc0d;
          }
        }
        else {
          if (param_3 == (undefined2 *)0x0) {
            DAT_8039c32c = FLOAT_803df734;
            DAT_8039c330 = FLOAT_803df734;
            DAT_8039c334 = FLOAT_803df734;
            DAT_8039c328 = FLOAT_803df728;
            DAT_8039c320 = 0;
            DAT_8039c322 = 0;
            DAT_8039c324 = 0;
            param_3 = &DAT_8039c320;
          }
          local_b2 = 0;
          local_b4 = 0;
          local_a8 = FLOAT_803df734;
          local_a4 = FLOAT_803df734;
          local_a0 = FLOAT_803df734;
          local_ac = FLOAT_803df728;
          if (param_3 != (undefined2 *)0x0) {
            local_90 = *(float *)(param_3 + 6);
            local_8c = FLOAT_803df7c4 + *(float *)(param_3 + 8);
            local_88 = *(float *)(param_3 + 10);
            local_b4 = *param_3;
            local_b0 = param_3[2];
          }
          local_60 = 0xff;
          local_84 = FLOAT_803df7c8;
          local_b8 = FUN_800221a0(0,10);
          local_b8 = local_b8 + 0x3c;
          local_7c = 0x6100100;
          local_78 = 0x2000000;
          local_7e = 100;
        }
      }
      else if (iVar4 == 0x39c) {
        local_60 = 0x37;
        local_84 = FLOAT_803df7a8;
        local_b8 = 300;
        local_7c = 0x480000;
        local_7e = 0x17c;
      }
      else if (iVar4 < 0x39c) {
        local_60 = 0xff;
        local_84 = FLOAT_803df740;
        local_b8 = 300;
        local_7c = 0x480000;
        local_7e = 0x17c;
      }
      else {
        local_60 = 0x87;
        local_84 = FLOAT_803df740;
        local_b8 = 0x1e;
        local_7c = 0x480200;
        local_78 = 0x2000;
        local_7e = 0x17c;
      }
    }
    else if (iVar4 == 0x3a3) {
      local_84 = FLOAT_803df73c;
      local_b8 = 4;
      local_7c = 0x80000;
      local_78 = 0x800;
      local_7e = 100;
      local_60 = 0x9b;
    }
    else if (iVar4 < 0x3a3) {
      if (iVar4 == 0x3a1) {
        if (param_3 == (undefined2 *)0x0) {
          DAT_8039c32c = FLOAT_803df734;
          DAT_8039c330 = FLOAT_803df734;
          DAT_8039c334 = FLOAT_803df734;
          DAT_8039c328 = FLOAT_803df728;
          DAT_8039c320 = 0;
          DAT_8039c322 = 0;
          DAT_8039c324 = 0;
          param_3 = &DAT_8039c320;
        }
        if (param_3 == (undefined2 *)0x0) {
          uVar2 = 0xffffffff;
          goto LAB_800b3050;
        }
        local_90 = *(float *)(param_3 + 6);
        local_8c = FLOAT_803df7a4 + *(float *)(param_3 + 8);
        local_88 = *(float *)(param_3 + 10);
        uStack44 = FUN_800221a0(0x14,0x1e);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_94 = FLOAT_803df724 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860)
        ;
        uStack52 = FUN_800221a0(0xffffffec,0x14);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_9c = FLOAT_803df7a8 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860)
        ;
        uStack60 = FUN_800221a0(0xffffffec,0x14);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_98 = FLOAT_803df7a8 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860)
        ;
        local_cc = FLOAT_803df734;
        local_c8 = FLOAT_803df734;
        local_c4 = FLOAT_803df734;
        local_d0 = FLOAT_803df728;
        local_d4 = puVar1[2];
        local_d6 = puVar1[1];
        local_d8 = *puVar1;
        FUN_80021ac8(&local_d8,&local_9c);
        local_84 = FLOAT_803df740;
        local_b8 = 0x32;
        local_60 = 0xff;
        local_7e = 0x167;
        local_78 = 0x200000;
        local_7c = 0x2000110;
      }
      else if (iVar4 < 0x3a1) {
        if (iVar4 < 0x3a0) {
          uStack44 = FUN_800221a0(10,0xe);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_98 = FLOAT_803df7b4 *
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          local_84 = FLOAT_803df7b8;
          local_b8 = 1;
          local_60 = 0x23;
          local_78 = 2;
          local_7e = 100;
        }
        else {
          if (param_3 == (undefined2 *)0x0) {
            DAT_8039c32c = FLOAT_803df734;
            DAT_8039c330 = FLOAT_803df734;
            DAT_8039c334 = FLOAT_803df734;
            DAT_8039c328 = FLOAT_803df728;
            DAT_8039c320 = 0;
            DAT_8039c322 = 0;
            DAT_8039c324 = 0;
            param_3 = &DAT_8039c320;
          }
          if (param_3 == (undefined2 *)0x0) {
            uVar2 = 0xffffffff;
            goto LAB_800b3050;
          }
          local_90 = *(float *)(param_3 + 6);
          local_8c = FLOAT_803df7a4 + *(float *)(param_3 + 8);
          local_88 = *(float *)(param_3 + 10);
          uStack44 = FUN_800221a0(0x14,0x1e);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_94 = FLOAT_803df7ac *
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          uStack52 = FUN_800221a0(0xffffffec,0x14);
          uStack52 = uStack52 ^ 0x80000000;
          local_38 = 0x43300000;
          local_9c = FLOAT_803df760 *
                     (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
          uStack60 = FUN_800221a0(2,6);
          uStack60 = uStack60 ^ 0x80000000;
          local_40 = 0x43300000;
          local_98 = FLOAT_803df7b0 *
                     (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
          local_cc = FLOAT_803df734;
          local_c8 = FLOAT_803df734;
          local_c4 = FLOAT_803df734;
          local_d0 = FLOAT_803df728;
          local_d4 = puVar1[2];
          local_d6 = puVar1[1];
          local_d8 = *puVar1;
          FUN_80021ac8(&local_d8,&local_9c);
          uStack68 = FUN_800221a0(8,0x14);
          uStack68 = uStack68 ^ 0x80000000;
          local_48 = 0x43300000;
          local_84 = FLOAT_803df764 *
                     (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
          local_b8 = FUN_800221a0(0x3c,0x78);
          local_7c = 0x80180000;
          local_78 = 0x1400020;
          local_7e = 0xc0b;
          local_60 = 0x7f;
          local_68 = 0xffff;
          local_66 = 0xffff;
          local_64 = -1;
          local_74 = 0x3caf;
          local_70 = 0x3caf;
          local_6c = 0x3caf;
        }
      }
      else {
LAB_800b00ec:
        if (param_3 == (undefined2 *)0x0) {
          DAT_8039c32c = FLOAT_803df734;
          DAT_8039c330 = FLOAT_803df734;
          DAT_8039c334 = FLOAT_803df734;
          DAT_8039c328 = FLOAT_803df728;
          DAT_8039c320 = 0;
          DAT_8039c322 = 0;
          DAT_8039c324 = 0;
          param_3 = &DAT_8039c320;
        }
        if (param_3 == (undefined2 *)0x0) {
          uVar2 = 0xffffffff;
          goto LAB_800b3050;
        }
        uStack44 = FUN_800221a0(0xffffff9c,100);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_9c = *(float *)(param_3 + 4) *
                   FLOAT_803df78c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860)
        ;
        uStack52 = FUN_800221a0(0x50,0x8c);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_98 = *(float *)(param_3 + 4) *
                   FLOAT_803df790 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860)
        ;
        uStack60 = FUN_800221a0(0xffffff9c,100);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_94 = *(float *)(param_3 + 4) *
                   FLOAT_803df794 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860)
        ;
        uStack68 = FUN_800221a0(0xffffff9c,100);
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_90 = FLOAT_803df798 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860)
        ;
        local_8c = FLOAT_803df75c;
        uStack76 = FUN_800221a0(0xffffff9c,100);
        uStack76 = uStack76 ^ 0x80000000;
        local_50 = 0x43300000;
        local_88 = FLOAT_803df79c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803df860)
        ;
        uStack84 = FUN_800221a0(0x16,0x46);
        uStack84 = uStack84 ^ 0x80000000;
        local_58 = 0x43300000;
        local_84 = *(float *)(param_3 + 4) *
                   FLOAT_803df7a0 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803df860)
        ;
        local_b8 = FUN_800221a0(0xe,0x30);
        local_b8 = local_b8 + 0x29;
        local_7e = 0x60;
        local_68 = 0xef75;
        local_66 = 0xc26e;
        local_64 = 0x4aab;
        local_74 = 0xfe9f;
        local_70 = 0x796c;
        local_6c = 0x57a0;
        local_60 = FUN_800221a0(0x29,100);
        local_7c = 0x80080108;
        if (iVar4 == 0x3a2) {
          local_7c = 0xa0080108;
        }
        local_78 = 0x8400820;
      }
    }
    else if (iVar4 == 0x3a5) {
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c32c = FLOAT_803df734;
        DAT_8039c330 = FLOAT_803df734;
        DAT_8039c334 = FLOAT_803df734;
        DAT_8039c328 = FLOAT_803df728;
        DAT_8039c320 = 0;
        DAT_8039c322 = 0;
        DAT_8039c324 = 0;
        param_3 = &DAT_8039c320;
      }
      if (param_3 == (undefined2 *)0x0) {
        local_88 = FLOAT_803df758;
        local_8c = FLOAT_803df75c;
      }
      else {
        local_88 = *(float *)(param_3 + 6);
        local_8c = *(float *)(param_3 + 8);
      }
      uStack68 = FUN_800221a0(0x1e,0x28);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = FLOAT_803df760 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
      uStack76 = FUN_800221a0(0xfffffff6,10);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803df738 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803df860);
      uStack84 = FUN_800221a0(0xfffffffc,4);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_98 = FLOAT_803df764 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803df860);
      uStack60 = FUN_800221a0(10,0x32);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803df768 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
      local_b8 = FUN_800221a0(0,10);
      local_b8 = local_b8 + 0x50;
      local_60 = 0xff;
      local_7e = 0x8e;
      local_7c = 0x40180100;
    }
    else if (iVar4 < 0x3a5) {
      uStack60 = FUN_800221a0(0x19,100);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803df774 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
      uStack68 = FUN_800221a0(0x42,100);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803df778 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
      uStack76 = FUN_800221a0(0x11,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = FLOAT_803df77c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803df860);
      uStack84 = FUN_800221a0(0xffffff9c,100);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_90 = FLOAT_803df780 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803df860);
      FUN_800221a0(0xffffff9c,100);
      local_8c = FLOAT_803df734;
      uStack52 = FUN_800221a0(0xffffff9c,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803df784 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
      uStack44 = FUN_800221a0(0x27,0x50);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803df788 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
      local_b8 = FUN_800221a0(0x14,0x20);
      local_b8 = local_b8 + 0xdb;
      local_7e = 0x20c;
      local_68 = 0xe2f5;
      local_66 = 0x5308;
      local_64 = 0x42d9;
      local_74 = 0x8afe;
      local_70 = 0x5866;
      local_6c = 0x40c3;
      local_60 = FUN_800221a0(0xd,0x53);
      local_7c = 0x480208;
      local_78 = 0x8002820;
    }
    else {
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c32c = FLOAT_803df734;
        DAT_8039c330 = FLOAT_803df734;
        DAT_8039c334 = FLOAT_803df734;
        DAT_8039c328 = FLOAT_803df728;
        DAT_8039c320 = 0;
        DAT_8039c322 = 0;
        DAT_8039c324 = 0;
        param_3 = &DAT_8039c320;
      }
      if (param_3 == (undefined2 *)0x0) {
        local_88 = FLOAT_803df758;
        local_8c = FLOAT_803df75c;
      }
      else {
        local_88 = *(float *)(param_3 + 6);
        local_8c = *(float *)(param_3 + 8);
      }
      uStack60 = FUN_800221a0(0x1e,0x28);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = FLOAT_803df76c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
      uStack68 = FUN_800221a0(0xfffffff6,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_9c = FLOAT_803df738 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
      uStack76 = FUN_800221a0(0xfffffffc,4);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_98 = FLOAT_803df764 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803df860);
      uStack84 = FUN_800221a0(0x28,0x32);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_84 = FLOAT_803df770 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803df860);
      local_b8 = FUN_800221a0(0,0x3c);
      local_b8 = local_b8 + 0x50;
      local_60 = 0xff;
      local_7e = 0xc0a;
      local_78 = 0x200000;
      local_7c = 0x42000100;
    }
  }
  else if (iVar4 == 0x5ed) {
    if (param_3 == (undefined2 *)0x0) {
      DAT_8039c32c = FLOAT_803df734;
      DAT_8039c330 = FLOAT_803df734;
      DAT_8039c334 = FLOAT_803df734;
      DAT_8039c328 = FLOAT_803df728;
      DAT_8039c320 = 0;
      DAT_8039c322 = 0;
      DAT_8039c324 = 0;
      param_3 = &DAT_8039c320;
    }
    local_b2 = 0;
    local_b4 = 0;
    local_a8 = FLOAT_803df734;
    local_a4 = FLOAT_803df734;
    local_a0 = FLOAT_803df734;
    local_ac = FLOAT_803df728;
    if (param_3 != (undefined2 *)0x0) {
      local_90 = *(float *)(param_3 + 6);
      local_8c = FLOAT_803df7c4 + *(float *)(param_3 + 8);
      local_88 = *(float *)(param_3 + 10);
      local_b4 = *param_3;
      local_b0 = param_3[2];
    }
    local_60 = 0xff;
    local_84 = FLOAT_803df7c8;
    local_b8 = 0x3c;
    local_7c = 0x6100100;
    local_7e = 0x5fe;
  }
  else if (iVar4 < 0x5ed) {
    if (iVar4 == 0x5e4) {
      uStack44 = FUN_800221a0(0x19,0x23);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803df7fc * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
      local_b8 = 0xf0;
      local_60 = 0x55;
      local_7c = 0x480000;
      local_78 = 0x100;
      local_7e = 0x156;
    }
    else if (iVar4 < 0x5e4) {
      if (iVar4 == 0x5df) {
        uStack44 = FUN_800221a0(0xfffffff4,0xc);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_88 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
        uStack52 = FUN_800221a0(0xfffffff4,0xc);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_8c = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
        uStack60 = FUN_800221a0(5,0xf);
        uStack60 = uStack60 ^ 0x80000000;
        local_40 = 0x43300000;
        local_9c = FLOAT_803df804 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860)
        ;
        local_98 = local_8c / FLOAT_803df808;
        local_94 = local_88 / FLOAT_803df808;
        uStack68 = FUN_800221a0(5,0xf);
        uStack68 = uStack68 ^ 0x80000000;
        local_48 = 0x43300000;
        local_84 = FLOAT_803df80c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860)
        ;
        local_b8 = 0xfa;
        local_60 = 0x9b;
        local_7c = 0x480100;
        local_7e = 0x528;
      }
      else if (iVar4 < 0x5df) {
        if (iVar4 == 0x5dd) {
          uStack44 = FUN_800221a0(0xfffffff4,0xc);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_88 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          uStack52 = FUN_800221a0(0xfffffff4,0xc);
          uStack52 = uStack52 ^ 0x80000000;
          local_38 = 0x43300000;
          local_8c = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
          uStack60 = FUN_800221a0(5,0xf);
          uStack60 = uStack60 ^ 0x80000000;
          local_40 = 0x43300000;
          local_9c = FLOAT_803df804 *
                     (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
          local_98 = local_8c / FLOAT_803df808;
          local_94 = local_88 / FLOAT_803df808;
          uStack68 = FUN_800221a0(5,0xf);
          uStack68 = uStack68 ^ 0x80000000;
          local_48 = 0x43300000;
          local_84 = FLOAT_803df80c *
                     (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
          local_b8 = 0xfa;
          local_60 = 0x9b;
          local_7c = 0x480100;
          local_7e = 0xc79;
        }
        else {
          if (iVar4 < 0x5dd) {
            if (iVar4 < 0x3a9) goto LAB_800b00ec;
LAB_800b2f6c:
            uVar2 = 0xffffffff;
            goto LAB_800b3050;
          }
          uStack44 = FUN_800221a0(0xfffffff4,0xc);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_88 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          uStack52 = FUN_800221a0(0xfffffff4,0xc);
          uStack52 = uStack52 ^ 0x80000000;
          local_38 = 0x43300000;
          local_8c = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
          uStack60 = FUN_800221a0(5,0xf);
          uStack60 = uStack60 ^ 0x80000000;
          local_40 = 0x43300000;
          local_9c = FLOAT_803df804 *
                     (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
          local_98 = local_8c / FLOAT_803df808;
          local_94 = local_88 / FLOAT_803df808;
          uStack68 = FUN_800221a0(5,0xf);
          uStack68 = uStack68 ^ 0x80000000;
          local_48 = 0x43300000;
          local_84 = FLOAT_803df80c *
                     (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
          local_b8 = 0xfa;
          local_60 = 0x9b;
          local_7c = 0x480100;
          local_7e = 0x166;
        }
      }
      else if (iVar4 == 0x5e2) {
        uStack44 = FUN_800221a0(0xffffff9c,100);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_9c = FLOAT_803df810 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860)
        ;
        local_98 = FLOAT_803df734;
        local_94 = FLOAT_803df734;
        local_90 = FLOAT_803df734;
        local_8c = FLOAT_803df734;
        local_88 = FLOAT_803df734;
        local_84 = FLOAT_803df814;
        local_b8 = 0x39;
        local_7e = 0xc75;
        local_68 = 0x7fff;
        local_66 = 0x7fff;
        local_64 = 0x7fff;
        local_74 = 0x7fff;
        local_70 = 0x7fff;
        local_6c = 0x7fff;
        local_60 = 0xff;
        local_7c = 0x80500100;
        local_78 = 0x8000800;
      }
      else if (iVar4 < 0x5e2) {
        if (iVar4 < 0x5e1) {
          uStack44 = FUN_800221a0(0xffffff9c,100);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_9c = FLOAT_803df810 *
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          local_98 = FLOAT_803df734;
          local_94 = FLOAT_803df734;
          local_90 = FLOAT_803df734;
          local_8c = FLOAT_803df734;
          local_88 = FLOAT_803df734;
          local_84 = FLOAT_803df814;
          local_b8 = 0x39;
          local_7e = 0xc76;
          local_68 = 0x7fff;
          local_66 = 0x7fff;
          local_64 = 0x7fff;
          local_74 = 0x7fff;
          local_70 = 0x7fff;
          local_6c = 0x7fff;
          local_60 = 0xff;
          local_7c = 0x80500100;
          local_78 = 0x8000800;
        }
        else {
          uStack44 = FUN_800221a0(0xffffff9c,100);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_9c = FLOAT_803df810 *
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          local_98 = FLOAT_803df734;
          local_94 = FLOAT_803df734;
          local_90 = FLOAT_803df734;
          local_8c = FLOAT_803df734;
          local_88 = FLOAT_803df734;
          local_84 = FLOAT_803df814;
          local_b8 = 0x39;
          local_7e = 0xc74;
          local_68 = 0x7fff;
          local_66 = 0x7fff;
          local_64 = 0x7fff;
          local_74 = 0x7fff;
          local_70 = 0x7fff;
          local_6c = 0x7fff;
          local_60 = 0xff;
          local_7c = 0x80500100;
          local_78 = 0x8000800;
        }
      }
      else {
        uStack44 = FUN_800221a0(0x19,0x23);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_84 = FLOAT_803df7fc * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860)
        ;
        local_b8 = 0xf0;
        local_60 = 0x55;
        local_7c = 0x480000;
        local_78 = 0x200;
        local_7e = 0x156;
      }
    }
    else if (iVar4 == 0x5e9) {
      local_84 = FLOAT_803df750;
      local_b8 = 0x14;
      local_60 = 0xff;
      local_7c = 0x480200;
      local_78 = 0x2000000;
      local_7e = 0x26c;
    }
    else if (iVar4 < 0x5e9) {
      if (iVar4 == 0x5e7) {
        uStack44 = FUN_800221a0(0x19,0x23);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_84 = FLOAT_803df7fc * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860)
        ;
        local_b8 = 6;
        local_60 = 0x55;
        local_7c = 0x480000;
        local_78 = 0x100;
        local_7e = 0x156;
      }
      else if (iVar4 < 0x5e7) {
        if (iVar4 < 0x5e6) {
          local_84 = FLOAT_803df800;
          local_b8 = 0xf0;
          local_60 = 0xb9;
          local_7c = 0x480000;
          local_7e = 0x156;
        }
        else {
          uStack44 = FUN_800221a0(0x19,0x23);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_84 = FLOAT_803df7fc *
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          local_b8 = 300;
          local_60 = 0x55;
          local_7c = 0x480000;
          local_78 = 0x200;
          local_7e = 0x156;
        }
      }
      else {
        local_84 = FLOAT_803df800;
        local_b8 = 6;
        local_60 = 0x55;
        local_7c = 0x480000;
        local_7e = 0x156;
      }
    }
    else if (iVar4 == 0x5eb) {
      uStack44 = FUN_800221a0(0xb4,200);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_94 = FLOAT_803df7f8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
      uStack52 = FUN_800221a0(0xffffffd8,0x28);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = FLOAT_803df7f0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
      uStack60 = FUN_800221a0(0,0x28);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803df740 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
      local_60 = 0x9b;
      local_84 = FLOAT_803df7ac;
      local_b8 = FUN_800221a0(0x8c,0xa5);
      local_7c = 0x81100000;
      local_78 = 0x408020;
      local_68 = 2000;
      local_66 = 2000;
      local_64 = FUN_800221a0(0xffffec78,5000);
      local_64 = local_64 + 10000;
      local_74 = 8000;
      local_70 = 8000;
      local_6c = FUN_800221a0(0xffffec78,5000);
      local_6c = local_6c + 12000;
      local_7e = 0x639;
    }
    else {
      if (0x5ea < iVar4) goto LAB_800b2f6c;
      uStack44 = FUN_800221a0(0xffffffe7,0x19);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
      uStack52 = FUN_800221a0(0xffffffe7,0x19);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
      local_60 = 0x9b;
      local_84 = FLOAT_803df7b0;
      local_b8 = FUN_800221a0(0x46,100);
      local_7c = 0x81100000;
      local_78 = 0x408020;
      local_68 = 2000;
      local_66 = 2000;
      local_64 = FUN_800221a0(0xffffec78,5000);
      local_64 = local_64 + 20000;
      local_74 = 8000;
      local_70 = 8000;
      local_6c = FUN_800221a0(0xffffec78,5000);
      local_6c = local_6c + 32000;
      local_7e = 0x639;
    }
  }
  else if (iVar4 == 0x5f6) {
    local_60 = 0xff;
    local_84 = FLOAT_803df7d8;
    local_b8 = 10;
    local_7c = 0x480000;
    local_78 = 0x202;
    local_7e = 0x26c;
    (**(code **)(*DAT_803dca78 + 8))(&local_c0,0,0x5f6,0);
    local_60 = 0xff;
    local_84 = FLOAT_803df7dc;
    local_b8 = 10;
    local_7c = 0x480000;
    local_78 = 2;
    local_7e = 0x528;
    (**(code **)(*DAT_803dca78 + 8))(&local_c0,0,0x5f6,0);
    local_60 = 0x37;
    local_84 = FLOAT_803df7b0;
    local_b8 = 10;
    local_7c = 0x480000;
    local_78 = 2;
    local_7e = 0x528;
    (**(code **)(*DAT_803dca78 + 8))(&local_c0,0,0x5f6,0);
    local_60 = 0x87;
    local_84 = FLOAT_803df7dc;
    local_b8 = 10;
    local_7c = 0x480200;
    local_78 = 0x2002;
    local_7e = 0x528;
  }
  else if (iVar4 < 0x5f6) {
    if (iVar4 == 0x5f2) {
      local_60 = 0x37;
      local_84 = FLOAT_803df7a8;
      local_b8 = 300;
      local_7c = 0x480000;
      local_7e = 0x528;
    }
    else if (iVar4 < 0x5f2) {
      if (iVar4 == 0x5f0) {
        local_60 = 0xff;
        local_84 = FLOAT_803df7bc;
        local_b8 = 300;
        local_7c = 0x480000;
        local_78 = 0x200;
        local_7e = 0x26c;
      }
      else if (iVar4 < 0x5f0) {
        if (iVar4 < 0x5ef) {
          uStack44 = FUN_800221a0(0xffffffd8,0x28);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_94 = FLOAT_803df7f0 *
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          uStack52 = FUN_800221a0(0xffffffd8,0x28);
          uStack52 = uStack52 ^ 0x80000000;
          local_38 = 0x43300000;
          local_98 = FLOAT_803df7f0 *
                     (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
          local_60 = 0xff;
          local_84 = FLOAT_803df7f4;
          local_b8 = FUN_800221a0(0,10);
          local_b8 = local_b8 + 0x3c;
          local_7c = 0x2000100;
          local_78 = 0x200;
          local_7e = 0x33;
        }
        else {
          uStack44 = FUN_800221a0(0xfffffe70,400);
          uStack44 = uStack44 ^ 0x80000000;
          local_30 = 0x43300000;
          local_90 = FLOAT_803df720 *
                     (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
          uStack52 = FUN_800221a0(0xfffffe70,400);
          uStack52 = uStack52 ^ 0x80000000;
          local_38 = 0x43300000;
          local_88 = FLOAT_803df720 *
                     (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
          local_98 = FLOAT_803df7e8;
          local_60 = 0x9b;
          local_84 = FLOAT_803df7ec;
          local_b8 = FUN_800221a0(0,10);
          local_b8 = local_b8 + 0x3c;
          local_7c = 0x80100;
          local_78 = 0x100;
          local_7e = 0x3f2;
        }
      }
      else {
        local_60 = 0xff;
        local_84 = FLOAT_803df740;
        local_b8 = 300;
        local_7c = 0x480000;
        local_7e = 0x528;
      }
    }
    else if (iVar4 == 0x5f4) {
      uStack44 = FUN_800221a0(0xffffff38,200);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = FLOAT_803df740 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
      uStack52 = FUN_800221a0(0xffffff38,200);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803df740 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
      uStack60 = FUN_800221a0(300,400);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = FLOAT_803df7e0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803df860);
      local_60 = 0xff;
      local_84 = FLOAT_803df7e0;
      local_b8 = 0x8c;
      local_7c = 0x480100;
      local_7e = 0x528;
    }
    else if (iVar4 < 0x5f4) {
      local_60 = 0x87;
      local_84 = FLOAT_803df740;
      local_b8 = 0x1e;
      local_7c = 0x480200;
      local_78 = 0x2000;
      local_7e = 0x528;
    }
    else {
      uStack44 = FUN_800221a0(0xfffffc7c,900);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_9c = FLOAT_803df7e0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
      uStack52 = FUN_800221a0(0xfffffc7c,900);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803df7e0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860);
      local_60 = 0xff;
      local_84 = FLOAT_803df7e4;
      local_b8 = 0x3c;
      local_7c = 0x110;
      local_78 = 0x100;
      local_7e = 0xe4;
    }
  }
  else if (iVar4 == 0x5fb) {
    local_84 = FLOAT_803df738;
    local_b8 = 10;
    local_60 = 0xff;
    local_7e = 0xe7;
  }
  else if (iVar4 < 0x5fb) {
    if (iVar4 == 0x5f9) {
      uStack68 = FUN_800221a0(0xfffffda8,600);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = FLOAT_803df748 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
      uStack76 = FUN_800221a0(0xfffffda8,600);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = FLOAT_803df748 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803df860);
      uStack84 = FUN_800221a0(800,0x4b0);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_98 = FLOAT_803df74c * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803df860);
      local_84 = FLOAT_803df750;
      local_b8 = 0xb4;
      local_60 = 0xff;
      local_7c = 0x80480100;
      local_78 = 0x2000000;
      local_bc = 0x5e9;
      local_7e = 0x26c;
    }
    else if (iVar4 < 0x5f9) {
      if (iVar4 < 0x5f8) {
        local_60 = 0xff;
        local_84 = FLOAT_803df7d4;
        local_b8 = 0x73;
        local_7c = 0x8100110;
        local_78 = 0x2000000;
        local_7e = 0x77;
      }
      else {
        uStack44 = FUN_800221a0(0xffffffd8,0x28);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_9c = FLOAT_803df7f0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860)
        ;
        uStack52 = FUN_800221a0(0xffffffd8,0x28);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_98 = FLOAT_803df7f0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803df860)
        ;
        local_60 = 0xff;
        local_84 = FLOAT_803df7f4;
        local_b8 = FUN_800221a0(0,10);
        local_b8 = local_b8 + 0x3c;
        local_7c = 0x2000100;
        local_78 = 0x400;
        local_7e = 0x33;
      }
    }
    else {
      uStack84 = FUN_800221a0(0xfffffda8,600);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_90 = FLOAT_803df73c * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803df860);
      uStack76 = FUN_800221a0(0xfffffda8,600);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = FLOAT_803df73c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803df860);
      uStack68 = FUN_800221a0(800,0x4b0);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803df740 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df860);
      local_84 = FLOAT_803df744;
      local_b8 = 0x28;
      local_60 = 0xff;
      local_78 = 0x200000;
      local_7e = 0x26c;
    }
  }
  else if (iVar4 == 0x5fd) {
    if (param_3 == (undefined2 *)0x0) {
      DAT_8039c32c = FLOAT_803df734;
      DAT_8039c330 = FLOAT_803df734;
      DAT_8039c334 = FLOAT_803df734;
      DAT_8039c328 = FLOAT_803df728;
      DAT_8039c320 = 0;
      DAT_8039c322 = 0;
      DAT_8039c324 = 0;
      param_3 = &DAT_8039c320;
    }
    local_b2 = 0;
    local_b4 = 0;
    local_a8 = FLOAT_803df734;
    local_a4 = FLOAT_803df734;
    local_a0 = FLOAT_803df734;
    local_ac = FLOAT_803df728;
    if (param_3 != (undefined2 *)0x0) {
      local_90 = *(float *)(param_3 + 6);
      local_8c = FLOAT_803df7c4 + *(float *)(param_3 + 8);
      local_88 = *(float *)(param_3 + 10);
      local_b4 = *param_3;
      local_b0 = param_3[2];
    }
    local_60 = 0xff;
    uStack44 = FUN_800221a0(1,3);
    uStack44 = uStack44 ^ 0x80000000;
    local_30 = 0x43300000;
    local_84 = FLOAT_803df7c8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df860);
    local_b8 = FUN_800221a0(0,100);
    local_b8 = local_b8 + 0x78;
    local_7c = 0x6100000;
    local_78 = 0x8000;
    local_7e = 0x5ff;
  }
  else {
    if (0x5fc < iVar4) goto LAB_800b2f6c;
    local_84 = FLOAT_803df738;
    local_b8 = 10;
    local_60 = 0xff;
    local_7e = 0x5c;
  }
  local_7c = local_7c | param_4;
  if (((local_7c & 1) != 0) && ((local_7c & 2) != 0)) {
    local_7c = local_7c ^ 2;
  }
  if ((local_7c & 1) != 0) {
    if ((param_4 & 0x200000) == 0) {
      if (local_c0 != (undefined2 *)0x0) {
        local_90 = local_90 + *(float *)(local_c0 + 0xc);
        local_8c = local_8c + *(float *)(local_c0 + 0xe);
        local_88 = local_88 + *(float *)(local_c0 + 0x10);
      }
    }
    else {
      local_90 = local_90 + local_a8;
      local_8c = local_8c + local_a4;
      local_88 = local_88 + local_a0;
    }
  }
  uVar2 = (**(code **)(*DAT_803dca78 + 8))(&local_c0,0xffffffff,iVar4,0);
LAB_800b3050:
  FUN_80286124(uVar2);
  return;
}

