// Function: FUN_800ca930
// Entry: 800ca930
// Size: 3116 bytes

undefined4
FUN_800ca930(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5,
            int param_6)

{
  undefined4 uVar1;
  int iVar2;
  int local_98;
  undefined4 local_94;
  int local_90;
  undefined2 local_8c;
  undefined2 local_8a;
  undefined2 local_88;
  undefined4 local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  undefined2 local_58;
  undefined2 local_56;
  uint local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined2 local_40;
  undefined2 local_3e;
  undefined2 local_3c;
  undefined local_3a;
  undefined local_38;
  undefined local_37;
  undefined local_36;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  FLOAT_803db850 = FLOAT_803db850 + FLOAT_803e01b8;
  if (FLOAT_803e01c0 < FLOAT_803db850) {
    FLOAT_803db850 = FLOAT_803e01bc;
  }
  FLOAT_803db854 = FLOAT_803db854 + FLOAT_803e01c4;
  if (FLOAT_803e01c0 < FLOAT_803db854) {
    FLOAT_803db854 = FLOAT_803e01c8;
  }
  if (param_1 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        return 0xffffffff;
      }
      local_80 = *(float *)(param_3 + 6);
      local_7c = *(float *)(param_3 + 8);
      local_78 = *(float *)(param_3 + 10);
      local_84 = *(undefined4 *)(param_3 + 4);
      local_88 = param_3[2];
      local_8a = param_3[1];
      local_8c = *param_3;
      local_36 = param_5;
    }
    local_54 = 0;
    local_50 = 0;
    local_3a = (undefined)param_2;
    local_68 = FLOAT_803e01cc;
    local_64 = FLOAT_803e01cc;
    local_60 = FLOAT_803e01cc;
    local_74 = FLOAT_803e01cc;
    local_70 = FLOAT_803e01cc;
    local_6c = FLOAT_803e01cc;
    local_5c = FLOAT_803e01cc;
    local_90 = 0;
    local_94 = 0xffffffff;
    local_38 = 0xff;
    local_37 = 0;
    local_56 = 0;
    local_40 = 0xffff;
    local_3e = 0xffff;
    local_3c = 0xffff;
    local_4c = 0xffff;
    local_48 = 0xffff;
    local_44 = 0xffff;
    local_58 = 0;
    local_98 = param_1;
    switch(param_2) {
    case 0x73a:
      uStack44 = FUN_800221a0(8,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_70 = FLOAT_803e01d0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0210);
      iVar2 = FUN_800221a0(0,0x28);
      if (iVar2 == 0) {
        uStack44 = FUN_800221a0(0x15,0x29);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_5c = FLOAT_803e01b8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0210)
        ;
        local_90 = 0x1cc;
      }
      else {
        uStack44 = FUN_800221a0(8,0x14);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_5c = FLOAT_803e01b8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0210)
        ;
        local_90 = FUN_800221a0(0x5a,0x78);
      }
      local_54 = 0x80180200;
      local_50 = 0x1000020;
      local_56 = 0xc0b;
      local_38 = 0x7f;
      local_3c = 0x3fff;
      local_3e = 0x3fff;
      local_40 = 0x3fff;
      local_44 = 0xffff;
      local_48 = 0xffff;
      local_4c = 0xffff;
      local_64 = FLOAT_803e01d4;
      break;
    case 0x73b:
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803e01d0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0210);
      uStack36 = FUN_800221a0(8,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = FLOAT_803e01d0 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0210);
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_6c = FLOAT_803e01d0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0210);
      local_5c = FLOAT_803e01d8;
      local_90 = 0x32;
      local_54 = 0x3000200;
      local_50 = 0x200020;
      local_56 = 0x33;
      local_38 = 0xff;
      local_40 = 0xffff;
      local_3e = 0xffff;
      local_3c = 0xffff;
      local_4c = 0xffff;
      local_48 = FUN_800221a0(0,0x8000);
      local_64 = FLOAT_803e01dc;
      local_44 = local_48;
      break;
    default:
      return 0xffffffff;
    case 0x73d:
      uStack28 = FUN_800221a0(0xfffffff6,10);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_68 = FLOAT_803e01bc * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0210);
      uStack36 = FUN_800221a0(0xfffffff6,100);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_64 = FLOAT_803e01d0 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0210);
      uStack44 = FUN_800221a0(0xfffffff6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_60 = FLOAT_803e01bc * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0210);
      uStack20 = FUN_800221a0(7,9);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e01e0 *
                 FLOAT_803e01e4 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0210);
      local_90 = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xde;
      break;
    case 0x73e:
      uStack20 = FUN_800221a0(0xfffffff6,10);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_68 = FLOAT_803e01bc * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0210);
      uStack28 = FUN_800221a0(0xfffffff6,100);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_64 = FLOAT_803e01d0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0210);
      uStack36 = FUN_800221a0(0xfffffff6,10);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_60 = FLOAT_803e01bc * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0210);
      uStack44 = FUN_800221a0(7,9);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e01e0 *
                 FLOAT_803e01e4 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0210);
      local_90 = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xdf;
      break;
    case 0x73f:
      if (param_6 == 0) {
        uStack20 = FUN_800221a0(0xfffffff6,10);
        uStack20 = uStack20 ^ 0x80000000;
        local_18 = 0x43300000;
        local_68 = FLOAT_803e01bc * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0210)
        ;
        uStack28 = FUN_800221a0(0xfffffff6,100);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_64 = FLOAT_803e01d0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0210)
        ;
        uStack36 = FUN_800221a0(0xfffffff6,10);
        uStack36 = uStack36 ^ 0x80000000;
        local_60 = FLOAT_803e01bc * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0210)
        ;
      }
      else {
        uStack20 = FUN_800221a0(0xfffffff6,10);
        uStack20 = uStack20 ^ 0x80000000;
        local_18 = 0x43300000;
        local_68 = FLOAT_803e01bc * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0210)
                   + FLOAT_803e01e8;
        uStack28 = FUN_800221a0(0xfffffff6,100);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_64 = FLOAT_803e01d0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0210)
                   + FLOAT_803e01ec;
        uStack36 = FUN_800221a0(0xfffffff6,10);
        uStack36 = uStack36 ^ 0x80000000;
        local_60 = FLOAT_803e01bc * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0210)
                   + FLOAT_803e01f0;
      }
      local_28 = 0x43300000;
      uStack20 = FUN_800221a0(7,9);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e01f4 *
                 FLOAT_803e01e4 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0210);
      local_90 = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xde;
      break;
    case 0x740:
      if (param_6 == 0) {
        uStack20 = FUN_800221a0(0xfffffff6,10);
        uStack20 = uStack20 ^ 0x80000000;
        local_18 = 0x43300000;
        local_68 = FLOAT_803e01bc * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0210)
        ;
        uStack28 = FUN_800221a0(0xfffffff6,100);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_64 = FLOAT_803e01d0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0210)
        ;
        uStack36 = FUN_800221a0(0xfffffff6,10);
        uStack36 = uStack36 ^ 0x80000000;
        local_60 = FLOAT_803e01bc * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0210)
        ;
      }
      else {
        uStack20 = FUN_800221a0(0xfffffff6,10);
        uStack20 = uStack20 ^ 0x80000000;
        local_18 = 0x43300000;
        local_68 = FLOAT_803e01bc * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0210)
                   + FLOAT_803e01e8;
        uStack28 = FUN_800221a0(0xfffffff6,100);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_64 = FLOAT_803e01d0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0210)
                   + FLOAT_803e01ec;
        uStack36 = FUN_800221a0(0xfffffff6,10);
        uStack36 = uStack36 ^ 0x80000000;
        local_60 = FLOAT_803e01bc * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0210)
                   + FLOAT_803e01f0;
      }
      local_28 = 0x43300000;
      uStack20 = FUN_800221a0(7,9);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e01f4 *
                 FLOAT_803e01e4 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0210);
      local_90 = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xdf;
      break;
    case 0x741:
      if (param_3 != (undefined2 *)0x0) {
        local_64 = *(float *)(param_3 + 8);
      }
      local_5c = FLOAT_803e01f8;
      local_90 = FUN_800221a0(0,0x1e);
      local_90 = local_90 + 0x50;
      local_38 = 0x60;
      local_54 = 0x80110;
      local_56 = 0x7b;
      local_37 = 0x20;
      break;
    case 0x742:
      local_6c = FLOAT_803e01fc;
      uStack20 = FUN_800221a0(0xffffffec,0x14);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = FLOAT_803e0200 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0210);
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_70 = FLOAT_803e0200 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0210);
      local_5c = FLOAT_803e0204;
      local_90 = FUN_800221a0(0x46,0x50);
      local_38 = 0xff;
      local_54 = 0x82000104;
      local_50 = 0x400;
      local_56 = 0x3f4;
      break;
    case 0x743:
      local_6c = FLOAT_803e01fc;
      uStack20 = FUN_800221a0(0xffffffec,0x14);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = FLOAT_803e0200 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0210);
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_70 = FLOAT_803e0200 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0210);
      local_5c = FLOAT_803e0204;
      local_90 = FUN_800221a0(0x46,0x50);
      local_38 = 0xff;
      local_54 = 0x82000104;
      local_50 = 0x400;
      local_56 = 0x500;
      break;
    case 0x744:
      iVar2 = FUN_800221a0(0,4);
      if (iVar2 == 4) {
        local_5c = FLOAT_803e0208;
        local_38 = 0x9b;
        local_54 = 0x480000;
        local_90 = FUN_800221a0(0x1e,0x28);
      }
      else {
        local_5c = FLOAT_803e020c;
        local_38 = 0x7d;
        local_54 = 0x180000;
        local_90 = 0x50;
      }
      local_50 = 0x2000000;
      local_56 = 0x88;
    }
    local_54 = local_54 | param_4;
    if (((local_54 & 1) != 0) && ((local_54 & 2) != 0)) {
      local_54 = local_54 ^ 2;
    }
    if ((local_54 & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_98 != 0) {
          local_68 = local_68 + *(float *)(local_98 + 0x18);
          local_64 = local_64 + *(float *)(local_98 + 0x1c);
          local_60 = local_60 + *(float *)(local_98 + 0x20);
        }
      }
      else {
        local_68 = local_68 + local_80;
        local_64 = local_64 + local_7c;
        local_60 = local_60 + local_78;
      }
    }
    uVar1 = (**(code **)(*DAT_803dca78 + 8))(&local_98,0xffffffff,param_2,0);
  }
  return uVar1;
}

