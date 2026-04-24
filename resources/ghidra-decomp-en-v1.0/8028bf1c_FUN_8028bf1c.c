// Function: FUN_8028bf1c
// Entry: 8028bf1c
// Size: 1080 bytes

/* WARNING: Removing unreachable block (ram,0x8028c2a0) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int FUN_8028bf1c(uint param_1,uint param_2,undefined4 param_3,int *param_4,int param_5)

{
  int iVar1;
  undefined4 extraout_r4;
  uint uVar2;
  uint local_128;
  undefined4 local_124;
  undefined4 local_120;
  undefined4 local_11c;
  undefined4 local_118;
  undefined4 local_114;
  uint local_110;
  uint local_10c;
  undefined4 local_108;
  undefined4 local_104;
  undefined4 local_100;
  undefined4 local_fc;
  undefined4 local_f8;
  undefined4 local_f4;
  undefined4 local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  uint local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  undefined4 local_d8;
  undefined4 local_d4;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  undefined4 local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  
  if (param_2 < 0x20) {
    local_11c = DAT_803322fc;
    local_118 = DAT_80332300;
    local_114 = _DAT_80332304;
    local_110 = DAT_80332308;
    DAT_80332308 = DAT_80332308 & 0xff00ffff;
    local_64 = DAT_802c2990;
    local_60 = DAT_802c2994;
    local_5c = DAT_802c2998;
    local_58 = DAT_802c299c;
    local_54 = DAT_802c29a0;
    local_50 = DAT_802c29a4;
    local_4c = DAT_802c29a8;
    local_6c = 0x7c98e2a6;
    local_68 = 0x90830000;
    local_48 = 0x4e800020;
    FUN_8028afe4(&local_6c,0x28);
    (*(code *)&local_6c)(&local_128,&DAT_803d8864);
    local_128 = local_128 | 0xa0000000;
    local_8c = DAT_802c2990;
    local_88 = DAT_802c2994;
    local_84 = DAT_802c2998;
    local_80 = DAT_802c299c;
    local_7c = DAT_802c29a0;
    local_78 = DAT_802c29a4;
    local_74 = DAT_802c29a8;
    local_94 = 0x80830000;
    local_90 = 0x7c98e3a6;
    local_70 = 0x4e800020;
    FUN_8028afe4(&local_94,0x28);
    (*(code *)&local_94)(&local_128,&DAT_803d8864);
    local_128 = 0;
    local_b4 = DAT_802c2990;
    local_b0 = DAT_802c2994;
    local_ac = DAT_802c2998;
    local_a8 = DAT_802c299c;
    local_a4 = DAT_802c29a0;
    local_a0 = DAT_802c29a4;
    local_9c = DAT_802c29a8;
    local_bc = 0x80830000;
    local_b8 = 0x7c90e3a6;
    local_98 = 0x4e800020;
    FUN_8028afe4(&local_bc,0x28);
    (*(code *)&local_bc)(&local_128,&DAT_803d8864);
    uVar2 = param_1 << 0x15;
    *param_4 = 0;
    iVar1 = 0;
    while ((param_1 <= param_2 && (iVar1 == 0))) {
      if (param_5 == 0) {
        FUN_80287060(param_3,&local_124);
        local_10c = uVar2 | 0xe0030000;
        local_108 = DAT_802c29b4;
        local_104 = DAT_802c29b8;
        local_100 = DAT_802c29bc;
        local_fc = DAT_802c29c0;
        local_f8 = DAT_802c29c4;
        local_f4 = DAT_802c29c8;
        local_f0 = DAT_802c29cc;
        local_ec = DAT_802c29d0;
        local_e8 = 0x4e800020;
        FUN_8028afe4(&local_10c,0x28);
        (*(code *)&local_10c)(&local_124,&DAT_803d8864);
        iVar1 = 0;
      }
      else {
        local_e4 = uVar2 | 0xe0030000;
        local_e0 = DAT_802c29b4;
        local_dc = DAT_802c29b8;
        local_d8 = DAT_802c29bc;
        local_d4 = DAT_802c29c0;
        local_d0 = DAT_802c29c4;
        local_cc = DAT_802c29c8;
        local_c8 = DAT_802c29cc;
        local_c4 = DAT_802c29d0;
        if (param_5 != 0) {
          local_e4 = uVar2 | 0xf0030000;
        }
        local_c0 = 0x4e800020;
        FUN_8028afe4(&local_e4,0x28);
        (*(code *)&local_e4)(&local_124,&DAT_803d8864);
        iVar1 = FUN_80287458(param_3,extraout_r4,local_124,local_120);
      }
      uVar2 = uVar2 + 0x200000;
      param_1 = param_1 + 1;
      *param_4 = *param_4 + 8;
    }
    if (DAT_80332308._1_1_ != '\0') {
      iVar1 = 0x702;
      *param_4 = 0;
    }
    DAT_803322fc = local_11c;
    DAT_80332300 = local_118;
    _DAT_80332304 = local_114;
    DAT_80332308 = local_110;
  }
  else {
    iVar1 = 0x701;
  }
  return iVar1;
}

