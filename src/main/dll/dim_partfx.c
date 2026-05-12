#include "ghidra_import.h"
#include "main/dll/dim_partfx.h"

extern undefined4 FUN_80006824();
extern double FUN_80006a30();
extern int FUN_80017730();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern undefined4 FUN_8007f3c8();
extern undefined8 FUN_80286824();
extern undefined8 FUN_80286828();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286874();
extern undefined4 FUN_80286880();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined DAT_80000064;
extern undefined4 DAT_8039d070;
extern undefined4 DAT_8039d072;
extern undefined4 DAT_8039d074;
extern undefined4 DAT_8039d078;
extern undefined4 DAT_8039d07c;
extern undefined4 DAT_8039d080;
extern undefined4 DAT_8039d084;
extern undefined4 DAT_8039d088;
extern undefined4 DAT_8039d08a;
extern undefined4 DAT_8039d08c;
extern undefined4 DAT_8039d090;
extern undefined4 DAT_8039d094;
extern undefined4 DAT_8039d098;
extern undefined4 DAT_8039d09c;
extern undefined4 DAT_8039d0a0;
extern undefined4 DAT_8039d0a2;
extern undefined4 DAT_8039d0a4;
extern undefined4 DAT_8039d0a8;
extern undefined4 DAT_8039d0ac;
extern undefined4 DAT_8039d0b0;
extern undefined4 DAT_8039d0b4;
extern undefined4 DAT_8039d0b8;
extern undefined4 DAT_8039d0bc;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd718;
extern undefined4 DAT_803de040;
extern undefined4 DAT_803de044;
extern undefined4 DAT_803de050;
extern undefined4 DAT_803de054;
extern undefined4 DAT_803de060;
extern undefined4 DAT_803de064;
extern undefined4 DAT_803de070;
extern undefined4 DAT_803de074;
extern undefined4 DAT_803de080;
extern undefined4 DAT_803de084;
extern undefined4 DAT_803de090;
extern f64 DOUBLE_803e0d80;
extern f64 DOUBLE_803e0df8;
extern f64 DOUBLE_803e0e30;
extern f64 DOUBLE_803e0e90;
extern f64 DOUBLE_803e0f40;
extern f64 DOUBLE_803e0f48;
extern f64 DOUBLE_803e0f80;
extern f64 DOUBLE_803e10e0;
extern f64 DOUBLE_803e1150;
extern f64 DOUBLE_803e1170;
extern f64 DOUBLE_803e1178;
extern f32 lbl_803DC074;
extern f32 lbl_803DC4A0;
extern f32 lbl_803DC4A4;
extern f32 lbl_803DC4A8;
extern f32 lbl_803DC4AC;
extern f32 lbl_803DC4B0;
extern f32 lbl_803DC4B4;
extern f32 lbl_803DC4B8;
extern f32 lbl_803DC4BC;
extern f32 lbl_803DC4C0;
extern f32 lbl_803DC4C4;
extern f32 lbl_803DC4C8;
extern f32 lbl_803DC4CC;
extern f32 lbl_803DC4D0;
extern f32 lbl_803DC4D4;
extern f32 lbl_803DC4D8;
extern f32 lbl_803DC4DC;
extern f32 lbl_803DC4E0;
extern f32 lbl_803DC4E4;
extern f32 lbl_803DC4E8;
extern f32 lbl_803DC4EC;
extern f32 lbl_803DE048;
extern f32 lbl_803DE04C;
extern f32 lbl_803DE058;
extern f32 lbl_803DE05C;
extern f32 lbl_803DE068;
extern f32 lbl_803DE06C;
extern f32 lbl_803DE078;
extern f32 lbl_803DE07C;
extern f32 lbl_803DE088;
extern f32 lbl_803DE08C;
extern f32 lbl_803E0D28;
extern f32 lbl_803E0D2C;
extern f32 lbl_803E0D30;
extern f32 lbl_803E0D34;
extern f32 lbl_803E0D38;
extern f32 lbl_803E0D3C;
extern f32 lbl_803E0D40;
extern f32 lbl_803E0D44;
extern f32 lbl_803E0D48;
extern f32 lbl_803E0D4C;
extern f32 lbl_803E0D50;
extern f32 lbl_803E0D54;
extern f32 lbl_803E0D58;
extern f32 lbl_803E0D5C;
extern f32 lbl_803E0D60;
extern f32 lbl_803E0D64;
extern f32 lbl_803E0D68;
extern f32 lbl_803E0D6C;
extern f32 lbl_803E0D70;
extern f32 lbl_803E0D74;
extern f32 lbl_803E0D78;
extern f32 lbl_803E0D90;
extern f32 lbl_803E0D94;
extern f32 lbl_803E0D98;
extern f32 lbl_803E0D9C;
extern f32 lbl_803E0DA0;
extern f32 lbl_803E0DA4;
extern f32 lbl_803E0DA8;
extern f32 lbl_803E0DAC;
extern f32 lbl_803E0DB0;
extern f32 lbl_803E0DB4;
extern f32 lbl_803E0DB8;
extern f32 lbl_803E0DBC;
extern f32 lbl_803E0DC0;
extern f32 lbl_803E0DC4;
extern f32 lbl_803E0DC8;
extern f32 lbl_803E0DCC;
extern f32 lbl_803E0DD0;
extern f32 lbl_803E0DD4;
extern f32 lbl_803E0DD8;
extern f32 lbl_803E0DDC;
extern f32 lbl_803E0DE0;
extern f32 lbl_803E0DE4;
extern f32 lbl_803E0DE8;
extern f32 lbl_803E0DEC;
extern f32 lbl_803E0DF0;
extern f32 lbl_803E0DF4;
extern f32 lbl_803E0E00;
extern f32 lbl_803E0E04;
extern f32 lbl_803E0E08;
extern f32 lbl_803E0E0C;
extern f32 lbl_803E0E10;
extern f32 lbl_803E0E14;
extern f32 lbl_803E0E18;
extern f32 lbl_803E0E1C;
extern f32 lbl_803E0E20;
extern f32 lbl_803E0E24;
extern f32 lbl_803E0E28;
extern f32 lbl_803E0E2C;
extern f32 lbl_803E0E38;
extern f32 lbl_803E0E3C;
extern f32 lbl_803E0E40;
extern f32 lbl_803E0E44;
extern f32 lbl_803E0E48;
extern f32 lbl_803E0E4C;
extern f32 lbl_803E0E50;
extern f32 lbl_803E0E54;
extern f32 lbl_803E0E58;
extern f32 lbl_803E0E5C;
extern f32 lbl_803E0E60;
extern f32 lbl_803E0E64;
extern f32 lbl_803E0E68;
extern f32 lbl_803E0E6C;
extern f32 lbl_803E0E70;
extern f32 lbl_803E0E74;
extern f32 lbl_803E0E78;
extern f32 lbl_803E0E7C;
extern f32 lbl_803E0E80;
extern f32 lbl_803E0E84;
extern f32 lbl_803E0E88;
extern f32 lbl_803E0E8C;
extern f32 lbl_803E0EA0;
extern f32 lbl_803E0EA4;
extern f32 lbl_803E0EA8;
extern f32 lbl_803E0EAC;
extern f32 lbl_803E0EB0;
extern f32 lbl_803E0EB4;
extern f32 lbl_803E0EB8;
extern f32 lbl_803E0EBC;
extern f32 lbl_803E0EC0;
extern f32 lbl_803E0EC4;
extern f32 lbl_803E0EC8;
extern f32 lbl_803E0ECC;
extern f32 lbl_803E0ED0;
extern f32 lbl_803E0ED4;
extern f32 lbl_803E0ED8;
extern f32 lbl_803E0EDC;
extern f32 lbl_803E0EE0;
extern f32 lbl_803E0EE4;
extern f32 lbl_803E0EE8;
extern f32 lbl_803E0EEC;
extern f32 lbl_803E0EF0;
extern f32 lbl_803E0EF4;
extern f32 lbl_803E0EF8;
extern f32 lbl_803E0EFC;
extern f32 lbl_803E0F00;
extern f32 lbl_803E0F04;
extern f32 lbl_803E0F08;
extern f32 lbl_803E0F0C;
extern f32 lbl_803E0F10;
extern f32 lbl_803E0F14;
extern f32 lbl_803E0F18;
extern f32 lbl_803E0F1C;
extern f32 lbl_803E0F20;
extern f32 lbl_803E0F24;
extern f32 lbl_803E0F28;
extern f32 lbl_803E0F2C;
extern f32 lbl_803E0F30;
extern f32 lbl_803E0F34;
extern f32 lbl_803E0F38;
extern f32 lbl_803E0F58;
extern f32 lbl_803E0F5C;
extern f32 lbl_803E0F60;
extern f32 lbl_803E0F64;
extern f32 lbl_803E0F68;
extern f32 lbl_803E0F6C;
extern f32 lbl_803E0F70;
extern f32 lbl_803E0F74;
extern f32 lbl_803E0F78;
extern f32 lbl_803E0F7C;
extern f32 lbl_803E0F90;
extern f32 lbl_803E0F94;
extern f32 lbl_803E0F98;
extern f32 lbl_803E0F9C;
extern f32 lbl_803E0FA0;
extern f32 lbl_803E0FA4;
extern f32 lbl_803E0FA8;
extern f32 lbl_803E0FAC;
extern f32 lbl_803E0FB0;
extern f32 lbl_803E0FB4;
extern f32 lbl_803E0FB8;
extern f32 lbl_803E0FBC;
extern f32 lbl_803E0FC0;
extern f32 lbl_803E0FCC;
extern f32 lbl_803E0FD0;
extern f32 lbl_803E0FD4;
extern f32 lbl_803E0FD8;
extern f32 lbl_803E0FDC;
extern f32 lbl_803E0FE0;
extern f32 lbl_803E0FE4;
extern f32 lbl_803E0FE8;
extern f32 lbl_803E0FEC;
extern f32 lbl_803E0FF0;
extern f32 lbl_803E0FF4;
extern f32 lbl_803E0FF8;
extern f32 lbl_803E0FFC;
extern f32 lbl_803E1000;
extern f32 lbl_803E1004;
extern f32 lbl_803E1008;
extern f32 lbl_803E100C;
extern f32 lbl_803E1010;
extern f32 lbl_803E1014;
extern f32 lbl_803E1018;
extern f32 lbl_803E101C;
extern f32 lbl_803E1020;
extern f32 lbl_803E1024;
extern f32 lbl_803E1028;
extern f32 lbl_803E102C;
extern f32 lbl_803E1030;
extern f32 lbl_803E1034;
extern f32 lbl_803E1038;
extern f32 lbl_803E103C;
extern f32 lbl_803E1040;
extern f32 lbl_803E1044;
extern f32 lbl_803E1048;
extern f32 lbl_803E104C;
extern f32 lbl_803E1050;
extern f32 lbl_803E1054;
extern f32 lbl_803E1058;
extern f32 lbl_803E105C;
extern f32 lbl_803E1060;
extern f32 lbl_803E1064;
extern f32 lbl_803E1068;
extern f32 lbl_803E106C;
extern f32 lbl_803E1070;
extern f32 lbl_803E1074;
extern f32 lbl_803E1078;
extern f32 lbl_803E107C;
extern f32 lbl_803E1080;
extern f32 lbl_803E1084;
extern f32 lbl_803E1088;
extern f32 lbl_803E108C;
extern f32 lbl_803E1090;
extern f32 lbl_803E1094;
extern f32 lbl_803E1098;
extern f32 lbl_803E109C;
extern f32 lbl_803E10A0;
extern f32 lbl_803E10A4;
extern f32 lbl_803E10A8;
extern f32 lbl_803E10AC;
extern f32 lbl_803E10B0;
extern f32 lbl_803E10B4;
extern f32 lbl_803E10B8;
extern f32 lbl_803E10BC;
extern f32 lbl_803E10C0;
extern f32 lbl_803E10C4;
extern f32 lbl_803E10C8;
extern f32 lbl_803E10CC;
extern f32 lbl_803E10D0;
extern f32 lbl_803E10D4;
extern f32 lbl_803E10D8;
extern f32 lbl_803E10DC;
extern f32 lbl_803E10E8;
extern f32 lbl_803E10EC;
extern f32 lbl_803E10F0;
extern f32 lbl_803E10F4;
extern f32 lbl_803E10F8;
extern f32 lbl_803E10FC;
extern f32 lbl_803E1100;
extern f32 lbl_803E1104;
extern f32 lbl_803E1108;
extern f32 lbl_803E110C;
extern f32 lbl_803E1110;
extern f32 lbl_803E1114;
extern f32 lbl_803E1118;
extern f32 lbl_803E111C;
extern f32 lbl_803E1120;
extern f32 lbl_803E1124;
extern f32 lbl_803E1128;
extern f32 lbl_803E112C;
extern f32 lbl_803E1130;
extern f32 lbl_803E1134;
extern f32 lbl_803E1138;
extern f32 lbl_803E113C;
extern f32 lbl_803E1140;
extern f32 lbl_803E1144;
extern f32 lbl_803E1148;
extern f32 lbl_803E1160;
extern f32 lbl_803E1164;
extern f32 lbl_803E1168;
extern f32 lbl_803E1180;
extern f32 lbl_803E1184;
extern f32 lbl_803E1188;

/*
 * --INFO--
 *
 * Function: FUN_800c8008
 * EN v1.0 Address: 0x800C8008
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800C8294
 * EN v1.1 Size: 4100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800c8008(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5,
            int param_6)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800c8010
 * EN v1.0 Address: 0x800C8010
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800C9298
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c8010(void)
{
  double dVar1;
  
  lbl_803DC4A8 = lbl_803DC4A8 + lbl_803E0D28 * lbl_803DC074;
  if (lbl_803E0D30 < lbl_803DC4A8) {
    lbl_803DC4A8 = lbl_803E0D2C;
  }
  lbl_803DC4AC = lbl_803DC4AC + lbl_803E0D28 * lbl_803DC074;
  if (lbl_803E0D30 < lbl_803DC4AC) {
    lbl_803DC4AC = lbl_803E0D38;
  }
  DAT_803de040 = DAT_803de040 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de040) {
    DAT_803de040 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE04C = (float)dVar1;
  DAT_803de044 = DAT_803de044 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de044) {
    DAT_803de044 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE048 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800c8104
 * EN v1.0 Address: 0x800C8104
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800C93CC
 * EN v1.1 Size: 4748b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c8104(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800c8108
 * EN v1.0 Address: 0x800C8108
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800CA658
 * EN v1.1 Size: 1380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800c8108(uint param_1,int param_2,undefined2 *param_3,uint param_4,undefined param_5)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800c8110
 * EN v1.0 Address: 0x800C8110
 * EN v1.0 Size: 904b
 * EN v1.1 Address: 0x800CABBC
 * EN v1.1 Size: 3116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800c8110(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5,
            int param_6)
{
  undefined4 uVar1;
  uint uVar2;
  int local_98 [3];
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
  uint local_48;
  uint local_44;
  undefined2 local_40;
  undefined2 local_3e;
  undefined2 local_3c;
  undefined local_3a;
  undefined local_38;
  undefined local_37;
  undefined local_36;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  lbl_803DC4B0 = lbl_803DC4B0 + lbl_803E0E38;
  if (lbl_803E0E40 < lbl_803DC4B0) {
    lbl_803DC4B0 = lbl_803E0E3C;
  }
  lbl_803DC4B4 = lbl_803DC4B4 + lbl_803E0E44;
  if (lbl_803E0E40 < lbl_803DC4B4) {
    lbl_803DC4B4 = lbl_803E0E48;
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
    local_68 = lbl_803E0E4C;
    local_64 = lbl_803E0E4C;
    local_60 = lbl_803E0E4C;
    local_74 = lbl_803E0E4C;
    local_70 = lbl_803E0E4C;
    local_6c = lbl_803E0E4C;
    local_5c = lbl_803E0E4C;
    local_98[2] = 0;
    local_98[1] = 0xffffffff;
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
    local_98[0] = param_1;
    switch(param_2) {
    case 0x73a:
      uStack_2c = FUN_80017760(8,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_70 = lbl_803E0E50 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0e90);
      uVar2 = FUN_80017760(0,0x28);
      if (uVar2 == 0) {
        uStack_2c = FUN_80017760(0x15,0x29);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_5c = lbl_803E0E38 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0e90);
        local_98[2] = 0x1cc;
      }
      else {
        uStack_2c = FUN_80017760(8,0x14);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_5c = lbl_803E0E38 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0e90);
        local_98[2] = FUN_80017760(0x5a,0x78);
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
      local_64 = lbl_803E0E54;
      break;
    case 0x73b:
      uStack_2c = FUN_80017760(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = lbl_803E0E50 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0e90);
      uStack_24 = FUN_80017760(8,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = lbl_803E0E50 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90);
      uStack_1c = FUN_80017760(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_6c = lbl_803E0E50 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
      local_5c = lbl_803E0E58;
      local_98[2] = 0x32;
      local_54 = 0x3000200;
      local_50 = 0x200020;
      local_56 = 0x33;
      local_38 = 0xff;
      local_40 = 0xffff;
      local_3e = 0xffff;
      local_3c = 0xffff;
      local_4c = 0xffff;
      local_48 = FUN_80017760(0,0x8000);
      local_64 = lbl_803E0E5C;
      local_44 = local_48;
      break;
    default:
      return 0xffffffff;
    case 0x73d:
      uStack_1c = FUN_80017760(0xfffffff6,10);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_68 = lbl_803E0E3C * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
      uStack_24 = FUN_80017760(0xfffffff6,100);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_64 = lbl_803E0E50 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90);
      uStack_2c = FUN_80017760(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_60 = lbl_803E0E3C * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0e90);
      uStack_14 = FUN_80017760(7,9);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = lbl_803E0E60 *
                 lbl_803E0E64 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
      local_98[2] = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xde;
      break;
    case 0x73e:
      uStack_14 = FUN_80017760(0xfffffff6,10);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_68 = lbl_803E0E3C * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
      uStack_1c = FUN_80017760(0xfffffff6,100);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_64 = lbl_803E0E50 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
      uStack_24 = FUN_80017760(0xfffffff6,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_60 = lbl_803E0E3C * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90);
      uStack_2c = FUN_80017760(7,9);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = lbl_803E0E60 *
                 lbl_803E0E64 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0e90);
      local_98[2] = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xdf;
      break;
    case 0x73f:
      if (param_6 == 0) {
        uStack_14 = FUN_80017760(0xfffffff6,10);
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        local_68 = lbl_803E0E3C *
                   (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
        uStack_1c = FUN_80017760(0xfffffff6,100);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_64 = lbl_803E0E50 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
        uStack_24 = FUN_80017760(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_60 = lbl_803E0E3C *
                   (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90);
      }
      else {
        uStack_14 = FUN_80017760(0xfffffff6,10);
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        local_68 = lbl_803E0E3C *
                   (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90) +
                   lbl_803E0E68;
        uStack_1c = FUN_80017760(0xfffffff6,100);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_64 = lbl_803E0E50 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90) +
                   lbl_803E0E6C;
        uStack_24 = FUN_80017760(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_60 = lbl_803E0E3C *
                   (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90) +
                   lbl_803E0E70;
      }
      local_28 = 0x43300000;
      uStack_14 = FUN_80017760(7,9);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = lbl_803E0E74 *
                 lbl_803E0E64 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
      local_98[2] = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xde;
      break;
    case 0x740:
      if (param_6 == 0) {
        uStack_14 = FUN_80017760(0xfffffff6,10);
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        local_68 = lbl_803E0E3C *
                   (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
        uStack_1c = FUN_80017760(0xfffffff6,100);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_64 = lbl_803E0E50 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
        uStack_24 = FUN_80017760(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_60 = lbl_803E0E3C *
                   (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90);
      }
      else {
        uStack_14 = FUN_80017760(0xfffffff6,10);
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        local_68 = lbl_803E0E3C *
                   (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90) +
                   lbl_803E0E68;
        uStack_1c = FUN_80017760(0xfffffff6,100);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_64 = lbl_803E0E50 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90) +
                   lbl_803E0E6C;
        uStack_24 = FUN_80017760(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_60 = lbl_803E0E3C *
                   (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0e90) +
                   lbl_803E0E70;
      }
      local_28 = 0x43300000;
      uStack_14 = FUN_80017760(7,9);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = lbl_803E0E74 *
                 lbl_803E0E64 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
      local_98[2] = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xdf;
      break;
    case 0x741:
      if (param_3 != (undefined2 *)0x0) {
        local_64 = *(float *)(param_3 + 8);
      }
      local_5c = lbl_803E0E78;
      local_98[2] = FUN_80017760(0,0x1e);
      local_98[2] = local_98[2] + 0x50;
      local_38 = 0x60;
      local_54 = 0x80110;
      local_56 = 0x7b;
      local_37 = 0x20;
      break;
    case 0x742:
      local_6c = lbl_803E0E7C;
      uStack_14 = FUN_80017760(0xffffffec,0x14);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = lbl_803E0E80 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
      uStack_1c = FUN_80017760(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_70 = lbl_803E0E80 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
      local_5c = lbl_803E0E84;
      local_98[2] = FUN_80017760(0x46,0x50);
      local_38 = 0xff;
      local_54 = 0x82000104;
      local_50 = 0x400;
      local_56 = 0x3f4;
      break;
    case 0x743:
      local_6c = lbl_803E0E7C;
      uStack_14 = FUN_80017760(0xffffffec,0x14);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = lbl_803E0E80 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0e90);
      uStack_1c = FUN_80017760(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_70 = lbl_803E0E80 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0e90);
      local_5c = lbl_803E0E84;
      local_98[2] = FUN_80017760(0x46,0x50);
      local_38 = 0xff;
      local_54 = 0x82000104;
      local_50 = 0x400;
      local_56 = 0x500;
      break;
    case 0x744:
      uVar2 = FUN_80017760(0,4);
      if (uVar2 == 4) {
        local_5c = lbl_803E0E88;
        local_38 = 0x9b;
        local_54 = 0x480000;
        local_98[2] = FUN_80017760(0x1e,0x28);
      }
      else {
        local_5c = lbl_803E0E8C;
        local_38 = 0x7d;
        local_54 = 0x180000;
        local_98[2] = 0x50;
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
        if (local_98[0] != 0) {
          local_68 = local_68 + *(float *)(local_98[0] + 0x18);
          local_64 = local_64 + *(float *)(local_98[0] + 0x1c);
          local_60 = local_60 + *(float *)(local_98[0] + 0x20);
        }
      }
      else {
        local_68 = local_68 + local_80;
        local_64 = local_64 + local_7c;
        local_60 = local_60 + local_78;
      }
    }
    uVar1 = (**(code **)(*DAT_803dd6f8 + 8))(local_98,0xffffffff,param_2,0);
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_800c8498
 * EN v1.0 Address: 0x800C8498
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800CB7E8
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c8498(void)
{
  double dVar1;
  
  lbl_803DC4B8 = lbl_803DC4B8 + lbl_803E0E38 * lbl_803DC074;
  if (lbl_803E0E40 < lbl_803DC4B8) {
    lbl_803DC4B8 = lbl_803E0E3C;
  }
  lbl_803DC4BC = lbl_803DC4BC + lbl_803E0E38 * lbl_803DC074;
  if (lbl_803E0E40 < lbl_803DC4BC) {
    lbl_803DC4BC = lbl_803E0E48;
  }
  DAT_803de050 = DAT_803de050 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de050) {
    DAT_803de050 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE05C = (float)dVar1;
  DAT_803de054 = DAT_803de054 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de054) {
    DAT_803de054 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE058 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800c858c
 * EN v1.0 Address: 0x800C858C
 * EN v1.0 Size: 1676b
 * EN v1.1 Address: 0x800CB91C
 * EN v1.1 Size: 6040b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c858c(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
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
  lbl_803DC4C0 = lbl_803DC4C0 + lbl_803E0EA0;
  if (lbl_803E0EA8 < lbl_803DC4C0) {
    lbl_803DC4C0 = lbl_803E0EA4;
  }
  lbl_803DC4C4 = lbl_803DC4C4 + lbl_803E0EAC;
  if (lbl_803E0EA8 < lbl_803DC4C4) {
    lbl_803DC4C4 = lbl_803E0EB0;
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
    local_98 = lbl_803E0EB4;
    local_94 = lbl_803E0EB4;
    local_90 = lbl_803E0EB4;
    local_a4 = lbl_803E0EB4;
    local_a0 = lbl_803E0EB4;
    local_9c = lbl_803E0EB4;
    local_8c = lbl_803E0EB4;
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
      fStack_5c = (float)FUN_80017760(10,0x19);
      fStack_5c = -fStack_5c;
      local_60 = 0x43300000;
      local_a4 = lbl_803E0EB8 * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      local_8c = lbl_803E0EA4;
      local_c0 = (float)FUN_80017760(0x15e,400);
      local_84 = 0xa100100;
      local_80 = 0x1000000;
      local_86 = 0x62;
      break;
    case 0x709:
      fStack_5c = (float)FUN_80017760(10,0x14);
      fStack_5c = -fStack_5c;
      local_60 = 0x43300000;
      local_a0 = lbl_803E0EBC * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      uVar2 = FUN_80017760(0,1);
      if (uVar2 != 0) {
        local_a0 = -local_a0;
      }
      local_8c = lbl_803E0EA0;
      local_c0 = 1.68156e-43;
      uVar2 = FUN_80017760(0x7f,0xff);
      local_68 = (undefined)uVar2;
      local_84 = 0x80480000;
      local_80 = 0x440000;
      uVar2 = FUN_80017760(0x525,0x528);
      local_86 = (undefined2)uVar2;
      break;
    case 0x70a:
      fStack_5c = (float)FUN_80017760(0xffffffec,0x14);
      fStack_5c = -fStack_5c;
      local_60 = 0x43300000;
      local_a4 = lbl_803E0EC0 * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      fStack_54 = (float)FUN_80017760(0xffffffec,0x14);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_a0 = lbl_803E0EC0 * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      uStack_4c = FUN_80017760(0xffffffec,0x14);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = lbl_803E0EC0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      local_8c = lbl_803E0EC4;
      local_c0 = 7.00649e-44;
      local_84 = 0x480100;
      uVar2 = FUN_80017760(0x525,0x528);
      local_86 = (undefined2)uVar2;
      break;
    case 0x70b:
      local_c0 = 1.4013e-43;
      local_8c = lbl_803E0EC8;
      local_84 = 0x180200;
      local_86 = 0x208;
      local_80 = 0x5000000;
      break;
    case 0x70c:
      local_c0 = (float)FUN_80017760(0x19,0x4b);
      uStack_4c = FUN_80017760(0xffffffd8,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a4 = lbl_803E0EBC * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      fStack_54 = -local_c0;
      local_58 = 0x43300000;
      local_a0 = lbl_803E0ECC * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      fStack_5c = (float)FUN_80017760(0xffffffd8,0x28);
      fStack_5c = -fStack_5c;
      local_60 = 0x43300000;
      local_9c = lbl_803E0EBC * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      uVar2 = FUN_80017760(0x32,100);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_8c = lbl_803E0ED0 * (float)(local_48 - DOUBLE_803e0f40);
      local_84 = 0x1082000;
      uVar2 = FUN_80017760(0x208,0x20a);
      local_86 = (undefined2)uVar2;
      local_80 = 0x1400000;
      break;
    default:
      goto LAB_800cd094;
    case 0x70f:
      local_c0 = (float)FUN_80017760(0xf,0x2d);
      uVar2 = FUN_80017760(0xfffffffb,5);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_98 = (float)(local_48 - DOUBLE_803e0f40);
      uStack_4c = FUN_80017760(0xfffffffb,5);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      fStack_54 = (float)FUN_80017760(0xffffffd8,0x28);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_a4 = lbl_803E0EBC * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      fStack_5c = -local_c0;
      local_60 = 0x43300000;
      local_a0 = lbl_803E0ECC * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80017760(0xffffffd8,0x28);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_9c = lbl_803E0EBC * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uStack_34 = FUN_80017760(0x32,0x46);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = lbl_803E0ED4 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      local_68 = 0xa0;
      local_84 = 0x1082000;
      local_80 = 0x5400000;
      uVar2 = FUN_80017760(0x208,0x20a);
      local_86 = (undefined2)uVar2;
      break;
    case 0x710:
      fVar3 = lbl_803E0EA8;
      if (param_6 != (float *)0x0) {
        fVar3 = *param_6;
      }
      dVar5 = (double)fVar3;
      local_c0 = (float)FUN_80017760(0xf,0x4b);
      local_94 = (float)((double)lbl_803E0ED8 * dVar5);
      local_90 = (float)((double)lbl_803E0EDC * dVar5);
      uStack_34 = FUN_80017760(0xffffffe2,0x1e);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = lbl_803E0EBC * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = -local_c0;
      local_40 = 0x43300000;
      local_a0 = lbl_803E0ECC * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80017760(0x14,0x46);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = lbl_803E0EE0 * (float)(local_48 - DOUBLE_803e0f40);
      uStack_4c = FUN_80017760(0x28,0x3c);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = lbl_803E0EE4 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      uVar2 = FUN_80017760(0x3c,0xa0);
      local_68 = (undefined)uVar2;
      local_84 = 0x81080200;
      local_80 = 0x4000800;
      local_86 = 0xc0f;
      break;
    case 0x711:
      fVar3 = lbl_803E0EA8;
      if (param_6 != (float *)0x0) {
        fVar3 = *param_6;
      }
      dVar5 = (double)fVar3;
      local_c0 = (float)FUN_80017760(0x23,0x4b);
      local_94 = (float)((double)lbl_803E0EE8 * dVar5);
      local_90 = (float)((double)lbl_803E0EDC * dVar5);
      uStack_34 = FUN_80017760(0xffffffce,0x32);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = lbl_803E0EBC * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = -local_c0;
      local_40 = 0x43300000;
      local_a0 = lbl_803E0EEC * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80017760(0x14,0x3c);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = lbl_803E0EE0 * (float)(local_48 - DOUBLE_803e0f40);
      uStack_4c = FUN_80017760(0x28,0x3c);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = lbl_803E0EE4 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      uVar2 = FUN_80017760(100,200);
      local_68 = (undefined)uVar2;
      local_84 = 0x81080200;
      local_80 = 0x4000800;
      local_86 = 0xc0f;
      break;
    case 0x712:
      local_c0 = (float)FUN_80017760(0x32,100);
      uStack_34 = FUN_80017760(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = lbl_803E0EBC * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = -local_c0;
      local_40 = 0x43300000;
      local_a0 = lbl_803E0EF0 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80017760(0xffffffec,0x14);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = lbl_803E0EBC * (float)(local_48 - DOUBLE_803e0f40);
      local_8c = lbl_803E0EF4;
      uVar2 = FUN_80017760(0,2);
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
      uVar2 = FUN_80017760(0x1e,0x28);
      local_68 = (undefined)uVar2;
      if (param_6 != (float *)0x0) {
        local_38 = 0x43300000;
        fStack_3c = -*param_6;
        local_40 = 0x43300000;
        iVar1 = (int)((float)((double)CONCAT44(0x43300000,uVar2 & 0xff) - DOUBLE_803e0f48) *
                     ((float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40) /
                     lbl_803E0EF8));
        local_48 = (double)(longlong)iVar1;
        local_68 = (undefined)iVar1;
        uStack_34 = uVar2 & 0xff;
      }
      uStack_34 = FUN_80017760(0x12,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = lbl_803E0EFC * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80017760(0x28,0x3c);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_8c = lbl_803E0F00 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80017760(8,0x14);
      local_84 = 0x80204;
      local_80 = 0x4002800;
      local_86 = 0xc0f;
      break;
    case 0x715:
      if (param_6 == (float *)0x0) {
        uStack_34 = FUN_80017760(0x32,100);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_8c = lbl_803E0F0C *
                   (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
        local_c0 = 1.68156e-43;
        local_84 = 0x80580200;
        local_80 = 0x800;
      }
      else {
        uStack_34 = FUN_80017760(0xffffffe7,0x19);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_a4 = lbl_803E0F04 *
                   (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
        fStack_3c = (float)FUN_80017760(5,0x32);
        fStack_3c = -fStack_3c;
        local_40 = 0x43300000;
        local_a0 = lbl_803E0F04 *
                   (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
        uVar2 = FUN_80017760(0xffffffe7,0x19);
        local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_9c = lbl_803E0F04 * (float)(local_48 - DOUBLE_803e0f40);
        local_8c = lbl_803E0F08;
        local_c0 = (float)FUN_80017760(0x28,0x78);
        local_84 = 0x80480000;
        local_80 = 0x400800;
      }
      local_68 = 0xff;
      local_86 = 0xc0f;
      break;
    case 0x716:
      uStack_34 = FUN_80017760(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80017760(0xffffffec,0x14);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80017760(0xffffffec,0x14);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_90 = (float)(local_48 - DOUBLE_803e0f40);
      uStack_4c = FUN_80017760(0x5a,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = lbl_803E0EB8 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      local_67 = 0xf;
      fStack_54 = (float)FUN_80017760(0x5a,100);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_8c = lbl_803E0EA0 * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      local_84 = 0x800c0100;
      local_80 = 0x4000800;
      uVar2 = FUN_80017760(0x96,200);
      local_68 = (undefined)uVar2;
      local_c0 = (float)FUN_80017760(0x32,0x46);
      local_86 = 0x185;
      break;
    case 0x717:
      fVar3 = lbl_803E0EA8;
      if (param_6 != (float *)0x0) {
        fVar3 = *param_6;
      }
      dVar5 = (double)fVar3;
      uStack_34 = FUN_80017760(0xffffff6a,0x96);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)(dVar5 * (double)(lbl_803E0EA4 *
                                         (float)((double)CONCAT44(0x43300000,uStack_34) -
                                                DOUBLE_803e0f40)));
      fStack_3c = (float)FUN_80017760(100,300);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_94 = (float)(dVar5 * (double)(lbl_803E0EA4 *
                                         (float)((double)CONCAT44(0x43300000,fStack_3c) -
                                                DOUBLE_803e0f40)));
      uVar2 = FUN_80017760(0xffffff6a,0xffffffce);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_90 = (float)(dVar5 * (double)(lbl_803E0EA4 * (float)(local_48 - DOUBLE_803e0f40)));
      local_8c = lbl_803E0EC4;
      local_c0 = (float)FUN_80017760(0x32,0x96);
      local_84 = 0x80480100;
      uVar2 = FUN_80017760(0x527,0x528);
      local_86 = (undefined2)uVar2;
      break;
    case 0x718:
      uStack_34 = FUN_80017760(8,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = lbl_803E0EFC * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      if (param_6 != (float *)0x0) {
        local_a0 = local_a0 * (lbl_803E0EA8 + *param_6 / lbl_803E0F10);
      }
      uStack_34 = FUN_80017760(6,0xc);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = lbl_803E0EC0 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80017760(0x3c,100);
      local_84 = 0x80180000;
      local_80 = 0x5440800;
      local_86 = 0xc0b;
      local_68 = 0x40;
      break;
    case 0x71a:
      local_90 = lbl_803E0F14;
      uStack_34 = FUN_80017760(0x4b,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = lbl_803E0F18 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      local_c0 = 1.4013e-45;
      local_84 = 0x80010;
      local_80 = 0x800;
      local_86 = 0xc7e;
      local_68 = 0x7f;
      break;
    case 0x71b:
      local_8c = lbl_803E0F1C;
      local_c0 = 1.4013e-43;
      local_84 = 0x180000;
      local_80 = 0x400800;
      local_86 = 0x73;
      local_68 = 0xff;
      break;
    case 0x71c:
      local_c0 = (float)FUN_80017760(0x28,0x78);
      uStack_34 = FUN_80017760(0xffffffce,0x32);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = lbl_803E0EFC * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = -local_c0;
      local_40 = 0x43300000;
      local_a0 = lbl_803E0F20 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80017760(0xffffffce,0x32);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_9c = lbl_803E0EFC * (float)(local_48 - DOUBLE_803e0f40);
      local_8c = lbl_803E0F04;
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
      uStack_34 = FUN_80017760(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80017760(0xffffffec,0x14);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80017760(0xffffffec,0x14);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_90 = (float)(local_48 - DOUBLE_803e0f40);
      local_67 = 0xf;
      uStack_4c = FUN_80017760(0x78,200);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = lbl_803E0EA0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      local_84 = 0x80180100;
      local_80 = 0x4000800;
      uVar2 = FUN_80017760(0x32,100);
      local_68 = (undefined)uVar2;
      local_c0 = (float)FUN_80017760(100,0x8c);
      local_86 = 0x185;
      break;
    case 0x71e:
      uStack_34 = FUN_80017760(0xffffffdd,0x23);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80017760(0,0x1e);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = FUN_80017760(0xffffffdd,0x23);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_90 = (float)(local_48 - DOUBLE_803e0f40);
      uStack_4c = FUN_80017760(8,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = lbl_803E0EFC * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      fStack_54 = (float)FUN_80017760(6,0xc);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_8c = lbl_803E0EC0 * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80017760(100,0x96);
      local_84 = 0x80180000;
      local_80 = 0x1440000;
      local_86 = 0x564;
      local_68 = 0x7f;
      break;
    case 0x71f:
      uStack_34 = FUN_80017760(8,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = lbl_803E0EFC * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80017760(6,0xc);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_8c = lbl_803E0F08 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80017760(0x3c,0x50);
      local_84 = 0x80180000;
      local_80 = 0x5440800;
      local_86 = 0x564;
      local_68 = 0x40;
      break;
    case 0x720:
      uStack_34 = FUN_80017760(8,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = lbl_803E0F24 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80017760(6,0xc);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_8c = lbl_803E0F08 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80017760(0x3c,0x50);
      local_84 = 0x80180200;
      local_80 = 0x5000800;
      local_86 = 0x564;
      local_68 = 0x40;
      break;
    case 0x721:
      uStack_34 = FUN_80017760(6,0xc);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = lbl_803E0F28 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80017760(0xfa,0x15e);
      local_84 = 0x80480008;
      local_80 = 0x400000;
      local_86 = 0xc0d;
      break;
    case 0x722:
      local_94 = lbl_803E0F2C;
      local_c0 = (float)FUN_80017760(0x1e,0x3c);
      uStack_34 = FUN_80017760(0xffffffc4,0x3c);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = lbl_803E0F24 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      dVar5 = FUN_80293900((double)(local_a4 * local_a4 + local_9c * local_9c));
      local_a0 = (float)((double)lbl_803E0F30 * dVar5);
      fStack_3c = (float)FUN_80017760(0xffffffc4,0x3c);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_9c = lbl_803E0F24 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_8c = lbl_803E0F24;
      local_84 = 0x80000;
      local_80 = 0x5400800;
      local_86 = 0x564;
      uVar2 = FUN_80017760(0x46,0xbe);
      local_68 = (undefined)((int)uVar2 >> 1);
      break;
    case 0x723:
      local_c0 = (float)FUN_80017760(0x23,0x2d);
      if (param_6 == (float *)0x0) {
        fVar3 = 7.00649e-45;
      }
      else {
        fVar3 = (float)((int)*param_6 + 5);
      }
      uStack_34 = FUN_80017760(8,0xc);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      fStack_3c = -fVar3;
      local_40 = 0x43300000;
      local_a0 = ((float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40) / lbl_803E0F34
                 ) * lbl_803E0F38 *
                     (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      uVar4 = 0x41 - (int)fVar3;
      uVar2 = FUN_80017760(-uVar4,uVar4);
      local_48 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_a4 = lbl_803E0ECC * (float)(local_48 - DOUBLE_803e0f40);
      uStack_4c = FUN_80017760(-uVar4,uVar4);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = lbl_803E0ECC * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0f40);
      fStack_54 = (float)FUN_80017760(6,0xc);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_8c = lbl_803E0EC0 * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      uVar2 = FUN_80017760(0x40,0x7f);
      local_68 = (undefined)((int)uVar2 >> 1);
      local_84 = 0x80080000;
      local_80 = 0x5400800;
      local_86 = 0x564;
      break;
    case 0x724:
      uStack_34 = FUN_80017760(8,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = lbl_803E0EFC * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0f40);
      fStack_3c = (float)FUN_80017760(6,0xc);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_8c = lbl_803E0EC0 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_c0 = (float)FUN_80017760(0x1e,0x3c);
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

/*
 * --INFO--
 *
 * Function: FUN_800c8c18
 * EN v1.0 Address: 0x800C8C18
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800CD0B4
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c8c18(void)
{
  double dVar1;
  
  lbl_803DC4C8 = lbl_803DC4C8 + lbl_803E0EA0 * lbl_803DC074;
  if (lbl_803E0EA8 < lbl_803DC4C8) {
    lbl_803DC4C8 = lbl_803E0EA4;
  }
  lbl_803DC4CC = lbl_803DC4CC + lbl_803E0EA0 * lbl_803DC074;
  if (lbl_803E0EA8 < lbl_803DC4CC) {
    lbl_803DC4CC = lbl_803E0EB0;
  }
  DAT_803de060 = DAT_803de060 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de060) {
    DAT_803de060 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE06C = (float)dVar1;
  DAT_803de064 = DAT_803de064 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de064) {
    DAT_803de064 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE068 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800c8d0c
 * EN v1.0 Address: 0x800C8D0C
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x800CD1E8
 * EN v1.1 Size: 928b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c8d0c(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)
{
  int iVar1;
  undefined8 uVar2;
  int local_a8 [3];
  undefined2 local_9c;
  undefined2 local_9a;
  undefined2 local_98;
  undefined4 local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  undefined2 local_68;
  undefined2 local_66;
  uint local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined2 local_50;
  undefined2 local_4e;
  undefined2 local_4c;
  undefined local_4a;
  undefined local_48;
  undefined local_47;
  undefined local_46;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  
  uVar2 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar2 >> 0x20);
  lbl_803DC4D0 = lbl_803DC4D0 + lbl_803E0F58;
  if (lbl_803E0F60 < lbl_803DC4D0) {
    lbl_803DC4D0 = lbl_803E0F5C;
  }
  lbl_803DC4D4 = lbl_803DC4D4 + lbl_803E0F64;
  if (lbl_803E0F60 < lbl_803DC4D4) {
    lbl_803DC4D4 = lbl_803E0F68;
  }
  if (iVar1 != 0) {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) goto LAB_800cd570;
      local_90 = *(float *)(param_3 + 6);
      local_8c = *(float *)(param_3 + 8);
      local_88 = *(float *)(param_3 + 10);
      local_94 = *(undefined4 *)(param_3 + 4);
      local_98 = param_3[2];
      local_9a = param_3[1];
      local_9c = *param_3;
      local_46 = param_5;
    }
    local_64 = 0;
    local_60 = 0;
    local_4a = (undefined)uVar2;
    local_78 = lbl_803E0F6C;
    local_74 = lbl_803E0F6C;
    local_70 = lbl_803E0F6C;
    local_84 = lbl_803E0F6C;
    local_80 = lbl_803E0F6C;
    local_7c = lbl_803E0F6C;
    local_6c = lbl_803E0F6C;
    local_a8[2] = 0;
    local_a8[1] = 0xffffffff;
    local_48 = 0xff;
    local_47 = 0;
    local_66 = 0;
    local_50 = 0xffff;
    local_4e = 0xffff;
    local_4c = 0xffff;
    local_5c = 0xffff;
    local_58 = 0xffff;
    local_54 = 0xffff;
    local_68 = 0;
    local_a8[0] = iVar1;
    if ((int)uVar2 == 0x76c) {
      uStack_3c = FUN_80017760(0x1e,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = lbl_803E0F70 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0f80);
      if (lbl_803E0F6C < *(float *)(param_3 + 6)) {
        local_84 = -local_84;
      }
      uStack_3c = FUN_80017760(0,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_80 = lbl_803E0F58 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0f80)
                 + lbl_803E0F5C;
      local_38 = (longlong)(int)*param_6;
      local_30 = (longlong)(int)param_6[1];
      uStack_24 = FUN_80017760((int)*param_6,(int)param_6[1]);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = lbl_803E0F5C * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0f80);
      local_78 = lbl_803E0F74;
      if (lbl_803E0F6C < *(float *)(param_3 + 6)) {
        local_78 = lbl_803E0F78;
      }
      uStack_24 = FUN_80017760(0xffffff9c,100);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_6c = lbl_803E0F7C * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0f80)
                 + param_6[2];
      local_a8[2] = 0x23;
      local_66 = 0x60;
      local_48 = 0xc4;
      local_64 = param_4 | 0x80108;
      if (((param_4 & 1) != 0) && ((param_4 & 2) != 0)) {
        local_64 = local_64 ^ 2;
      }
      if ((local_64 & 1) != 0) {
        if ((param_4 & 0x200000) == 0) {
          if (local_a8[0] != 0) {
            local_78 = local_78 + *(float *)(local_a8[0] + 0x18);
            local_74 = local_74 + *(float *)(local_a8[0] + 0x1c);
            local_70 = local_70 + *(float *)(local_a8[0] + 0x20);
          }
        }
        else {
          local_78 = local_78 + local_90;
          local_74 = local_74 + local_8c;
          local_70 = local_70 + local_88;
        }
      }
      (**(code **)(*DAT_803dd6f8 + 8))(local_a8,0xffffffff,0x76c,0);
    }
  }
LAB_800cd570:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800c8e44
 * EN v1.0 Address: 0x800C8E44
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800CD588
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c8e44(void)
{
  double dVar1;
  
  lbl_803DC4D8 = lbl_803DC4D8 + lbl_803E0F58 * lbl_803DC074;
  if (lbl_803E0F60 < lbl_803DC4D8) {
    lbl_803DC4D8 = lbl_803E0F5C;
  }
  lbl_803DC4DC = lbl_803DC4DC + lbl_803E0F58 * lbl_803DC074;
  if (lbl_803E0F60 < lbl_803DC4DC) {
    lbl_803DC4DC = lbl_803E0F68;
  }
  DAT_803de070 = DAT_803de070 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de070) {
    DAT_803de070 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE07C = (float)dVar1;
  DAT_803de074 = DAT_803de074 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de074) {
    DAT_803de074 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE078 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800c8f38
 * EN v1.0 Address: 0x800C8F38
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800CD6BC
 * EN v1.1 Size: 32716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c8f38(undefined4 param_1,undefined4 param_2,ushort *param_3,uint param_4,
                 undefined param_5,float *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800c8f3c
 * EN v1.0 Address: 0x800C8F3C
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800D5688
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c8f3c(void)
{
  double dVar1;
  
  lbl_803DC4E8 = lbl_803DC4E8 + lbl_803E0F90 * lbl_803DC074;
  if (lbl_803E0F98 < lbl_803DC4E8) {
    lbl_803DC4E8 = lbl_803E0F94;
  }
  lbl_803DC4EC = lbl_803DC4EC + lbl_803E0F90 * lbl_803DC074;
  if (lbl_803E0F98 < lbl_803DC4EC) {
    lbl_803DC4EC = lbl_803E0FA0;
  }
  DAT_803de080 = DAT_803de080 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de080) {
    DAT_803de080 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE08C = (float)dVar1;
  DAT_803de084 = DAT_803de084 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de084) {
    DAT_803de084 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE088 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800c9030
 * EN v1.0 Address: 0x800C9030
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x800D57BC
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800c9030(uint param_1,int *param_2)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  *param_2 = -1;
  if ((int)param_1 < 0) {
    return 0;
  }
  iVar1 = DAT_803de090 + -1;
  iVar2 = 0;
  while( true ) {
    while( true ) {
      if (iVar1 < iVar2) {
        *param_2 = -1;
        return 0;
      }
      iVar3 = iVar1 + iVar2 >> 1;
      if (param_1 <= (uint)(&DAT_8039d0b8)[iVar3 * 2]) break;
      iVar2 = iVar3 + 1;
    }
    if ((uint)(&DAT_8039d0b8)[iVar3 * 2] <= param_1) break;
    iVar1 = iVar3 + -1;
  }
  *param_2 = iVar3;
  return (&DAT_8039d0bc)[iVar3 * 2];
}

/*
 * --INFO--
 *
 * Function: FUN_800c90b0
 * EN v1.0 Address: 0x800C90B0
 * EN v1.0 Size: 2428b
 * EN v1.1 Address: 0x800D5848
 * EN v1.1 Size: 2500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c90b0(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 float *param_5,float *param_6,float *param_7,uint param_8)
{
  uint uVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double extraout_f1;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double in_f20;
  double dVar16;
  double in_f21;
  double dVar17;
  double in_f22;
  double in_f23;
  double in_f24;
  double in_f25;
  double dVar18;
  double in_f26;
  double in_f27;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar19;
  double in_ps20_1;
  double in_ps21_1;
  double in_ps22_1;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar20;
  int aiStack_168 [2];
  undefined4 local_160;
  uint uStack_15c;
  undefined4 local_158;
  uint uStack_154;
  undefined4 local_150;
  uint uStack_14c;
  undefined4 local_148;
  uint uStack_144;
  undefined4 local_140;
  uint uStack_13c;
  undefined4 local_138;
  uint uStack_134;
  undefined4 local_130;
  uint uStack_12c;
  undefined4 local_128;
  uint uStack_124;
  undefined4 local_120;
  uint uStack_11c;
  undefined4 local_118;
  uint uStack_114;
  undefined4 local_110;
  uint uStack_10c;
  undefined4 local_108;
  uint uStack_104;
  undefined4 local_100;
  uint uStack_fc;
  undefined4 local_f8;
  uint uStack_f4;
  float local_b8;
  float fStack_b4;
  float local_a8;
  float fStack_a4;
  float local_98;
  float fStack_94;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  local_98 = (float)in_f22;
  fStack_94 = (float)in_ps22_1;
  local_a8 = (float)in_f21;
  fStack_a4 = (float)in_ps21_1;
  local_b8 = (float)in_f20;
  fStack_b4 = (float)in_ps20_1;
  uVar20 = FUN_80286824();
  iVar3 = (int)((ulonglong)uVar20 >> 0x20);
  if (iVar3 != 0) {
    dVar15 = extraout_f1;
    iVar4 = FUN_800c9030(*(uint *)(iVar3 + (int)uVar20 * 4 + 0x20),aiStack_168);
    if (iVar4 == 0) {
      iVar4 = FUN_800c9030(*(uint *)(iVar3 + (1 - (int)uVar20) * 4 + 0x20),aiStack_168);
    }
    if (iVar4 != 0) {
      uStack_15c = (uint)*(byte *)(iVar3 + 0x29) << 8 ^ 0x80000000;
      local_160 = 0x43300000;
      dVar9 = (double)FUN_80293f90();
      dVar9 = -dVar9;
      uStack_154 = (uint)*(byte *)(iVar3 + 0x29) << 8 ^ 0x80000000;
      local_158 = 0x43300000;
      dVar10 = (double)FUN_80294964();
      dVar10 = -dVar10;
      uStack_14c = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
      local_150 = 0x43300000;
      dVar11 = (double)FUN_80293f90();
      dVar11 = -dVar11;
      uStack_144 = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
      local_148 = 0x43300000;
      dVar12 = (double)FUN_80294964();
      dVar14 = DOUBLE_803e1170;
      dVar12 = -dVar12;
      uStack_13c = (uint)*(byte *)(iVar3 + 0x2a);
      local_140 = 0x43300000;
      dVar17 = (double)(lbl_803E1160 *
                       (float)((double)CONCAT44(0x43300000,uStack_13c) - DOUBLE_803e1178));
      uStack_134 = (uint)*(byte *)(iVar4 + 0x2a);
      local_138 = 0x43300000;
      dVar16 = (double)(lbl_803E1160 *
                       (float)((double)CONCAT44(0x43300000,uStack_134) - DOUBLE_803e1178));
      uVar1 = param_8 & 0xff;
      if (uVar1 == 1) {
        iVar5 = 0;
        iVar8 = 0;
        dVar18 = (double)(float)(dVar17 * dVar10);
        dVar12 = (double)(float)(dVar16 * dVar12);
        dVar10 = (double)(float)(dVar17 * -dVar9);
        dVar9 = (double)(float)(dVar16 * -dVar11);
        dVar11 = (double)lbl_803E1164;
        dVar19 = (double)lbl_803E1168;
        dVar15 = DOUBLE_803e1178;
        do {
          iVar7 = iVar3 + iVar8;
          uStack_134 = (int)*(char *)(iVar7 + 0x2d) ^ 0x80000000;
          local_138 = 0x43300000;
          *param_5 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack_134) - dVar14) *
                             dVar18 + (double)*(float *)(iVar3 + 8));
          iVar6 = iVar4 + iVar8;
          uStack_13c = (int)*(char *)(iVar6 + 0x2d) ^ 0x80000000;
          local_140 = 0x43300000;
          param_5[1] = (float)((double)(float)((double)CONCAT44(0x43300000,uStack_13c) - dVar14) *
                               dVar12 + (double)*(float *)(iVar4 + 8));
          uStack_144 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
          local_148 = 0x43300000;
          dVar13 = (double)FUN_80293f90();
          uStack_14c = (uint)*(byte *)(iVar3 + 0x3d);
          local_150 = 0x43300000;
          param_5[2] = (float)(dVar11 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                         uStack_14c)
                                                                       - dVar15) * dVar13));
          uStack_154 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
          local_158 = 0x43300000;
          dVar13 = (double)FUN_80293f90();
          uStack_15c = (uint)*(byte *)(iVar4 + 0x3d);
          local_160 = 0x43300000;
          param_5[3] = (float)(dVar11 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                         uStack_15c)
                                                                       - dVar15) * dVar13));
          uStack_12c = (int)*(char *)(iVar7 + 0x31) ^ 0x80000000;
          local_130 = 0x43300000;
          *param_6 = (float)(dVar17 * (double)(float)((double)CONCAT44(0x43300000,uStack_12c) -
                                                     dVar14) + (double)*(float *)(iVar3 + 0xc));
          uStack_124 = (int)*(char *)(iVar6 + 0x31) ^ 0x80000000;
          local_128 = 0x43300000;
          param_6[1] = (float)(dVar16 * (double)(float)((double)CONCAT44(0x43300000,uStack_124) -
                                                       dVar14) + (double)*(float *)(iVar4 + 0xc));
          param_6[2] = (float)dVar19;
          param_6[3] = (float)dVar19;
          uStack_11c = (int)*(char *)(iVar7 + 0x2d) ^ 0x80000000;
          local_120 = 0x43300000;
          *param_7 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack_11c) - dVar14) *
                             dVar10 + (double)*(float *)(iVar3 + 0x10));
          uStack_114 = (int)*(char *)(iVar6 + 0x2d) ^ 0x80000000;
          local_118 = 0x43300000;
          param_7[1] = (float)((double)(float)((double)CONCAT44(0x43300000,uStack_114) - dVar14) *
                               dVar9 + (double)*(float *)(iVar4 + 0x10));
          uStack_10c = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
          local_110 = 0x43300000;
          dVar13 = (double)FUN_80294964();
          uStack_104 = (uint)*(byte *)(iVar3 + 0x3d);
          local_108 = 0x43300000;
          param_7[2] = (float)(dVar11 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                         uStack_104)
                                                                       - dVar15) * dVar13));
          uStack_fc = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
          local_100 = 0x43300000;
          dVar13 = (double)FUN_80294964();
          uStack_f4 = (uint)*(byte *)(iVar4 + 0x3d);
          local_f8 = 0x43300000;
          param_7[3] = (float)(dVar11 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                         uStack_f4)
                                                                       - dVar15) * dVar13));
          iVar8 = iVar8 + 1;
          param_5 = param_5 + 4;
          param_6 = param_6 + 4;
          param_7 = param_7 + 4;
          iVar5 = iVar5 + 4;
        } while (iVar5 < 0x10);
      }
      else if (uVar1 == 0) {
        *param_5 = (float)(dVar15 * (double)(float)(dVar17 * dVar10) + (double)*(float *)(iVar3 + 8)
                          );
        param_5[1] = (float)(dVar15 * (double)(float)(dVar16 * dVar12) +
                            (double)*(float *)(iVar4 + 8));
        uStack_f4 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
        local_f8 = 0x43300000;
        dVar14 = (double)FUN_80293f90();
        uStack_fc = (uint)*(byte *)(iVar3 + 0x3d);
        local_100 = 0x43300000;
        param_5[2] = lbl_803E1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_fc) -
                                            DOUBLE_803e1178) * dVar14);
        uStack_104 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
        local_108 = 0x43300000;
        dVar14 = (double)FUN_80293f90();
        uStack_10c = (uint)*(byte *)(iVar4 + 0x3d);
        local_110 = 0x43300000;
        param_5[3] = lbl_803E1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_10c) -
                                            DOUBLE_803e1178) * dVar14);
        *param_6 = (float)(dVar17 * param_2 + (double)*(float *)(iVar3 + 0xc));
        param_6[1] = (float)(dVar16 * param_2 + (double)*(float *)(iVar4 + 0xc));
        fVar2 = lbl_803E1168;
        param_6[2] = lbl_803E1168;
        param_6[3] = fVar2;
        *param_7 = (float)(dVar15 * (double)(float)(dVar17 * -dVar9) +
                          (double)*(float *)(iVar3 + 0x10));
        param_7[1] = (float)(dVar15 * (double)(float)(dVar16 * -dVar11) +
                            (double)*(float *)(iVar4 + 0x10));
        uStack_114 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
        local_118 = 0x43300000;
        dVar15 = (double)FUN_80294964();
        uStack_11c = (uint)*(byte *)(iVar3 + 0x3d);
        local_120 = 0x43300000;
        param_7[2] = lbl_803E1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_11c) -
                                            DOUBLE_803e1178) * dVar15);
        uStack_124 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
        local_128 = 0x43300000;
        dVar15 = (double)FUN_80294964();
        uStack_12c = (uint)*(byte *)(iVar4 + 0x3d);
        local_130 = 0x43300000;
        param_7[3] = lbl_803E1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_12c) -
                                            DOUBLE_803e1178) * dVar15);
      }
      else {
        iVar5 = iVar3 + (uVar1 - 2);
        uStack_f4 = (int)*(char *)(iVar5 + 0x2d) ^ 0x80000000;
        local_f8 = 0x43300000;
        *param_5 = (float)((double)CONCAT44(0x43300000,uStack_f4) - DOUBLE_803e1170) *
                   (float)(dVar17 * dVar10) + *(float *)(iVar3 + 8);
        iVar8 = iVar4 + (uVar1 - 2);
        uStack_fc = (int)*(char *)(iVar8 + 0x2d) ^ 0x80000000;
        local_100 = 0x43300000;
        param_5[1] = (float)((double)CONCAT44(0x43300000,uStack_fc) - dVar14) *
                     (float)(dVar16 * dVar12) + *(float *)(iVar4 + 8);
        uStack_104 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
        local_108 = 0x43300000;
        dVar15 = (double)FUN_80293f90();
        uStack_10c = (uint)*(byte *)(iVar3 + 0x3d);
        local_110 = 0x43300000;
        param_5[2] = lbl_803E1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_10c) -
                                            DOUBLE_803e1178) * dVar15);
        uStack_114 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
        local_118 = 0x43300000;
        dVar15 = (double)FUN_80293f90();
        uStack_11c = (uint)*(byte *)(iVar4 + 0x3d);
        local_120 = 0x43300000;
        param_5[3] = lbl_803E1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_11c) -
                                            DOUBLE_803e1178) * dVar15);
        dVar15 = DOUBLE_803e1170;
        uStack_124 = (int)*(char *)(iVar5 + 0x31) ^ 0x80000000;
        local_128 = 0x43300000;
        *param_6 = (float)(dVar17 * (double)(float)((double)CONCAT44(0x43300000,uStack_124) -
                                                   DOUBLE_803e1170) +
                          (double)*(float *)(iVar3 + 0xc));
        uStack_12c = (int)*(char *)(iVar8 + 0x31) ^ 0x80000000;
        local_130 = 0x43300000;
        param_6[1] = (float)(dVar16 * (double)(float)((double)CONCAT44(0x43300000,uStack_12c) -
                                                     dVar15) + (double)*(float *)(iVar4 + 0xc));
        fVar2 = lbl_803E1168;
        param_6[2] = lbl_803E1168;
        param_6[3] = fVar2;
        uStack_134 = (int)*(char *)(iVar5 + 0x2d) ^ 0x80000000;
        local_138 = 0x43300000;
        *param_7 = (float)((double)CONCAT44(0x43300000,uStack_134) - dVar15) *
                   (float)(dVar17 * -dVar9) + *(float *)(iVar3 + 0x10);
        uStack_13c = (int)*(char *)(iVar8 + 0x2d) ^ 0x80000000;
        local_140 = 0x43300000;
        param_7[1] = (float)((double)CONCAT44(0x43300000,uStack_13c) - dVar15) *
                     (float)(dVar16 * -dVar11) + *(float *)(iVar4 + 0x10);
        uStack_144 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
        local_148 = 0x43300000;
        dVar15 = (double)FUN_80294964();
        uStack_14c = (uint)*(byte *)(iVar3 + 0x3d);
        local_150 = 0x43300000;
        param_7[2] = lbl_803E1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_14c) -
                                            DOUBLE_803e1178) * dVar15);
        uStack_154 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
        local_158 = 0x43300000;
        dVar15 = (double)FUN_80294964();
        uStack_15c = (uint)*(byte *)(iVar4 + 0x3d);
        local_160 = 0x43300000;
        param_7[3] = lbl_803E1164 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack_15c) -
                                            DOUBLE_803e1178) * dVar15);
      }
    }
  }
  FUN_80286870();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800c9a2c
 * EN v1.0 Address: 0x800C9A2C
 * EN v1.0 Size: 572b
 * EN v1.1 Address: 0x800D620C
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c9a2c(uint param_1,float *param_2,char *param_3)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  int aiStack_38 [2];
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  iVar2 = FUN_800c9030(param_1,aiStack_38);
  if (iVar2 != 0) {
    uStack_2c = FUN_80017760(0xffffff9d,99);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    *param_2 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e1170) / lbl_803E1180;
    uStack_24 = FUN_80017760(0xffffff9d,99);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    param_2[1] = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1170) / lbl_803E1180;
    uStack_1c = FUN_80017760(0,99);
    uStack_1c = uStack_1c ^ 0x80000000;
    local_20 = 0x43300000;
    param_2[2] = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e1170) / lbl_803E1180;
    bVar1 = false;
    if ((*(uint *)(iVar2 + 0x20) != 0) &&
       (iVar3 = FUN_800c9030(*(uint *)(iVar2 + 0x20),aiStack_38), -1 < *(int *)(iVar3 + 0x20))) {
      bVar1 = true;
    }
    if (*param_3 == '\0') {
      if (bVar1) {
        param_2[4] = *(float *)(iVar2 + 0x20);
      }
      else if (-1 < (int)*(float *)(iVar2 + 0x18)) {
        param_2[4] = *(float *)(iVar2 + 0x18);
        *param_3 = '\x01';
      }
    }
    else if (*(float *)(iVar2 + 0x18) == 0.0) {
      if (bVar1) {
        param_2[4] = *(float *)(iVar2 + 0x20);
        *param_3 = '\0';
      }
    }
    else {
      param_2[4] = *(float *)(iVar2 + 0x18);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800c9c68
 * EN v1.0 Address: 0x800C9C68
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800D639C
 * EN v1.1 Size: 988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c9c68(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
}


/* sda21 globals used by leaf accessors below. */
extern s16 lbl_803DD414;
extern s16 lbl_803DD416;
extern u32 lbl_803DD418;
extern u32 lbl_803DD41C;
extern s32 lbl_803DD410;

typedef struct PartFxKV { u32 key; u32 value; } PartFxKV;
extern PartFxKV lbl_8039C458[];
extern f32 lbl_803E04E8;

typedef struct PartFxNode {
    u8 _pad0[0xc];
    f32 _0xc;
    s32 _0x10;
    u8 _pad14[4];
    s32 _0x18;
    s32 _0x1c;
} PartFxNode;

/* Binary search for key in lbl_8039C458 (count = lbl_803DD410). */
#pragma dont_inline on
u32 fn_800D5530(s32 key, s32 *idx_out)
{
    s32 high;
    s32 low;
    s32 mid;
    *idx_out = -1;
    if (key < 0) return 0;
    high = lbl_803DD410 - 1;
    low = 0;
    while (high >= low) {
        mid = (high + low) >> 1;
        if ((u32)key > lbl_8039C458[mid].key) {
            low = mid + 1;
        } else if ((u32)key == lbl_8039C458[mid].key) {
            *idx_out = mid;
            return lbl_8039C458[mid].value;
        } else {
            high = mid - 1;
        }
    }
    *idx_out = -1;
    return 0;
}
#pragma dont_inline off

/* Set *p to lbl_803DD414 (sign-extended) and return lbl_803DD418. */
u32 fn_800D65A8(s32 *p)
{
    *p = lbl_803DD414;
    return lbl_803DD418;
}

/* Swap lbl_803DD418 with lbl_803DD41C; copy 416 into 414 then clear 416. */
#pragma push
#pragma scheduling off
#pragma peephole off
void fn_800D6584(void)
{
    u32 tmp = lbl_803DD418;
    lbl_803DD418 = lbl_803DD41C;
    lbl_803DD41C = tmp;
    lbl_803DD414 = lbl_803DD416;
    lbl_803DD416 = 0;
}
#pragma pop

/* Rank object r3 against array at lbl_803DD418 by (int@0x1c, float@0xc) descending. */
typedef struct PartFxItem {
    u8 _pad0[0xc];
    f32 _0xc;
    u8 _pad10[0xc];
    s32 _0x1c;
} PartFxItem;

/* NOTE: 96.8% — register choice differs (r5 vs r7 for rank). */
#pragma push
#pragma scheduling off
s32 fn_800D6488(PartFxItem *p)
{
    s32 rank = 1;
    PartFxItem **arr = (PartFxItem **)lbl_803DD418;
    s32 n = lbl_803DD414;
    s32 i;
    for (i = 0; i < n; i++) {
        PartFxItem *q = *arr;
        if (q != p) {
            if (q->_0x1c > p->_0x1c) {
                rank++;
            } else if (q->_0x1c == p->_0x1c) {
                if (q->_0xc > p->_0xc) {
                    rank++;
                }
            }
        }
        arr++;
    }
    return rank;
}
#pragma pop

/* Find item in lbl_803DD418 array whose rank equals target_rank. */
PartFxItem *fn_800D64EC(s32 target_rank)
{
    s32 i;
    PartFxItem **outer = (PartFxItem **)lbl_803DD418;
    s32 n = lbl_803DD414;
    for (i = 0; i < n; i++) {
        PartFxItem *cur = *outer;
        s32 rank = 1;
        PartFxItem **inner = (PartFxItem **)lbl_803DD418;
        s32 j;
        for (j = 0; j < n; j++) {
            PartFxItem *other = *inner;
            if (other != cur) {
                if (other->_0x1c > cur->_0x1c) {
                    rank++;
                } else if (other->_0x1c == cur->_0x1c) {
                    if (other->_0xc > cur->_0xc) {
                        rank++;
                    }
                }
            }
            inner++;
        }
        if (rank == target_rank) {
            return cur;
        }
        outer++;
    }
    return 0;
}

/* Walk a chain via fn_800D5530 lookups starting from o->_0x10. */
#pragma push
#pragma scheduling off
void fn_800D65B8(PartFxNode *o)
{
    s32 local_idx;
    PartFxNode *ret;
    s32 nxt;
    ret = (PartFxNode *)fn_800D5530(o->_0x10, &local_idx);
    if (ret == 0) {
        o->_0x18 = 0;
        o->_0xc = lbl_803E04E8;
    } else {
        while ((nxt = ret->_0x18) > -1) {
            ret = (PartFxNode *)fn_800D5530(nxt, &local_idx);
            o->_0x1c = o->_0x1c + 1;
        }
        o->_0x18 = o->_0x10;
        o->_0xc = lbl_803E04E8;
    }
}
#pragma pop

/* Append v to array pointed to by lbl_803DD41C, capped at 10 entries.
 * NOTE: stuck on instruction order — compiler computes arr load early. */
void fn_800D663C(u32 v)
{
    s32 i = lbl_803DD416;
    u32 *arr;
    if (i >= 10) return;
    arr = (u32 *)lbl_803DD41C;
    lbl_803DD416 = (s16)(i + 1);
    arr[i] = v;
}

/* Trivial 4b 0-arg blr leaves. */
void fn_800C9134(void) {}
void Effect16_release(void) {}
void Effect16_initialise(void) {}
void fn_800CA3BC(void) {}
void fn_800CA3C0(void) {}
void Effect15_release(void) {}
void Effect15_initialise(void) {}
void fn_800CA920(void) {}
void fn_800CA924(void) {}
void Effect13_release(void) {}
void Effect13_initialise(void) {}
void fn_800CB684(void) {}
void Effect17_release(void) {}
void Effect17_initialise(void) {}
void fn_800CCF50(void) {}
void Effect18_release(void) {}
void Effect18_initialise(void) {}
void fn_800CD424(void) {}
void Effect19_release(void) {}
void Effect19_initialise(void) {}
void fn_800D5524(void) {}
void Effect20_release(void) {}
void Effect20_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_800D6108(void) { return 0x1; }
