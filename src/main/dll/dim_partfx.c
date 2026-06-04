#include "ghidra_import.h"
#include "main/dll/dim_partfx.h"


#define SFXsc_snort02 645

#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_80006824();
extern double FUN_80006a30();
extern int FUN_80017730();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
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
 * Function: Effect16_func04
 * EN v1.0 Address: 0x800C8008
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800C8294
 * EN v1.1 Size: 4100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* Effect16_func04 is defined further below (full recovered body). */

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
      uStack_2c = randomGetRange(8,10);
      local_70 = lbl_803E0E50 * (f32)(s32)uStack_2c;
      uVar2 = randomGetRange(0,0x28);
      if (uVar2 == 0) {
        uStack_2c = randomGetRange(0x15,0x29);
        local_5c = lbl_803E0E38 *
                   (f32)(s32)uStack_2c;
        local_98[2] = 0x1cc;
      }
      else {
        uStack_2c = randomGetRange(8,0x14);
        local_5c = lbl_803E0E38 *
                   (f32)(s32)uStack_2c;
        local_98[2] = randomGetRange(0x5a,0x78);
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
      uStack_2c = randomGetRange(0xffffffec,0x14);
      local_74 = lbl_803E0E50 * (f32)(s32)uStack_2c;
      uStack_24 = randomGetRange(8,0x14);
      local_70 = lbl_803E0E50 * (f32)(s32)uStack_24;
      uStack_1c = randomGetRange(0xffffffec,0x14);
      local_6c = lbl_803E0E50 * (f32)(s32)uStack_1c;
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
      local_48 = randomGetRange(0,0x8000);
      local_64 = lbl_803E0E5C;
      local_44 = local_48;
      break;
    default:
      return 0xffffffff;
    case 0x73d:
      uStack_1c = randomGetRange(0xfffffff6,10);
      local_68 = lbl_803E0E3C * (f32)(s32)uStack_1c;
      uStack_24 = randomGetRange(0xfffffff6,100);
      local_64 = lbl_803E0E50 * (f32)(s32)uStack_24;
      uStack_2c = randomGetRange(0xfffffff6,10);
      local_60 = lbl_803E0E3C * (f32)(s32)uStack_2c;
      uStack_14 = randomGetRange(7,9);
      local_5c = lbl_803E0E60 *
                 lbl_803E0E64 * (f32)(s32)uStack_14;
      local_98[2] = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xde;
      break;
    case 0x73e:
      uStack_14 = randomGetRange(0xfffffff6,10);
      local_68 = lbl_803E0E3C * (f32)(s32)uStack_14;
      uStack_1c = randomGetRange(0xfffffff6,100);
      local_64 = lbl_803E0E50 * (f32)(s32)uStack_1c;
      uStack_24 = randomGetRange(0xfffffff6,10);
      local_60 = lbl_803E0E3C * (f32)(s32)uStack_24;
      uStack_2c = randomGetRange(7,9);
      local_5c = lbl_803E0E60 *
                 lbl_803E0E64 * (f32)(s32)uStack_2c;
      local_98[2] = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xdf;
      break;
    case 0x73f:
      if (param_6 == 0) {
        uStack_14 = randomGetRange(0xfffffff6,10);
        local_68 = lbl_803E0E3C *
                   (f32)(s32)uStack_14;
        uStack_1c = randomGetRange(0xfffffff6,100);
        local_64 = lbl_803E0E50 *
                   (f32)(s32)uStack_1c;
        uStack_24 = randomGetRange(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_60 = lbl_803E0E3C *
                   (f32)(s32)uStack_24;
      }
      else {
        uStack_14 = randomGetRange(0xfffffff6,10);
        local_68 = lbl_803E0E3C *
                   (f32)(s32)uStack_14 +
                   lbl_803E0E68;
        uStack_1c = randomGetRange(0xfffffff6,100);
        local_64 = lbl_803E0E50 *
                   (f32)(s32)uStack_1c +
                   lbl_803E0E6C;
        uStack_24 = randomGetRange(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_60 = lbl_803E0E3C *
                   (f32)(s32)uStack_24 +
                   lbl_803E0E70;
      }
      local_28 = 0x43300000;
      uStack_14 = randomGetRange(7,9);
      local_5c = lbl_803E0E74 *
                 lbl_803E0E64 * (f32)(s32)uStack_14;
      local_98[2] = 0x3c;
      local_54 = 0x80100;
      local_37 = 0x10;
      local_56 = 0xde;
      break;
    case 0x740:
      if (param_6 == 0) {
        uStack_14 = randomGetRange(0xfffffff6,10);
        local_68 = lbl_803E0E3C *
                   (f32)(s32)uStack_14;
        uStack_1c = randomGetRange(0xfffffff6,100);
        local_64 = lbl_803E0E50 *
                   (f32)(s32)uStack_1c;
        uStack_24 = randomGetRange(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_60 = lbl_803E0E3C *
                   (f32)(s32)uStack_24;
      }
      else {
        uStack_14 = randomGetRange(0xfffffff6,10);
        local_68 = lbl_803E0E3C *
                   (f32)(s32)uStack_14 +
                   lbl_803E0E68;
        uStack_1c = randomGetRange(0xfffffff6,100);
        local_64 = lbl_803E0E50 *
                   (f32)(s32)uStack_1c +
                   lbl_803E0E6C;
        uStack_24 = randomGetRange(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_60 = lbl_803E0E3C *
                   (f32)(s32)uStack_24 +
                   lbl_803E0E70;
      }
      local_28 = 0x43300000;
      uStack_14 = randomGetRange(7,9);
      local_5c = lbl_803E0E74 *
                 lbl_803E0E64 * (f32)(s32)uStack_14;
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
      local_98[2] = randomGetRange(0,0x1e);
      local_98[2] = local_98[2] + 0x50;
      local_38 = 0x60;
      local_54 = 0x80110;
      local_56 = 0x7b;
      local_37 = 0x20;
      break;
    case 0x742:
      local_6c = lbl_803E0E7C;
      uStack_14 = randomGetRange(0xffffffec,0x14);
      local_74 = lbl_803E0E80 * (f32)(s32)uStack_14;
      uStack_1c = randomGetRange(0xffffffec,0x14);
      local_70 = lbl_803E0E80 * (f32)(s32)uStack_1c;
      local_5c = lbl_803E0E84;
      local_98[2] = randomGetRange(0x46,0x50);
      local_38 = 0xff;
      local_54 = 0x82000104;
      local_50 = 0x400;
      local_56 = 0x3f4;
      break;
    case 0x743:
      local_6c = lbl_803E0E7C;
      uStack_14 = randomGetRange(0xffffffec,0x14);
      local_74 = lbl_803E0E80 * (f32)(s32)uStack_14;
      uStack_1c = randomGetRange(0xffffffec,0x14);
      local_70 = lbl_803E0E80 * (f32)(s32)uStack_1c;
      local_5c = lbl_803E0E84;
      local_98[2] = randomGetRange(0x46,0x50);
      local_38 = 0xff;
      local_54 = 0x82000104;
      local_50 = 0x400;
      local_56 = 0x500;
      break;
    case 0x744:
      uVar2 = randomGetRange(0,4);
      if (uVar2 == 4) {
        local_5c = lbl_803E0E88;
        local_38 = 0x9b;
        local_54 = 0x480000;
        local_98[2] = randomGetRange(0x1e,0x28);
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
      fStack_5c = (float)randomGetRange(10,0x19);
      fStack_5c = -fStack_5c;
      local_60 = 0x43300000;
      local_a4 = lbl_803E0EB8 * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      local_8c = lbl_803E0EA4;
      local_c0 = (float)randomGetRange(0x15e,400);
      local_84 = 0xa100100;
      local_80 = 0x1000000;
      local_86 = 0x62;
      break;
    case 0x709:
      fStack_5c = (float)randomGetRange(10,0x14);
      fStack_5c = -fStack_5c;
      local_60 = 0x43300000;
      local_a0 = lbl_803E0EBC * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      uVar2 = randomGetRange(0,1);
      if (uVar2 != 0) {
        local_a0 = -local_a0;
      }
      local_8c = lbl_803E0EA0;
      local_c0 = 1.68156e-43;
      uVar2 = randomGetRange(0x7f,0xff);
      local_68 = (undefined)uVar2;
      local_84 = 0x80480000;
      local_80 = 0x440000;
      uVar2 = randomGetRange(0x525,0x528);
      local_86 = (undefined2)uVar2;
      break;
    case 0x70a:
      fStack_5c = (float)randomGetRange(0xffffffec,0x14);
      fStack_5c = -fStack_5c;
      local_60 = 0x43300000;
      local_a4 = lbl_803E0EC0 * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      fStack_54 = (float)randomGetRange(0xffffffec,0x14);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_a0 = lbl_803E0EC0 * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      uStack_4c = randomGetRange(0xffffffec,0x14);
      local_9c = lbl_803E0EC0 * (f32)(s32)uStack_4c;
      local_8c = lbl_803E0EC4;
      local_c0 = 7.00649e-44;
      local_84 = 0x480100;
      uVar2 = randomGetRange(0x525,0x528);
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
      local_c0 = (float)randomGetRange(0x19,0x4b);
      uStack_4c = randomGetRange(0xffffffd8,0x28);
      local_a4 = lbl_803E0EBC * (f32)(s32)uStack_4c;
      fStack_54 = -local_c0;
      local_58 = 0x43300000;
      local_a0 = lbl_803E0ECC * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      fStack_5c = (float)randomGetRange(0xffffffd8,0x28);
      fStack_5c = -fStack_5c;
      local_60 = 0x43300000;
      local_9c = lbl_803E0EBC * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      uVar2 = randomGetRange(0x32,100);
      local_8c = lbl_803E0ED0 * (f32)(s32)(uVar2);
      local_84 = 0x1082000;
      uVar2 = randomGetRange(0x208,0x20a);
      local_86 = (undefined2)uVar2;
      local_80 = 0x1400000;
      break;
    default:
      goto LAB_800cd094;
    case 0x70f:
      local_c0 = (float)randomGetRange(0xf,0x2d);
      uVar2 = randomGetRange(0xfffffffb,5);
      local_98 = (f32)(s32)(uVar2);
      uStack_4c = randomGetRange(0xfffffffb,5);
      local_90 = (f32)(s32)uStack_4c;
      fStack_54 = (float)randomGetRange(0xffffffd8,0x28);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_a4 = lbl_803E0EBC * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      fStack_5c = -local_c0;
      local_60 = 0x43300000;
      local_a0 = lbl_803E0ECC * (float)((double)CONCAT44(0x43300000,fStack_5c) - DOUBLE_803e0f40);
      fStack_3c = (float)randomGetRange(0xffffffd8,0x28);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_9c = lbl_803E0EBC * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uStack_34 = randomGetRange(0x32,0x46);
      local_8c = lbl_803E0ED4 * (f32)(s32)uStack_34;
      local_68 = 0xa0;
      local_84 = 0x1082000;
      local_80 = 0x5400000;
      uVar2 = randomGetRange(0x208,0x20a);
      local_86 = (undefined2)uVar2;
      break;
    case 0x710:
      fVar3 = lbl_803E0EA8;
      if (param_6 != (float *)0x0) {
        fVar3 = *param_6;
      }
      dVar5 = (double)fVar3;
      local_c0 = (float)randomGetRange(0xf,0x4b);
      local_94 = (float)((double)lbl_803E0ED8 * dVar5);
      local_90 = (float)((double)lbl_803E0EDC * dVar5);
      uStack_34 = randomGetRange(0xffffffe2,0x1e);
      local_a4 = lbl_803E0EBC * (f32)(s32)uStack_34;
      fStack_3c = -local_c0;
      local_40 = 0x43300000;
      local_a0 = lbl_803E0ECC * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = randomGetRange(0x14,0x46);
      local_9c = lbl_803E0EE0 * (f32)(s32)(uVar2);
      uStack_4c = randomGetRange(0x28,0x3c);
      local_8c = lbl_803E0EE4 * (f32)(s32)uStack_4c;
      uVar2 = randomGetRange(0x3c,0xa0);
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
      local_c0 = (float)randomGetRange(0x23,0x4b);
      local_94 = (float)((double)lbl_803E0EE8 * dVar5);
      local_90 = (float)((double)lbl_803E0EDC * dVar5);
      uStack_34 = randomGetRange(0xffffffce,0x32);
      local_a4 = lbl_803E0EBC * (f32)(s32)uStack_34;
      fStack_3c = -local_c0;
      local_40 = 0x43300000;
      local_a0 = lbl_803E0EEC * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = randomGetRange(0x14,0x3c);
      local_9c = lbl_803E0EE0 * (f32)(s32)(uVar2);
      uStack_4c = randomGetRange(0x28,0x3c);
      local_8c = lbl_803E0EE4 * (f32)(s32)uStack_4c;
      uVar2 = randomGetRange(100,200);
      local_68 = (undefined)uVar2;
      local_84 = 0x81080200;
      local_80 = 0x4000800;
      local_86 = 0xc0f;
      break;
    case 0x712:
      local_c0 = (float)randomGetRange(0x32,100);
      uStack_34 = randomGetRange(0xffffffec,0x14);
      local_a4 = lbl_803E0EBC * (f32)(s32)uStack_34;
      fStack_3c = -local_c0;
      local_40 = 0x43300000;
      local_a0 = lbl_803E0EF0 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = randomGetRange(0xffffffec,0x14);
      local_9c = lbl_803E0EBC * (f32)(s32)(uVar2);
      local_8c = lbl_803E0EF4;
      uVar2 = randomGetRange(0,2);
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
      uVar2 = randomGetRange(0x1e,0x28);
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
      uStack_34 = randomGetRange(0x12,0x14);
      local_9c = lbl_803E0EFC * (f32)(s32)uStack_34;
      fStack_3c = (float)randomGetRange(0x28,0x3c);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_8c = lbl_803E0F00 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_c0 = (float)randomGetRange(8,0x14);
      local_84 = 0x80204;
      local_80 = 0x4002800;
      local_86 = 0xc0f;
      break;
    case 0x715:
      if (param_6 == (float *)0x0) {
        uStack_34 = randomGetRange(0x32,100);
        local_8c = lbl_803E0F0C *
                   (f32)(s32)uStack_34;
        local_c0 = 1.68156e-43;
        local_84 = 0x80580200;
        local_80 = 0x800;
      }
      else {
        uStack_34 = randomGetRange(0xffffffe7,0x19);
        local_a4 = lbl_803E0F04 *
                   (f32)(s32)uStack_34;
        fStack_3c = (float)randomGetRange(5,0x32);
        fStack_3c = -fStack_3c;
        local_40 = 0x43300000;
        local_a0 = lbl_803E0F04 *
                   (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
        uVar2 = randomGetRange(0xffffffe7,0x19);
        local_9c = lbl_803E0F04 * (f32)(s32)(uVar2);
        local_8c = lbl_803E0F08;
        local_c0 = (float)randomGetRange(0x28,0x78);
        local_84 = 0x80480000;
        local_80 = 0x400800;
      }
      local_68 = 0xff;
      local_86 = 0xc0f;
      break;
    case 0x716:
      uStack_34 = randomGetRange(0xffffffec,0x14);
      local_98 = (f32)(s32)uStack_34;
      fStack_3c = (float)randomGetRange(0xffffffec,0x14);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = randomGetRange(0xffffffec,0x14);
      local_90 = (f32)(s32)(uVar2);
      uStack_4c = randomGetRange(0x5a,100);
      local_a0 = lbl_803E0EB8 * (f32)(s32)uStack_4c;
      local_67 = 0xf;
      fStack_54 = (float)randomGetRange(0x5a,100);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_8c = lbl_803E0EA0 * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      local_84 = 0x800c0100;
      local_80 = 0x4000800;
      uVar2 = randomGetRange(0x96,200);
      local_68 = (undefined)uVar2;
      local_c0 = (float)randomGetRange(0x32,0x46);
      local_86 = 0x185;
      break;
    case 0x717:
      fVar3 = lbl_803E0EA8;
      if (param_6 != (float *)0x0) {
        fVar3 = *param_6;
      }
      dVar5 = (double)fVar3;
      uStack_34 = randomGetRange(0xffffff6a,0x96);
      local_98 = (float)(dVar5 * (double)(lbl_803E0EA4 *
                                         (float)((double)CONCAT44(0x43300000,uStack_34) -
                                                DOUBLE_803e0f40)));
      fStack_3c = (float)randomGetRange(100,300);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_94 = (float)(dVar5 * (double)(lbl_803E0EA4 *
                                         (float)((double)CONCAT44(0x43300000,fStack_3c) -
                                                DOUBLE_803e0f40)));
      uVar2 = randomGetRange(0xffffff6a,0xffffffce);
      local_90 = (float)(dVar5 * (double)(lbl_803E0EA4 * (f32)(s32)(uVar2)));
      local_8c = lbl_803E0EC4;
      local_c0 = (float)randomGetRange(0x32,0x96);
      local_84 = 0x80480100;
      uVar2 = randomGetRange(0x527,0x528);
      local_86 = (undefined2)uVar2;
      break;
    case 0x718:
      uStack_34 = randomGetRange(8,10);
      local_a0 = lbl_803E0EFC * (f32)(s32)uStack_34;
      if (param_6 != (float *)0x0) {
        local_a0 = local_a0 * (lbl_803E0EA8 + *param_6 / lbl_803E0F10);
      }
      uStack_34 = randomGetRange(6,0xc);
      local_8c = lbl_803E0EC0 * (f32)(s32)uStack_34;
      local_c0 = (float)randomGetRange(0x3c,100);
      local_84 = 0x80180000;
      local_80 = 0x5440800;
      local_86 = 0xc0b;
      local_68 = 0x40;
      break;
    case 0x71a:
      local_90 = lbl_803E0F14;
      uStack_34 = randomGetRange(0x4b,100);
      local_8c = lbl_803E0F18 * (f32)(s32)uStack_34;
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
      local_c0 = (float)randomGetRange(0x28,0x78);
      uStack_34 = randomGetRange(0xffffffce,0x32);
      local_a4 = lbl_803E0EFC * (f32)(s32)uStack_34;
      fStack_3c = -local_c0;
      local_40 = 0x43300000;
      local_a0 = lbl_803E0F20 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = randomGetRange(0xffffffce,0x32);
      local_9c = lbl_803E0EFC * (f32)(s32)(uVar2);
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
      uStack_34 = randomGetRange(0xffffffec,0x14);
      local_98 = (f32)(s32)uStack_34;
      fStack_3c = (float)randomGetRange(0xffffffec,0x14);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = randomGetRange(0xffffffec,0x14);
      local_90 = (f32)(s32)(uVar2);
      local_67 = 0xf;
      uStack_4c = randomGetRange(0x78,200);
      local_8c = lbl_803E0EA0 * (f32)(s32)uStack_4c;
      local_84 = 0x80180100;
      local_80 = 0x4000800;
      uVar2 = randomGetRange(0x32,100);
      local_68 = (undefined)uVar2;
      local_c0 = (float)randomGetRange(100,0x8c);
      local_86 = 0x185;
      break;
    case 0x71e:
      uStack_34 = randomGetRange(0xffffffdd,0x23);
      local_98 = (f32)(s32)uStack_34;
      fStack_3c = (float)randomGetRange(0,0x1e);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      uVar2 = randomGetRange(0xffffffdd,0x23);
      local_90 = (f32)(s32)(uVar2);
      uStack_4c = randomGetRange(8,10);
      local_a0 = lbl_803E0EFC * (f32)(s32)uStack_4c;
      fStack_54 = (float)randomGetRange(6,0xc);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_8c = lbl_803E0EC0 * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      local_c0 = (float)randomGetRange(100,0x96);
      local_84 = 0x80180000;
      local_80 = 0x1440000;
      local_86 = 0x564;
      local_68 = 0x7f;
      break;
    case 0x71f:
      uStack_34 = randomGetRange(8,10);
      local_a0 = lbl_803E0EFC * (f32)(s32)uStack_34;
      fStack_3c = (float)randomGetRange(6,0xc);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_8c = lbl_803E0F08 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_c0 = (float)randomGetRange(0x3c,0x50);
      local_84 = 0x80180000;
      local_80 = 0x5440800;
      local_86 = 0x564;
      local_68 = 0x40;
      break;
    case 0x720:
      uStack_34 = randomGetRange(8,10);
      local_a0 = lbl_803E0F24 * (f32)(s32)uStack_34;
      fStack_3c = (float)randomGetRange(6,0xc);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_8c = lbl_803E0F08 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_c0 = (float)randomGetRange(0x3c,0x50);
      local_84 = 0x80180200;
      local_80 = 0x5000800;
      local_86 = 0x564;
      local_68 = 0x40;
      break;
    case 0x721:
      uStack_34 = randomGetRange(6,0xc);
      local_8c = lbl_803E0F28 * (f32)(s32)uStack_34;
      local_c0 = (float)randomGetRange(0xfa,0x15e);
      local_84 = 0x80480008;
      local_80 = 0x400000;
      local_86 = 0xc0d;
      break;
    case 0x722:
      local_94 = lbl_803E0F2C;
      local_c0 = (float)randomGetRange(0x1e,0x3c);
      uStack_34 = randomGetRange(0xffffffc4,0x3c);
      local_a4 = lbl_803E0F24 * (f32)(s32)uStack_34;
      dVar5 = FUN_80293900((double)(local_a4 * local_a4 + local_9c * local_9c));
      local_a0 = (float)((double)lbl_803E0F30 * dVar5);
      fStack_3c = (float)randomGetRange(0xffffffc4,0x3c);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_9c = lbl_803E0F24 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_8c = lbl_803E0F24;
      local_84 = 0x80000;
      local_80 = 0x5400800;
      local_86 = 0x564;
      uVar2 = randomGetRange(0x46,0xbe);
      local_68 = (undefined)((int)uVar2 >> 1);
      break;
    case 0x723:
      local_c0 = (float)randomGetRange(0x23,0x2d);
      if (param_6 == (float *)0x0) {
        fVar3 = 7.00649e-45;
      }
      else {
        fVar3 = (float)((int)*param_6 + 5);
      }
      uStack_34 = randomGetRange(8,0xc);
      fStack_3c = -fVar3;
      local_40 = 0x43300000;
      local_a0 = ((float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40) / lbl_803E0F34
                 ) * lbl_803E0F38 *
                     (f32)(s32)uStack_34;
      uVar4 = 0x41 - (int)fVar3;
      uVar2 = randomGetRange(-uVar4,uVar4);
      local_a4 = lbl_803E0ECC * (f32)(s32)(uVar2);
      uStack_4c = randomGetRange(-uVar4,uVar4);
      local_9c = lbl_803E0ECC * (f32)(s32)uStack_4c;
      fStack_54 = (float)randomGetRange(6,0xc);
      fStack_54 = -fStack_54;
      local_58 = 0x43300000;
      local_8c = lbl_803E0EC0 * (float)((double)CONCAT44(0x43300000,fStack_54) - DOUBLE_803e0f40);
      uVar2 = randomGetRange(0x40,0x7f);
      local_68 = (undefined)((int)uVar2 >> 1);
      local_84 = 0x80080000;
      local_80 = 0x5400800;
      local_86 = 0x564;
      break;
    case 0x724:
      uStack_34 = randomGetRange(8,10);
      local_a0 = lbl_803E0EFC * (f32)(s32)uStack_34;
      fStack_3c = (float)randomGetRange(6,0xc);
      fStack_3c = -fStack_3c;
      local_40 = 0x43300000;
      local_8c = lbl_803E0EC0 * (float)((double)CONCAT44(0x43300000,fStack_3c) - DOUBLE_803e0f40);
      local_c0 = (float)randomGetRange(0x1e,0x3c);
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
      uStack_3c = randomGetRange(0x1e,100);
      local_84 = lbl_803E0F70 * (f32)(s32)uStack_3c;
      if (lbl_803E0F6C < *(float *)(param_3 + 6)) {
        local_84 = -local_84;
      }
      uStack_3c = randomGetRange(0,100);
      local_80 = lbl_803E0F58 * (f32)(s32)uStack_3c
                 + lbl_803E0F5C;
      local_38 = (longlong)(int)*param_6;
      local_30 = (longlong)(int)param_6[1];
      uStack_24 = randomGetRange((int)*param_6,(int)param_6[1]);
      local_70 = lbl_803E0F5C * (f32)(s32)uStack_24;
      local_78 = lbl_803E0F74;
      if (lbl_803E0F6C < *(float *)(param_3 + 6)) {
        local_78 = lbl_803E0F78;
      }
      uStack_24 = randomGetRange(0xffffff9c,100);
      local_6c = lbl_803E0F7C * (f32)(s32)uStack_24
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
                       (f32)(s32)uStack_13c);
      uStack_134 = (uint)*(byte *)(iVar4 + 0x2a);
      local_138 = 0x43300000;
      dVar16 = (double)(lbl_803E1160 *
                       (f32)(s32)uStack_134);
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
                     (float)((f64)(f32)(s32)uStack_fc * dVar14);
        uStack_104 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
        local_108 = 0x43300000;
        dVar14 = (double)FUN_80293f90();
        uStack_10c = (uint)*(byte *)(iVar4 + 0x3d);
        local_110 = 0x43300000;
        param_5[3] = lbl_803E1164 *
                     (float)((f64)(f32)(s32)uStack_10c * dVar14);
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
                     (float)((f64)(f32)(s32)uStack_11c * dVar15);
        uStack_124 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
        local_128 = 0x43300000;
        dVar15 = (double)FUN_80294964();
        uStack_12c = (uint)*(byte *)(iVar4 + 0x3d);
        local_130 = 0x43300000;
        param_7[3] = lbl_803E1164 *
                     (float)((f64)(f32)(s32)uStack_12c * dVar15);
      }
      else {
        iVar5 = iVar3 + (uVar1 - 2);
        uStack_f4 = (int)*(char *)(iVar5 + 0x2d) ^ 0x80000000;
        local_f8 = 0x43300000;
        *param_5 = (f32)(s32)uStack_f4 *
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
                     (float)((f64)(f32)(s32)uStack_10c * dVar15);
        uStack_114 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
        local_118 = 0x43300000;
        dVar15 = (double)FUN_80293f90();
        uStack_11c = (uint)*(byte *)(iVar4 + 0x3d);
        local_120 = 0x43300000;
        param_5[3] = lbl_803E1164 *
                     (float)((f64)(f32)(s32)uStack_11c * dVar15);
        dVar15 = DOUBLE_803e1170;
        uStack_124 = (int)*(char *)(iVar5 + 0x31) ^ 0x80000000;
        local_128 = 0x43300000;
        *param_6 = (float)(dVar17 * (f64)(f32)(s32)uStack_124 +
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
                     (float)((f64)(f32)(s32)uStack_14c * dVar15);
        uStack_154 = (uint)*(byte *)(iVar4 + 0x3e) << 8 ^ 0x80000000;
        local_158 = 0x43300000;
        dVar15 = (double)FUN_80294964();
        uStack_15c = (uint)*(byte *)(iVar4 + 0x3d);
        local_160 = 0x43300000;
        param_7[3] = lbl_803E1164 *
                     (float)((f64)(f32)(s32)uStack_15c * dVar15);
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
    uStack_2c = randomGetRange(0xffffff9d,99);
    *param_2 = (f32)(s32)uStack_2c / lbl_803E1180;
    uStack_24 = randomGetRange(0xffffff9d,99);
    param_2[1] = (f32)(s32)uStack_24 / lbl_803E1180;
    uStack_1c = randomGetRange(0,99);
    param_2[2] = (f32)(s32)uStack_1c / lbl_803E1180;
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
extern f32 lbl_803E0500;

/* Globals for tick functions Effect16_func05 / Effect17_func05 / Effect18_func05 / Effect19_func05 / Effect20_func05. */
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 fn_80293E80(f32 x);

extern f32 lbl_803DB848; extern f32 lbl_803DB84C;
extern f32 lbl_803E00A8; extern f32 lbl_803E00AC;
extern f32 lbl_803E00B0; extern f32 lbl_803E00B8;
extern s32 lbl_803DD3C0; extern s32 lbl_803DD3C4;
extern f32 lbl_803DD3C8; extern f32 lbl_803DD3CC;
extern f32 lbl_803E0108; extern f32 lbl_803E010C;

extern f32 lbl_803DB858; extern f32 lbl_803DB85C;
extern f32 lbl_803E01B8; extern f32 lbl_803E01BC;
extern f32 lbl_803E01C0; extern f32 lbl_803E01C8;
extern s32 lbl_803DD3D0; extern s32 lbl_803DD3D4;
extern f32 lbl_803DD3D8; extern f32 lbl_803DD3DC;
extern f32 lbl_803E0218; extern f32 lbl_803E021C;

extern f32 lbl_803DB868; extern f32 lbl_803DB86C;
extern f32 lbl_803E0220; extern f32 lbl_803E0224;
extern f32 lbl_803E0228; extern f32 lbl_803E0230;
extern s32 lbl_803DD3E0; extern s32 lbl_803DD3E4;
extern f32 lbl_803DD3E8; extern f32 lbl_803DD3EC;
extern f32 lbl_803E02D0; extern f32 lbl_803E02D4;

extern f32 lbl_803DB878; extern f32 lbl_803DB87C;
extern f32 lbl_803E02D8; extern f32 lbl_803E02DC;
extern f32 lbl_803E02E0; extern f32 lbl_803E02E8;
extern s32 lbl_803DD3F0; extern s32 lbl_803DD3F4;
extern f32 lbl_803DD3F8; extern f32 lbl_803DD3FC;
extern f32 lbl_803E0308; extern f32 lbl_803E030C;

extern f32 lbl_803DB870; extern f32 lbl_803DB874;
extern f32 lbl_803E02E4; extern f32 lbl_803E02EC;
extern f32 lbl_803E02F0; extern f32 lbl_803E02F4;
extern f32 lbl_803E02F8; extern f32 lbl_803E02FC;
extern int *gExpgfxInterface;

extern f32 lbl_803E0180; extern f32 lbl_803E0184;
extern f32 lbl_803E0188; extern f32 lbl_803E018C;
extern f32 lbl_803E0190; extern f32 lbl_803E0194;
extern f32 lbl_803E0198; extern f32 lbl_803E019C;
extern f32 lbl_803E01A0; extern f32 lbl_803E01A4;
extern f32 lbl_803E01A8; extern f32 lbl_803E01AC;
extern int *gWaterfxInterface;
extern void Sfx_PlayFromObject(int obj, int sfxId);

typedef struct WaterfxCfg {
    s16 x;
    s16 y;
    s16 z;
    u8  pad6[2];
    f32 f8;
    f32 fc;
    f32 f10;
    f32 f14;
} WaterfxCfg;
extern WaterfxCfg lbl_8039C440;

extern f32 lbl_803DB850; extern f32 lbl_803DB854;
extern f32 lbl_803E01B8; extern f32 lbl_803E01BC;
extern f32 lbl_803E01C0; extern f32 lbl_803E01C4;
extern f32 lbl_803E01C8; extern f32 lbl_803E01CC;
extern f32 lbl_803E01D0; extern f32 lbl_803E01D4;
extern f32 lbl_803E01D8; extern f32 lbl_803E01DC;
extern f32 lbl_803E01E0; extern f32 lbl_803E01E4;
extern f32 lbl_803E01E8; extern f32 lbl_803E01EC;
extern f32 lbl_803E01F0; extern f32 lbl_803E01F4;
extern f32 lbl_803E01F8; extern f32 lbl_803E01FC;
extern f32 lbl_803E0200; extern f32 lbl_803E0204;
extern f32 lbl_803E0208; extern f32 lbl_803E020C;

extern f32 lbl_803E0110; extern f32 lbl_803E0114;
extern f32 lbl_803E0118; extern f32 lbl_803E011C;
extern f32 lbl_803E0120; extern f32 lbl_803E0124;
extern f32 lbl_803E0128; extern f32 lbl_803E012C;
extern f32 lbl_803E0130; extern f32 lbl_803E0134;
extern f32 lbl_803E0138; extern f32 lbl_803E013C;
extern f32 lbl_803E0140; extern f32 lbl_803E0144;
extern f32 lbl_803E0148; extern f32 lbl_803E014C;
extern f32 lbl_803E0150; extern f32 lbl_803E0154;
extern f32 lbl_803E0158; extern f32 lbl_803E015C;
extern f32 lbl_803E0160; extern f32 lbl_803E0164;
extern f32 lbl_803E0168; extern f32 lbl_803E016C;
extern f32 lbl_803E0170; extern f32 lbl_803E0174;
extern WaterfxCfg lbl_8039C428;

extern f32 lbl_803DB840; extern f32 lbl_803DB844;
extern f32 lbl_803E00B4; extern f32 lbl_803E00BC;
extern f32 lbl_803E00C0; extern f32 lbl_803E00C4;
extern f32 lbl_803E00C8; extern f32 lbl_803E00CC;
extern f32 lbl_803E00D0; extern f32 lbl_803E00D4;
extern f32 lbl_803E00D8; extern f32 lbl_803E00DC;
extern f32 lbl_803E00E0; extern f32 lbl_803E00E4;
extern f32 lbl_803E00E8; extern f32 lbl_803E00EC;
extern f32 lbl_803E00F0; extern f32 lbl_803E00F4;
extern f32 lbl_803E00F8;
extern WaterfxCfg lbl_8039C410;

extern f32 lbl_803DB888; extern f32 lbl_803DB88C;
extern f32 lbl_803E0310; extern f32 lbl_803E0314;
extern f32 lbl_803E0318; extern f32 lbl_803E0320;
extern s32 lbl_803DD400; extern s32 lbl_803DD404;
extern f32 lbl_803DD408; extern f32 lbl_803DD40C;
extern f32 lbl_803E0344; extern f32 lbl_803E0348;

extern f32 lbl_803DB860; extern f32 lbl_803DB864;
extern f32 lbl_803E0220; extern f32 lbl_803E0224;
extern f32 lbl_803E0228; extern f32 lbl_803E022C;
extern f32 lbl_803E0230; extern f32 lbl_803E0234;
extern f32 lbl_803E0238; extern f32 lbl_803E023C;
extern f32 lbl_803E0240; extern f32 lbl_803E0244;
extern f32 lbl_803E0248; extern f32 lbl_803E024C;
extern f32 lbl_803E0250; extern f32 lbl_803E0254;
extern f32 lbl_803E0258; extern f32 lbl_803E025C;
extern f32 lbl_803E0260; extern f32 lbl_803E0264;
extern f32 lbl_803E0268; extern f32 lbl_803E026C;
extern f32 lbl_803E0270; extern f32 lbl_803E0274;
extern f32 lbl_803E0278; extern f32 lbl_803E027C;
extern f32 lbl_803E0280; extern f32 lbl_803E0284;
extern f32 lbl_803E0288; extern f32 lbl_803E028C;
extern f32 lbl_803E0290; extern f32 lbl_803E0294;
extern f32 lbl_803E0298; extern f32 lbl_803E029C;
extern f32 lbl_803E02A0; extern f32 lbl_803E02A4;
extern f32 lbl_803E02A8; extern f32 lbl_803E02AC;
extern f32 lbl_803E02B0; extern f32 lbl_803E02B4;
extern f32 lbl_803E02B8;
extern f32 sqrtf(f32);

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
#pragma push
#pragma scheduling off
u32 Checkpoint_find(s32 key, s32 *idx_out)
{
    s32 high;
    s32 low;
    s32 mid;
    *idx_out = -1;
    if (key < 0) return 0;
    high = lbl_803DD410 - 1;
    low = 0;
    while (low <= high) {
        mid = (low + high) >> 1;
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
#pragma pop
#pragma dont_inline off

extern f32 lbl_803E04D8;
extern f32 lbl_803E04DC;
extern f32 lbl_803E04E0;
extern f32 lbl_803E04E4;
extern f32 sin(f32 x);

typedef struct CheckpointPair {
    u8 pad[0x20];
    s32 keys[2];
} CheckpointPair;

/* Build particle quad positions from a checkpoint pair. */
#pragma push
#pragma scheduling off
s32 fn_800D55BC(u8 *p, s32 idx, f32 *out1, f32 *out2, f32 *out3, u8 mode, f32 fa, f32 fb)
{
    s32 local_idx;
    u8 *q;
    f32 cosA;
    f32 sinA;
    f32 cosB;
    f32 sinB;
    f32 sclA;
    f32 sclB;
    s32 ret;
    s32 i;
    s32 j;
    f32 *v3;

    ret = 1;
    if (p == NULL) {
        return 0;
    }
    q = (u8 *)Checkpoint_find(((CheckpointPair *)p)->keys[idx], &local_idx);
    if (q == NULL) {
        q = (u8 *)Checkpoint_find(((CheckpointPair *)p)->keys[1 - idx], &local_idx);
        ret = 2;
    }
    if (q == NULL) {
        return 0;
    }

    cosA = -fn_80293E80(lbl_803E04D8 * (f32)(*(u8 *)(p + 0x29) << 8) / lbl_803E04DC);
    sinA = -sin(lbl_803E04D8 * (f32)(*(u8 *)(p + 0x29) << 8) / lbl_803E04DC);
    cosB = -fn_80293E80(lbl_803E04D8 * (f32)(*(u8 *)(q + 0x29) << 8) / lbl_803E04DC);
    sinB = -sin(lbl_803E04D8 * (f32)(*(u8 *)(q + 0x29) << 8) / lbl_803E04DC);
    sclA = lbl_803E04E0 * (f32)(u32)*(u8 *)(p + 0x2a);
    sclB = lbl_803E04E0 * (f32)(u32)*(u8 *)(q + 0x2a);

    if (mode == 1) {
        f32 prodA;
        f32 prodB;
        f32 prodC;
        f32 prodD;
        f32 kD8;
        f32 kDC;
        f32 kE4;
        f32 kE8;
        j = 0;
        i = 0;
        v3 = out3;
        prodA = sclA * sinA;
        prodB = sclB * sinB;
        prodC = sclA * -cosA;
        prodD = sclB * -cosB;
        kD8 = lbl_803E04D8;
        kDC = lbl_803E04DC;
        kE4 = lbl_803E04E4;
        kE8 = lbl_803E04E8;
        do {
            u8 *pp;
            u8 *qq;
            pp = p + i;
            out1[0] = (f32)*(s8 *)(pp + 0x2d) * prodA + *(f32 *)(p + 8);
            qq = q + i;
            out1[1] = (f32)*(s8 *)(qq + 0x2d) * prodB + *(f32 *)(q + 8);
            out1[2] = kE4 * ((f32)(u32)*(u8 *)(p + 0x3d) *
                             fn_80293E80(kD8 * (f32)(*(u8 *)(p + 0x3e) << 8) / kDC));
            out1[3] = kE4 * ((f32)(u32)*(u8 *)(q + 0x3d) *
                             fn_80293E80(kD8 * (f32)(*(u8 *)(q + 0x3e) << 8) / kDC));
            out2[0] = sclA * (f32)*(s8 *)(pp + 0x31) + *(f32 *)(p + 0xc);
            out2[1] = sclB * (f32)*(s8 *)(qq + 0x31) + *(f32 *)(q + 0xc);
            out2[2] = kE8;
            out2[3] = kE8;
            v3[0] = (f32)*(s8 *)(pp + 0x2d) * prodC + *(f32 *)(p + 0x10);
            v3[1] = (f32)*(s8 *)(qq + 0x2d) * prodD + *(f32 *)(q + 0x10);
            v3[2] = kE4 * ((f32)(u32)*(u8 *)(p + 0x3d) *
                           sin(kD8 * (f32)(*(u8 *)(p + 0x3e) << 8) / kDC));
            v3[3] = kE4 * ((f32)(u32)*(u8 *)(q + 0x3d) *
                           sin(kD8 * (f32)(*(u8 *)(q + 0x3e) << 8) / kDC));
            i += 1;
            out1 += 4;
            out2 += 4;
            v3 += 4;
            j += 4;
        } while (j < 0x10);
    } else if (mode == 0) {
        out1[0] = fa * (sclA * sinA) + *(f32 *)(p + 8);
        out1[1] = fa * (sclB * sinB) + *(f32 *)(q + 8);
        out1[2] = lbl_803E04E4 * ((f32)(u32)*(u8 *)(p + 0x3d) *
                                  fn_80293E80(lbl_803E04D8 * (f32)(*(u8 *)(p + 0x3e) << 8) / lbl_803E04DC));
        out1[3] = lbl_803E04E4 * ((f32)(u32)*(u8 *)(q + 0x3d) *
                                  fn_80293E80(lbl_803E04D8 * (f32)(*(u8 *)(q + 0x3e) << 8) / lbl_803E04DC));
        out2[0] = sclA * fb + *(f32 *)(p + 0xc);
        out2[1] = sclB * fb + *(f32 *)(q + 0xc);
        {
            f32 e8 = lbl_803E04E8;
            out2[2] = e8;
            out2[3] = e8;
        }
        out3[0] = fa * (sclA * -cosA) + *(f32 *)(p + 0x10);
        out3[1] = fa * (sclB * -cosB) + *(f32 *)(q + 0x10);
        out3[2] = lbl_803E04E4 * ((f32)(u32)*(u8 *)(p + 0x3d) *
                                  sin(lbl_803E04D8 * (f32)(*(u8 *)(p + 0x3e) << 8) / lbl_803E04DC));
        out3[3] = lbl_803E04E4 * ((f32)(u32)*(u8 *)(q + 0x3d) *
                                  sin(lbl_803E04D8 * (f32)(*(u8 *)(q + 0x3e) << 8) / lbl_803E04DC));
    } else {
        u8 *pp;
        u8 *qq;
        pp = p + (mode - 2);
        out1[0] = (f32)*(s8 *)(pp + 0x2d) * (sclA * sinA) + *(f32 *)(p + 8);
        qq = q + (mode - 2);
        out1[1] = (f32)*(s8 *)(qq + 0x2d) * (sclB * sinB) + *(f32 *)(q + 8);
        out1[2] = lbl_803E04E4 * ((f32)(u32)*(u8 *)(p + 0x3d) *
                                  fn_80293E80(lbl_803E04D8 * (f32)(*(u8 *)(p + 0x3e) << 8) / lbl_803E04DC));
        out1[3] = lbl_803E04E4 * ((f32)(u32)*(u8 *)(q + 0x3d) *
                                  fn_80293E80(lbl_803E04D8 * (f32)(*(u8 *)(q + 0x3e) << 8) / lbl_803E04DC));
        out2[0] = sclA * (f32)*(s8 *)(pp + 0x31) + *(f32 *)(p + 0xc);
        out2[1] = sclB * (f32)*(s8 *)(qq + 0x31) + *(f32 *)(q + 0xc);
        {
            f32 e8 = lbl_803E04E8;
            out2[2] = e8;
            out2[3] = e8;
        }
        out3[0] = (f32)*(s8 *)(pp + 0x2d) * (sclA * -cosA) + *(f32 *)(p + 0x10);
        out3[1] = (f32)*(s8 *)(qq + 0x2d) * (sclB * -cosB) + *(f32 *)(q + 0x10);
        out3[2] = lbl_803E04E4 * ((f32)(u32)*(u8 *)(p + 0x3d) *
                                  sin(lbl_803E04D8 * (f32)(*(u8 *)(p + 0x3e) << 8) / lbl_803E04DC));
        out3[3] = lbl_803E04E4 * ((f32)(u32)*(u8 *)(q + 0x3d) *
                                  sin(lbl_803E04D8 * (f32)(*(u8 *)(q + 0x3e) << 8) / lbl_803E04DC));
    }
    return ret;
}
#pragma pop

/* Set *p to lbl_803DD414 (sign-extended) and return lbl_803DD418. */
u32 Checkpoint_func0E(s32 *p)
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

/* NOTE: 96.8% ? register choice differs (r5 vs r7 for rank). */
#pragma push
#pragma scheduling off
s32 Checkpoint_func0F(PartFxItem *p)
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
PartFxItem *Checkpoint_func10(s32 target_rank)
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

/* Init random offsets / chain advance with lookup. */
#pragma push
void Checkpoint_func0A(s32 key, f32 *out_vec, u8 *flag_byte)
{
    s32 local_idx;
    PartFxNode *n;
    s32 alt_found;
    n = (PartFxNode *)Checkpoint_find(key, &local_idx);
    if (n == 0) return;
    out_vec[0] = (f32)(s32)randomGetRange(-0x63, 0x63) / lbl_803E0500;
    out_vec[1] = (f32)(s32)randomGetRange(-0x63, 0x63) / lbl_803E0500;
    out_vec[2] = (f32)(s32)randomGetRange(0, 0x63) / lbl_803E0500;
    alt_found = 0;
    {
        s32 v = *(s32 *)((char *)n + 0x20);
        if (v != 0) {
            PartFxNode *m = (PartFxNode *)Checkpoint_find(v, &local_idx);
            if (*(s32 *)((char *)m + 0x20) > -1) {
                alt_found = 1;
            }
        }
    }
    if ((s8)*flag_byte == 0) {
        if (alt_found != 0) {
            *(s32 *)(out_vec + 4) = *(s32 *)((char *)n + 0x20);
        } else {
            s32 v = *(s32 *)((char *)n + 0x18);
            if (v > -1) {
                *(s32 *)(out_vec + 4) = v;
                *flag_byte = 1;
            }
        }
    } else {
        s32 v = *(s32 *)((char *)n + 0x18);
        if (v != 0) {
            *(s32 *)(out_vec + 4) = v;
        } else if (alt_found != 0) {
            *(s32 *)(out_vec + 4) = *(s32 *)((char *)n + 0x20);
            *flag_byte = 0;
        }
    }
}
#pragma pop

/* Walk a chain via Checkpoint_find lookups starting from o->_0x10. */
#pragma push
#pragma scheduling off
#pragma peephole off
void Checkpoint_func0C(PartFxNode *o)
{
    s32 local_idx;
    PartFxNode *ret;
    s32 nxt;
    ret = (PartFxNode *)Checkpoint_find(o->_0x10, &local_idx);
    if (ret == 0) {
        o->_0x18 = 0;
        o->_0xc = lbl_803E04E8;
    } else {
        while ((nxt = ret->_0x18) > -1) {
            ret = (PartFxNode *)Checkpoint_find(nxt, &local_idx);
            o->_0x1c = o->_0x1c + 1;
        }
        o->_0x18 = o->_0x10;
        o->_0xc = lbl_803E04E8;
    }
}
#pragma pop

/* Append v to array pointed to by lbl_803DD41C, capped at 10 entries.
 * NOTE: stuck at ~78% ? instruction scheduling differs. */
void Checkpoint_func0D(u32 v)
{
    s32 i;
    i = lbl_803DD416;
    if (i >= 10) return;
    lbl_803DD416 = (s16)(i + 1);
    ((u32 *)lbl_803DD41C)[i] = v;
}

/* Tick: counter1, counter2 + rate*timeDelta; clamp; periodic sin. */
#pragma push
#pragma scheduling off
void Effect16_func05(void)
{
    f32 sum;
    sum = lbl_803DB848 + lbl_803E00A8 * timeDelta;
    lbl_803DB848 = sum;
    if (sum > lbl_803E00B0) lbl_803DB848 = lbl_803E00AC;
    sum = lbl_803DB84C + lbl_803E00A8 * timeDelta;
    lbl_803DB84C = sum;
    if (sum > lbl_803E00B0) lbl_803DB84C = lbl_803E00B8;
    lbl_803DD3C0 = lbl_803DD3C0 + (s32)framesThisStep * 0x64;
    if (lbl_803DD3C0 > 0x7fff) lbl_803DD3C0 = 0;
    lbl_803DD3CC = fn_80293E80(lbl_803E0108 * (f32)(s16)lbl_803DD3C0 / lbl_803E010C);
    lbl_803DD3C4 = lbl_803DD3C4 + (s32)framesThisStep * 0x32;
    if (lbl_803DD3C4 > 0x7fff) lbl_803DD3C4 = 0;
    lbl_803DD3C8 = fn_80293E80(lbl_803E0108 * (f32)(s16)lbl_803DD3C4 / lbl_803E010C);
}

void Effect17_func05(void)
{
    f32 sum;
    sum = lbl_803DB858 + lbl_803E01B8 * timeDelta;
    lbl_803DB858 = sum;
    if (sum > lbl_803E01C0) lbl_803DB858 = lbl_803E01BC;
    sum = lbl_803DB85C + lbl_803E01B8 * timeDelta;
    lbl_803DB85C = sum;
    if (sum > lbl_803E01C0) lbl_803DB85C = lbl_803E01C8;
    lbl_803DD3D0 = lbl_803DD3D0 + (s32)framesThisStep * 0x64;
    if (lbl_803DD3D0 > 0x7fff) lbl_803DD3D0 = 0;
    lbl_803DD3DC = fn_80293E80(lbl_803E0218 * (f32)(s16)lbl_803DD3D0 / lbl_803E021C);
    lbl_803DD3D4 = lbl_803DD3D4 + (s32)framesThisStep * 0x32;
    if (lbl_803DD3D4 > 0x7fff) lbl_803DD3D4 = 0;
    lbl_803DD3D8 = fn_80293E80(lbl_803E0218 * (f32)(s16)lbl_803DD3D4 / lbl_803E021C);
}

void Effect18_func05(void)
{
    f32 sum;
    sum = lbl_803DB868 + lbl_803E0220 * timeDelta;
    lbl_803DB868 = sum;
    if (sum > lbl_803E0228) lbl_803DB868 = lbl_803E0224;
    sum = lbl_803DB86C + lbl_803E0220 * timeDelta;
    lbl_803DB86C = sum;
    if (sum > lbl_803E0228) lbl_803DB86C = lbl_803E0230;
    lbl_803DD3E0 = lbl_803DD3E0 + (s32)framesThisStep * 0x64;
    if (lbl_803DD3E0 > 0x7fff) lbl_803DD3E0 = 0;
    lbl_803DD3EC = fn_80293E80(lbl_803E02D0 * (f32)(s16)lbl_803DD3E0 / lbl_803E02D4);
    lbl_803DD3E4 = lbl_803DD3E4 + (s32)framesThisStep * 0x32;
    if (lbl_803DD3E4 > 0x7fff) lbl_803DD3E4 = 0;
    lbl_803DD3E8 = fn_80293E80(lbl_803E02D0 * (f32)(s16)lbl_803DD3E4 / lbl_803E02D4);
}

typedef struct PartFxSpawn {
    void *f00;
    int f04;
    int f08;
    s16 f0c;
    s16 f0e;
    s16 f10;
    u8  pad12[2];
    f32 f14;
    f32 f18;
    f32 f1c;
    f32 f20;
    f32 f24;
    f32 f28;
    f32 f2c;
    f32 f30;
    f32 f34;
    f32 f38;
    f32 f3c;
    s16 f40;
    s16 f42;
    u32 f44;
    u32 f48;
    u32 f4c;
    u32 f50;
    u32 f54;
    s16 f58;
    s16 f5a;
    s16 f5c;
    u8  f5e;
    u8  f60;
    u8  f61;
    u8  f62;
} PartFxSpawn;

int Effect19_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                    u8 param_5, f32 *param_6)
{
    int uVar1;
    PartFxSpawn cfg;

    lbl_803DB870 = lbl_803DB870 + lbl_803E02D8;
    if (lbl_803DB870 > lbl_803E02E0) lbl_803DB870 = lbl_803E02DC;
    lbl_803DB874 = lbl_803DB874 + lbl_803E02E4;
    if (lbl_803DB874 > lbl_803E02E0) lbl_803DB874 = lbl_803E02E8;
    if (param_1 == 0) {
        uVar1 = -1;
    } else {
        if ((param_4 & 0x200000) != 0) {
            if (param_3 == 0) return -1;
            cfg.f18 = *(f32 *)(param_3 + 6);
            cfg.f1c = *(f32 *)(param_3 + 8);
            cfg.f20 = *(f32 *)(param_3 + 10);
            cfg.f14 = *(f32 *)(param_3 + 4);
            cfg.f10 = param_3[2];
            cfg.f0e = param_3[1];
            cfg.f0c = *param_3;
            cfg.f62 = param_5;
        }
        cfg.f44 = 0;
        cfg.f48 = 0;
        cfg.f5e = (u8)param_2;
        cfg.f00 = param_1;
        cfg.f30 = lbl_803E02EC;
        cfg.f34 = lbl_803E02EC;
        cfg.f38 = lbl_803E02EC;
        cfg.f24 = lbl_803E02EC;
        cfg.f28 = lbl_803E02EC;
        cfg.f2c = lbl_803E02EC;
        cfg.f3c = lbl_803E02EC;
        cfg.f08 = 0;
        cfg.f04 = -1;
        cfg.f60 = 0xff;
        cfg.f61 = 0;
        cfg.f42 = 0;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0xffff;
        cfg.f4c = 0xffff;
        cfg.f50 = 0xffff;
        cfg.f54 = 0xffff;
        cfg.f40 = 0;
        if (param_2 == 0x76c) {
            cfg.f24 = lbl_803E02F0 * (f32)(s32)randomGetRange(0x1e, 0x64);
            if (*(f32 *)(param_3 + 6) > lbl_803E02EC) cfg.f24 = -cfg.f24;
            cfg.f28 = lbl_803E02D8 * (f32)(s32)randomGetRange(0, 0x64) + lbl_803E02DC;
            cfg.f38 = lbl_803E02DC *
                      (f32)(s32)randomGetRange((s32)param_6[0], (s32)param_6[1]);
            cfg.f30 = lbl_803E02F4;
            if (*(f32 *)(param_3 + 6) > lbl_803E02EC) cfg.f30 = lbl_803E02F8;
            cfg.f3c = lbl_803E02FC * (f32)(s32)randomGetRange(-0x64, 0x64) + param_6[2];
            cfg.f08 = 0x23;
            cfg.f44 = 0x80108;
            cfg.f42 = 0x60;
            cfg.f60 = 0xc4;
        } else {
            return -1;
        }
        cfg.f44 = cfg.f44 | param_4;
        if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 = cfg.f44 ^ 2;
        if ((cfg.f44 & 1) != 0) {
            if ((param_4 & 0x200000) == 0) {
                if (cfg.f00 != 0) {
                    cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                    cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                    cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
                }
            } else {
                cfg.f30 = cfg.f30 + cfg.f18;
                cfg.f34 = cfg.f34 + cfg.f1c;
                cfg.f38 = cfg.f38 + cfg.f20;
            }
        }
        uVar1 = (*(int (**)())(*gExpgfxInterface + 8))(&cfg, -1, param_2, 0);
    }
    return uVar1;
}

int Effect13_func04(void *param_1, int param_2, s16 *param_3, u32 param_4, u8 param_5)
{
    int uVar1;
    PartFxSpawn cfg;

    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = *(f32 *)(param_3 + 6);
        cfg.f1c = *(f32 *)(param_3 + 8);
        cfg.f20 = *(f32 *)(param_3 + 10);
        cfg.f14 = *(f32 *)(param_3 + 4);
        cfg.f10 = param_3[2];
        cfg.f0e = param_3[1];
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = lbl_803E0180;
    cfg.f34 = lbl_803E0180;
    cfg.f38 = lbl_803E0180;
    cfg.f24 = lbl_803E0180;
    cfg.f28 = lbl_803E0180;
    cfg.f2c = lbl_803E0180;
    cfg.f3c = lbl_803E0180;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    switch (param_2) {
    case 0x44c:
        cfg.f24 = lbl_803E0184 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f28 = lbl_803E0188 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f2c = lbl_803E0184 * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f3c = lbl_803E018C;
        cfg.f08 = 0x6e;
        cfg.f44 = 0x8a100208;
        cfg.f48 = 0x20;
        cfg.f42 = 0x5f;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0xffff;
        cfg.f4c = 0x400;
        cfg.f50 = 0xea60;
        cfg.f54 = 0x1000;
        break;
    case 0x44d:
        cfg.f24 = lbl_803E018C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f2c = lbl_803E018C * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f3c = lbl_803E0190;
        cfg.f08 = 0x258;
        cfg.f60 = 0x7f;
        cfg.f44 = 0x0a100100;
        cfg.f48 = 0x20;
        cfg.f42 = 0x62;
        cfg.f58 = 0x400;
        cfg.f5a = 0xea60;
        cfg.f5c = 0x1000;
        cfg.f4c = 0;
        cfg.f50 = 0xc350;
        cfg.f54 = 0;
        break;
    case 0x44e:
        cfg.f34 = lbl_803E0194;
        cfg.f3c = lbl_803E0198;
        cfg.f08 = 0xc8;
        cfg.f44 = 0x11000004;
        cfg.f42 = 0x151;
        cfg.f04 = 0x44f;
        break;
    case 0x44f:
        if (param_3 == 0) {
            lbl_8039C440.fc = lbl_803E0180;
            lbl_8039C440.f10 = lbl_803E0180;
            lbl_8039C440.f14 = lbl_803E0180;
            lbl_8039C440.f8 = lbl_803E019C;
            lbl_8039C440.x = 0;
            lbl_8039C440.y = 0;
            lbl_8039C440.z = 0;
            param_3 = (s16 *)&lbl_8039C440;
        }
        (*(void (*)(int, f32, f32, f32, f32))(*(int *)(*gWaterfxInterface + 0x10)))(
            0, *(f32 *)(param_3 + 6), *(f32 *)(param_3 + 8), *(f32 *)(param_3 + 10),
            lbl_803E01A0);
        Sfx_PlayFromObject((int)param_1, SFXsc_snort02);
        cfg.f08 = 1;
        cfg.f3c = lbl_803E01A4;
        cfg.f44 = 0x0a000001;
        cfg.f42 = 0x56;
        break;
    case 0x450:
        cfg.f34 = lbl_803E01A8;
        cfg.f3c = lbl_803E0198;
        cfg.f08 = 0xc8;
        cfg.f44 = 0x11000004;
        cfg.f42 = 0x151;
        cfg.f04 = 0x451;
        break;
    case 0x451:
        Sfx_PlayFromObject((int)param_1, SFXsc_snort02);
        cfg.f08 = 0x64;
        cfg.f3c = lbl_803E01AC * (f32)(s32)cfg.f08;
        cfg.f44 = 0x0a100201;
        cfg.f42 = 0x56;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 = cfg.f44 ^ 2;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*(int (**)())(*gExpgfxInterface + 8))(&cfg, -1, param_2, 0);
    return uVar1;
}

int Effect17_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                    u8 param_5, int param_6)
{
    int uVar1;
    PartFxSpawn cfg;

    lbl_803DB850 = lbl_803DB850 + lbl_803E01B8;
    if (lbl_803DB850 > lbl_803E01C0) lbl_803DB850 = lbl_803E01BC;
    lbl_803DB854 = lbl_803DB854 + lbl_803E01C4;
    if (lbl_803DB854 > lbl_803E01C0) lbl_803DB854 = lbl_803E01C8;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = *(f32 *)(param_3 + 6);
        cfg.f1c = *(f32 *)(param_3 + 8);
        cfg.f20 = *(f32 *)(param_3 + 10);
        cfg.f14 = *(f32 *)(param_3 + 4);
        cfg.f10 = param_3[2];
        cfg.f0e = param_3[1];
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = lbl_803E01CC;
    cfg.f34 = lbl_803E01CC;
    cfg.f38 = lbl_803E01CC;
    cfg.f24 = lbl_803E01CC;
    cfg.f28 = lbl_803E01CC;
    cfg.f2c = lbl_803E01CC;
    cfg.f3c = lbl_803E01CC;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    cfg.f40 = 0;
    switch (param_2) {
    case 0x73a:
        cfg.f28 = lbl_803E01D0 * (f32)(s32)randomGetRange(8, 0xa);
        if (randomGetRange(0, 0x28) != 0) {
            cfg.f3c = lbl_803E01B8 * (f32)(s32)randomGetRange(8, 0x14);
            cfg.f08 = randomGetRange(0x5a, 0x78);
        } else {
            cfg.f3c = lbl_803E01B8 * (f32)(s32)randomGetRange(0x15, 0x29);
            cfg.f08 = 0x1cc;
        }
        cfg.f44 = 0x80180200;
        cfg.f48 = 0x1000020;
        cfg.f42 = 0xc0b;
        cfg.f60 = 0x7f;
        cfg.f5c = 0x3fff;
        cfg.f5a = 0x3fff;
        cfg.f58 = 0x3fff;
        cfg.f54 = 0xffff;
        cfg.f50 = 0xffff;
        cfg.f4c = 0xffff;
        cfg.f34 = lbl_803E01D4;
        break;
    case 0x73b:
        cfg.f24 = lbl_803E01D0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803E01D0 * (f32)(s32)randomGetRange(8, 0x14);
        cfg.f2c = lbl_803E01D0 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803E01D8;
        cfg.f08 = 0x32;
        cfg.f44 = 0x3000200;
        cfg.f48 = 0x200020;
        cfg.f42 = 0x33;
        cfg.f60 = 0xff;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0xffff;
        cfg.f4c = 0xffff;
        cfg.f54 = randomGetRange(0, 0x8000);
        cfg.f50 = cfg.f54;
        cfg.f34 = lbl_803E01DC;
        break;
    case 0x73d:
        cfg.f30 = lbl_803E01BC * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f34 = lbl_803E01D0 * (f32)(s32)randomGetRange(-0xa, 0x64);
        cfg.f38 = lbl_803E01BC * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f3c = lbl_803E01E0 * (lbl_803E01E4 * (f32)(s32)randomGetRange(7, 9));
        cfg.f08 = 0x3c;
        cfg.f44 = 0x80100;
        cfg.f61 = 0x10;
        cfg.f42 = 0xde;
        break;
    case 0x73e:
        cfg.f30 = lbl_803E01BC * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f34 = lbl_803E01D0 * (f32)(s32)randomGetRange(-0xa, 0x64);
        cfg.f38 = lbl_803E01BC * (f32)(s32)randomGetRange(-0xa, 0xa);
        cfg.f3c = lbl_803E01E0 * (lbl_803E01E4 * (f32)(s32)randomGetRange(7, 9));
        cfg.f08 = 0x3c;
        cfg.f44 = 0x80100;
        cfg.f61 = 0x10;
        cfg.f42 = 0xdf;
        break;
    case 0x73f:
        if (param_6 != 0) {
            cfg.f30 = lbl_803E01BC * (f32)(s32)randomGetRange(-0xa, 0xa) + lbl_803E01E8;
            cfg.f34 = lbl_803E01D0 * (f32)(s32)randomGetRange(-0xa, 0x64) + lbl_803E01EC;
            cfg.f38 = lbl_803E01BC * (f32)(s32)randomGetRange(-0xa, 0xa) + lbl_803E01F0;
        } else {
            cfg.f30 = lbl_803E01BC * (f32)(s32)randomGetRange(-0xa, 0xa);
            cfg.f34 = lbl_803E01D0 * (f32)(s32)randomGetRange(-0xa, 0x64);
            cfg.f38 = lbl_803E01BC * (f32)(s32)randomGetRange(-0xa, 0xa);
        }
        cfg.f3c = lbl_803E01F4 * (lbl_803E01E4 * (f32)(s32)randomGetRange(7, 9));
        cfg.f08 = 0x3c;
        cfg.f44 = 0x80100;
        cfg.f61 = 0x10;
        cfg.f42 = 0xde;
        break;
    case 0x740:
        if (param_6 != 0) {
            cfg.f30 = lbl_803E01BC * (f32)(s32)randomGetRange(-0xa, 0xa) + lbl_803E01E8;
            cfg.f34 = lbl_803E01D0 * (f32)(s32)randomGetRange(-0xa, 0x64) + lbl_803E01EC;
            cfg.f38 = lbl_803E01BC * (f32)(s32)randomGetRange(-0xa, 0xa) + lbl_803E01F0;
        } else {
            cfg.f30 = lbl_803E01BC * (f32)(s32)randomGetRange(-0xa, 0xa);
            cfg.f34 = lbl_803E01D0 * (f32)(s32)randomGetRange(-0xa, 0x64);
            cfg.f38 = lbl_803E01BC * (f32)(s32)randomGetRange(-0xa, 0xa);
        }
        cfg.f3c = lbl_803E01F4 * (lbl_803E01E4 * (f32)(s32)randomGetRange(7, 9));
        cfg.f08 = 0x3c;
        cfg.f44 = 0x80100;
        cfg.f61 = 0x10;
        cfg.f42 = 0xdf;
        break;
    case 0x741:
        if (param_3 != 0) cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f3c = lbl_803E01F8;
        cfg.f08 = randomGetRange(0, 0x1e) + 0x50;
        cfg.f60 = 0x60;
        cfg.f44 = 0x80110;
        cfg.f42 = 0x7b;
        cfg.f61 = 0x20;
        break;
    case 0x742:
        cfg.f2c = lbl_803E01FC;
        cfg.f24 = lbl_803E0200 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803E0200 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803E0204;
        cfg.f08 = randomGetRange(0x46, 0x50);
        cfg.f60 = 0xff;
        cfg.f44 = 0x82000104;
        cfg.f48 = 0x400;
        cfg.f42 = 0x3f4;
        break;
    case 0x743:
        cfg.f2c = lbl_803E01FC;
        cfg.f24 = lbl_803E0200 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803E0200 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803E0204;
        cfg.f08 = randomGetRange(0x46, 0x50);
        cfg.f60 = 0xff;
        cfg.f44 = 0x82000104;
        cfg.f48 = 0x400;
        cfg.f42 = 0x500;
        break;
    case 0x744:
        if (randomGetRange(0, 4) == 4) {
            cfg.f3c = lbl_803E0208;
            cfg.f60 = 0x9b;
            cfg.f44 = 0x480000;
            cfg.f08 = randomGetRange(0x1e, 0x28);
        } else {
            cfg.f3c = lbl_803E020C;
            cfg.f60 = 0x7d;
            cfg.f44 = 0x180000;
            cfg.f08 = 0x50;
        }
        cfg.f48 = 0x2000000;
        cfg.f42 = 0x88;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 = cfg.f44 ^ 2;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*(int (**)())(*gExpgfxInterface + 8))(&cfg, -1, param_2, 0);
    return uVar1;
}

int Effect16_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                    u8 param_5, int param_6)
{
    int uVar1;
    PartFxSpawn cfg;

    lbl_803DB840 = lbl_803DB840 + lbl_803E00A8;
    if (lbl_803DB840 > lbl_803E00B0) lbl_803DB840 = lbl_803E00AC;
    lbl_803DB844 = lbl_803DB844 + lbl_803E00B4;
    if (lbl_803DB844 > lbl_803E00B0) lbl_803DB844 = lbl_803E00B8;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = *(f32 *)(param_3 + 6);
        cfg.f1c = *(f32 *)(param_3 + 8);
        cfg.f20 = *(f32 *)(param_3 + 10);
        cfg.f14 = *(f32 *)(param_3 + 4);
        cfg.f10 = param_3[2];
        cfg.f0e = param_3[1];
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = lbl_803E00BC;
    cfg.f34 = lbl_803E00BC;
    cfg.f38 = lbl_803E00BC;
    cfg.f24 = lbl_803E00BC;
    cfg.f28 = lbl_803E00BC;
    cfg.f2c = lbl_803E00BC;
    cfg.f3c = lbl_803E00BC;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    switch (param_2) {
    case 0x6d7:
        if (param_3 == 0) {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            param_3 = (s16 *)&lbl_8039C410;
        }
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f3c = lbl_803E00A8 * (f32)(s32)randomGetRange(0xa, 0x1e);
        cfg.f08 = randomGetRange(0x118, 0x12c);
        cfg.f44 = 0x80180214;
        cfg.f42 = 0x5c;
        break;
    case 0x6d8:
        if (param_3 == 0) {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            param_3 = (s16 *)&lbl_8039C410;
        }
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f3c = lbl_803E00A8 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f08 = randomGetRange(0x118, 0x12c);
        cfg.f44 = 0x80180214;
        cfg.f42 = 0xc79;
        break;
    case 0x6d9:
        cfg.f24 = lbl_803E00C0 * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f28 = lbl_803E00C0 * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f2c = lbl_803E00C0 * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f3c = lbl_803E00C4 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f08 = 0x64;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80114;
        cfg.f48 = 0x10008;
        cfg.f42 = 0x157;
        break;
    case 0x6da:
        cfg.f3c = lbl_803E00C8;
        cfg.f08 = 0x14;
        cfg.f44 = 0x80480210;
        cfg.f42 = 0xc79;
        cfg.f60 = 0x9d;
        break;
    case 0x6db:
        if (param_6 != 0) {
            cfg.f24 = lbl_803E00CC * (f32)(s32)randomGetRange(-0x96, 0x96);
            cfg.f2c = lbl_803E00CC * (f32)(s32)randomGetRange(-0x96, 0x96);
            cfg.f28 = lbl_803E00CC * (f32)(s32)randomGetRange(0x64, 0x190);
            cfg.f3c = lbl_803E00D0 * (f32)(s32)randomGetRange(0xf, 0x14);
            cfg.f08 = 0x32;
            cfg.f58 = 0xffff;
            cfg.f5a = 0xffff;
            cfg.f5c = 0xffff;
            cfg.f4c = 0xffff;
            cfg.f50 = 0;
            cfg.f54 = 0;
            cfg.f44 = 0x3000200;
            cfg.f48 = 0x200022;
        } else {
            cfg.f3c = lbl_803E00D4 * (f32)(s32)randomGetRange(0xf, 0x14);
            cfg.f08 = 1;
            cfg.f44 = 0x80000;
        }
        cfg.f60 = 0xff;
        cfg.f42 = 0xc79;
        break;
    case 0x6dc:
        cfg.f28 = lbl_803E00D8 * (f32)(s32)randomGetRange(8, 0xa);
        cfg.f3c = lbl_803E00A8 * (f32)(s32)randomGetRange(0x12, 0x1c);
        cfg.f08 = randomGetRange(0x32, 0x64);
        cfg.f44 = 0x80180200;
        cfg.f42 = 0xc0b;
        cfg.f60 = 0xff;
        break;
    case 0x6dd:
        cfg.f3c = lbl_803E00AC;
        cfg.f08 = 0xa;
        cfg.f60 = 0xc3;
        cfg.f61 = 0x10;
        cfg.f44 = 0x580110;
        cfg.f42 = 0xc79;
        break;
    case 0x6de:
        cfg.f24 = lbl_803E00DC * lbl_803DB840 * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.f2c = lbl_803E00DC * lbl_803DB840 * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.f28 = lbl_803E00DC * lbl_803DB840 * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.f60 = 0x7d;
        cfg.f3c = lbl_803E00E0 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f44 = 0x3000000;
        cfg.f48 = 0x300000;
        cfg.f08 = 0x14;
        cfg.f42 = 0xc79;
        break;
    case 0x6df:
        cfg.f24 = lbl_803E00CC * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.f2c = lbl_803E00CC * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.f28 = lbl_803E00CC * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803E00E4 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f44 = 0x80200;
        cfg.f48 = 0x100000;
        cfg.f08 = 0x64;
        cfg.f42 = 0x125;
        break;
    case 0x6e0:
        cfg.f24 = lbl_803E00E8 * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.f2c = lbl_803E00E8 * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.f28 = lbl_803E00E8 * (f32)(s32)randomGetRange(-0xf, 0xf);
        cfg.f60 = 0xff;
        cfg.f3c = lbl_803E00E0 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f44 = 0x2000200;
        cfg.f48 = 0x300000;
        cfg.f08 = 0x1e;
        cfg.f42 = 0x33;
        break;
    case 0x6e1:
        cfg.f08 = 0x46;
        cfg.f3c = lbl_803E00EC;
        cfg.f58 = 0xff00;
        cfg.f5a = 0xff00;
        cfg.f5c = 0xff00;
        cfg.f4c = 0xff00;
        cfg.f50 = 0;
        cfg.f54 = 0xff00;
        cfg.f44 = 0x100100;
        cfg.f48 = 0x20;
        cfg.f60 = 0x7f;
        cfg.f42 = 0x72;
        break;
    case 0x6f2:
        if (param_3 == 0) {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            param_3 = (s16 *)&lbl_8039C410;
        }
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f24 = lbl_803E00C0 * (f32)(s32)randomGetRange(-7, 3);
        cfg.f28 = lbl_803E00C0 * (f32)(s32)randomGetRange(5, 0xf);
        cfg.f2c = lbl_803E00C0 * (f32)(s32)randomGetRange(-7, 3);
        cfg.f3c = lbl_803E00F0 * (f32)(s32)randomGetRange(0x32, 0x3c);
        cfg.f08 = randomGetRange(0x3c, 0x5a);
        cfg.f44 = 0x580004;
        cfg.f48 = 0x400000;
        cfg.f60 = 0xff;
        cfg.f42 = 0xc0d;
        break;
    case 0x6f3:
        if (param_3 == 0) {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            param_3 = (s16 *)&lbl_8039C410;
        }
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f3c = lbl_803E00F4 * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.f08 = 0x64;
        cfg.f44 = 0xc0804;
        cfg.f48 = 0x8800001;
        cfg.f60 = 0xff;
        cfg.f42 = 0x58f;
        break;
    case 0x6f4:
        if (param_3 == 0) {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            param_3 = (s16 *)&lbl_8039C410;
        }
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f3c = lbl_803E00F8 * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.f08 = 0x64;
        cfg.f44 = 0xc0804;
        cfg.f48 = 0x4800001;
        cfg.f60 = 0xff;
        cfg.f42 = 0x590;
        break;
    case 0x6f5:
        if (param_3 == 0) {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            param_3 = (s16 *)&lbl_8039C410;
        }
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f3c = lbl_803E00F4 * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.f08 = 0x64;
        cfg.f44 = 0xc0804;
        cfg.f48 = 0x8800001;
        cfg.f60 = 0xff;
        cfg.f42 = 0x403;
        break;
    case 0x6f6:
        if (param_3 == 0) {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            param_3 = (s16 *)&lbl_8039C410;
        }
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f3c = lbl_803E00F8 * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.f08 = 0x64;
        cfg.f44 = 0xc0804;
        cfg.f48 = 0x4800001;
        cfg.f60 = 0xff;
        cfg.f42 = 0x404;
        break;
    case 0x6f7:
        if (param_3 == 0) {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            param_3 = (s16 *)&lbl_8039C410;
        }
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f3c = lbl_803E00F4 * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.f08 = 0x64;
        cfg.f44 = 0xc0804;
        cfg.f48 = 0x8800001;
        cfg.f60 = 0xff;
        cfg.f42 = 0x405;
        break;
    case 0x6f8:
        if (param_3 == 0) {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            param_3 = (s16 *)&lbl_8039C410;
        }
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f3c = lbl_803E00F8 * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.f08 = 0x64;
        cfg.f44 = 0xc0804;
        cfg.f48 = 0x8800001;
        cfg.f60 = 0xff;
        cfg.f42 = 0x406;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 = cfg.f44 ^ 2;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*(int (**)())(*gExpgfxInterface + 8))(&cfg, -1, param_2, 0);
    return uVar1;
}

int Effect15_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                    u8 param_5, f32 *param_6)
{
    int uVar1;
    PartFxSpawn cfg;

    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = *(f32 *)(param_3 + 6);
        cfg.f1c = *(f32 *)(param_3 + 8);
        cfg.f20 = *(f32 *)(param_3 + 10);
        cfg.f14 = *(f32 *)(param_3 + 4);
        cfg.f10 = param_3[2];
        cfg.f0e = param_3[1];
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = lbl_803E0110;
    cfg.f34 = lbl_803E0110;
    cfg.f38 = lbl_803E0110;
    cfg.f24 = lbl_803E0110;
    cfg.f28 = lbl_803E0110;
    cfg.f2c = lbl_803E0110;
    cfg.f3c = lbl_803E0110;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    switch (param_2) {
    case 0x3e8:
        cfg.f3c = lbl_803E0114 * (f32)(s32)randomGetRange(0x5a, 0x64);
        cfg.f24 = lbl_803E0118 * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f28 = lbl_803E0110;
        cfg.f2c = lbl_803E0118 * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f08 = 0x28;
        cfg.f44 |= 0x80218;
        cfg.f48 = 0x20;
        switch (randomGetRange(0, 2)) {
        case 0:
            cfg.f42 = 0x156;
            break;
        case 1:
            cfg.f42 = 0x157;
            break;
        case 2:
            cfg.f42 = 0xc0e;
            break;
        default:
            cfg.f42 = 0x156;
            break;
        }
        cfg.f58 = 0xffff;
        cfg.f5a = 0xd6d8;
        cfg.f5c = 0xffff;
        cfg.f4c = 0xffff;
        cfg.f50 = 0x7530;
        cfg.f54 = 0xffff;
        cfg.f60 = 0xff;
        break;
    case 0x3e9:
        if (param_3 == 0) {
            lbl_8039C428.fc = lbl_803E0110;
            lbl_8039C428.f10 = lbl_803E0110;
            lbl_8039C428.f14 = lbl_803E0110;
            lbl_8039C428.f8 = lbl_803E011C;
            lbl_8039C428.x = 0;
            lbl_8039C428.y = 0;
            lbl_8039C428.z = 0;
            param_3 = (s16 *)&lbl_8039C428;
        }
        cfg.f30 = *(f32 *)(param_3 + 6);
        cfg.f34 = *(f32 *)(param_3 + 8);
        cfg.f38 = *(f32 *)(param_3 + 10);
        cfg.f3c = lbl_803E0120;
        cfg.f44 |= 0x180110;
        cfg.f48 = 0x20;
        cfg.f08 = 0x12;
        cfg.f60 = 0xff;
        cfg.f42 = 0x159;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0xffff;
        cfg.f4c = 0xffff;
        cfg.f50 = 0xc350;
        cfg.f54 = 0xffff;
        break;
    case 0x3ea:
        if (param_3 == 0) {
            lbl_8039C428.fc = lbl_803E0110;
            lbl_8039C428.f10 = lbl_803E0110;
            lbl_8039C428.f14 = lbl_803E0110;
            lbl_8039C428.f8 = lbl_803E011C;
            lbl_8039C428.x = 0;
            lbl_8039C428.y = 0;
            lbl_8039C428.z = 0;
            param_3 = (s16 *)&lbl_8039C428;
        }
        cfg.f30 = (f32)(s32)randomGetRange(0, 0x64) / lbl_803E0124;
        cfg.f34 = (f32)(s32)(-(s32)randomGetRange(0x64, 0x96)) / lbl_803E0128;
        cfg.f38 = (f32)(s32)randomGetRange(-0x64, 0x64) / lbl_803E0124;
        cfg.f44 |= 0x80208;
        cfg.f48 = 0x10000;
        cfg.f24 = lbl_803E012C * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f2c = lbl_803E012C * (f32)(s32)randomGetRange(-0x64, 0x64);
        cfg.f60 = 0xff;
        cfg.f08 = 0x3c;
        cfg.f42 = 0x7b;
        cfg.f3c = *(f32 *)(param_3 + 4) *
                  (lbl_803E0130 * (lbl_803E0134 * (f32)(s32)randomGetRange(0x32, 0x64))) +
                  lbl_803E012C;
        break;
    case 0x3eb:
        cfg.f24 = lbl_803E0138 * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f28 = lbl_803E013C * (f32)(s32)randomGetRange(-5, 5);
        cfg.f2c = lbl_803E0138 * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f30 = lbl_803E0110;
        cfg.f34 = (f32)(s32)randomGetRange(-6, 2);
        cfg.f38 = lbl_803E0110;
        cfg.f3c = lbl_803E013C;
        cfg.f08 = 0x32;
        cfg.f44 = 0x80080208;
        cfg.f42 = 0x60;
        cfg.f58 = 0x7f00;
        cfg.f5a = 0x6400;
        cfg.f5c = 0;
        cfg.f4c = 0x5a00;
        cfg.f50 = 0;
        cfg.f54 = 0;
        cfg.f48 = 0x20;
        cfg.f60 = 0x7f;
        break;
    case 0x3ec:
        return -1;
    case 0x3ed:
        cfg.f24 = lbl_803E013C * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f28 = lbl_803E0120 * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f2c = lbl_803E013C * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f3c = lbl_803E0140 * (f32)(s32)randomGetRange(0xa, 0x14);
        cfg.f08 = 0x32;
        cfg.f44 = 0x80210;
        cfg.f48 = 0x8000800;
        cfg.f42 = 0x79;
        break;
    case 0x3ee:
        cfg.f30 = cfg.f30 + (f32)(s32)randomGetRange(-0xa, 0xa) / lbl_803E0144;
        cfg.f34 = cfg.f34 + (f32)(s32)randomGetRange(-0x1e, 0) / lbl_803E0148;
        cfg.f38 = cfg.f38 + (f32)(s32)randomGetRange(-0xa, 0xa) / lbl_803E0144;
        cfg.f24 = lbl_803E012C * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803E014C * (f32)(s32)(-(s32)randomGetRange(0x28, 0x64));
        cfg.f2c = lbl_803E012C * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803E012C * (f32)(s32)randomGetRange(0xf, 0x16);
        cfg.f08 = 0x258;
        cfg.f44 = 0x180100;
        cfg.f42 = 0xc10;
        cfg.f60 = (u8)randomGetRange(0x96, 0xfa);
        break;
    case 0x3ef:
        cfg.f30 = (f32)(s32)randomGetRange(-0x4b0, 0x4b0) / lbl_803E0128;
        cfg.f38 = (f32)(s32)randomGetRange(-0x4b0, 0x4b0) / lbl_803E0128;
        cfg.f28 = lbl_803E014C * (f32)(s32)randomGetRange(0x1e, 0x46);
        cfg.f3c = lbl_803E0154 * (f32)(s32)randomGetRange(0, 0x14) + lbl_803E0150;
        cfg.f08 = 0xc8;
        cfg.f44 = 0x80100;
        cfg.f42 = 0x33;
        cfg.f60 = 0xb4;
        cfg.f48 = 0x8100800;
        break;
    case 0x3f0:
        cfg.f30 = (f32)(s32)randomGetRange(-0x3e8, 0x3e8) / lbl_803E0128;
        cfg.f38 = (f32)(s32)randomGetRange(-0x3e8, 0x3e8) / lbl_803E0128;
        cfg.f28 = lbl_803E0158 * (f32)(s32)randomGetRange(0x1e, 0x46);
        cfg.f3c = lbl_803E0154 * (f32)(s32)randomGetRange(0, 0x14) + lbl_803E015C;
        cfg.f08 = 0xfa;
        cfg.f44 = 0x80100;
        cfg.f42 = 0x33;
        cfg.f48 = 0x8000800;
        cfg.f60 = 0xb4;
        break;
    case 0x3f1:
        cfg.f30 = lbl_803E0110;
        cfg.f34 = lbl_803E0110;
        cfg.f38 = lbl_803E0110;
        cfg.f44 = 0x80800;
        cfg.f42 = 0x76;
        cfg.f60 = 0xd2;
        cfg.f3c = lbl_803E0160;
        cfg.f08 = 0x64;
        break;
    case 0x3f2:
        if (param_6 == 0) return 0;
        if (param_3 == 0) {
            lbl_8039C428.fc = lbl_803E0110;
            lbl_8039C428.f10 = lbl_803E0110;
            lbl_8039C428.f14 = lbl_803E0110;
            lbl_8039C428.f8 = lbl_803E011C;
            lbl_8039C428.x = 0;
            lbl_8039C428.y = 0;
            lbl_8039C428.z = 0;
            param_3 = (s16 *)&lbl_8039C428;
        }
        if (param_3 != 0) {
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f34 = *(f32 *)(param_3 + 8);
            cfg.f38 = *(f32 *)(param_3 + 10);
        }
        if (param_6 != 0) {
            cfg.f24 = param_6[0];
            cfg.f28 = lbl_803E0164 * (f32)(s32)randomGetRange(0, 0x14);
            cfg.f2c = param_6[1];
        }
        cfg.f3c = lbl_803E0168 *
                  (lbl_803E0170 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803E016C);
        cfg.f08 = randomGetRange(0xbe, 0xfa);
        cfg.f60 = 0xff;
        cfg.f44 = 0x81088000;
        cfg.f42 = 0x23c;
        break;
    case 0x3f3:
        cfg.f30 = (f32)(s32)randomGetRange(-0x32, 0x32) / lbl_803E0128;
        cfg.f34 = (f32)(s32)randomGetRange(-0x32, 0x32) / lbl_803E0128;
        cfg.f38 = (f32)(s32)randomGetRange(-0x32, 0x32) / lbl_803E0128;
        cfg.f24 = lbl_803E0118 * (f32)(s32)randomGetRange(0x1e, 0x3c);
        if (randomGetRange(0, 1) != 0) cfg.f24 = -cfg.f24;
        cfg.f28 = lbl_803E0118 * (f32)(s32)randomGetRange(0x1e, 0x3c);
        if (randomGetRange(0, 1) != 0) cfg.f28 = -cfg.f28;
        cfg.f2c = lbl_803E0118 * (f32)(s32)randomGetRange(0x1e, 0x3c);
        if (randomGetRange(0, 1) != 0) cfg.f2c = -cfg.f2c;
        cfg.f3c = lbl_803E0154 * (f32)(s32)randomGetRange(0, 0xa) + lbl_803E012C;
        cfg.f08 = 0x46;
        cfg.f44 = 0x80208;
        cfg.f42 = 0x76;
        cfg.f60 = 0xb4;
        cfg.f48 = 0x100000;
        break;
    case 0x3f4:
    case 0x3f5:
    case 0x3f6:
        if (param_3 != 0) {
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f34 = *(f32 *)(param_3 + 8);
            cfg.f38 = *(f32 *)(param_3 + 10);
            cfg.f30 = cfg.f30 - *(f32 *)((char *)cfg.f00 + 0x18);
            cfg.f34 = cfg.f34 - *(f32 *)((char *)cfg.f00 + 0x1c);
            cfg.f38 = cfg.f38 - *(f32 *)((char *)cfg.f00 + 0x20);
        }
        if (randomGetRange(0, 0x28) == 0) cfg.f3c = lbl_803E0130;
        else cfg.f3c = lbl_803E015C;
        cfg.f08 = 0x14;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80210;
        switch (param_2) {
        case 0x3f4:
            cfg.f42 = 0x156;
            break;
        case 0x3f5:
            cfg.f42 = 0x157;
            break;
        case 0x3f6:
            cfg.f42 = 0xc0e;
            break;
        default:
            cfg.f42 = 0x156;
            break;
        }
        break;
    case 0x3f7:
    case 0x3f8:
    case 0x3f9:
        if (param_3 != 0) {
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f34 = *(f32 *)(param_3 + 8);
            cfg.f38 = *(f32 *)(param_3 + 10);
            cfg.f30 = cfg.f30 - *(f32 *)((char *)cfg.f00 + 0x18);
            cfg.f34 = cfg.f34 - *(f32 *)((char *)cfg.f00 + 0x1c);
            cfg.f38 = cfg.f38 - *(f32 *)((char *)cfg.f00 + 0x20);
            cfg.f2c = lbl_803E0174;
        }
        cfg.f3c = lbl_803E015C;
        cfg.f08 = 0x64;
        cfg.f60 = 0xff;
        cfg.f44 = 0x480210;
        cfg.f48 = 0x100000;
        switch (param_2) {
        case 0x3f7:
            cfg.f42 = 0x4fb;
            break;
        case 0x3f8:
            cfg.f42 = 0x4fc;
            break;
        case 0x3f9:
            cfg.f42 = 0x4fd;
            break;
        default:
            cfg.f42 = 0x4fb;
            break;
        }
        break;
    case 0x3fa:
        if (param_3 != 0) {
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f34 = *(f32 *)(param_3 + 8);
            cfg.f38 = *(f32 *)(param_3 + 10);
            cfg.f30 = cfg.f30 - *(f32 *)((char *)cfg.f00 + 0x18);
            cfg.f34 = cfg.f34 - *(f32 *)((char *)cfg.f00 + 0x1c);
            cfg.f38 = cfg.f38 - *(f32 *)((char *)cfg.f00 + 0x20);
            cfg.f2c = lbl_803E0134;
        }
        cfg.f3c = lbl_803E015C;
        cfg.f08 = 0x64;
        cfg.f60 = 0xff;
        cfg.f44 = 0x480210;
        cfg.f48 = 0x100000;
        cfg.f42 = 0x4fb;
        break;
    case 0x3fb:
        if (param_3 != 0) {
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f34 = *(f32 *)(param_3 + 8);
            cfg.f38 = *(f32 *)(param_3 + 10);
            cfg.f30 = cfg.f30 - *(f32 *)((char *)cfg.f00 + 0x18);
            cfg.f34 = cfg.f34 - *(f32 *)((char *)cfg.f00 + 0x1c);
            cfg.f38 = cfg.f38 - *(f32 *)((char *)cfg.f00 + 0x20);
            cfg.f3c = *(f32 *)(param_3 + 4);
        }
        cfg.f08 = 5;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80800;
        cfg.f48 = 0x1000000;
        cfg.f42 = 0x5ea;
        break;
    case 0x3fc:
        if (param_3 != 0) {
            cfg.f30 = *(f32 *)(param_3 + 6);
            cfg.f34 = *(f32 *)(param_3 + 8);
            cfg.f38 = *(f32 *)(param_3 + 10);
            cfg.f30 = cfg.f30 - *(f32 *)((char *)cfg.f00 + 0x18);
            cfg.f34 = cfg.f34 - *(f32 *)((char *)cfg.f00 + 0x1c);
            cfg.f38 = cfg.f38 - *(f32 *)((char *)cfg.f00 + 0x20);
            cfg.f3c = *(f32 *)(param_3 + 4);
        }
        cfg.f08 = 5;
        cfg.f60 = 0xff;
        cfg.f44 = 0x80800;
        cfg.f48 = 0x1000000;
        cfg.f42 = 0x5eb;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 = cfg.f44 ^ 2;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*(int (**)())(*gExpgfxInterface + 8))(&cfg, -1, param_2, 0);
    return uVar1;
}

int Effect18_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                    u8 param_5, void *param_6)
{
    int uVar1;
    f32 thr;
    PartFxSpawn cfg;

    lbl_803DB860 = lbl_803DB860 + lbl_803E0220;
    if (lbl_803DB860 > lbl_803E0228) lbl_803DB860 = lbl_803E0224;
    lbl_803DB864 = lbl_803DB864 + lbl_803E022C;
    if (lbl_803DB864 > lbl_803E0228) lbl_803DB864 = lbl_803E0230;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = *(f32 *)(param_3 + 6);
        cfg.f1c = *(f32 *)(param_3 + 8);
        cfg.f20 = *(f32 *)(param_3 + 10);
        cfg.f14 = *(f32 *)(param_3 + 4);
        cfg.f10 = param_3[2];
        cfg.f0e = param_3[1];
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f00 = param_1;
    cfg.f30 = lbl_803E0234;
    cfg.f34 = lbl_803E0234;
    cfg.f38 = lbl_803E0234;
    cfg.f24 = lbl_803E0234;
    cfg.f28 = lbl_803E0234;
    cfg.f2c = lbl_803E0234;
    cfg.f3c = lbl_803E0234;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    switch (param_2) {
    case 0x708:
        cfg.f24 = lbl_803E0238 * (f32)(s32)randomGetRange(0xa, 0x19);
        cfg.f3c = lbl_803E0224;
        cfg.f08 = randomGetRange(0x15e, 0x190);
        cfg.f44 = 0xa100100;
        cfg.f48 = 0x1000000;
        cfg.f42 = 0x62;
        break;
    case 0x709:
        cfg.f28 = lbl_803E023C * (f32)(s32)randomGetRange(0xa, 0x14);
        if (randomGetRange(0, 1) != 0) cfg.f28 = -cfg.f28;
        cfg.f3c = lbl_803E0220;
        cfg.f08 = 0x78;
        cfg.f60 = (u8)randomGetRange(0x7f, 0xff);
        cfg.f44 = 0x80480000;
        cfg.f48 = 0x440000;
        cfg.f42 = (s16)randomGetRange(0x525, 0x528);
        break;
    case 0x70a:
        cfg.f24 = lbl_803E0240 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803E0240 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f2c = lbl_803E0240 * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803E0244;
        cfg.f08 = 0x32;
        cfg.f44 = 0x480100;
        cfg.f42 = (s16)randomGetRange(0x525, 0x528);
        break;
    case 0x70b:
        cfg.f08 = 0x64;
        cfg.f3c = lbl_803E0248;
        cfg.f44 = 0x180200;
        cfg.f42 = 0x208;
        cfg.f48 = 0x5000000;
        break;
    case 0x70c:
        cfg.f08 = randomGetRange(0x19, 0x4b);
        cfg.f24 = lbl_803E023C * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803E024C * (f32)(s32)cfg.f08;
        cfg.f2c = lbl_803E023C * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f3c = lbl_803E0250 * (f32)(s32)randomGetRange(0x32, 0x64);
        cfg.f44 = 0x1082000;
        cfg.f42 = (s16)randomGetRange(0x208, 0x20a);
        cfg.f48 = 0x1400000;
        break;
    case 0x70f:
        cfg.f08 = randomGetRange(0xf, 0x2d);
        cfg.f30 = (f32)(s32)randomGetRange(-5, 5);
        cfg.f38 = (f32)(s32)randomGetRange(-5, 5);
        cfg.f24 = lbl_803E023C * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f28 = lbl_803E024C * (f32)(s32)cfg.f08;
        cfg.f2c = lbl_803E023C * (f32)(s32)randomGetRange(-0x28, 0x28);
        cfg.f3c = lbl_803E0254 * (f32)(s32)randomGetRange(0x32, 0x46);
        cfg.f60 = 0xa0;
        cfg.f44 = 0x1082000;
        cfg.f48 = 0x5400000;
        cfg.f42 = (s16)randomGetRange(0x208, 0x20a);
        break;
    case 0x710:
        if (param_6 != 0) thr = *(f32 *)param_6;
        else thr = lbl_803E0228;
        cfg.f08 = randomGetRange(0xf, 0x4b);
        cfg.f34 = lbl_803E0258 * thr;
        cfg.f38 = lbl_803E025C * thr;
        cfg.f24 = lbl_803E023C * (f32)(s32)randomGetRange(-0x1e, 0x1e);
        cfg.f28 = lbl_803E024C * (f32)(s32)cfg.f08;
        cfg.f2c = lbl_803E0260 * (f32)(s32)randomGetRange(0x14, 0x46);
        cfg.f3c = lbl_803E0264 * (f32)(s32)randomGetRange(0x28, 0x3c);
        cfg.f60 = (u8)randomGetRange(0x3c, 0xa0);
        cfg.f44 = 0x81080200;
        cfg.f48 = 0x4000800;
        cfg.f42 = 0xc0f;
        break;
    case 0x711:
        if (param_6 != 0) thr = *(f32 *)param_6;
        else thr = lbl_803E0228;
        cfg.f08 = randomGetRange(0x23, 0x4b);
        cfg.f34 = lbl_803E0268 * thr;
        cfg.f38 = lbl_803E025C * thr;
        cfg.f24 = lbl_803E023C * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f28 = lbl_803E026C * (f32)(s32)cfg.f08;
        cfg.f2c = lbl_803E0260 * (f32)(s32)randomGetRange(0x14, 0x3c);
        cfg.f3c = lbl_803E0264 * (f32)(s32)randomGetRange(0x28, 0x3c);
        cfg.f60 = (u8)randomGetRange(0x64, 0xc8);
        cfg.f44 = 0x81080200;
        cfg.f48 = 0x4000800;
        cfg.f42 = 0xc0f;
        break;
    case 0x712:
        cfg.f08 = randomGetRange(0x32, 0x64);
        cfg.f24 = lbl_803E023C * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803E0270 * (f32)(s32)cfg.f08;
        cfg.f2c = lbl_803E023C * (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f3c = lbl_803E0274;
        if (randomGetRange(0, 2) != 0) cfg.f44 = 0xa100008;
        else cfg.f44 = 0x180008;
        cfg.f48 = 0x1400000;
        cfg.f42 = 0x5f;
        break;
    case 0x713:
        break;
    case 0x714:
        cfg.f60 = (u8)randomGetRange(0x1e, 0x28);
        if (param_6 != 0) {
            cfg.f60 = (u8)(s32)((f32)(u32)cfg.f60 *
                      ((f32)(s32)*(int *)param_6 / lbl_803E0278));
        }
        cfg.f34 = lbl_803E027C * (f32)(s32)randomGetRange(0x12, 0x14);
        cfg.f3c = lbl_803E0280 * (f32)(s32)randomGetRange(0x28, 0x3c);
        cfg.f08 = randomGetRange(8, 0x14);
        cfg.f44 = 0x80204;
        cfg.f48 = 0x4002800;
        cfg.f42 = 0xc0f;
        break;
    case 0x715:
        if (param_6 != 0) {
            cfg.f24 = lbl_803E0284 * (f32)(s32)randomGetRange(-0x19, 0x19);
            cfg.f28 = lbl_803E0284 * (f32)(s32)randomGetRange(5, 0x32);
            cfg.f2c = lbl_803E0284 * (f32)(s32)randomGetRange(-0x19, 0x19);
            cfg.f3c = lbl_803E0288;
            cfg.f08 = randomGetRange(0x28, 0x78);
            cfg.f44 = 0x80480000;
            cfg.f48 = 0x400800;
        } else {
            cfg.f3c = lbl_803E028C * (f32)(s32)randomGetRange(0x32, 0x64);
            cfg.f08 = 0x78;
            cfg.f44 = 0x80580200;
            cfg.f48 = 0x800;
        }
        cfg.f60 = 0xff;
        cfg.f42 = 0xc0f;
        break;
    case 0x716:
        cfg.f30 = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f34 = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f38 = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f28 = lbl_803E0238 * (f32)(s32)randomGetRange(0x5a, 0x64);
        cfg.f61 = 0xf;
        cfg.f3c = lbl_803E0220 * (f32)(s32)randomGetRange(0x5a, 0x64);
        cfg.f44 = 0x800c0100;
        cfg.f48 = 0x4000800;
        cfg.f60 = (u8)randomGetRange(0x96, 0xc8);
        cfg.f08 = randomGetRange(0x32, 0x46);
        cfg.f42 = 0x185;
        break;
    case 0x717:
        if (param_6 != 0) thr = *(f32 *)param_6;
        else thr = lbl_803E0228;
        cfg.f30 = thr * (lbl_803E0224 * (f32)(s32)randomGetRange(-0x96, 0x96));
        cfg.f34 = thr * (lbl_803E0224 * (f32)(s32)randomGetRange(0x64, 0x12c));
        cfg.f38 = thr * (lbl_803E0224 * (f32)(s32)randomGetRange(-0x96, -0x32));
        cfg.f3c = lbl_803E0244;
        cfg.f08 = randomGetRange(0x32, 0x96);
        cfg.f44 = 0x80480100;
        cfg.f42 = (s16)randomGetRange(0x527, 0x528);
        break;
    case 0x718: {
        f32 v = lbl_803E027C * (f32)(s32)randomGetRange(8, 0xa);
        cfg.f28 = v;
        if (param_6 != 0) {
            cfg.f28 = v * (lbl_803E0228 + *(f32 *)param_6 / lbl_803E0290);
        }
        cfg.f3c = lbl_803E0240 * (f32)(s32)randomGetRange(6, 0xc);
        cfg.f08 = randomGetRange(0x3c, 0x64);
        cfg.f44 = 0x80180000;
        cfg.f48 = 0x5440800;
        cfg.f42 = 0xc0b;
        cfg.f60 = 0x40;
        break;
    }
    case 0x71a:
        cfg.f38 = lbl_803E0294;
        cfg.f3c = lbl_803E0298 * (f32)(s32)randomGetRange(0x4b, 0x64);
        cfg.f08 = 1;
        cfg.f44 = 0x80010;
        cfg.f48 = 0x800;
        cfg.f42 = 0xc7e;
        cfg.f60 = 0x7f;
        break;
    case 0x71b:
        cfg.f3c = lbl_803E029C;
        cfg.f08 = 0x64;
        cfg.f44 = 0x180000;
        cfg.f48 = 0x400800;
        cfg.f42 = 0x73;
        cfg.f60 = 0xff;
        break;
    case 0x71c:
        cfg.f08 = randomGetRange(0x28, 0x78);
        cfg.f24 = lbl_803E027C * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f28 = lbl_803E02A0 * (f32)(s32)cfg.f08;
        cfg.f2c = lbl_803E027C * (f32)(s32)randomGetRange(-0x32, 0x32);
        cfg.f3c = lbl_803E0284;
        cfg.f44 = 0x3000000;
        cfg.f48 = 0x600820;
        cfg.f42 = 0x20d;
        cfg.f60 = 0xff;
        cfg.f58 = 0xffff;
        cfg.f5a = 0xffff;
        cfg.f5c = 0xffff;
        cfg.f4c = 0xffff;
        cfg.f54 = 0;
        cfg.f50 = 0;
        break;
    case 0x71d:
        cfg.f30 = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f34 = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f38 = (f32)(s32)randomGetRange(-0x14, 0x14);
        cfg.f61 = 0xf;
        cfg.f3c = lbl_803E0220 * (f32)(s32)randomGetRange(0x78, 0xc8);
        cfg.f44 = 0x80180100;
        cfg.f48 = 0x4000800;
        cfg.f60 = (u8)randomGetRange(0x32, 0x64);
        cfg.f08 = randomGetRange(0x64, 0x8c);
        cfg.f42 = 0x185;
        break;
    case 0x71e:
        cfg.f30 = (f32)(s32)randomGetRange(-0x23, 0x23);
        cfg.f34 = (f32)(s32)randomGetRange(0, 0x1e);
        cfg.f38 = (f32)(s32)randomGetRange(-0x23, 0x23);
        cfg.f28 = lbl_803E027C * (f32)(s32)randomGetRange(8, 0xa);
        cfg.f3c = lbl_803E0240 * (f32)(s32)randomGetRange(6, 0xc);
        cfg.f08 = randomGetRange(0x64, 0x96);
        cfg.f44 = 0x80180000;
        cfg.f48 = 0x1440000;
        cfg.f42 = 0x564;
        cfg.f60 = 0x7f;
        break;
    case 0x71f:
        cfg.f28 = lbl_803E027C * (f32)(s32)randomGetRange(8, 0xa);
        cfg.f3c = lbl_803E0288 * (f32)(s32)randomGetRange(6, 0xc);
        cfg.f08 = randomGetRange(0x3c, 0x50);
        cfg.f44 = 0x80180000;
        cfg.f48 = 0x5440800;
        cfg.f42 = 0x564;
        cfg.f60 = 0x40;
        break;
    case 0x720:
        cfg.f28 = lbl_803E02A4 * (f32)(s32)randomGetRange(8, 0xa);
        cfg.f3c = lbl_803E0288 * (f32)(s32)randomGetRange(6, 0xc);
        cfg.f08 = randomGetRange(0x3c, 0x50);
        cfg.f44 = 0x80180200;
        cfg.f48 = 0x5000800;
        cfg.f42 = 0x564;
        cfg.f60 = 0x40;
        break;
    case 0x721:
        cfg.f3c = lbl_803E02A8 * (f32)(s32)randomGetRange(6, 0xc);
        cfg.f08 = randomGetRange(0xfa, 0x15e);
        cfg.f44 = 0x80480008;
        cfg.f48 = 0x400000;
        cfg.f42 = 0xc0d;
        break;
    case 0x722:
        cfg.f34 = lbl_803E02AC;
        cfg.f08 = randomGetRange(0x1e, 0x3c);
        cfg.f24 = lbl_803E02A4 * (f32)(s32)randomGetRange(-0x3c, 0x3c);
        cfg.f28 = lbl_803E02B0 * sqrtf(cfg.f24 * cfg.f24 + cfg.f2c * cfg.f2c);
        cfg.f2c = lbl_803E02A4 * (f32)(s32)randomGetRange(-0x3c, 0x3c);
        cfg.f3c = lbl_803E02A4;
        cfg.f44 = 0x80000;
        cfg.f48 = 0x5400800;
        cfg.f42 = 0x564;
        cfg.f60 = (u8)(randomGetRange(0x46, 0xbe) >> 1);
        break;
    case 0x723: {
        int base, span;
        cfg.f08 = randomGetRange(0x23, 0x2d);
        if (param_6 != 0) base = *(int *)param_6 + 5;
        else base = 5;
        cfg.f28 = (f32)(s32)base / lbl_803E02B4 *
                  (lbl_803E02B8 * (f32)(s32)randomGetRange(8, 0xc));
        span = 0x41 - base;
        cfg.f24 = lbl_803E024C * (f32)(s32)randomGetRange(-span, span);
        cfg.f2c = lbl_803E024C * (f32)(s32)randomGetRange(-span, span);
        cfg.f3c = lbl_803E0240 * (f32)(s32)randomGetRange(6, 0xc);
        cfg.f60 = (u8)(randomGetRange(0x40, 0x7f) >> 1);
        cfg.f44 = 0x80080000;
        cfg.f48 = 0x5400800;
        cfg.f42 = 0x564;
        break;
    }
    case 0x724:
        cfg.f28 = lbl_803E027C * (f32)(s32)randomGetRange(8, 0xa);
        cfg.f3c = lbl_803E0240 * (f32)(s32)randomGetRange(6, 0xc);
        cfg.f08 = randomGetRange(0x1e, 0x3c);
        cfg.f44 = 0x80080000;
        cfg.f48 = 0x5440800;
        cfg.f42 = 0xc0b;
        cfg.f60 = 0x40;
        break;
    default:
        return -1;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 = cfg.f44 ^ 2;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) != 0) {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        } else {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        }
    }
    uVar1 = (*(int (**)())(*gExpgfxInterface + 8))(&cfg, -1, param_2, 0);
    return uVar1;
}

void Effect19_func05(void)
{
    f32 sum;
    sum = lbl_803DB878 + lbl_803E02D8 * timeDelta;
    lbl_803DB878 = sum;
    if (sum > lbl_803E02E0) lbl_803DB878 = lbl_803E02DC;
    sum = lbl_803DB87C + lbl_803E02D8 * timeDelta;
    lbl_803DB87C = sum;
    if (sum > lbl_803E02E0) lbl_803DB87C = lbl_803E02E8;
    lbl_803DD3F0 = lbl_803DD3F0 + (s32)framesThisStep * 0x64;
    if (lbl_803DD3F0 > 0x7fff) lbl_803DD3F0 = 0;
    lbl_803DD3FC = fn_80293E80(lbl_803E0308 * (f32)(s16)lbl_803DD3F0 / lbl_803E030C);
    lbl_803DD3F4 = lbl_803DD3F4 + (s32)framesThisStep * 0x32;
    if (lbl_803DD3F4 > 0x7fff) lbl_803DD3F4 = 0;
    lbl_803DD3F8 = fn_80293E80(lbl_803E0308 * (f32)(s16)lbl_803DD3F4 / lbl_803E030C);
}

/* ---- Effect20_func04 (FUN_800cd430, v1.0) ---- */
extern f32 lbl_803DB880;
extern f32 lbl_803DB884;
extern f32 lbl_803E031C;
extern f32 lbl_803E0324;
extern f32 lbl_803E0328;
extern f32 lbl_803E032C;
extern f32 lbl_803E0330;
extern f32 lbl_803E0334;
extern f32 lbl_803E0338;
extern f32 lbl_803E033C;
extern f32 lbl_803E0340;
extern f32 lbl_803E034C;
extern f32 lbl_803E0350;
extern f32 lbl_803E0354;
extern f32 lbl_803E0358;
extern f32 lbl_803E035C;
extern f32 lbl_803E0360;
extern f32 lbl_803E0364;
extern f32 lbl_803E0368;
extern f32 lbl_803E036C;
extern f32 lbl_803E0370;
extern f32 lbl_803E0374;
extern f32 lbl_803E0378;
extern f32 lbl_803E037C;
extern f32 lbl_803E0380;
extern f32 lbl_803E0384;
extern f32 lbl_803E0388;
extern f32 lbl_803E038C;
extern f32 lbl_803E0390;
extern f32 lbl_803E0394;
extern f32 lbl_803E0398;
extern f32 lbl_803E039C;
extern f32 lbl_803E03A0;
extern f32 lbl_803E03A4;
extern f32 lbl_803E03A8;
extern f32 lbl_803E03AC;
extern f32 lbl_803E03B0;
extern f32 lbl_803E03B4;
extern f32 lbl_803E03B8;
extern f32 lbl_803E03BC;
extern f32 lbl_803E03C0;
extern f32 lbl_803E03C4;
extern f32 lbl_803E03C8;
extern f32 lbl_803E03CC;
extern f32 lbl_803E03D0;
extern f32 lbl_803E03D4;
extern f32 lbl_803E03D8;
extern f32 lbl_803E03DC;
extern f32 lbl_803E03E0;
extern f32 lbl_803E03E4;
extern f32 lbl_803E03E8;
extern f32 lbl_803E03EC;
extern f32 lbl_803E03F0;
extern f32 lbl_803E03F4;
extern f32 lbl_803E03F8;
extern f32 lbl_803E03FC;
extern f32 lbl_803E0400;
extern f32 lbl_803E0404;
extern f32 lbl_803E0408;
extern f32 lbl_803E040C;
extern f32 lbl_803E0410;
extern f32 lbl_803E0414;
extern f32 lbl_803E0418;
extern f32 lbl_803E041C;
extern f32 lbl_803E0420;
extern f32 lbl_803E0424;
extern f32 lbl_803E0428;
extern f32 lbl_803E042C;
extern f32 lbl_803E0430;
extern f32 lbl_803E0434;
extern f32 lbl_803E0438;
extern f32 lbl_803E043C;
extern f32 lbl_803E0440;
extern f32 lbl_803E0444;
extern f32 lbl_803E0448;
extern f32 lbl_803E044C;
extern f32 lbl_803E0450;
extern f32 lbl_803E0454;
extern f32 lbl_803E0458;
extern f32 lbl_803E045C;
extern f32 lbl_803E0460;
extern f32 lbl_803E0468;
extern f32 lbl_803E046C;
extern f32 lbl_803E0470;
extern f32 lbl_803E0474;
extern f32 lbl_803E0478;
extern f32 lbl_803E047C;
extern f32 lbl_803E0480;
extern f32 lbl_803E0484;
extern f32 lbl_803E0488;
extern f32 lbl_803E048C;
extern f32 lbl_803E0490;
extern f32 lbl_803E0494;
extern f32 lbl_803E0498;
extern f32 lbl_803E049C;
extern f32 lbl_803E04A0;
extern f32 lbl_803E04A4;
extern f32 lbl_803E04A8;
extern f32 lbl_803E04AC;
extern f32 lbl_803E04B0;
extern f32 lbl_803E04B4;
extern f32 lbl_803E04B8;
extern f32 lbl_803E04BC;
extern f32 lbl_803E04C0;
extern f32 lbl_803E04C4;
extern f32 lbl_803E04C8;
extern u8 framesThisStep;
extern f32 sin(f32 x);
extern void mathFn_80021ac8(void *params, f32 *vec);
extern int randFn_80080100(int range);

int Effect20_func04(void *param_1, int param_2, s16 *param_3, u32 param_4,
                    u8 param_5, f32 *param_6)
{
    int ret;
    int iVar1;
    s16 sVar3;
    f32 fVar7;
    f32 fVar8;
    f32 fVar9;
    PartFxSpawn cfg;

    ret = 0;
    lbl_803DB880 = lbl_803DB880 + lbl_803E0310;
    if (lbl_803DB880 > lbl_803E0318) lbl_803DB880 = lbl_803E0314;
    lbl_803DB884 = lbl_803DB884 + lbl_803E031C;
    if (lbl_803DB884 > lbl_803E0318) lbl_803DB884 = lbl_803E0320;
    if (param_1 == 0) return -1;
    if ((param_4 & 0x200000) != 0) {
        if (param_3 == 0) return -1;
        cfg.f18 = *(f32 *)(param_3 + 6);
        cfg.f1c = *(f32 *)(param_3 + 8);
        cfg.f20 = *(f32 *)(param_3 + 10);
        cfg.f14 = *(f32 *)(param_3 + 4);
        cfg.f10 = param_3[2];
        cfg.f0e = param_3[1];
        cfg.f0c = *param_3;
        cfg.f62 = param_5;
    }
    cfg.f44 = 0;
    cfg.f48 = 0;
    cfg.f5e = (u8)param_2;
    cfg.f30 = lbl_803E0324;
    cfg.f34 = lbl_803E0324;
    cfg.f38 = lbl_803E0324;
    cfg.f24 = lbl_803E0324;
    cfg.f28 = lbl_803E0324;
    cfg.f2c = lbl_803E0324;
    cfg.f3c = lbl_803E0324;
    cfg.f08 = 0;
    cfg.f04 = -1;
    cfg.f60 = 0xff;
    cfg.f61 = 0;
    cfg.f42 = 0;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    cfg.f00 = param_1;
    switch (param_2) {
  case 0x79e:
    if (param_6 != NULL) {
      cfg.f24 = lbl_803E0320 * *param_6 + lbl_803E0310 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = lbl_803E0320 * param_6[1] + lbl_803E0310 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = lbl_803E0320 * param_6[2] + lbl_803E0310 * (f32)(s32)randomGetRange(0xffffff9c,100);
    }
    cfg.f3c = lbl_803E0328 * (f32)(s32)randomGetRange(0x32,100);
    cfg.f08 = 100;
    cfg.f44 = 0x80480200;
    cfg.f48 = 0x8000800;
    cfg.f60 = 0xff;
    cfg.f42 = 0x84;
    break;
  case 0x79f:
    cfg.f3c = lbl_803E0318;
    if (param_6 != NULL) {
      cfg.f3c = *param_6;
    }
    cfg.f3c = cfg.f3c * lbl_803E0310 * (f32)(s32)randomGetRange(0x32,100);
    cfg.f08 = 0x1e;
    cfg.f44 = 0x180010;
    cfg.f48 = 0x8000;
    cfg.f60 = 0xff;
    cfg.f42 = 0xc80;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    break;
  case 0x7a0:
    if (param_3 == NULL) {
      cfg.f24 = lbl_803E0330 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = lbl_803E0330 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = lbl_803E0330 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f08 = randomGetRange(0x14,0x28);
      cfg.f44 = 0x80010;
      cfg.f48 = 0x8480800;
      cfg.f3c = lbl_803E032C * (f32)(s32)randomGetRange(0x32,100);
    }
    else {
      cfg.f08 = (int)param_3[3];
      cfg.f44 = 0x80080210;
      cfg.f48 = 0x8000800;
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E032C * (f32)(s32)randomGetRange(0x32,100);
    }
    cfg.f60 = 0xff;
    cfg.f42 = 0xdb;
    break;
  case 0x7a1:
    if (param_3 == NULL) {
      cfg.f24 = lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f08 = randomGetRange(0x14,0x28);
      cfg.f44 = 0x80010;
      cfg.f48 = 0x8480800;
      cfg.f3c = lbl_803E032C * (f32)(s32)randomGetRange(0x32,100);
    }
    else {
      cfg.f08 = (int)param_3[3];
      cfg.f44 = 0x80080210;
      cfg.f48 = 0x8000800;
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E032C * (f32)(s32)randomGetRange(0x32,100);
    }
    cfg.f60 = 0xff;
    cfg.f42 = 0x157;
    break;
  case 0x7a2:
    if (param_6 != NULL) {
      cfg.f24 = lbl_803E0338 * *param_6 + lbl_803E0310 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = lbl_803E0338 * param_6[1] + lbl_803E0310 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = lbl_803E0338 * param_6[2] + lbl_803E0310 * (f32)(s32)randomGetRange(0xffffff9c,100);
    }
    cfg.f08 = randomGetRange(10,0x1e);
    cfg.f44 = 0x480000;
    cfg.f48 = 0x400800;
    cfg.f3c = lbl_803E033C * (f32)(s32)randomGetRange(0x32,100);
    cfg.f60 = 0xff;
    cfg.f42 = 0xde;
    break;
  case 0x7a3:
    fVar8 = (lbl_803E0344 * (f32)(s32)randomGetRange(0xffff8001,0x7fff)) / lbl_803E0348;
    fVar7 = sin(fVar8);
    cfg.f24 = (lbl_803E0340 * (f32)(s32)randomGetRange(100,0x96)) * fVar7;
    fVar7 = fn_80293E80(fVar8);
    cfg.f28 = (lbl_803E0340 * (f32)(s32)randomGetRange(100,0x96)) * fVar7;
    cfg.f2c = lbl_803E0324;
    cfg.f08 = randomGetRange(0x14,0x1e);
    cfg.f44 = 0x480000;
    cfg.f48 = 0x480800;
    cfg.f3c = lbl_803E033C * (f32)(s32)randomGetRange(0x32,100);
    cfg.f60 = 0xff;
    cfg.f42 = 0xde;
    break;
  case 0x7a4:
    if (param_6 != NULL) {
      cfg.f24 = lbl_803E0338 * *param_6 + lbl_803E0310 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = lbl_803E0338 * param_6[1] + lbl_803E0310 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = lbl_803E0338 * param_6[2] + lbl_803E0310 * (f32)(s32)randomGetRange(0xffffff9c,100);
    }
    cfg.f08 = randomGetRange(10,0x1e);
    cfg.f44 = 0x480000;
    cfg.f48 = 0x400800;
    cfg.f3c = lbl_803E033C * (f32)(s32)randomGetRange(0x32,100);
    cfg.f60 = 0xff;
    cfg.f42 = 0xc22;
    break;
  case 0x7a5:
    fVar8 = (lbl_803E0344 * (f32)(s32)randomGetRange(0xffff8001,0x7fff)) / lbl_803E0348;
    fVar7 = sin(fVar8);
    cfg.f24 = (lbl_803E0330 * (f32)(s32)randomGetRange(100,0x96)) * fVar7;
    fVar7 = fn_80293E80(fVar8);
    cfg.f28 = (lbl_803E0330 * (f32)(s32)randomGetRange(100,0x96)) * fVar7;
    cfg.f2c = lbl_803E0324;
    cfg.f08 = randomGetRange(0x1e,0x28);
    cfg.f44 = 0x480000;
    cfg.f48 = 0x480800;
    cfg.f3c = lbl_803E033C * (f32)(s32)randomGetRange(0x32,100);
    cfg.f60 = 0xff;
    cfg.f42 = 0xc22;
    break;
  case 0x7a6:
    if (param_3 == NULL) {
      cfg.f24 = lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f08 = randomGetRange(0x14,0x28);
      cfg.f44 = 0x80010;
      cfg.f48 = 0x8480800;
      cfg.f3c = lbl_803E032C * (f32)(s32)randomGetRange(0x32,100);
    }
    else {
      cfg.f08 = (int)param_3[3];
      cfg.f44 = 0x80080210;
      cfg.f48 = 0x8000800;
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E032C * (f32)(s32)randomGetRange(0x32,100);
    }
    cfg.f60 = 0xff;
    cfg.f42 = 0xc7e;
    break;
  case 0x7a7:
    if (param_3 == NULL) {
      cfg.f24 = lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f08 = randomGetRange(0x14,0x28);
      cfg.f44 = 0x80010;
      cfg.f48 = 0x8480800;
      cfg.f3c = lbl_803E032C * (f32)(s32)randomGetRange(0x32,100);
    }
    else {
      cfg.f08 = (int)param_3[3];
      cfg.f44 = 0x80080210;
      cfg.f48 = 0x8000800;
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E032C * (f32)(s32)randomGetRange(0x32,100);
    }
    cfg.f60 = 0xff;
    cfg.f42 = 0xc13;
    break;
  case 0x7a8:
    if (param_3 != NULL) {
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(100,200);
      cfg.f30 = *(f32 *)(param_3 + 4) * lbl_803E0350 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8) * *(f32 *)(param_3 + 4);
      cfg.f38 = *(f32 *)(param_3 + 4) * lbl_803E0350 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 10);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0354 * (f32)(s32)randomGetRange(0x50,100);
      cfg.f08 = randomGetRange(1,0x14);
      cfg.f08 = cfg.f08 + 10;
      cfg.f42 = param_3[3];
      cfg.f60 = 0xff;
      cfg.f44 = (param_4 | 0x80200);
      cfg.f48 = 0x4040800;
    }
    break;
  case 0x7a9:
    if (param_3 != NULL) {
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E0358 * (f32)(s32)randomGetRange(100,200);
      cfg.f30 = *(f32 *)(param_3 + 4) * lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8) * *(f32 *)(param_3 + 4);
      cfg.f38 = *(f32 *)(param_3 + 4) * lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 10);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0354 * (f32)(s32)randomGetRange(0x50,100);
      cfg.f08 = randomGetRange(1,0x14);
      cfg.f08 = cfg.f08 + 10;
      cfg.f42 = param_3[3];
      cfg.f60 = 0xff;
      cfg.f44 = (param_4 | 0x80200);
      cfg.f48 = 0x4040800;
    }
    break;
  case 0x7aa:
    if (param_3 != NULL) {
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E035C * (f32)(s32)randomGetRange(100,200);
      cfg.f30 = *(f32 *)(param_3 + 4) * lbl_803E0314 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8) * *(f32 *)(param_3 + 4);
      cfg.f38 = *(f32 *)(param_3 + 4) * lbl_803E0314 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 10);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0360 * (f32)(s32)randomGetRange(0x50,100);
      cfg.f08 = randomGetRange(1,0x23);
      cfg.f08 = cfg.f08 + 0x19;
      cfg.f42 = param_3[3];
      cfg.f60 = 0xff;
      cfg.f44 = (param_4 | 0x80200);
      cfg.f48 = 0x4040820;
      cfg.f4c = 0xffff;
      cfg.f50 = 0xffff;
      cfg.f54 = randomGetRange(0, 0xffff);
      cfg.f58 = 0xffff;
      cfg.f5a = randomGetRange(0,0x7fff);
      cfg.f5c = (ushort)cfg.f54;
    }
    break;
  case 0x7ab:
    if (param_3 != NULL) {
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E0364 * (f32)(s32)randomGetRange(100,200);
      cfg.f30 = *(f32 *)(param_3 + 4) * lbl_803E0368 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 4) * lbl_803E0368 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 10);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0354 * (f32)(s32)randomGetRange(0x23,100);
      cfg.f08 = randomGetRange(1,0x12);
      cfg.f08 = cfg.f08 + 10;
      cfg.f42 = param_3[3];
      cfg.f60 = 0xff;
      cfg.f44 = (param_4 | 0x80080200);
      cfg.f48 = 0x4010800;
      ret = 1;
    }
    break;
  case 0x7ac:
    if (param_3 != NULL) {
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E0364 * (f32)(s32)randomGetRange(100,200);
      cfg.f30 = *(f32 *)(param_3 + 4) * lbl_803E036C * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8) * *(f32 *)(param_3 + 4);
      cfg.f38 = *(f32 *)(param_3 + 4) * lbl_803E036C * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 10);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0354 * (f32)(s32)randomGetRange(0x50,100);
      cfg.f08 = randomGetRange(1,0x17);
      cfg.f08 = cfg.f08 + 5;
      cfg.f42 = param_3[3];
      cfg.f60 = 0xff;
      cfg.f44 = (param_4 | 0x80080200);
      cfg.f48 = 0x40800;
    }
    break;
  case 0x7ad:
    if (param_3 != NULL) {
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E0370 * (f32)(s32)randomGetRange(100,200);
      cfg.f34 = *(f32 *)(param_3 + 4) * (lbl_803E0374 * (f32)(s32)randomGetRange(0xf,0x14) + *(f32 *)(param_3 + 8));
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0378 * (f32)(s32)randomGetRange(0x50,0x8c);
      cfg.f08 = randomGetRange(0,10);
      cfg.f08 = cfg.f08 + 0x32;
      cfg.f42 = 0xc10;
      cfg.f60 = 0xff;
      cfg.f44 = 0x80100;
      cfg.f48 = 0x4010020;
      cfg.f4c = (uint)param_3[3];
      cfg.f58 = (ushort)((int)cfg.f4c >> 1);
      cfg.f50 = cfg.f4c;
      cfg.f54 = cfg.f4c;
      cfg.f5a = cfg.f58;
      cfg.f5c = cfg.f58;
    }
    break;
  case 0x7ae:
    if (param_3 != NULL) {
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E037C * (f32)(s32)randomGetRange(100,200);
      cfg.f30 = *(f32 *)(param_3 + 4) * lbl_803E0380 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f34 = *(f32 *)(param_3 + 4) * (lbl_803E0374 * (f32)(s32)randomGetRange(0xf,0x14) + *(f32 *)(param_3 + 8));
      cfg.f38 = *(f32 *)(param_3 + 4) * lbl_803E0380 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0384 * (f32)(s32)randomGetRange(0x50,100);
      cfg.f08 = randomGetRange(0,10);
      cfg.f08 = cfg.f08 + 0x32;
      cfg.f42 = 0xc0d;
      cfg.f60 = 0xff;
      cfg.f44 = 0x80480000;
      cfg.f48 = 0x410800;
    }
    break;
  case 0x7af:
    if (param_3 != NULL) {
      cfg.f3c = *(f32 *)(param_3 + 4);
      cfg.f28 = cfg.f3c * lbl_803E0388 * (f32)(s32)randomGetRange(100,200);
      cfg.f34 = (lbl_803E038C + *(f32 *)(param_3 + 8)) * cfg.f3c;
      cfg.f3c = lbl_803E0390 * cfg.f3c;
      cfg.f08 = 5;
      cfg.f42 = 0x5e6;
      cfg.f60 = (char)param_3[3];
      cfg.f44 = 0x80200;
      cfg.f48 = 0x4088000;
      cfg.f58 = 0xffff;
      cfg.f5a = 0xffff;
      cfg.f5c = 0xffff;
      cfg.f4c = 0xffff;
      cfg.f50 = 0xffff;
      cfg.f54 = 0xffff;
    }
    break;
  case 0x7b0:
    if (param_3 != NULL) {
      cfg.f3c = *(f32 *)(param_3 + 4);
      cfg.f28 = cfg.f3c * lbl_803E0388 * (f32)(s32)randomGetRange(100,200);
      cfg.f34 = (lbl_803E038C + *(f32 *)(param_3 + 8)) * cfg.f3c;
      cfg.f3c = lbl_803E0390 * cfg.f3c;
      cfg.f08 = 0xf;
      cfg.f42 = 0x5e6;
      cfg.f60 = (char)param_3[3];
      cfg.f44 = 0x80100;
      cfg.f48 = 0x4088000;
      cfg.f58 = 0xffff;
      cfg.f5a = 0xffff;
      cfg.f5c = 0xffff;
      cfg.f4c = 0xffff;
      cfg.f50 = 0xffff;
      cfg.f54 = 0xffff;
    }
    break;
  case 0x7b1:
    if (param_3 != NULL) {
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E0394 * (f32)(s32)randomGetRange(0xffffffe5,100);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0398 * (f32)(s32)randomGetRange(10,0x14);
      cfg.f08 = randomGetRange(0x23,100);
      cfg.f60 = 0xff;
      cfg.f42 = param_3[3];
      cfg.f44 = 0x80480100;
      cfg.f48 = 0x8010800;
    }
    break;
  case 0x7b2:
    if (param_3 != NULL) {
      cfg.f24 = lbl_803E0390 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = lbl_803E0390 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f34 = *(f32 *)(param_3 + 6);
      cfg.f3c = lbl_803E039C * (f32)(s32)randomGetRange(0x1c,0x20);
      cfg.f08 = (int)param_3[3];
      cfg.f42 = *param_3;
      cfg.f44 = 0x480204;
      cfg.f48 = 0x808;
    }
    break;
  case 0x7b3:
    if (param_3 != NULL) {
      cfg.f3c = lbl_803E03A0 * *(f32 *)(param_3 + 4);
      cfg.f08 = (int)param_3[3];
      cfg.f28 = *(f32 *)(param_3 + 8) * (f32)(s32)randomGetRange(0x154,0x2d5);
      cfg.f34 = *(f32 *)(param_3 + 6);
      cfg.f42 = *param_3;
      cfg.f44 = 0x80114;
      cfg.f48 = 0x4000800;
    }
    break;
  case 0x7b4:
    if (param_3 != NULL) {
      cfg.f24 = lbl_803E0390 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = lbl_803E0390 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f34 = *(f32 *)(param_3 + 6);
      cfg.f3c = lbl_803E039C * (f32)(s32)randomGetRange(0x1c,0x20);
      cfg.f08 = (int)param_3[3];
      cfg.f42 = *param_3;
      cfg.f44 = 0x480004;
      cfg.f48 = 0x480800;
    }
    break;
  case 0x7b5:
    if (param_3 != NULL) {
      if (param_3[3] == 0) {
        cfg.f3c = lbl_803E0330 * *(f32 *)(param_3 + 4);
        cfg.f44 = 0xc1180000;
        cfg.f48 = 0x4400800;
        cfg.f08 = randomGetRange(0x1c,0x22);
        cfg.f08 = cfg.f08 + 10;
      }
      else {
        cfg.f3c = lbl_803E031C * *(f32 *)(param_3 + 4) * (f32)(s32)randomGetRange(6,10);
        cfg.f44 = 0xc1080000;
        cfg.f48 = 0x4400800;
        cfg.f08 = 10;
      }
      cfg.f34 = *(f32 *)(param_3 + 8) * *(f32 *)(param_3 + 4);
      cfg.f2c = lbl_803E0314 * *(f32 *)(param_3 + 4) * lbl_803E03A4 * (f32)(s32)randomGetRange(100,0x96);
      mathFn_80021ac8(param_1,&cfg.f24);
      cfg.f42 = 0xc0a;
      cfg.f48 = cfg.f48 | 0x20;
      cfg.f4c = 0xffff;
      cfg.f50 = 0xffff;
      cfg.f54 = randomGetRange(0, 0xffff);
      cfg.f58 = 0xffff;
      cfg.f5a = randomGetRange(0,0x7fff);
      cfg.f5c = (ushort)cfg.f54;
    }
    break;
  case 0x7b6:
    if (param_3 != NULL) {
      if (param_3[3] == 0) {
        cfg.f3c = lbl_803E0330 * *(f32 *)(param_3 + 4);
        cfg.f44 = 0x81180000;
        cfg.f48 = 0x4400800;
        cfg.f08 = randomGetRange(0x1c,0x22);
        cfg.f08 = cfg.f08 + 10;
      }
      else {
        cfg.f3c = lbl_803E031C * *(f32 *)(param_3 + 4) * (f32)(s32)randomGetRange(6,10);
        cfg.f44 = 0x81080000;
        cfg.f48 = 0x4400800;
        cfg.f08 = 10;
      }
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8) * *(f32 *)(param_3 + 4);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f2c = lbl_803E0314 * *(f32 *)(param_3 + 4) * lbl_803E03A4 * (f32)(s32)randomGetRange(100,0x96);
      mathFn_80021ac8(param_1,&cfg.f24);
      cfg.f42 = 0x5f5;
    }
    break;
  case 0x7b7:
    if (param_3 != NULL) {
      if (param_6 == NULL) {
        cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E03A8 * (f32)(s32)randomGetRange(0x5a,100) ;
      }
      else {
        cfg.f24 = lbl_803E0320 * *param_6 + lbl_803E0310 * (f32)(s32)randomGetRange(0xffffff9c,100) ;
        if (lbl_803E0324 != cfg.f28) {
          cfg.f28 = lbl_803E0320 * param_6[1] + lbl_803E0310 * (f32)(s32)randomGetRange(0xffffff9c,100);
        }
        cfg.f2c = lbl_803E0320 * param_6[2] + lbl_803E0310 * (f32)(s32)randomGetRange(0xffffff9c,100) ;
      }
      cfg.f30 = *(f32 *)(param_3 + 4) * (f32)(s32)randomGetRange(0xffffffec,0x14);
      cfg.f34 = *(f32 *)(param_3 + 4) * (f32)(s32)randomGetRange(0xffffffec,0x14);
      cfg.f38 = *(f32 *)(param_3 + 4) * (f32)(s32)randomGetRange(0xffffffec,0x14);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0310 * (f32)(s32)randomGetRange(0x5a,100);
      cfg.f60 = randomGetRange(0x9b,0xff);
      cfg.f08 = randomGetRange(1,0x14);
      cfg.f08 = param_3[2] + cfg.f08;
      if (param_3[1] == 0) {
        cfg.f44 = 0x80480000;
      }
      else {
        cfg.f44 = 0x80080000;
      }
      if (*param_3 == 0) {
        cfg.f48 = 0x4400000;
      }
      else {
        cfg.f48 = 0x4400800;
      }
      cfg.f42 = param_3[3];
      cfg.f61 = 0xf;
    }
    break;
  case 0x7b8:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
    }
    cfg.f3c = lbl_803E03AC * (f32)(s32)randomGetRange(0x46,0x50);
    cfg.f08 = 5;
    cfg.f42 = 0x2d;
    cfg.f44 = 0x180200;
    cfg.f48 = 0;
    break;
  case 0x7b9:
    if (param_3 != NULL) {
      cfg.f24 = lbl_803E0390 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = lbl_803E0390 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = lbl_803E0390 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f08 = (int)*(short *)((int)param_6 + 6);
      cfg.f42 = *(short *)param_6;
      cfg.f3c = lbl_803E039C * (f32)(s32)randomGetRange(0x1c,0x20);
      cfg.f44 = 0x480200;
      cfg.f48 = 0x808;
    }
    break;
  case 0x7ba:
    if (param_3 != NULL) {
      cfg.f08 = (int)*(short *)((int)param_6 + 6);
      cfg.f42 = *(short *)param_6;
      cfg.f3c = lbl_803E03A0 * param_6[2];
      cfg.f44 = 0x80110;
      cfg.f48 = 0x4000800;
    }
    break;
  case 0x7bb:
    if (param_3 != NULL) {
      if (param_3[3] == 0) {
        cfg.f3c = lbl_803E0330 * *(f32 *)(param_3 + 4);
        cfg.f44 = 0xc0180200;
        cfg.f48 = 0x4010000;
        cfg.f08 = randomGetRange(0x1c,0x22);
        cfg.f08 = cfg.f08 + 10;
        cfg.f60 = randomGetRange((s32)param_3[2],param_3[2] + 10);
      }
      else {
        cfg.f3c = lbl_803E03B0 * *(f32 *)(param_3 + 4) * (f32)(s32)randomGetRange(7,10);
        cfg.f44 = 0xc0080200;
        cfg.f48 = 0x4010000;
        cfg.f08 = 10;
        cfg.f60 = 0x7f;
      }
      cfg.f34 = *(f32 *)(param_3 + 8) * *(f32 *)(param_3 + 4);
      cfg.f2c = lbl_803E03B4 * *(f32 *)(param_3 + 4) * lbl_803E03A8 * (f32)(s32)randomGetRange(100,0x96);
      mathFn_80021ac8(param_1,&cfg.f24);
      cfg.f42 = 0xc10;
    }
    break;
  case 0x7bc:
    if (param_3 != NULL) {
      if (param_3[3] == 0) {
        cfg.f3c = lbl_803E0330 * *(f32 *)(param_3 + 4);
        cfg.f44 = 0xc1180200;
        cfg.f48 = 0x5010000;
        cfg.f08 = randomGetRange(0x1c,0x22);
        cfg.f08 = cfg.f08 + 10;
        cfg.f60 = randomGetRange((s32)param_3[2],param_3[2] + 10);
      }
      else {
        cfg.f3c = lbl_803E03B0 * *(f32 *)(param_3 + 4) * (f32)(s32)randomGetRange(7,10);
        cfg.f44 = 0xc1080200;
        cfg.f48 = 0x5010000;
        cfg.f08 = 10;
        cfg.f60 = 0x7f;
      }
      cfg.f34 = *(f32 *)(param_3 + 8) * *(f32 *)(param_3 + 4);
      cfg.f2c = lbl_803E03B4 * *(f32 *)(param_3 + 4) * lbl_803E03B8 * (f32)(s32)randomGetRange(100,0x96);
      mathFn_80021ac8(param_1,&cfg.f24);
      cfg.f42 = 0xc10;
    }
    break;
  case 0x7bd:
    if (param_3 != NULL) {
      cfg.f3c = lbl_803E0310 * *(f32 *)(param_3 + 4);
      cfg.f44 = 0x83000200;
      cfg.f48 = 0x1200000;
      cfg.f08 = randomGetRange(10,0x18);
      cfg.f60 = 0xff;
      cfg.f34 = *(f32 *)(param_3 + 8) * *(f32 *)(param_3 + 4);
      cfg.f24 = lbl_803E03BC * *(f32 *)(param_3 + 4) * lbl_803E0330 * (f32)(s32)randomGetRange(0xffffff6a,0x96);
      cfg.f28 = lbl_803E03BC * *(f32 *)(param_3 + 4) * lbl_803E0330 * (f32)(s32)randomGetRange(0xffffff6a,0x96);
      cfg.f2c = lbl_803E0314 * *(f32 *)(param_3 + 4) * lbl_803E03C0 * (f32)(s32)randomGetRange(100,0x96);
      mathFn_80021ac8(param_1,&cfg.f24);
      cfg.f42 = 0xc10;
    }
    break;
  case 0x7be:
    if (param_3 != NULL) {
      if (param_6 == NULL) {
        cfg.f2c = *(f32 *)(param_3 + 6) * *(f32 *)(param_3 + 4) * lbl_803E03B8 * (f32)(s32)randomGetRange(100,0x6b) ;
      }
      else {
        cfg.f30 = param_6[3];
        cfg.f34 = param_6[4];
        cfg.f38 = param_6[5];
        if (param_6[2] <= lbl_803E0324) {
          if (param_6[2] >= lbl_803E0324) {
            cfg.f2c = *(f32 *)(param_3 + 6) * *(f32 *)(param_3 + 4) * lbl_803E03B8 * (f32)(s32)randomGetRange(100,0x6b);
          }
          else {
            cfg.f2c = *(f32 *)(param_3 + 6) * *(f32 *)(param_3 + 4) * lbl_803E03C4 * (f32)(s32)randomGetRange(100,0x6b);
          }
        }
        else {
          cfg.f28 = *(f32 *)(param_3 + 6) * *(f32 *)(param_3 + 4) * lbl_803E03C4 * (f32)(s32)randomGetRange(100,0x6b);
        }
      }
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E03C8 * (f32)(s32)randomGetRange(0x1c,0x22);
      cfg.f08 = randomGetRange(0x14,0x1b);
      cfg.f60 = 0xff;
      cfg.f44 = 0x80004;
      cfg.f48 = 0x8002820;
      if (param_3[2] == 0) {
        cfg.f58 = 0x69;
        cfg.f5a = 0x863;
        cfg.f5c = 0x7fff;
        cfg.f4c = 0x7fff;
        cfg.f50 = 0x2d1a;
        cfg.f54 = 0x8000;
      }
      else {
        cfg.f58 = 0xff2d;
        cfg.f5a = 0xa8f;
        cfg.f5c = 0x2c;
        cfg.f4c = 0xf78f;
        cfg.f50 = 0x9126;
        cfg.f54 = 0x4828;
      }
      cfg.f42 = param_3[3];
    }
    break;
  case 0x7bf:
    if (param_3 != NULL) {
      if (param_6 != NULL) {
        cfg.f30 = param_6[3];
        cfg.f34 = param_6[4];
        cfg.f38 = param_6[5];
      }
      cfg.f3c = (lbl_803E0374 + *(f32 *)(param_3 + 6)) * *(f32 *)(param_3 + 4) * lbl_803E03CC * (f32)(s32)randomGetRange(10,0xd);
      cfg.f08 = randomGetRange(1,2);
      cfg.f08 = cfg.f08 + 2;
      cfg.f44 = 0x80014;
      cfg.f48 = 0x4000820;
      cfg.f60 = (char)(int)(lbl_803E03D0 * *(f32 *)(param_3 + 6)) + 0x40;
      cfg.f42 = param_3[3];
      if (param_3[2] == 0) {
        cfg.f58 = 0x7fff;
        cfg.f5a = 0x1806;
        cfg.f5c = 0x4cb3;
        cfg.f4c = 0xf48c;
        cfg.f50 = 0x9882;
        cfg.f54 = 0xd97d;
      }
      else {
        cfg.f58 = 0xff87;
        cfg.f5a = 0x4817;
        cfg.f5c = 0x23;
        cfg.f4c = 0xf78f;
        cfg.f50 = 0xffa9;
        cfg.f54 = 0xb32b;
      }
    }
    break;
  case 0x7c0:
    if (param_3 != NULL) {
      if (param_6 != NULL) {
        cfg.f30 = param_6[3];
        cfg.f34 = param_6[4];
        cfg.f38 = param_6[5];
      }
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E03D4 * (f32)(s32)randomGetRange(0x2d,0x3a);
      cfg.f08 = randomGetRange(1,7);
      cfg.f08 = cfg.f08 + 0x1e;
      cfg.f60 = 0xff;
      cfg.f44 = 0x80004;
      cfg.f48 = 0x8440820;
      cfg.f58 = 0xfb54;
      cfg.f5a = 0;
      cfg.f5c = 0;
      cfg.f4c = 0xffff;
      cfg.f50 = 0x8347;
      cfg.f54 = 0x9b49;
      cfg.f2c = *(f32 *)(param_3 + 6) * *(f32 *)(param_3 + 4) * lbl_803E03D8 * (f32)(s32)randomGetRange(100,0x6c);
      cfg.f28 = lbl_803E0324;
      cfg.f24 = lbl_803E0324;
      if (param_6 != NULL) {
        mathFn_80021ac8(param_6,&cfg.f24);
      }
      cfg.f42 = param_3[3];
    }
    break;
  case 0x7c1:
    if (param_3 != NULL) {
      if (param_6 != NULL) {
        cfg.f30 = param_6[3];
        cfg.f34 = param_6[4];
        cfg.f38 = param_6[5];
      }
      cfg.f3c = (lbl_803E0374 + *(f32 *)(param_3 + 6)) * *(f32 *)(param_3 + 4) * lbl_803E03DC * (f32)(s32)randomGetRange(2,0xd);
      cfg.f08 = 0x11;
      cfg.f44 = 0x80114;
      cfg.f48 = 0x4000900;
      iVar1 = (int)(lbl_803E03D0 * *(f32 *)(param_3 + 6));
      cfg.f60 = (char)iVar1 + 0x40;
      cfg.f42 = param_3[3];
    }
    break;
  case 0x7c2:
    if (param_3 != NULL) {
      cfg.f28 = lbl_803E0350 * (f32)(s32)randomGetRange(0,100);
      cfg.f24 = *(f32 *)(param_3 + 4) * (lbl_803E03E0 + cfg.f28) * lbl_803E03E4 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * (lbl_803E03E0 + cfg.f28) * lbl_803E03E4 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = -cfg.f28 * *(f32 *)(param_3 + 4);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E03B0 * (f32)(s32)randomGetRange(0x19,0x32);
      cfg.f34 = lbl_803E03E8 * *(f32 *)(param_3 + 4);
      cfg.f08 = randomGetRange(0x28,0x50);
      cfg.f42 = 0xc10;
      cfg.f60 = '@';
      cfg.f44 = 0x80104;
      cfg.f48 = 0x4800808;
    }
    break;
  case 0x7c3:
    if (param_3 != NULL) {
      fVar9 = lbl_803E0330 * (f32)(s32)randomGetRange(0xffffff9c,100) + (f32)param_3[3];
      fVar8 = (lbl_803E0344 * (f32)(s32)randomGetRange(0, param_3[2])) / lbl_803E0348;
      fVar7 = fn_80293E80(fVar8);
      cfg.f30 = fVar9 * fVar7 + *(f32 *)(param_3 + 6);
      cfg.f34 = lbl_803E0314 * (f32)(s32)randomGetRange(0,(s32)param_3[2]) + *(f32 *)(param_3 + 8);
      fVar7 = sin(fVar8);
      cfg.f38 = fVar9 * fVar7 + *(f32 *)(param_3 + 10);
      cfg.f08 = randomGetRange(10,0x28);
      cfg.f42 = 0x156;
      cfg.f44 = 0x80480104;
      cfg.f48 = 0x4000800;
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E03EC * (f32)(s32)randomGetRange(0x31,0x39);
      cfg.f60 = 0xff;
    }
    break;
  case 0x7c4:
    if (param_3 != NULL) {
      if (param_6 != NULL) {
        cfg.f30 = param_6[3];
        cfg.f34 = param_6[4];
        cfg.f38 = param_6[5];
      }
      cfg.f3c = (lbl_803E0374 + *(f32 *)(param_3 + 6)) * *(f32 *)(param_3 + 4) * lbl_803E03CC * (f32)(s32)randomGetRange(10,0xd);
      cfg.f08 = randomGetRange(1,2);
      cfg.f08 = cfg.f08 + 2;
      cfg.f44 = 0x80004;
      cfg.f48 = 0x4000820;
      cfg.f60 = (char)(int)(lbl_803E03D0 * *(f32 *)(param_3 + 6)) + 0x40;
      cfg.f42 = param_3[3];
      if (param_3[2] == 0) {
        cfg.f58 = 0x7fff;
        cfg.f5a = 0x1806;
        cfg.f5c = 0x4cb3;
        cfg.f4c = 0xf48c;
        cfg.f50 = 0x9882;
        cfg.f54 = 0xd97d;
      }
      else {
        cfg.f58 = 0xff87;
        cfg.f5a = 0x4817;
        cfg.f5c = 0x23;
        cfg.f4c = 0xf78f;
        cfg.f50 = 0xffa9;
        cfg.f54 = 0xb32b;
      }
    }
    break;
  case 0x7c5:
    if (param_3 != NULL) {
      if (param_6 != NULL) {
        cfg.f30 = param_6[3];
        cfg.f34 = param_6[4];
        cfg.f38 = param_6[5];
      }
      cfg.f3c = (lbl_803E0374 + *(f32 *)(param_3 + 6)) * *(f32 *)(param_3 + 4) * lbl_803E03DC * (f32)(s32)randomGetRange(2,0xd);
      cfg.f08 = 0x11;
      cfg.f44 = 0x80104;
      cfg.f48 = 0x4000900;
      iVar1 = (int)(lbl_803E03D0 * *(f32 *)(param_3 + 6));
      cfg.f60 = (char)iVar1 + 0x40;
      cfg.f42 = param_3[3];
    }
    break;
  case 0x7c6:
    cfg.f3c = lbl_803E03A8;
    cfg.f08 = randomGetRange(0x27,0x31);
    cfg.f44 = 0x180000;
    cfg.f48 = 0x408000;
    cfg.f42 = 0x5ff;
    break;
  case 0x7c7:
    if (param_3 != NULL) {
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(100,200);
      cfg.f30 = *(f32 *)(param_3 + 4) * lbl_803E0350 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 4) * lbl_803E0350 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 10);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0354 * (f32)(s32)randomGetRange(0x50,100);
      cfg.f08 = randomGetRange(1,0x14);
      cfg.f08 = cfg.f08 + 10;
      cfg.f42 = param_3[3];
      cfg.f60 = 0xff;
      cfg.f44 = 0x80200;
      cfg.f48 = 0x4040800;
    }
    break;
  case 0x7c8:
    if (param_3 != NULL) {
      cfg.f24 = lbl_803E034C * (f32)(s32)randomGetRange(0xfffffed4,300);
      cfg.f28 = lbl_803E034C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = lbl_803E034C * (f32)(s32)randomGetRange(0xfffffed4,300);
      cfg.f34 = lbl_803E03F0;
      cfg.f3c = lbl_803E03F4;
      cfg.f08 = randomGetRange(0x19,0x20);
      cfg.f42 = param_3[3];
      cfg.f44 = 0x80100;
      cfg.f48 = 0x40808;
    }
    break;
  case 0x7c9:
    cfg.f24 = lbl_803E03F8 * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f28 = lbl_803E03FC * (f32)(s32)randomGetRange(0,100);
    cfg.f2c = lbl_803E0400 * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f3c = lbl_803E0404 * (f32)(s32)randomGetRange(0xf,0x14);
    cfg.f08 = randomGetRange(300,0x1c2);
    cfg.f42 = 0xc10;
    cfg.f44 = 0x8000100;
    cfg.f48 = 0x1000000;
    cfg.f60 = 0x7f;
    break;
  case 0x7ca:
    if (param_3 != NULL) {
      cfg.f24 = lbl_803E035C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = lbl_803E0408 * (f32)(s32)randomGetRange(0,100);
      cfg.f2c = lbl_803E035C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = lbl_803E03E4 * (f32)(s32)randomGetRange(1,0x14);
      cfg.f08 = randomGetRange(100,0x78);
      cfg.f42 = 0x605;
      if (param_3[1] == 1) {
        cfg.f58 = 0x2234;
        cfg.f5a = 0x8a54;
        cfg.f5c = 0xfff6;
        cfg.f4c = 0x2234;
        cfg.f50 = 0x8a54;
        cfg.f54 = 0xfff6;
      }
      else if (param_3[1] == 2) {
        cfg.f58 = 0xfff6;
        cfg.f5a = 0x1524;
        cfg.f5c = 0x1524;
        cfg.f4c = 0xfff6;
        cfg.f50 = 0x1524;
        cfg.f54 = 0x1524;
      }
      else {
        cfg.f58 = 0xfff6;
        cfg.f5a = 0x8a54;
        cfg.f5c = 0x2234;
        cfg.f4c = 0xfff6;
        cfg.f50 = 0x8a54;
        cfg.f54 = 0x2234;
      }
      cfg.f44 = 0x80110;
      cfg.f48 = 0x8002828;
      cfg.f60 = -0x40;
    }
    break;
  case 0x7cb:
    if (param_3 != NULL) {
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = lbl_803E040C;
      cfg.f08 = (int)(*(f32 *)(param_3 + 4) * (f32)(s32)randomGetRange(0x32,0x3c));
      cfg.f42 = 0x88;
      cfg.f44 = 0x480400;
      cfg.f48 = 0x80800;
    }
    break;
  case 0x7cc:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 4) * lbl_803E0380 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f34 = *(f32 *)(param_3 + 4) * lbl_803E0380 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f38 = *(f32 *)(param_3 + 4) * lbl_803E0380 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = lbl_803E031C * (f32)(s32)randomGetRange(5,0x14);
      cfg.f08 = randomGetRange(0x2a,0x32);
      cfg.f42 = param_3[3];
      cfg.f44 = 0x580000;
      cfg.f48 = 0x800;
    }
    break;
  case 0x7cd:
    if (param_3 != NULL) {
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E0358 * (f32)(s32)randomGetRange(100,200);
      cfg.f30 = *(f32 *)(param_3 + 4) * lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 4) * lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 10);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0354 * (f32)(s32)randomGetRange(0x50,100);
      cfg.f08 = randomGetRange(1,0x14);
      cfg.f08 = cfg.f08 + 10;
      cfg.f42 = param_3[3];
      cfg.f60 = 0xff;
      cfg.f44 = 0x280201;
      cfg.f48 = 0x4040800;
    }
    break;
  case 0x7ce:
    if (param_3 != NULL) {
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E0358 * (f32)(s32)randomGetRange(100,200);
      cfg.f30 = *(f32 *)(param_3 + 4) * lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 4) * lbl_803E0334 * (f32)(s32)randomGetRange(0xffffff9c,100) + *(f32 *)(param_3 + 10);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0354 * (f32)(s32)randomGetRange(0x50,100);
      cfg.f08 = randomGetRange(5,0xf);
      cfg.f42 = param_3[3];
      cfg.f60 = 0xff;
      cfg.f44 = 0x280201;
      cfg.f48 = 0x4040800;
    }
    break;
  case 1999:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f3c = lbl_803E0410 * *(f32 *)(param_3 + 4);
      cfg.f08 = 10;
      cfg.f42 = param_3[3];
      cfg.f60 = 0x7f;
      cfg.f44 = 0x280101;
      cfg.f48 = 0x822;
      cfg.f58 = 0x75b;
      cfg.f5a = 0x1642;
      cfg.f5c = 0xffff;
      cfg.f4c = 0x656a;
      cfg.f50 = 0x9f8;
      cfg.f54 = 0xffff;
      if (param_3[2] != 0) {
        cfg.f44 = 0x20280101;
      }
    }
    break;
  case 2000:
    if (param_3 != NULL) {
      if (param_6 == NULL) {
        cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E0370 * (f32)(s32)randomGetRange(100,200) ;
        cfg.f2c = lbl_803E0414 * *(f32 *)(param_3 + 4) * lbl_803E0418 * (f32)(s32)randomGetRange(100,200);
      }
      else {
        cfg.f28 = lbl_803E0328 * (f32)(s32)randomGetRange(100,200) ;
        cfg.f2c = lbl_803E041C * *(f32 *)(param_3 + 4) * lbl_803E0420 * (f32)(s32)randomGetRange(0x32,100);
      }
      cfg.f30 = lbl_803E03E0 * (f32)(s32)randomGetRange(0xffffffec,0x14) + *(f32 *)(param_3 + 6);
      cfg.f34 = lbl_803E0374 * (f32)(s32)randomGetRange(0xf,0x14) + *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0378 * (f32)(s32)randomGetRange(0x50,0x8c);
      cfg.f08 = randomGetRange(0,10);
      cfg.f08 = cfg.f08 + 0xf;
      cfg.f42 = 0xc10;
      cfg.f60 = 0xff;
      cfg.f44 = 0x20080100;
      cfg.f48 = 0x4010020;
      cfg.f4c = (uint)param_3[3];
      cfg.f58 = (ushort)((int)cfg.f4c >> 1);
      cfg.f50 = cfg.f4c;
      cfg.f54 = cfg.f4c;
      cfg.f5a = cfg.f58;
      cfg.f5c = cfg.f58;
    }
    break;
  case 0x7d1:
    if (param_3 != NULL) {
      if (param_6 == NULL) {
        cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E0328 * (f32)(s32)randomGetRange(100,200) ;
        cfg.f2c = lbl_803E0424 * *(f32 *)(param_3 + 4) * lbl_803E0418 * (f32)(s32)randomGetRange(100,200);
      }
      else {
        cfg.f28 = lbl_803E0328 * (f32)(s32)randomGetRange(100,200) ;
        cfg.f2c = lbl_803E0424 * *(f32 *)(param_3 + 4) * lbl_803E0370 * (f32)(s32)randomGetRange(100,200);
      }
      cfg.f34 = lbl_803E0380 * (f32)(s32)randomGetRange(0xffffffec,0x14) + *(f32 *)(param_3 + 8);
      cfg.f30 = lbl_803E0380 * (f32)(s32)randomGetRange(0xffffffec,0x14) + *(f32 *)(param_3 + 6);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0354 * (f32)(s32)randomGetRange(0x50,100);
      cfg.f08 = randomGetRange(1,0x14);
      cfg.f08 = cfg.f08 + 10;
      cfg.f42 = param_3[3];
      cfg.f60 = 0xff;
      cfg.f44 = 0x20080200;
      cfg.f48 = 0x4040800;
    }
    break;
  case 0x7d2:
    if (param_3 != NULL) {
      if (*param_3 == 0) {
        cfg.f24 = lbl_803E0358 * (f32)(s32)randomGetRange(0xffffff9c,100) ;
        cfg.f28 = lbl_803E036C * (f32)(s32)randomGetRange(0xffffff9c,100);
        cfg.f2c = lbl_803E0358 * (f32)(s32)randomGetRange(0xffffff9c,100) ;
        cfg.f34 = lbl_803E0314 * (f32)(s32)randomGetRange(100,200);
      }
      else {
        cfg.f34 = lbl_803E0428;
        cfg.f24 = lbl_803E0328 * (f32)(s32)randomGetRange(0xffffff9c,100) ;
        cfg.f28 = lbl_803E03B0 * (f32)(s32)randomGetRange(0xffffff9c,100);
        cfg.f2c = lbl_803E0328 * (f32)(s32)randomGetRange(0xffffff9c,100) ;
      }
      cfg.f3c = *(f32 *)(param_3 + 4) * (f32)(s32)randomGetRange(5,10);
      cfg.f08 = (int)param_3[3];
      cfg.f42 = param_3[2];
      cfg.f60 = 0xff;
      cfg.f44 = 0x80110;
      cfg.f48 = 0x20900;
    }
    break;
  case 0x7d3:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = lbl_803E0430 * (f32)(s32)randomGetRange(10,0x14);
      cfg.f08 = randomGetRange(1,0x28);
      cfg.f08 = param_3[1] + cfg.f08;
      cfg.f42 = param_3[3];
      cfg.f60 = 0xff;
      cfg.f44 = 0x480104;
      cfg.f48 = 0x8000080;
    }
    break;
  case 0x7d4:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = lbl_803E0430 * (f32)(s32)randomGetRange(10,0x14);
      cfg.f08 = randomGetRange(1,0x28);
      cfg.f08 = param_3[1] + cfg.f08;
      cfg.f42 = param_3[3];
      cfg.f60 = 0xff;
      cfg.f44 = 0x1480104;
      cfg.f48 = 0x8000080;
    }
    break;
  case 0x7d5:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = lbl_803E0430 * (f32)(s32)randomGetRange(10,0x14);
      cfg.f08 = randomGetRange(1,0x28);
      cfg.f08 = param_3[1] + cfg.f08;
      cfg.f42 = param_3[3];
      cfg.f60 = 0xff;
      cfg.f44 = 0x48010c;
      cfg.f48 = 0x8000080;
    }
    break;
  case 0x7d6:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = lbl_803E0430 * (f32)(s32)randomGetRange(10,0x14);
      cfg.f08 = randomGetRange(1,0x28);
      cfg.f08 = param_3[1] + cfg.f08;
      cfg.f42 = param_3[3];
      cfg.f60 = 0xff;
      cfg.f44 = 0x40480104;
      cfg.f48 = 0x8000080;
    }
    break;
  case 0x7d7:
    cfg.f3c = lbl_803E03E4;
    cfg.f08 = (uint)framesThisStep * 3;
    cfg.f60 = 0x2;
    cfg.f42 = 0x605;
    cfg.f44 = 0x80200;
    cfg.f48 = 0x820;
    cfg.f58 = 0;
    cfg.f5a = 0;
    cfg.f5c = 0xffff;
    cfg.f4c = 0x656a;
    cfg.f50 = 0;
    cfg.f54 = 0xffff;
    break;
  case 0x7d8:
    cfg.f34 = lbl_803E0434;
    cfg.f38 = lbl_803E0438;
    cfg.f2c = lbl_803E043C;
    cfg.f3c = lbl_803E03B0 * (f32)(s32)randomGetRange(0x50,0x58);
    cfg.f08 = randomGetRange(0xd2,0xe6);
    cfg.f42 = 0x7b;
    cfg.f58 = 0xfaab;
    cfg.f5a = 0xa9f;
    cfg.f5c = 0x1d3;
    cfg.f4c = 0x7fff;
    cfg.f50 = 0x7fff;
    cfg.f54 = 0xff4b;
    cfg.f60 = ',';
    cfg.f44 = 0x80004;
    cfg.f48 = 0x420820;
    if (param_3 != NULL) {
      cfg.f30 = lbl_803E03A8 * (f32)(s32)randomGetRange(0xffffff9c,100) + cfg.f30;
      cfg.f34 = lbl_803E03A8 * (f32)(s32)randomGetRange(0xffffff9c,100) + cfg.f34;
      cfg.f2c = lbl_803E0440 * (f32)(s32)randomGetRange(0x5a,0x6e);
      cfg.f3c = lbl_803E035C;
      cfg.f44 = (cfg.f44 | 0x400000);
    }
    break;
  case 0x7d9:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
    }
    cfg.f3c = lbl_803E0330 * *(f32 *)(param_3 + 4);
    cfg.f08 = 10;
    cfg.f42 = param_3[3];
    cfg.f60 = '@';
    cfg.f44 = 0x80104;
    cfg.f48 = 0x880;
    break;
  case 0x7da:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
    }
    cfg.f3c = lbl_803E0330 * *(f32 *)(param_3 + 4);
    cfg.f08 = 0x14;
    cfg.f42 = param_3[3];
    cfg.f60 = 0x0;
    cfg.f44 = 0x80104;
    cfg.f48 = 0x880;
    break;
  case 0x7db:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
    }
    cfg.f3c = lbl_803E0330 * *(f32 *)(param_3 + 4);
    cfg.f08 = 0x14;
    cfg.f42 = param_3[3];
    cfg.f60 = 0x0;
    cfg.f44 = 0x80104;
    cfg.f48 = 0x4000880;
    break;
  case 0x7dc:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = ((f32)param_3[2] / lbl_803E0444) * lbl_803E033C * (f32)(s32)randomGetRange(5,100);
      cfg.f08 = randomGetRange(1,0x28);
      cfg.f08 = param_3[1] + cfg.f08;
      cfg.f60 = randomGetRange(0x20,0x40);
      cfg.f60 = (char)*param_3 + cfg.f60;
      cfg.f42 = 0x605;
      cfg.f44 = 0x80104;
      cfg.f48 = 0x8a0;
      sVar3 = param_3[3];
      if (sVar3 == 0xe0) {
        cfg.f58 = 0;
        cfg.f5a = 0;
        cfg.f5c = 0xffff;
        cfg.f4c = 0x656a;
        cfg.f50 = 0;
        cfg.f54 = 0xffff;
      }
      else if (sVar3 < 0xe0) {
        if (sVar3 == 0xdd) {
          cfg.f58 = 40000;
          cfg.f5a = 0;
          cfg.f5c = 0;
          cfg.f4c = 0xffff;
          cfg.f50 = 0x7ffd;
          cfg.f54 = 0x4000;
        }
        else if (sVar3 < 0xdd) {
          if (sVar3 != 0x7b) goto LAB_800d20d4;
          cfg.f58 = 0;
          cfg.f5a = 0x7fff;
          cfg.f5c = 0xffff;
          cfg.f4c = randomGetRange(0x4b0,32000);
          cfg.f50 = 0xffff;
          cfg.f54 = 0xffff;
        }
        else if (sVar3 < 0xdf) {
          cfg.f58 = 0xffff;
          cfg.f5a = 0x7fff;
          cfg.f5c = 0;
          cfg.f4c = 0xffff;
          cfg.f50 = 0xffff;
          cfg.f54 = 5000;
        }
        else {
          cfg.f58 = 0;
          cfg.f5a = 0;
          cfg.f5c = 0xffff;
          cfg.f4c = 12000;
          cfg.f50 = randomGetRange(0x4b0,32000);
          cfg.f54 = 0xffff;
        }
      }
      else if (sVar3 == 0x160) {
        cfg.f58 = 0;
        cfg.f5a = 0xffff;
        cfg.f5c = 0;
        cfg.f4c = 0x656a;
        cfg.f50 = 0xffff;
        cfg.f54 = 5000;
      }
      else if (sVar3 < 0x160) {
        if (sVar3 == 0xe4) {
          cfg.f58 = 40000;
          cfg.f5a = 40000;
          cfg.f5c = 0xffff;
          cfg.f4c = 0xffff;
          cfg.f50 = 0xffff;
          cfg.f54 = 0xffff;
        }
        else {
LAB_800d20d4:
          cfg.f58 = 0;
          cfg.f5a = 0;
          cfg.f5c = 0xffff;
          cfg.f4c = 0x656a;
          cfg.f50 = 0;
          cfg.f54 = 0xffff;
        }
      }
      else {
        if (sVar3 != 0x200) goto LAB_800d20d4;
        cfg.f58 = 0xffff;
        cfg.f5a = 0;
        cfg.f5c = 0;
        cfg.f4c = 0xffff;
        cfg.f50 = 0x7fff;
        cfg.f54 = 5000;
      }
    }
    break;
  case 0x7dd:
    if (param_3 != NULL) {
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E03A8 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E03A8 * (f32)(s32)randomGetRange(0,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E03A8 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f3c = lbl_803E034C * *(f32 *)(param_3 + 4);
      cfg.f08 = randomGetRange(0x1e,0x6e);
      cfg.f60 = 0xff;
      cfg.f44 = 0x3000000;
      cfg.f48 = 0x780880;
      cfg.f42 = param_3[3];
    }
    break;
  case 0x7de:
    if (param_3 != NULL) {
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E0340 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E0334 * (f32)(s32)randomGetRange(0x32,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E0340 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f3c = lbl_803E0448 * *(f32 *)(param_3 + 4);
      cfg.f08 = (int)(cfg.f28 * (f32)(s32)randomGetRange(0x19,100));
      cfg.f44 = 0x1482000;
      cfg.f48 = 0x8400880;
      cfg.f42 = param_3[3];
    }
    break;
  case 0x7df:
    if (param_3 != NULL) {
      cfg.f2c = *(f32 *)(param_3 + 4);
      mathFn_80021ac8(param_3,&cfg.f24);
      cfg.f30 = cfg.f30 + cfg.f24;
      cfg.f38 = cfg.f38 + cfg.f2c;
      cfg.f24 = lbl_803E0324;
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E044C * (f32)(s32)randomGetRange(0x32,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E0310 * (f32)(s32)randomGetRange(0x4b,100);
      mathFn_80021ac8(param_3,&cfg.f24);
      cfg.f3c = lbl_803E034C;
      cfg.f08 = (int)(cfg.f28 * (f32)(s32)randomGetRange(0x32,100));
      cfg.f60 = 0x7f;
      cfg.f44 = 0x3000000;
      cfg.f48 = 0x1600080;
      cfg.f42 = 0xc10;
    }
    break;
  case 0x7e0:
    cfg.f24 = lbl_803E0450 * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f2c = lbl_803E0454 * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f3c = lbl_803E0408;
    cfg.f08 = randomGetRange(0x28,0x32);
    cfg.f42 = 0xc10;
    cfg.f60 = 0x5a;
    cfg.f44 = 0xa100000;
    cfg.f48 = 0x400000;
    break;
  case 0x7e1:
    if (param_3 != NULL) {
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E03B0 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(0x32,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E03B0 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = lbl_803E042C;
      cfg.f08 = (int)(cfg.f28 * (f32)(s32)randomGetRange(0x32,100));
      cfg.f60 = 0x7f;
      cfg.f44 = 0x1080000;
      cfg.f48 = 0x5400080;
      cfg.f42 = 0xc10;
    }
    break;
  case 0x7e2:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = lbl_803E03E4 * (f32)(s32)randomGetRange(0xffffffd8,0x28);
      cfg.f28 = lbl_803E036C * (f32)(s32)randomGetRange(10,0x50);
      cfg.f2c = lbl_803E03E4 * (f32)(s32)randomGetRange(0xffffffd8,0x28);
      cfg.f3c = lbl_803E033C * (f32)(s32)randomGetRange(0xf,0x1e);
      cfg.f08 = randomGetRange(0x122,0x15e);
      cfg.f60 = 0xff;
      cfg.f44 = 0x86000008;
      cfg.f48 = 0x1000000;
      cfg.f42 = param_3[3];
      if (param_3[1] == 1) {
        cfg.f4c = randomGetRange(0x63bf,0xffff);
        cfg.f4c = cfg.f4c & 0xffff;
        cfg.f58 = (ushort)cfg.f4c;
        cfg.f50 = randomGetRange(0x3caf,0xd8ef);
        cfg.f50 = cfg.f50 & 0xffff;
        cfg.f5a = (ushort)cfg.f50;
        cfg.f54 = randomGetRange(0x159f,0x3caf);
        cfg.f54 = cfg.f54 & 0xffff;
        cfg.f5c = (ushort)cfg.f54;
        cfg.f48 = cfg.f48 | 0x20;
      }
      else if (param_3[1] == 2) {
        cfg.f4c = randomGetRange(0x3caf,0x7fff);
        cfg.f4c = cfg.f4c & 0xffff;
        cfg.f58 = (ushort)cfg.f4c;
        cfg.f50 = randomGetRange(0x7fff,0xffff);
        cfg.f50 = cfg.f50 & 0xffff;
        cfg.f5a = (ushort)cfg.f50;
        cfg.f54 = randomGetRange(0x159f,0x3caf);
        cfg.f54 = cfg.f54 & 0xffff;
        cfg.f5c = (ushort)cfg.f54;
        cfg.f48 = cfg.f48 | 0x20;
      }
      if (param_3[2] != 0) {
        cfg.f44 = (cfg.f44 | 0x800000);
        cfg.f60 = 'A';
      }
      cfg.f0c = randomGetRange(0,0xffff);
      cfg.f0e = randomGetRange(0,0xffff);
      cfg.f0c = randomGetRange(0,0xffff);
      cfg.f18 = (f32)(s32)randomGetRange(0xe6,800);
      cfg.f1c = (f32)(s32)randomGetRange(0xe6,800);
      cfg.f20 = (f32)(s32)randomGetRange(0xe6,800);
    }
    break;
  case 0x7e3:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = lbl_803E03E4 * (f32)(s32)randomGetRange(0xffffffd8,0x28);
      cfg.f28 = lbl_803E0458 * (f32)(s32)randomGetRange(10,0x50);
      cfg.f2c = lbl_803E03E4 * (f32)(s32)randomGetRange(0xffffffd8,0x28);
      cfg.f3c = lbl_803E033C * (f32)(s32)randomGetRange(10,0x14);
      cfg.f08 = randomGetRange(0x122,0x15e);
      cfg.f60 = 0xff;
      cfg.f44 = 0x80008;
      cfg.f48 = 0x5000000;
      cfg.f42 = 0xc10;
    }
    break;
  case 0x7e4:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = lbl_803E03E4 * (f32)(s32)randomGetRange(0xffffffd8,0x28);
      cfg.f28 = lbl_803E036C * (f32)(s32)randomGetRange(10,0x50);
      cfg.f2c = lbl_803E03E4 * (f32)(s32)randomGetRange(0xffffffd8,0x28);
      cfg.f3c = lbl_803E045C * (f32)(s32)randomGetRange(5,10);
      cfg.f08 = randomGetRange(0x122,0x15e);
      cfg.f60 = 0xff;
      cfg.f44 = 0x80008;
      cfg.f48 = 0x5000100;
      cfg.f42 = param_3[3];
    }
    break;
  case 0x7e5:
    if (param_6 != NULL) {
      cfg.f24 = *param_6;
      cfg.f28 = param_6[1];
      cfg.f2c = param_6[2];
    }
    cfg.f3c = lbl_803E033C * (f32)(s32)randomGetRange(0x44,100);
    cfg.f08 = randomGetRange(100,0x82);
    cfg.f42 = 0xc10;
    cfg.f60 = randomGetRange(0x28,0x2c);
    cfg.f44 = 0x180100;
    cfg.f48 = 0x5080800;
    break;
  case 0x7e6:
    if (param_3 != NULL) {
      if (param_6 == NULL) {
      }
      else {
        cfg.f24 = *param_6;
        cfg.f28 = param_6[1];
        cfg.f2c = param_6[2];
      }
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(0xffffff9c,100) + cfg.f24;
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E036C * (f32)(s32)randomGetRange(0x32,100) + cfg.f28;
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(0xffffff9c,100) + cfg.f2c;
      cfg.f3c = (f32)(*(f32 *)(param_3 + 4) * lbl_803E0460 * (f32)(s32)randomGetRange(0x44,100));
      cfg.f08 = randomGetRange(0x2d,0x5f);
      cfg.f42 = 0xc10;
      cfg.f44 = 0x180100;
      cfg.f48 = 0x5080000;
      if (*param_3 == 3) {
        cfg.f60 = randomGetRange(0x26,0x2b);
        cfg.f48 = cfg.f48 | 0x800;
      }
      else {
        cfg.f60 = randomGetRange(0x26,0x2b);
      }
    }
    break;
  case 0x7e7:
    cfg.f24 = lbl_803E03F8 * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f28 = lbl_803E03FC * (f32)(s32)randomGetRange(0,100);
    cfg.f2c = lbl_803E0400 * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f3c = lbl_803E0404 * (f32)(s32)randomGetRange(0xf,0x14);
    cfg.f08 = randomGetRange(0x96,300);
    cfg.f42 = 0xc10;
    cfg.f44 = 0x8000100;
    cfg.f48 = 0x820;
    cfg.f58 = 0;
    cfg.f5a = 0xffff;
    cfg.f5c = 0;
    cfg.f4c = 0;
    cfg.f50 = 0xffff;
    cfg.f54 = 0x4000;
    cfg.f60 = '@';
    break;
  case 0x7e8:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
    }
    cfg.f3c = lbl_803E0330 * *(f32 *)(param_3 + 4);
    cfg.f08 = 10;
    cfg.f42 = param_3[3];
    cfg.f60 = '@';
    cfg.f44 = 0x80100;
    cfg.f48 = 0x800;
    break;
  case 0x7e9:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
    }
    cfg.f3c = lbl_803E0330 * *(f32 *)(param_3 + 4);
    cfg.f08 = 0x14;
    cfg.f42 = param_3[3];
    cfg.f60 = 0x0;
    cfg.f44 = 0x80100;
    cfg.f48 = 0x800;
    break;
  case 0x7ea:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
    }
    cfg.f3c = lbl_803E0330 * *(f32 *)(param_3 + 4);
    cfg.f08 = 0x14;
    cfg.f42 = param_3[3];
    cfg.f60 = 0x0;
    cfg.f44 = 0x80100;
    cfg.f48 = 0x4000800;
    break;
  case 0x7eb:
    if (param_3 != NULL) {
      if (param_6 != NULL) {
        cfg.f30 = param_6[3];
        cfg.f34 = param_6[4];
        cfg.f38 = param_6[5];
      }
      iVar1 = randomGetRange(0,4);
      if (iVar1 == 0) {
        cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0x1c,0x22) ;
        cfg.f44 = 0x80000;
        cfg.f48 = 0x8000820;
      }
      else {
        cfg.f28 = *(f32 *)(param_3 + 6) * *(f32 *)(param_3 + 4) * lbl_803E03C4 * (f32)(s32)randomGetRange(100,0x6b) ;
        cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E03C8 * (f32)(s32)randomGetRange(0x1c,0x22);
        cfg.f44 = 0x80080000;
        cfg.f48 = 0x8002820;
      }
      cfg.f60 = 0xff;
      cfg.f08 = randomGetRange(0x14,0x1b);
      cfg.f58 = 2000;
      cfg.f5a = 2000;
      cfg.f5c = 0x7fff;
      cfg.f4c = 7000;
      cfg.f50 = 0x7fff;
      cfg.f54 = 0xffff;
      cfg.f42 = param_3[3];
    }
    break;
  case 0x7ec:
    if (param_3 != NULL) {
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E033C * (f32)(s32)randomGetRange(0x1e,0x46);
      cfg.f08 = randomGetRange(0x1e,0x28);
      cfg.f60 = randomGetRange(0x40,0x7f);
      cfg.f42 = 0x605;
      cfg.f44 = (u32)randFn_80080100;
      cfg.f48 = 0x28a0;
      cfg.f58 = 0;
      cfg.f5a = 0x7fff;
      cfg.f5c = 0xffff;
      cfg.f4c = randomGetRange(40000, 0xffff);
      cfg.f50 = randomGetRange(0x4b0,32000);
      cfg.f54 = 0xffff;
    }
    break;
  case 0x7ed:
    cfg.f34 = lbl_803E0468;
    cfg.f28 = lbl_803E0424;
    cfg.f3c = lbl_803E03B0 * (f32)(s32)randomGetRange(0x50,0x58);
    cfg.f08 = randomGetRange(0x50,0x5a);
    cfg.f42 = 0x7b;
    cfg.f58 = 0xfaab;
    cfg.f5a = 0xa9f;
    cfg.f5c = 0x1d3;
    cfg.f4c = 0x7fff;
    cfg.f50 = 0x7fff;
    cfg.f54 = 0xff4b;
    cfg.f60 = ',';
    cfg.f44 = 0x200c0004;
    cfg.f48 = 0x420820;
    if (param_3 != NULL) {
      cfg.f30 = lbl_803E03A8 * (f32)(s32)randomGetRange(0xffffff9c,100) + cfg.f30;
      cfg.f34 = lbl_803E03A8 * (f32)(s32)randomGetRange(0xffffff9c,100) + cfg.f34;
      cfg.f28 = lbl_803E0358 * (f32)(s32)randomGetRange(0x5a,0x6e);
      cfg.f3c = lbl_803E035C;
      cfg.f44 = (cfg.f44 | 0x400000);
    }
    break;
  case 0x7ee:
    if (param_3 != NULL) {
      cfg.f3c = lbl_803E03B0 * (f32)(s32)randomGetRange(0x1e,0x46);
      cfg.f44 = (u32)randFn_80080100;
      cfg.f48 = 0x8a0;
      cfg.f58 = randomGetRange(40000,0xffff);
      cfg.f5a = randomGetRange(0x4b0,32000);
      cfg.f5c = 0xffff;
      cfg.f4c = 0;
      cfg.f50 = 0x7fff;
      cfg.f54 = 0xffff;
      cfg.f08 = randomGetRange(0x1c,0x22);
      cfg.f08 = cfg.f08 + 0x14;
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f2c = lbl_803E0324;
      cfg.f28 = *(f32 *)(param_3 + 4);
      if (param_3[3] == 0) {
        cfg.f24 = lbl_803E046C;
      }
      else {
        cfg.f24 = lbl_803E0374;
      }
      cfg.f42 = 0x605;
    }
    break;
  case 0x7ef:
  case 0x801:
  case 0x808:
    cfg.f30 = *(f32 *)(param_3 + 6);
    cfg.f34 = *(f32 *)(param_3 + 8);
    cfg.f38 = *(f32 *)(param_3 + 10);
    cfg.f24 = lbl_803E0470 * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f28 = lbl_803E0474 * (f32)(s32)randomGetRange(0x32,100);
    cfg.f2c = lbl_803E0478 * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f3c = lbl_803E047C * (f32)(s32)randomGetRange(0x14,100);
    if (param_2 == 0x808) {
      cfg.f3c = cfg.f3c * lbl_803E0314;
    }
    cfg.f08 = randomGetRange(0x14,100);
    cfg.f42 = 0xc10;
    cfg.f58 = 0xffe4;
    cfg.f5a = 0x15;
    cfg.f5c = 0xc67b;
    cfg.f4c = 0x1378;
    cfg.f50 = 0xfec0;
    cfg.f54 = 0x2d55;
    cfg.f60 = 0xff;
    cfg.f44 = 0x80080200;
    if ((param_2 == 0x7ef) || (param_2 == 0x808)) {
      cfg.f44 = 0x80280201;
    }
    cfg.f48 = 0x4080820;
    break;
  case 0x7f0:
    cfg.f24 = lbl_803E0480 * (f32)(s32)randomGetRange(0x32,100);
    cfg.f28 = lbl_803E040C;
    cfg.f3c = lbl_803E0484;
    cfg.f08 = 0x73;
    cfg.f42 = 0x632;
    cfg.f58 = 0;
    cfg.f5a = 0;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0xffff;
    cfg.f54 = 0xffff;
    cfg.f60 = 0xff;
    cfg.f44 = 0x40180140;
    cfg.f48 = 0x820;
    break;
  case 0x7f1:
    cfg.f28 = lbl_803E0380 * (f32)(s32)randomGetRange(8,10);
    cfg.f34 = lbl_803E0488;
    cfg.f3c = lbl_803E0420 * (f32)(s32)randomGetRange(6,0xc);
    cfg.f08 = randomGetRange(0x3c,0x5a);
    cfg.f44 = 0x80180000;
    cfg.f48 = 0x5440820;
    cfg.f42 = 0xc0b;
    cfg.f60 = '@';
    cfg.f58 = 0;
    cfg.f5a = 0xffff;
    cfg.f5c = 0xffff;
    cfg.f4c = 0xffff;
    cfg.f50 = 0;
    cfg.f54 = 0xffff;
    break;
  case 0x7f2:
    cfg.f34 = lbl_803E048C;
    cfg.f24 = lbl_803E0340 * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f28 = lbl_803E0368 * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f2c = lbl_803E0340 * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f3c = lbl_803E0490;
    cfg.f08 = randomGetRange(0xc,0x3d);
    cfg.f42 = 0x605;
    cfg.f58 = 0xffcc;
    cfg.f5a = 0x23a8;
    cfg.f5c = 0x325f;
    cfg.f4c = 0xfec1;
    cfg.f50 = 0x130c;
    cfg.f54 = 0xacf;
    cfg.f60 = 0x80;
    cfg.f44 = 0x80100;
    cfg.f48 = 0x80820;
    break;
  case 0x7f3:
    if (param_3 != NULL) {
      cfg.f08 = 0x37;
      cfg.f42 = 0xc86;
      cfg.f60 = -0xd;
      cfg.f44 = 0x80100;
      cfg.f48 = 0x828;
      if (param_3[3] == 0) {
        cfg.f3c = lbl_803E0368 * (f32)(s32)randomGetRange(10,0x14) ;
        cfg.f34 = lbl_803E048C;
        cfg.f58 = 0xffcc;
        cfg.f5a = 0x23a8;
        cfg.f5c = 0x325f;
        cfg.f4c = 0xfec1;
        cfg.f50 = 0x130c;
        cfg.f54 = 0xacf;
      }
      if (param_3[3] == 1) {
        cfg.f3c = lbl_803E040C * (f32)(s32)randomGetRange(10,0x14) ;
        cfg.f34 = lbl_803E0494;
        cfg.f58 = 0x23a8;
        cfg.f5a = 0xffcc;
        cfg.f5c = 0x325f;
        cfg.f4c = 0x130c;
        cfg.f50 = 0xfec1;
        cfg.f54 = 0xacf;
      }
      if (param_3[3] == 2) {
        cfg.f3c = lbl_803E0498 * (f32)(s32)randomGetRange(10,0x14) ;
        cfg.f34 = lbl_803E0494;
        cfg.f58 = 0xffcc;
        cfg.f5a = 0xffcc;
        cfg.f5c = 0x325f;
        cfg.f4c = 0xfec1;
        cfg.f50 = 0xffcc;
        cfg.f54 = 0xacf;
      }
    }
    break;
  case 0x7f4:
    cfg.f30 = *(f32 *)(param_3 + 6);
    cfg.f34 = *(f32 *)(param_3 + 8);
    cfg.f38 = *(f32 *)(param_3 + 10);
    cfg.f24 = *param_6;
    cfg.f28 = param_6[1];
    cfg.f2c = param_6[2];
    cfg.f3c = lbl_803E033C * (f32)(s32)randomGetRange(0x50,0x58);
    cfg.f42 = 0x7b;
    cfg.f08 = 0x50;
    sVar3 = param_3[3];
    if ((sVar3 == 0) || (sVar3 == 3)) {
      cfg.f58 = 65000;
      cfg.f5a = 10000;
      cfg.f5c = 10000;
      cfg.f08 = 0x55;
    }
    else if ((sVar3 == 1) || (sVar3 == 4)) {
      cfg.f58 = 0;
      cfg.f5a = 65000;
      cfg.f5c = 0;
    }
    else if ((sVar3 == 2) || (sVar3 == 5)) {
      cfg.f58 = 0;
      cfg.f5a = 0;
      cfg.f5c = 65000;
    }
    if (param_3[3] < 3) {
      cfg.f4c = (uint)cfg.f58;
      cfg.f50 = (uint)cfg.f5a;
      cfg.f54 = (uint)cfg.f5c;
    }
    else {
      cfg.f4c = 65000;
      cfg.f50 = 65000;
      cfg.f54 = 0;
      cfg.f08 = 0x5a;
    }
    cfg.f60 = ',';
    cfg.f44 = 0x80002;
    cfg.f48 = 0x420820;
    break;
  case 0x7f5:
    if (param_3 != NULL) {
      if (param_3[3] == 0) {
        cfg.f3c = lbl_803E0330 * *(f32 *)(param_3 + 4);
        cfg.f44 = 0x81180000;
        cfg.f48 = 0x8400800;
        cfg.f08 = randomGetRange(0x14,0x1a);
        cfg.f08 = cfg.f08 + 10;
      }
      else {
        cfg.f3c = lbl_803E049C * lbl_803E031C * *(f32 *)(param_3 + 4);
        cfg.f44 = 0x81080000;
        cfg.f48 = 0x4400800;
        cfg.f08 = 10;
      }
      cfg.f28 = lbl_803E0314 * *(f32 *)(param_3 + 4) * lbl_803E04A0 * (f32)(s32)randomGetRange(100,0x96);
      mathFn_80021ac8(param_1,&cfg.f24);
      cfg.f42 = 0x5f5;
      cfg.f60 = 0x80;
    }
    break;
  default:
    return -1;
  case 0x7f7:
    if (param_3 != NULL) {
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E0350 * (f32)(s32)randomGetRange(200,300);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0x37,0x41);
      cfg.f08 = (int)(*(f32 *)(param_3 + 4) * (f32)(s32)randomGetRange(0x1e,0x28));
      cfg.f42 = 0xc10;
      cfg.f60 = 0x20;
      cfg.f44 = 0xc0080100;
      cfg.f48 = 0x4000800;
    }
    break;
  case 0x7f9:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E03E4 * (f32)(s32)randomGetRange(0x32,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E04A4 * (f32)(s32)randomGetRange(0,100);
      cfg.f3c = lbl_803E0330 * *(f32 *)(param_3 + 4);
      cfg.f08 = randomGetRange(0x3c,0x4b);
      cfg.f42 = 0xc73;
      cfg.f58 = 5000;
      sVar3 = randomGetRange(0,10000);
      cfg.f5a = sVar3 + 10000;
      sVar3 = randomGetRange(0,10000);
      cfg.f5c = sVar3 + 20000;
      cfg.f4c = 0;
      cfg.f50 = randomGetRange(0,10000);
      iVar1 = randomGetRange(0,10000);
      cfg.f54 = iVar1 + 20000;
      cfg.f60 = 0xff;
      cfg.f44 = 0x1080004;
      cfg.f48 = 0x800a020;
    }
    break;
  case 0x7fa:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E03E4 * (f32)(s32)randomGetRange(0x32,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E04A8 * (f32)(s32)randomGetRange(0,100);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E040C * (f32)(s32)randomGetRange(10,0x1e);
      cfg.f08 = randomGetRange(0x32,0x50);
      cfg.f42 = 0xc10;
      cfg.f58 = 0xffcf;
      cfg.f5a = 0xf987;
      cfg.f5c = 0xfff8;
      cfg.f4c = 0x7a;
      cfg.f50 = 0x57d2;
      cfg.f54 = 0xffee;
      cfg.f60 = randomGetRange(0x7b,0xff);
      cfg.f44 = 0x40080204;
      cfg.f48 = 0x4080820;
    }
    break;
  case 0x7fb:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E04AC * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E04AC * (f32)(s32)randomGetRange(0x32,0x96);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E04AC * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = lbl_803E0330 * *(f32 *)(param_3 + 4);
      cfg.f08 = randomGetRange(0x28,0x41);
      cfg.f42 = 0xc73;
      cfg.f58 = 5000;
      sVar3 = randomGetRange(0,10000);
      cfg.f5a = sVar3 + 10000;
      sVar3 = randomGetRange(0,10000);
      cfg.f5c = sVar3 + 20000;
      cfg.f4c = 0;
      cfg.f50 = randomGetRange(0,10000);
      iVar1 = randomGetRange(0,10000);
      cfg.f54 = iVar1 + 20000;
      cfg.f60 = 0xff;
      cfg.f44 = 0x1080000;
      cfg.f48 = 0x800a020;
    }
    break;
  case 0x7fc:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E03E4 * (f32)(s32)randomGetRange(0x32,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E0310 * (f32)(s32)randomGetRange(10,0x1e);
      cfg.f08 = randomGetRange(0x32,0x50);
      cfg.f42 = 0xc10;
      cfg.f58 = 0xffcf;
      cfg.f5a = 0xf987;
      cfg.f5c = 0xfff8;
      cfg.f4c = 0x7a;
      cfg.f50 = 0x57d2;
      cfg.f54 = 0xffee;
      cfg.f60 = randomGetRange(0x40,0x7f);
      cfg.f44 = 0x40080200;
      cfg.f48 = 0x4000820;
    }
    break;
  case 0x7fd:
    cfg.f30 = lbl_803E03E8 - (f32)(s32)randomGetRange(0,4);
    cfg.f34 = lbl_803E03E8 - (f32)(s32)randomGetRange(0,4);
    cfg.f38 = lbl_803E03E8 - (f32)(s32)randomGetRange(0,4);
    cfg.f3c = lbl_803E04AC;
    cfg.f08 = randomGetRange(8,0xe);
    cfg.f44 = 0x110100;
    cfg.f48 = 0x4000000;
    cfg.f42 = 0xdf;
    break;
  case 0x7fe:
    cfg.f3c = lbl_803E04B0 * (f32)(s32)randomGetRange(100,200);
    cfg.f08 = randomGetRange(0x43,100);
    cfg.f42 = 0xc10;
    cfg.f58 = 0x7fff;
    cfg.f5a = 0x7fff;
    cfg.f5c = 0x7fff;
    cfg.f4c = 0x65a7;
    cfg.f50 = 0x433a;
    cfg.f54 = 0x1855;
    cfg.f60 = 0xff;
    cfg.f44 = 0x80180200;
    cfg.f48 = 0x5000020;
    break;
  case 0x7ff:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E03B8 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E0330 * (f32)(s32)randomGetRange(0,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E03B8 * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = lbl_803E04B4 * *(f32 *)(param_3 + 4) * (f32)(s32)randomGetRange(0x19,100);
      cfg.f08 = randomGetRange(0x28,0xa5);
      cfg.f42 = 0xc73;
      cfg.f58 = 15000;
      sVar3 = randomGetRange(0,10000);
      cfg.f5a = sVar3 + 20000;
      sVar3 = randomGetRange(0,10000);
      cfg.f5c = sVar3 + 30000;
      cfg.f4c = 10000;
      cfg.f50 = randomGetRange(10000,20000);
      iVar1 = randomGetRange(0,10000);
      cfg.f54 = iVar1 + 30000;
      cfg.f60 = 0xff;
      cfg.f44 = 0x1080000;
      cfg.f48 = 0x800a020;
    }
    break;
  case 0x800:
    if (param_3 != NULL) {
      cfg.f30 = *(f32 *)(param_3 + 6);
      cfg.f34 = *(f32 *)(param_3 + 8);
      cfg.f38 = *(f32 *)(param_3 + 10);
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E03E4 * (f32)(s32)randomGetRange(0x32,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E034C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = *(f32 *)(param_3 + 4) * lbl_803E04B8 * (f32)(s32)randomGetRange(10,0x1e);
      iVar1 = randomGetRange(0,1);
      cfg.f08 = randomGetRange(0x32,0xb4);
      cfg.f08 = cfg.f08 + iVar1 * 100;
      cfg.f42 = 0xc10;
      cfg.f58 = 0xffcf;
      cfg.f5a = 0xf987;
      cfg.f5c = 0xfff8;
      cfg.f4c = 0x7a;
      cfg.f50 = 0x57d2;
      cfg.f54 = 0xffee;
      cfg.f60 = randomGetRange(0x40,0x7f);
      cfg.f44 = 0x40080200;
      cfg.f48 = 0x4000820;
    }
    break;
  case 0x802:
    cfg.f24 = lbl_803E04AC * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f28 = lbl_803E0350 * (f32)(s32)randomGetRange(0x28,100);
    cfg.f2c = lbl_803E04AC * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f3c = lbl_803E04B8 * (f32)(s32)randomGetRange(4,10);
    cfg.f08 = randomGetRange(0x19,0x23);
    cfg.f42 = 0xc10;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 50000;
    cfg.f4c = 0xffff;
    cfg.f50 = 54000;
    cfg.f54 = 0x7fff;
    cfg.f60 = randomGetRange(0x54,0x7a);
    cfg.f44 = 0x1080200;
    cfg.f48 = 0x5000020;
    break;
  case 0x803:
    cfg.f24 = lbl_803E04BC * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f28 = lbl_803E04BC * (f32)(s32)randomGetRange(0xffffffb5,100);
    cfg.f3c = lbl_803E036C;
    cfg.f08 = 0x32;
    cfg.f58 = 2000;
    cfg.f5a = 2000;
    sVar3 = randomGetRange(0xffffec78,5000);
    cfg.f5c = sVar3 + 10000;
    cfg.f4c = 8000;
    cfg.f50 = 8000;
    iVar1 = randomGetRange(0xffffec78,5000);
    cfg.f54 = iVar1 + 12000;
    cfg.f42 = 0x639;
    cfg.f60 = 0xff;
    cfg.f44 = 0x1080004;
    cfg.f48 = 0x408028;
    break;
  case 0x804:
    if (param_3 != NULL) {
      cfg.f24 = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f28 = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f2c = *(f32 *)(param_3 + 4) * lbl_803E042C * (f32)(s32)randomGetRange(0xffffff9c,100);
      cfg.f3c = lbl_803E0430 * (f32)(s32)randomGetRange(10,0x14);
      cfg.f08 = randomGetRange(1,0x28);
      cfg.f08 = param_3[1] + cfg.f08;
      cfg.f42 = 0xdf;
      cfg.f60 = 0xff;
      cfg.f44 = 0x480100;
      cfg.f48 = 0x8000000;
    }
    break;
  case 0x805:
    cfg.f3c = lbl_803E04B4 * (f32)(s32)randomGetRange(0x50,0x58);
    cfg.f08 = randomGetRange(100,0x6e);
    cfg.f42 = 0x7b;
    if (param_3[1] == 0) {
      cfg.f58 = 20000;
      cfg.f5a = 20000;
      cfg.f5c = 0xffff;
      cfg.f4c = 20000;
      cfg.f50 = 10000;
      cfg.f54 = 0xffff;
    }
    else {
      cfg.f58 = 0xffff;
      cfg.f5a = 50000;
      cfg.f5c = 0;
      cfg.f4c = 0xffff;
      cfg.f50 = 50000;
      cfg.f54 = 0;
    }
    cfg.f60 = ',';
    cfg.f44 = 0x80004;
    cfg.f48 = 0x420820;
    cfg.f24 = *param_6;
    cfg.f28 = param_6[1];
    cfg.f2c = param_6[2];
    break;
  case 0x806:
    cfg.f38 = lbl_803E0488;
    mathFn_80021ac8(param_1,&cfg.f30);
    cfg.f28 = lbl_803E04C0;
    cfg.f3c = lbl_803E0328 * (f32)(s32)randomGetRange(0x50,0x5f);
    cfg.f08 = 0xfa;
    cfg.f42 = 0x7b;
    cfg.f58 = 0xfaab;
    cfg.f5a = 0xa9f;
    cfg.f5c = 0x1d3;
    cfg.f4c = 0x7fff;
    cfg.f50 = 0x7fff;
    cfg.f54 = 0xff4b;
    cfg.f60 = randomGetRange(0x32,0x36);
    cfg.f44 = 0x80000;
    cfg.f48 = 0x4000820;
    break;
  case 0x807:
    cfg.f38 = lbl_803E0488;
    mathFn_80021ac8(param_1,&cfg.f30);
    cfg.f28 = lbl_803E04C4;
    cfg.f3c = lbl_803E0328 * (f32)(s32)randomGetRange(0x50,0x5f);
    cfg.f08 = 0xfa;
    cfg.f42 = 0x7b;
    cfg.f58 = 2000;
    cfg.f5a = 2000;
    cfg.f5c = 0xfaab;
    cfg.f4c = 0x7fff;
    cfg.f50 = 0x7fff;
    cfg.f54 = 0xff4b;
    cfg.f60 = randomGetRange(0x32,0x36);
    cfg.f44 = 0x80000;
    cfg.f48 = 0x4000820;
    break;
  case 0x809:
    cfg.f24 = lbl_803E04AC * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f28 = lbl_803E0330 * (f32)(s32)randomGetRange(0x28,100);
    cfg.f2c = lbl_803E04AC * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f3c = lbl_803E036C * (f32)(s32)randomGetRange(4,10);
    cfg.f08 = randomGetRange(0x19,0x23);
    cfg.f42 = 0xc10;
    cfg.f58 = 0xffff;
    cfg.f5a = 0xffff;
    cfg.f5c = 50000;
    cfg.f4c = 0xffff;
    cfg.f50 = 58000;
    cfg.f54 = 38000;
    cfg.f60 = randomGetRange(0xb8,0xde);
    cfg.f44 = 0x1080200;
    cfg.f48 = 0x5000020;
    break;
  case 0x80a:
    cfg.f24 = lbl_803E04AC * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f28 = lbl_803E04AC * (f32)(s32)randomGetRange(0x28,100);
    cfg.f2c = lbl_803E04AC * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f3c = lbl_803E036C * (f32)(s32)randomGetRange(4,10);
    cfg.f08 = randomGetRange(0x19,0x23);
    cfg.f42 = 0xc10;
    cfg.f60 = randomGetRange(0x40,0x7f);
    cfg.f44 = 0x80010;
    cfg.f48 = 0x4400800;
    break;
  case 0x80b:
    cfg.f24 = lbl_803E0330 * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f28 = lbl_803E0330 * (f32)(s32)randomGetRange(0x28,100);
    cfg.f2c = lbl_803E0330 * (f32)(s32)randomGetRange(0xffffff9c,100);
    cfg.f3c = lbl_803E03B0 * (f32)(s32)randomGetRange(4,10);
    cfg.f08 = randomGetRange(0x19,0x23);
    cfg.f42 = 0xc10;
    cfg.f60 = 0xff;
    cfg.f44 = 0x3000000;
    cfg.f48 = 0x600820;
    cfg.f58 = 0xffff;
    cfg.f50 = randomGetRange(0x7fff, 0xffff);
    cfg.f50 = cfg.f50 & 0xffff;
    cfg.f5a = (ushort)cfg.f50;
    cfg.f5c = 0xffff;
    cfg.f4c = (uint)cfg.f58;
    cfg.f54 = 0xffff;
    break;
  case 0x80c:
    if (param_3 != NULL) {
      cfg.f24 = *(f32 *)(param_3 + 6);
      cfg.f28 = *(f32 *)(param_3 + 8);
      cfg.f2c = *(f32 *)(param_3 + 10);
    }
    cfg.f38 = (f32)(s32)randomGetRange(0xfffffff0,0x10);
    cfg.f34 = lbl_803E04C8;
    cfg.f3c = lbl_803E0310 * (f32)(s32)randomGetRange(4,8);
    cfg.f08 = randomGetRange(0xf,0x14);
    cfg.f42 = 0xc10;
    cfg.f60 = randomGetRange(0x20,0x40);
    cfg.f44 = 0x1080010;
    cfg.f48 = 0x4400800;
    }
    cfg.f44 = cfg.f44 | param_4;
    if (((cfg.f44 & 1) != 0) && ((cfg.f44 & 2) != 0)) cfg.f44 = cfg.f44 ^ 2;
    if ((cfg.f44 & 1) != 0) {
        if ((param_4 & 0x200000) == 0) {
            if (cfg.f00 != 0) {
                cfg.f30 = cfg.f30 + *(f32 *)((char *)cfg.f00 + 0x18);
                cfg.f34 = cfg.f34 + *(f32 *)((char *)cfg.f00 + 0x1c);
                cfg.f38 = cfg.f38 + *(f32 *)((char *)cfg.f00 + 0x20);
            }
        } else {
            cfg.f30 = cfg.f30 + cfg.f18;
            cfg.f34 = cfg.f34 + cfg.f1c;
            cfg.f38 = cfg.f38 + cfg.f20;
        }
    }
    ret = (*(int (**)())(*gExpgfxInterface + 8))(&cfg, -1, param_2, ret);
    return ret;
}


void Effect20_func05(void)
{
    f32 sum;
    sum = lbl_803DB888 + lbl_803E0310 * timeDelta;
    lbl_803DB888 = sum;
    if (sum > lbl_803E0318) lbl_803DB888 = lbl_803E0314;
    sum = lbl_803DB88C + lbl_803E0310 * timeDelta;
    lbl_803DB88C = sum;
    if (sum > lbl_803E0318) lbl_803DB88C = lbl_803E0320;
    lbl_803DD400 = lbl_803DD400 + (s32)framesThisStep * 0x64;
    if (lbl_803DD400 > 0x7fff) lbl_803DD400 = 0;
    lbl_803DD40C = fn_80293E80(lbl_803E0344 * (f32)(s16)lbl_803DD400 / lbl_803E0348);
    lbl_803DD404 = lbl_803DD404 + (s32)framesThisStep * 0x32;
    if (lbl_803DD404 > 0x7fff) lbl_803DD404 = 0;
    lbl_803DD408 = fn_80293E80(lbl_803E0344 * (f32)(s16)lbl_803DD404 / lbl_803E0348);
}
#pragma pop

/* Trivial 4b 0-arg blr leaves. */
void Effect16_func03_nop(void) {}
void Effect16_release(void) {}
void Effect16_initialise(void) {}
void Effect15_func05_nop(void) {}
void Effect15_func03_nop(void) {}
void Effect15_release(void) {}
void Effect15_initialise(void) {}
void Effect13_func05_nop(void) {}
void Effect13_func03_nop(void) {}
void Effect13_release(void) {}
void Effect13_initialise(void) {}
void Effect17_func03_nop(void) {}
void Effect17_release(void) {}
void Effect17_initialise(void) {}
void Effect18_func03_nop(void) {}
void Effect18_release(void) {}
void Effect18_initialise(void) {}
void Effect19_func03_nop(void) {}
void Effect19_release(void) {}
void Effect19_initialise(void) {}
void Effect20_func03_nop(void) {}
void Effect20_release(void) {}
void Effect20_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int Checkpoint_func09_ret_1(void) { return 0x1; }

extern f32 lbl_803E0504;
extern f32 lbl_803E0508;
extern f32 curveFn_80010dc0(f32 *values, f32 t, f32 *outTangent);
extern u16 getAngle(f32 a, f32 b);

/* Advance along the checkpoint curve by dist; write position/angles to out. */
#pragma push
#pragma scheduling off
s32 Checkpoint_func08(u8 *out, u8 *o, f32 dist, s32 p3, u8 flag)
{
    f32 v1[4];
    f32 v2[4];
    f32 v3[4];
    f32 outX;
    f32 outY;
    f32 outZ;
    s32 local_idx;
    s32 mode;
    s32 alt;
    u8 *n;
    s32 i;
    s8 clamp;
    s32 ang1;
    s32 ang2;
    f32 kMax;
    f32 kMin;
    f32 t;
    f32 seg;
    f32 x;
    f32 y;
    f32 z;
    f32 len;

    i = 0;
    mode = p3 + 2;
    kMin = lbl_803E04E8;
    kMax = lbl_803E0504;
    do {
        if (*(s32 *)(o + 0x10) < 0) {
            return 1;
        }
        n = (u8 *)Checkpoint_find(*(s32 *)(o + 0x10), &local_idx);
        if (n == NULL) {
            return 1;
        }
        if (*(s32 *)(n + 0x20) < 0) {
            *(s32 *)(o + 0x10) = -1;
            return 1;
        }
        alt = 0;
        if (*(s32 *)(n + 0x24) > -1 && *(u8 *)(o + 0x30) != 0) {
            alt = 1;
        }
        if (fn_800D55BC(n, alt, v1, v2, v3, mode, lbl_803E04E8, lbl_803E04E8) == 0) {
            return 1;
        }
        len = sqrtf((v3[0] - v3[1]) * (v3[0] - v3[1]) +
                    ((v1[0] - v1[1]) * (v1[0] - v1[1]) + (v2[0] - v2[1]) * (v2[0] - v2[1])));
        t = *(f32 *)(o + 8) + dist / len;
        clamp = 0;
        if (t < kMin) {
            t = kMin;
            clamp = -1;
        }
        if (t > kMax) {
            t = kMax;
            clamp = 1;
        }
        x = curveFn_80010dc0(v1, t, &outX);
        y = curveFn_80010dc0(v2, t, &outY);
        z = curveFn_80010dc0(v3, t, &outZ);
        ang1 = getAngle(outX, outZ) + 0x8000;
        if (flag != 0) {
            f32 xd;
            f32 zd;
            ang2 = getAngle(sqrtf(outX * outX + outZ * outZ), outY) - 0x4000;
            xd = x - *(f32 *)(out + 0xc);
            zd = z - *(f32 *)(out + 0x14);
            seg = sqrtf(xd * xd + zd * zd);
        } else {
            f32 xd;
            f32 zd;
            xd = x - *(f32 *)(out + 0xc);
            zd = z - *(f32 *)(out + 0x14);
            seg = sqrtf(xd * xd + zd * zd);
        }
        if (dist < kMin) {
            seg = -seg;
        }
        if (clamp == -1 && seg < dist) {
            *(s32 *)(o + 0x10) = *(s32 *)(n + alt * 4 + 0x18);
            *(f32 *)(o + 8) = lbl_803E0508;
            if (alt != 0 && *(s32 *)(o + 0x10) < 0) {
                *(s32 *)(o + 0x10) = *(s32 *)(n + 0x18);
            }
        } else if (clamp == 1 && seg < dist) {
            *(s32 *)(o + 0x10) = *(s32 *)(n + alt * 4 + 0x20);
            *(f32 *)(o + 8) = lbl_803E04E8;
            if (alt != 0 && *(s32 *)(o + 0x10) < 0) {
                *(s32 *)(o + 0x10) = *(s32 *)(n + 0x20);
            }
        } else {
            *(f32 *)(o + 8) = t;
        }
        dist -= seg;
        *(f32 *)(out + 0xc) = x;
        if (flag != 0) {
            *(f32 *)(out + 0x10) = y;
        }
        *(f32 *)(out + 0x14) = z;
        i += 1;
    } while (i < 3);
    *(s16 *)(out + 0) = (s16)ang1;
    if (flag != 0) {
        *(s16 *)(out + 2) = (s16)ang2;
    }
    return 0;
}
#pragma pop

#pragma peephole off
#pragma scheduling off
void Checkpoint_onGameLoop(void)
{
    u32 tmp = lbl_803DD418;
    lbl_803DD418 = lbl_803DD41C;
    lbl_803DD41C = tmp;
    lbl_803DD414 = lbl_803DD416;
    lbl_803DD416 = 0;
}
#pragma scheduling reset
#pragma peephole reset
