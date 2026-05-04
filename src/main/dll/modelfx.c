#include "ghidra_import.h"
#include "main/dll/modelfx.h"

extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293f90();
extern byte SUB41();

extern undefined4 DAT_8039d010;
extern undefined4 DAT_8039d012;
extern undefined4 DAT_8039d014;
extern undefined4 DAT_8039d018;
extern undefined4 DAT_8039d01c;
extern undefined4 DAT_8039d020;
extern undefined4 DAT_8039d024;
extern undefined4 DAT_8039d028;
extern undefined4 DAT_8039d02a;
extern undefined4 DAT_8039d02c;
extern undefined4 DAT_8039d030;
extern undefined4 DAT_8039d034;
extern undefined4 DAT_8039d038;
extern undefined4 DAT_8039d03c;
extern undefined4 DAT_8039d040;
extern undefined4 DAT_8039d042;
extern undefined4 DAT_8039d044;
extern undefined4 DAT_8039d048;
extern undefined4 DAT_8039d04c;
extern undefined4 DAT_8039d050;
extern undefined4 DAT_8039d054;
extern undefined4 DAT_8039d058;
extern undefined4 DAT_8039d05a;
extern undefined4 DAT_8039d05c;
extern undefined4 DAT_8039d060;
extern undefined4 DAT_8039d064;
extern undefined4 DAT_8039d068;
extern undefined4 DAT_8039d06c;
extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4 DAT_803de030;
extern undefined4 DAT_803de034;
extern f64 DOUBLE_803e0ba8;
extern f64 DOUBLE_803e0c20;
extern f64 DOUBLE_803e0c78;
extern f64 DOUBLE_803e0d08;
extern f64 DOUBLE_803e0d18;
extern f64 DOUBLE_803e0d20;
extern f32 lbl_803DC074;
extern f32 lbl_803DC490;
extern f32 lbl_803DC494;
extern f32 lbl_803DC498;
extern f32 lbl_803DC49C;
extern f32 lbl_803DE038;
extern f32 lbl_803DE03C;
extern f32 lbl_803E0B38;
extern f32 lbl_803E0B3C;
extern f32 lbl_803E0B40;
extern f32 lbl_803E0B44;
extern f32 lbl_803E0B48;
extern f32 lbl_803E0B4C;
extern f32 lbl_803E0B50;
extern f32 lbl_803E0B54;
extern f32 lbl_803E0B58;
extern f32 lbl_803E0B5C;
extern f32 lbl_803E0B60;
extern f32 lbl_803E0B64;
extern f32 lbl_803E0B68;
extern f32 lbl_803E0B6C;
extern f32 lbl_803E0B70;
extern f32 lbl_803E0B74;
extern f32 lbl_803E0B78;
extern f32 lbl_803E0B7C;
extern f32 lbl_803E0B80;
extern f32 lbl_803E0B84;
extern f32 lbl_803E0B88;
extern f32 lbl_803E0B8C;
extern f32 lbl_803E0B90;
extern f32 lbl_803E0B94;
extern f32 lbl_803E0B98;
extern f32 lbl_803E0B9C;
extern f32 lbl_803E0BA0;
extern f32 lbl_803E0BA4;
extern f32 lbl_803E0BB8;
extern f32 lbl_803E0BBC;
extern f32 lbl_803E0BC0;
extern f32 lbl_803E0BC4;
extern f32 lbl_803E0BC8;
extern f32 lbl_803E0BCC;
extern f32 lbl_803E0BD0;
extern f32 lbl_803E0BD4;
extern f32 lbl_803E0BD8;
extern f32 lbl_803E0BDC;
extern f32 lbl_803E0BE0;
extern f32 lbl_803E0BE4;
extern f32 lbl_803E0BE8;
extern f32 lbl_803E0BEC;
extern f32 lbl_803E0BF0;
extern f32 lbl_803E0BF4;
extern f32 lbl_803E0BF8;
extern f32 lbl_803E0BFC;
extern f32 lbl_803E0C00;
extern f32 lbl_803E0C04;
extern f32 lbl_803E0C08;
extern f32 lbl_803E0C0C;
extern f32 lbl_803E0C10;
extern f32 lbl_803E0C14;
extern f32 lbl_803E0C18;
extern f32 lbl_803E0C1C;
extern f32 lbl_803E0C28;
extern f32 lbl_803E0C2C;
extern f32 lbl_803E0C30;
extern f32 lbl_803E0C34;
extern f32 lbl_803E0C38;
extern f32 lbl_803E0C3C;
extern f32 lbl_803E0C40;
extern f32 lbl_803E0C44;
extern f32 lbl_803E0C48;
extern f32 lbl_803E0C4C;
extern f32 lbl_803E0C50;
extern f32 lbl_803E0C54;
extern f32 lbl_803E0C58;
extern f32 lbl_803E0C5C;
extern f32 lbl_803E0C60;
extern f32 lbl_803E0C64;
extern f32 lbl_803E0C68;
extern f32 lbl_803E0C6C;
extern f32 lbl_803E0C70;
extern f32 lbl_803E0C80;
extern f32 lbl_803E0C84;
extern f32 lbl_803E0C88;
extern f32 lbl_803E0C8C;
extern f32 lbl_803E0C90;
extern f32 lbl_803E0C94;
extern f32 lbl_803E0C98;
extern f32 lbl_803E0C9C;
extern f32 lbl_803E0CA0;
extern f32 lbl_803E0CA4;
extern f32 lbl_803E0CA8;
extern f32 lbl_803E0CAC;
extern f32 lbl_803E0CB0;
extern f32 lbl_803E0CB4;
extern f32 lbl_803E0CB8;
extern f32 lbl_803E0CBC;
extern f32 lbl_803E0CC0;
extern f32 lbl_803E0CC4;
extern f32 lbl_803E0CC8;
extern f32 lbl_803E0CCC;
extern f32 lbl_803E0CD0;
extern f32 lbl_803E0CD4;
extern f32 lbl_803E0CD8;
extern f32 lbl_803E0CDC;
extern f32 lbl_803E0CE0;
extern f32 lbl_803E0CE4;
extern f32 lbl_803E0CE8;
extern f32 lbl_803E0CEC;
extern f32 lbl_803E0CF0;
extern f32 lbl_803E0CF4;
extern f32 lbl_803E0CF8;
extern f32 lbl_803E0CFC;
extern f32 lbl_803E0D00;
extern f32 lbl_803E0D10;
extern f32 lbl_803E0D14;

/*
 * --INFO--
 *
 * Function: FUN_800c291c
 * EN v1.0 Address: 0x800C291C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800C2BA8
 * EN v1.1 Size: 7700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800c291c(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5,
            float *param_6)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800c2924
 * EN v1.0 Address: 0x800C2924
 * EN v1.0 Size: 244b
 * EN v1.1 Address: 0x800C49BC
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c2924(void)
{
  double dVar1;
  
  lbl_803DC498 = lbl_803DC498 + lbl_803E0B38 * lbl_803DC074;
  if (lbl_803E0B40 < lbl_803DC498) {
    lbl_803DC498 = lbl_803E0B3C;
  }
  lbl_803DC49C = lbl_803DC49C + lbl_803E0B38 * lbl_803DC074;
  if (lbl_803E0B40 < lbl_803DC49C) {
    lbl_803DC49C = lbl_803E0B48;
  }
  DAT_803de030 = DAT_803de030 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de030) {
    DAT_803de030 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE03C = (float)dVar1;
  DAT_803de034 = DAT_803de034 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de034) {
    DAT_803de034 = 0;
  }
  dVar1 = (double)FUN_80293f90();
  lbl_803DE038 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800c2a18
 * EN v1.0 Address: 0x800C2A18
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800C4AF0
 * EN v1.1 Size: 3708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c2a18(undefined4 param_1,undefined4 param_2,ushort *param_3,uint param_4,
                 undefined param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800c2a1c
 * EN v1.0 Address: 0x800C2A1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800C596C
 * EN v1.1 Size: 3796b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c2a1c(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800c2a20
 * EN v1.0 Address: 0x800C2A20
 * EN v1.0 Size: 1888b
 * EN v1.1 Address: 0x800C6840
 * EN v1.1 Size: 6724b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c2a20(undefined4 param_1,undefined4 param_2,ushort *param_3,uint param_4,
                 undefined param_5,float *param_6)
{
  ushort *puVar1;
  uint uVar2;
  undefined8 uVar3;
  ushort local_d8;
  ushort local_d6;
  ushort local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  ushort *local_c0;
  undefined4 local_bc;
  uint local_b8;
  ushort local_b4;
  ushort local_b2;
  ushort local_b0;
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
  short local_7e;
  uint local_7c;
  undefined4 local_78;
  uint local_74;
  uint local_70;
  uint local_6c;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  undefined local_62;
  byte local_60;
  undefined local_5f;
  undefined local_5e;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  uVar3 = FUN_8028683c();
  puVar1 = (ushort *)((ulonglong)uVar3 >> 0x20);
  if (puVar1 != (ushort *)0x0) {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (ushort *)0x0) goto LAB_800c826c;
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
    local_62 = (undefined)uVar3;
    local_90 = lbl_803E0C80;
    local_8c = lbl_803E0C80;
    local_88 = lbl_803E0C80;
    local_9c = lbl_803E0C80;
    local_98 = lbl_803E0C80;
    local_94 = lbl_803E0C80;
    local_84 = lbl_803E0C80;
    local_b8 = 0;
    local_bc = 0xffffffff;
    local_60 = 0xff;
    local_5f = 0;
    local_7e = 0;
    local_68 = 0xffff;
    local_66 = 0xffff;
    local_64 = 0xffff;
    local_74 = 0xffff;
    local_70 = 0xffff;
    local_6c = 0xffff;
    local_c0 = puVar1;
    switch((int)uVar3) {
    case 0x4b0:
      if (param_6 == (float *)0x0) goto LAB_800c826c;
      uStack_54 = (int)(uint)*(ushort *)param_6 >> 1 & 0xff;
      local_60 = (byte)((int)(uint)*(ushort *)param_6 >> 1);
      local_58 = 0x43300000;
      local_84 = lbl_803E0C84 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0d18);
      local_b8 = 1;
      local_7c = 0x80000;
      local_78 = 0x800;
      local_7e = 0xc7e;
      break;
    case 0x4b1:
      uStack_54 = FUN_80017760(0xffffff9c,100);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = lbl_803E0C88 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0d20);
      uStack_4c = FUN_80017760(0xffffffe7,0x96);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_98 = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0d20);
      uStack_44 = FUN_80017760(0xffffff9c,100);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = lbl_803E0C88 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      local_b8 = 100;
      local_84 = lbl_803E0C90;
      local_7c = 0x1180200;
      local_7e = 0x167;
      local_68 = 0xff00;
      local_66 = 0xff00;
      local_64 = 0xff00;
      local_74 = 0xff00;
      local_70 = 0;
      local_6c = 0;
      local_78 = 0x20;
      break;
    case 0x4b2:
      local_b8 = 0x46;
      local_84 = lbl_803E0C94;
      local_7c = 0x100100;
      local_7e = 0x73;
      local_68 = 0xff00;
      local_66 = 0xff00;
      local_64 = 0xff00;
      local_74 = 0xff00;
      local_70 = 0;
      local_6c = 0xff00;
      local_78 = 0x20;
      local_60 = 0x7f;
      break;
    case 0x4b3:
      local_b8 = 0x23;
      local_84 = lbl_803E0C98;
      local_7c = 0x100200;
      local_78 = 0x4000800;
      local_7e = 0x73;
      break;
    case 0x4b4:
      uStack_44 = FUN_80017760(0xffffffff,1);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      uStack_4c = FUN_80017760(0xfffffff9,7);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0d20);
      uStack_54 = FUN_80017760(0xffffffff,1);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0d20);
      uStack_3c = FUN_80017760(0xfffffff9,7);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80017760(0,0x1e);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_2c = FUN_80017760(0xfffffff9,7);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_94 = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_24 = FUN_80017760(0x32,100);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_84 = lbl_803E0C9C * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uVar2 = FUN_80017760(0x5c,0xc0);
      local_60 = (byte)uVar2;
      local_b8 = FUN_80017760(0x32,0x50);
      local_7c = 0x1180000;
      local_78 = 0x4400820;
      local_7e = 0x30;
      local_68 = 0;
      uVar2 = FUN_80017760(0,0xffff);
      local_66 = (undefined2)uVar2;
      uVar2 = FUN_80017760(0,0xffff);
      local_64 = (undefined2)uVar2;
      local_74 = 0;
      local_70 = 0xff00;
      local_6c = FUN_80017760(0,0xffff);
      break;
    case 0x4b5:
      if (param_6 != (float *)0x0) {
        local_9c = *param_6;
        local_98 = param_6[1];
        local_94 = param_6[2];
      }
      local_84 = lbl_803E0CA0;
      local_b8 = 0x5f;
      local_7c = 0x1180200;
      local_78 = 0x4000820;
      local_7e = 0x62;
      local_68 = 0;
      uVar2 = FUN_80017760(0x8000,0xffff);
      local_66 = (undefined2)uVar2;
      local_64 = 0;
      local_74 = FUN_80017760(0,0x8000);
      local_70 = FUN_80017760(0,0xffff);
      local_6c = 0;
      break;
    case 0x4b6:
      if (param_6 != (float *)0x0) {
        local_9c = *param_6;
        local_98 = param_6[1];
        local_94 = param_6[2];
      }
      local_60 = 0x40;
      local_84 = lbl_803E0CA4;
      local_b8 = 0x32;
      local_7c = 0x180110;
      local_78 = 0x4000800;
      local_7e = 0x62;
      break;
    case 0x4b7:
      uStack_24 = FUN_80017760(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      local_8c = lbl_803E0CA8;
      uStack_2c = FUN_80017760(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80017760(0xffffff9c,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_3c = FUN_80017760(0,0x32);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      uStack_44 = FUN_80017760(0xffffff9c,100);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      local_84 = lbl_803E0C8C;
      local_b8 = 0x28;
      local_7c = 0x80200;
      local_7e = 0x5f;
      local_60 = 0x3f;
      break;
    case 0x4b8:
      if (param_6 != (float *)0x0) {
        local_9c = *param_6;
        local_98 = param_6[1];
        local_94 = param_6[2];
      }
      local_b8 = 0x25;
      local_84 = lbl_803E0CAC;
      local_7c = 0x80200;
      local_78 = 0x4000800;
      uVar2 = FUN_80017760(0,2);
      if (uVar2 == 0) {
        local_7e = 0xc0e;
      }
      else {
        uVar2 = FUN_80017760(0x156,0x157);
        local_7e = (short)uVar2;
      }
      break;
    default:
      goto LAB_800c826c;
    case 0x4ba:
      uStack_24 = FUN_80017760(0xfffffff9,7);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80017760(0xfffffff9,7);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80017760(0xfffffff9,7);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_3c = FUN_80017760(0xffffffce,0x32);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = lbl_803E0CA4 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      uStack_44 = FUN_80017760(0xffffffce,0x32);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = lbl_803E0CA4 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      uStack_4c = FUN_80017760(0xffffffce,0x32);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = lbl_803E0CA4 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0d20);
      local_84 = lbl_803E0C8C;
      local_b8 = 0x28;
      local_60 = 0x96;
      local_7c = 0x1080200;
      local_7e = 0x62;
      local_68 = 0;
      local_66 = 0xffff;
      local_64 = 0;
      local_74 = 0xffff;
      local_70 = 0xffff;
      local_6c = 0x7fff;
      local_78 = 0x4000820;
      break;
    case 0x4bb:
      local_b8 = 0x24;
      local_84 = lbl_803E0CB0;
      local_7c = 0x100200;
      local_7e = 0x27;
      local_68 = 0xff00;
      local_66 = 0xff00;
      local_64 = 0xff00;
      local_74 = 0;
      local_70 = 0xff00;
      local_6c = 0;
      local_78 = 0x4000820;
      break;
    case 0x4bc:
      if (param_6 == (float *)0x0) goto LAB_800c826c;
      uStack_24 = FUN_80017760(0xfffffff6,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      uStack_2c = (uint)local_60;
      local_30 = 0x43300000;
      local_90 = lbl_803E0CB4 *
                 (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d18) *
                 (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_34 = FUN_80017760(0,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      uStack_3c = (uint)local_60;
      local_40 = 0x43300000;
      local_8c = lbl_803E0CB4 *
                 (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d18) *
                 (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_44 = FUN_80017760(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      uStack_4c = (uint)local_60;
      local_50 = 0x43300000;
      local_88 = lbl_803E0CB4 *
                 (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0d18) *
                 (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      uStack_54 = (uint)*param_6 & 0xff;
      local_60 = SUB41(*param_6,0);
      local_58 = 0x43300000;
      local_84 = lbl_803E0CB8 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0d18)
                 + lbl_803E0CB8;
      local_b8 = FUN_80017760(0xf,0x1e);
      local_7c = 0xc1080100;
      local_78 = 0x800;
      local_7e = 0xdb;
      break;
    case 0x4bd:
      uStack_24 = FUN_80017760(0xfffffffb,5);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80017760(0,0xf);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80017760(0xfffffffb,5);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      local_98 = lbl_803E0CBC;
      uStack_3c = FUN_80017760(5,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = lbl_803E0CC0 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      local_b8 = FUN_80017760(0x3c,0x5a);
      local_60 = 0x5a;
      local_7c = 0xc0180200;
      local_7e = 0x5f;
      local_68 = 0xff00;
      local_66 = 0xff00;
      local_64 = 0;
      local_74 = 0xff00;
      local_70 = 0;
      local_6c = 0x8000;
      local_78 = 0x4000820;
      break;
    case 0x4be:
      uStack_24 = FUN_80017760(0xfffffe3e,0x1c2);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      local_8c = lbl_803E0CC4;
      uStack_2c = FUN_80017760(0xfffffe3e,0x1c2);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80017760(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_3c = FUN_80017760(0,0x14);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = lbl_803E0CC8 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      uStack_44 = FUN_80017760(0xffffffec,0x14);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      uStack_4c = FUN_80017760(0,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_84 = lbl_803E0CD0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0d20)
                 + lbl_803E0CCC;
      local_b8 = FUN_80017760(0xbe,0xfa);
      local_7c = 0x81488000;
      uVar2 = FUN_80017760(0,2);
      local_7e = (short)uVar2 + 0x208;
      local_68 = 0x2000;
      local_66 = 0x8000;
      local_64 = 0xc000;
      local_74 = 0xc000;
      local_70 = 0xff00;
      local_6c = 0xff00;
      local_78 = 0x20;
      break;
    case 0x4bf:
      uStack_24 = FUN_80017760(0xffffff92,0x6e);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      local_8c = lbl_803E0CD4;
      uStack_2c = FUN_80017760(0xffffffc4,0x3c);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      local_84 = lbl_803E0CD8;
      local_b8 = 100;
      local_7c = 0x11000004;
      local_7e = 0x151;
      local_68 = 0xff00;
      local_66 = 0x4000;
      local_64 = 0;
      local_74 = 0x4000;
      local_70 = 0xc800;
      local_6c = 0;
      local_bc = 0x4c0;
      local_78 = 0x20;
      break;
    case 0x4c0:
      local_8c = lbl_803E0CDC;
      local_b8 = 0x4b;
      uStack_24 = 0x8000004b;
      local_28 = 0x43300000;
      local_84 = lbl_803E0CE0 * (float)(4503601774854219.0 - DOUBLE_803e0d20);
      local_7c = 0xa100200;
      local_7e = 0x56;
      break;
    case 0x4c1:
      uStack_24 = FUN_80017760(0xfffffffb,5);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80017760(0xfffffffb,5);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80017760(0xfffffffb,5);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_3c = FUN_80017760(0xffffff88,0x78);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      uVar2 = FUN_80017760(0xffffffff,1);
      uStack_44 = uVar2 * 0xc ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      uStack_4c = FUN_80017760(0xffffffba,0x46);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0d20);
      local_84 = lbl_803E0C88;
      local_b8 = 200;
      local_7c = 0xa100100;
      local_7e = 0xc10;
      local_68 = 0xff00;
      local_66 = 0xff00;
      local_64 = 0;
      local_74 = 0xff00;
      local_70 = 0;
      local_6c = 0x8000;
      local_78 = 0x20;
      break;
    case 0x4c2:
      uStack_24 = FUN_80017760(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80017760(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_94 = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      local_84 = lbl_803E0CE4;
      local_b8 = 0x46;
      local_7c = 0xa100200;
      local_78 = 0x1000800;
      local_7e = 0x5f;
      local_60 = 0x40;
      break;
    case 0x4c3:
      uStack_24 = FUN_80017760(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80017760(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_94 = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80017760(0xfffffe70,400);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_3c = FUN_80017760(0xfffffe70,400);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      local_84 = lbl_803E0CE8;
      local_b8 = 600;
      local_60 = 0x7f;
      local_7c = 0xa100100;
      local_7e = 0x62;
      break;
    case 0x4c4:
      local_84 = lbl_803E0CE8;
      local_b8 = FUN_80017760(100,300);
      local_60 = 0xb4;
      local_7c = 0x80180208;
      local_7e = 0x62;
      break;
    case 0x4c5:
      if (param_3 == (ushort *)0x0) {
        DAT_8039d064 = lbl_803E0C80;
        DAT_8039d068 = lbl_803E0C80;
        DAT_8039d06c = lbl_803E0C80;
        DAT_8039d060 = lbl_803E0CEC;
        DAT_8039d058 = 0;
        DAT_8039d05a = 0;
        DAT_8039d05c = 0;
      }
      uStack_24 = FUN_80017760(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80017760(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = lbl_803E0C8C * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80017760(10,0x1e);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = lbl_803E0CF0 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      local_cc = lbl_803E0C80;
      local_c8 = lbl_803E0C80;
      local_c4 = lbl_803E0C80;
      local_d0 = lbl_803E0CEC;
      local_d4 = puVar1[2];
      local_d6 = puVar1[1];
      local_d8 = *puVar1;
      FUN_80017748(&local_d8,&local_9c);
      local_7c = 0x3000000;
      local_78 = 0x200000;
      local_84 = lbl_803E0C8C;
      local_60 = 0xff;
      local_b8 = 0x32;
      local_7e = 0x151;
      break;
    case 0x4c6:
      local_60 = 0x40;
      local_84 = lbl_803E0CBC;
      local_b8 = 1;
      local_7c = 0x6000000;
      local_7e = 0x45b;
      local_a8 = lbl_803E0C80;
      local_a4 = lbl_803E0C80;
      local_a0 = lbl_803E0C80;
      local_ac = lbl_803E0CEC;
      local_b0 = puVar1[2];
      local_b2 = puVar1[1];
      local_b4 = *puVar1;
      break;
    case 0x4c7:
      local_60 = 0x40;
      local_84 = lbl_803E0CF4;
      local_b8 = 1;
      local_7c = 0x6000000;
      local_7e = 0x45b;
      local_a8 = lbl_803E0C80;
      local_a4 = lbl_803E0C80;
      local_a0 = lbl_803E0C80;
      local_ac = lbl_803E0CEC;
      local_b0 = puVar1[2];
      local_b2 = puVar1[1];
      local_b4 = *puVar1;
      break;
    case 0x4c8:
      uStack_24 = FUN_80017760(0xfffffff6,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = lbl_803E0CF8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80017760(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = lbl_803E0CF8 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80017760(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = lbl_803E0CF8 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      local_84 = lbl_803E0CFC;
      local_b8 = FUN_80017760(0x4b,100);
      local_60 = 0x7f;
      local_7c = 0x1080200;
      local_7e = 0x151;
      break;
    case 0x4c9:
      local_b8 = FUN_80017760(0x3c,100);
      uStack_24 = FUN_80017760(0xffffffce,0x32);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = lbl_803E0CBC * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = local_b8 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = lbl_803E0D00 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80017760(0xffffffce,0x32);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = lbl_803E0CBC * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      local_84 = lbl_803E0C90;
      local_7c = 0x3000000;
      local_78 = 0x600020;
      local_7e = 0x20d;
      local_60 = 0xff;
      local_74 = 0xffff;
      local_70 = 0xffff;
      local_6c = 0xffff;
      local_68 = 0xffff;
      local_66 = 0x4000;
      local_64 = 0;
      break;
    case 0x4ca:
      uStack_24 = FUN_80017760(0xffffff38,200);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = lbl_803E0CC8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80017760(0xffffff38,200);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = lbl_803E0CC8 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80017760(0xf,0x2d);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)(DOUBLE_803e0d08 *
                        (double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20));
      uStack_3c = FUN_80017760(6,0xc);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = lbl_803E0D10 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      local_b8 = FUN_80017760(0x46,0x82);
      local_7c = 0x1580000;
      local_78 = 0x400000;
      local_7e = 0x23b;
      local_60 = 0xff;
      break;
    case 0x4cb:
      uStack_24 = FUN_80017760(8,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_98 = lbl_803E0CE8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80017760(6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = lbl_803E0D14 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      local_b8 = FUN_80017760(0x3c,0x78);
      local_7c = 0x80080000;
      local_78 = 0x4440820;
      local_74 = 0xffff;
      local_70 = 0xffff;
      local_6c = 0;
      local_68 = 0xffff;
      local_66 = 0;
      local_64 = 0;
      local_7e = 0xc0b;
      local_60 = 0x40;
      break;
    case 0x4cc:
      local_b8 = FUN_80017760(0x3c,100);
      uStack_24 = FUN_80017760(0xffffffce,0x32);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = lbl_803E0CBC * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = local_b8 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = lbl_803E0D00 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80017760(0xffffffce,0x32);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = lbl_803E0CBC * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      local_84 = lbl_803E0C90;
      local_7c = 0x3000000;
      local_78 = 0x600020;
      local_7e = 0x20d;
      local_60 = 0xff;
      local_74 = 0xffff;
      local_70 = 0xffff;
      local_6c = 0xffff;
      local_68 = 0x4000;
      local_66 = 0xffff;
      local_64 = 0;
      break;
    case 0x4cd:
      uStack_24 = FUN_80017760(8,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_98 = lbl_803E0CE8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80017760(6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = lbl_803E0D14 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      local_b8 = FUN_80017760(0x3c,0x78);
      local_7c = 0x80080000;
      local_78 = 0x4440820;
      local_74 = 0xffff;
      local_70 = 0xffff;
      local_6c = 0;
      local_68 = 0;
      local_66 = 0xffff;
      local_64 = 0;
      local_7e = 0xc0b;
      local_60 = 0x40;
    }
    local_7c = local_7c | param_4;
    if (((local_7c & 1) != 0) && ((local_7c & 2) != 0)) {
      local_7c = local_7c ^ 2;
    }
    if ((local_7c & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_c0 != (ushort *)0x0) {
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
    (**(code **)(*DAT_803dd6f8 + 8))(&local_c0,0xffffffff,(int)uVar3,0);
  }
LAB_800c826c:
  FUN_80286888();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_800C4858(void) {}
void fn_800C485C(void) {}
void fn_800C4860(void) {}
void fn_800C56D0(void) {}
void fn_800C56D4(void) {}
void fn_800C56D8(void) {}
void fn_800C56DC(void) {}
void fn_800C65A4(void) {}
void fn_800C65A8(void) {}
void fn_800C65AC(void) {}
void fn_800C65B0(void) {}
void fn_800C7FF8(void) {}
void fn_800C7FFC(void) {}
void fn_800C8000(void) {}
void fn_800C8004(void) {}
