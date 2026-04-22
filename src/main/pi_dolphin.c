#include "ghidra_import.h"
#include "main/pi_dolphin.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_8000f4a0();
extern undefined4 FUN_8000f578();
extern undefined4 FUN_8000f7a0();
extern uint FUN_80013774();
extern uint FUN_8001377c();
extern undefined4 FUN_8001378c();
extern undefined4 FUN_800137c8();
extern undefined4 FUN_8001383c();
extern undefined4 FUN_800138ac();
extern uint FUN_80014e9c();
extern undefined8 FUN_80014f6c();
extern undefined4 FUN_80015650();
extern undefined4 FUN_80015888();
extern undefined8 FUN_80019c5c();
extern uint FUN_80020078();
extern undefined4 FUN_80020390();
extern undefined8 FUN_800206cc();
extern double FUN_80021794();
extern uint FUN_80022264();
extern undefined4 FUN_80022e00();
extern undefined4 FUN_80022e1c();
extern undefined8 FUN_800235b0();
extern undefined8 FUN_800238c4();
extern int FUN_80023d8c();
extern void* FUN_8002419c();
extern undefined4 FUN_800241f8();
extern undefined4 FUN_80024240();
extern undefined4 FUN_800293b8();
extern undefined4 FUN_8002a51c();
extern int FUN_8002a690();
extern uint FUN_8002a698();
extern int FUN_8002bac4();
extern undefined4 FUN_80041e28();
extern undefined4 FUN_80041f34();
extern undefined4 FUN_80042338();
extern undefined4 FUN_800423f0();
extern undefined4 FUN_800424a8();
extern undefined4 FUN_80042560();
extern undefined4 FUN_80042618();
extern undefined4 FUN_800426d0();
extern undefined4 FUN_80042734();
extern undefined4 FUN_800427ec();
extern undefined4 FUN_800428b8();
extern undefined4 FUN_80042984();
extern undefined4 FUN_80042a3c();
extern undefined4 FUN_80042b08();
extern undefined4 FUN_80042bd4();
extern undefined4 FUN_80042c8c();
extern undefined4 FUN_80042d44();
extern undefined4 FUN_80042dfc();
extern undefined4 FUN_80042eb4();
extern undefined4 FUN_800431d8();
extern undefined4 FUN_80043e64();
extern uint FUN_8005383c();
extern undefined4 FUN_8005387c();
extern undefined4 FUN_80053dbc();
extern undefined4 FUN_80054e14();
extern undefined4 FUN_80056d08();
extern undefined4 FUN_80060cbc();
extern undefined4 FUN_8006c680();
extern undefined4 FUN_8006c68c();
extern undefined4 FUN_8006c6a4();
extern undefined4 FUN_8006c6bc();
extern undefined4 FUN_8006c734();
extern undefined4 FUN_8006c760();
extern double FUN_8006c7ec();
extern undefined4 FUN_8006c86c();
extern int FUN_8006c8c8();
extern int FUN_8006c8d0();
extern undefined4 FUN_8006c8d8();
extern undefined4 FUN_8006cc38();
extern undefined4 FUN_80070434();
extern undefined4 FUN_8007048c();
extern undefined4 FUN_8007d858();
extern undefined4 FUN_80089ab8();
extern undefined4 FUN_80118434();
extern undefined8 FUN_801378a8();
extern undefined4 FUN_80137cd0();
extern undefined8 FUN_80137f08();
extern undefined4 FUN_80241cfc();
extern int FUN_80241d0c();
extern int FUN_80241d7c();
extern uint FUN_80241de8();
extern int FUN_80241df0();
extern undefined4 FUN_80241e00();
extern undefined4 FUN_802420b0();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_80242114();
extern undefined4 FUN_80243e74();
extern undefined4 FUN_80243e9c();
extern uint FUN_8024533c();
extern undefined4 FUN_80246190();
extern undefined4 FUN_802461cc();
extern undefined8 FUN_80246298();
extern undefined4 FUN_80246308();
extern undefined4 FUN_802464dc();
extern undefined4 FUN_802464ec();
extern undefined4 FUN_802471c4();
extern undefined4 FUN_802472b0();
extern undefined4 FUN_802475b8();
extern undefined4 FUN_80247618();
extern undefined4 FUN_8024782c();
extern undefined4 FUN_80247944();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_80247b70();
extern undefined4 FUN_80247dfc();
extern int FUN_80249300();
extern undefined4 FUN_802493c8();
extern undefined4 FUN_80249610();
extern undefined4 FUN_8024c8cc();
extern undefined4 FUN_8024c910();
extern undefined4 FUN_8024d054();
extern undefined4 FUN_8024d51c();
extern undefined4 FUN_8024dcb8();
extern undefined4 FUN_8024ddd4();
extern undefined4 FUN_8024de40();
extern undefined4 FUN_802554d0();
extern undefined4 FUN_8025665c();
extern undefined4 FUN_80256738();
extern undefined4 FUN_80256744();
extern undefined4 FUN_80256854();
extern undefined8 FUN_80256ac8();
extern undefined4 FUN_80256b2c();
extern undefined4 FUN_80256bc4();
extern undefined8 FUN_80256c08();
extern undefined8 FUN_80256ca0();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_80257ba8();
extern undefined4 FUN_80258664();
extern undefined4 FUN_80258674();
extern undefined4 FUN_8025898c();
extern undefined4 FUN_80258a04();
extern undefined4 FUN_80258a94();
extern undefined4 FUN_80258b60();
extern short FUN_80258c18();
extern undefined4 FUN_80258dac();
extern undefined4 FUN_80259224();
extern undefined4 FUN_80259288();
extern undefined4 FUN_80259340();
extern undefined4 FUN_802594c0();
extern undefined4 FUN_8025971c();
extern undefined4 FUN_802597f0();
extern undefined4 FUN_80259858();
extern undefined4 FUN_80259a80();
extern undefined8 FUN_80259a9c();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_8025aa74();
extern undefined4 FUN_8025ace8();
extern undefined4 FUN_8025aeac();
extern undefined4 FUN_8025b054();
extern undefined4 FUN_8025b210();
extern undefined4 FUN_8025b94c();
extern undefined4 FUN_8025b9e8();
extern undefined4 FUN_8025bb48();
extern undefined4 FUN_8025bd1c();
extern undefined4 FUN_8025be80();
extern undefined4 FUN_8025bec8();
extern undefined4 FUN_8025c000();
extern undefined4 FUN_8025c1a4();
extern undefined4 FUN_8025c224();
extern undefined4 FUN_8025c2a8();
extern undefined4 FUN_8025c368();
extern undefined4 FUN_8025c428();
extern undefined4 FUN_8025c49c();
extern undefined4 FUN_8025c510();
extern undefined4 FUN_8025c584();
extern undefined4 FUN_8025c5f0();
extern undefined4 FUN_8025c65c();
extern undefined4 FUN_8025c6b4();
extern undefined4 FUN_8025c828();
extern undefined4 FUN_8025cce8();
extern undefined8 FUN_8025ce2c();
extern undefined4 FUN_8025cf24();
extern undefined4 FUN_8025d034();
extern undefined4 FUN_8025d100();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d888();
extern undefined4 FUN_8025d8c4();
extern undefined4 FUN_8025da64();
extern undefined4 FUN_8025da88();
extern undefined4 FUN_8025dc78();
extern undefined4 FUN_8025e520();
extern int FUN_80286718();
extern ulonglong FUN_80286820();
extern longlong FUN_8028682c();
extern uint FUN_80286830();
extern uint FUN_80286834();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80286cd0();
extern undefined8 FUN_8028fde8();
extern int FUN_80291d74();
extern undefined4 FUN_802943c4();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();
extern uint countLeadingZeros();

extern undefined4 DAT_800000f8;
extern undefined1 DAT_802c23d0;
extern undefined4 DAT_802c23e4;
extern undefined4 DAT_802c23e6;
extern undefined4 DAT_802c2458;
extern undefined4 DAT_802c245a;
extern undefined4 DAT_802c24d0;
extern undefined4 DAT_802c24d4;
extern undefined4 DAT_802c24d8;
extern undefined4 DAT_802c24dc;
extern undefined4 DAT_802c24e0;
extern undefined4 DAT_802c24e4;
extern undefined4 DAT_802c24e8;
extern undefined4 DAT_802c24ec;
extern undefined4 DAT_802c24f0;
extern undefined4 DAT_802c24f4;
extern undefined4 DAT_802c24f8;
extern undefined4 DAT_802c24fc;
extern undefined4 DAT_802c2500;
extern undefined4 DAT_802c2504;
extern undefined4 DAT_802c2508;
extern undefined4 DAT_802c250c;
extern undefined4 DAT_802c2510;
extern undefined4 DAT_802c2514;
extern undefined4 DAT_802c2518;
extern undefined4 DAT_802c251c;
extern undefined4 DAT_802c2520;
extern undefined4 DAT_802c2524;
extern undefined4 DAT_802c2528;
extern undefined4 DAT_802c252c;
extern undefined4 DAT_802c2530;
extern undefined4 DAT_802c2534;
extern undefined4 DAT_802c2538;
extern undefined4 DAT_802c253c;
extern undefined4 DAT_802c2540;
extern undefined4 DAT_802c2544;
extern undefined4 DAT_802c2548;
extern undefined4 DAT_802c254c;
extern undefined4 DAT_802c2550;
extern undefined4 DAT_802c2554;
extern undefined4 DAT_802c2558;
extern undefined4 DAT_802c255c;
extern undefined4 DAT_802c2560;
extern undefined4 DAT_802c2564;
extern undefined4 DAT_802c2568;
extern undefined4 DAT_802c256c;
extern undefined4 DAT_802c2570;
extern undefined4 DAT_802c2574;
extern undefined4 DAT_802c2590;
extern undefined4 DAT_802c2594;
extern undefined4 DAT_802c2598;
extern undefined4 DAT_802c259c;
extern undefined4 DAT_802c25a0;
extern undefined4 DAT_802c25a4;
extern undefined4 DAT_802c25a8;
extern undefined4 DAT_802c25ac;
extern undefined4 DAT_802c25b0;
extern undefined4 DAT_802c25b4;
extern undefined4 DAT_802c25b8;
extern undefined4 DAT_802c25bc;
extern int DAT_802cc8a8;
extern undefined4 DAT_802cc9d4;
extern undefined4 DAT_802cd260;
extern undefined DAT_8030d440;
extern undefined DAT_8030d960;
extern undefined DAT_8030d980;
extern undefined4 DAT_8030d9a0;
extern undefined4 DAT_8030da9c;
extern undefined4 DAT_8032f2b4;
extern undefined4 DAT_80346bd0;
extern undefined4 DAT_80346d30;
extern undefined4 DAT_8034ec70;
extern undefined4 DAT_80350c70;
extern undefined4 DAT_80352c70;
extern undefined4 DAT_80356c70;
extern undefined4 DAT_8035ac70;
extern undefined4 DAT_8035db50;
extern undefined DAT_8035fb50;
extern int DAT_8035fba8;
extern undefined4 DAT_8035fbdc;
extern undefined4 DAT_8035fc28;
extern undefined4 DAT_8035fc34;
extern undefined4 DAT_8035fc3c;
extern undefined4 DAT_8035fc54;
extern undefined4 DAT_8035fc68;
extern undefined4 DAT_8035fcc0;
extern undefined4 DAT_8035fcc4;
extern undefined4 DAT_8035fcd0;
extern undefined4 DAT_8035fcd4;
extern undefined4 DAT_8035fcdc;
extern undefined4 DAT_8035fcfc;
extern int DAT_8035fd08;
extern undefined4 DAT_8035fd8c;
extern undefined4 DAT_8035fd98;
extern undefined4 DAT_8035fe68;
extern int DAT_80360048;
extern undefined4 DAT_8036007c;
extern undefined4 DAT_80360080;
extern undefined4 DAT_803600b0;
extern undefined4 DAT_803600b4;
extern undefined4 DAT_803600bc;
extern undefined4 DAT_803600c0;
extern undefined4 DAT_803600c8;
extern undefined4 DAT_803600cc;
extern undefined4 DAT_803600d4;
extern undefined4 DAT_803600d8;
extern undefined4 DAT_803600dc;
extern undefined4 DAT_803600e0;
extern undefined4 DAT_803600f0;
extern undefined4 DAT_803600f4;
extern undefined4 DAT_80360104;
extern undefined4 DAT_80360108;
extern undefined4 DAT_8036015c;
extern undefined4 DAT_80360160;
extern undefined4 DAT_80360164;
extern undefined4 DAT_80360168;
extern undefined4 DAT_8036016c;
extern undefined4 DAT_80360170;
extern undefined4 DAT_80360174;
extern undefined4 DAT_80360178;
extern undefined4 DAT_8036017c;
extern undefined4 DAT_80360180;
extern undefined4 DAT_80360184;
extern undefined4 DAT_80360188;
extern undefined4 DAT_80360190;
extern undefined4 DAT_80360194;
extern undefined4 DAT_80360198;
extern undefined4 DAT_8036019c;
extern undefined4 DAT_803601a0;
extern undefined2 DAT_803601a8;
extern undefined4 DAT_803601c2;
extern undefined4 DAT_803601c4;
extern undefined4 DAT_803601dc;
extern undefined4 DAT_803601de;
extern undefined4 DAT_803601e8;
extern undefined4 DAT_803601ea;
extern undefined4 DAT_803601ee;
extern undefined4 DAT_803601f0;
extern undefined4 DAT_803601f2;
extern undefined4 DAT_803601f4;
extern undefined4 DAT_803601fc;
extern undefined4 DAT_803601fe;
extern undefined4 DAT_80360206;
extern undefined4 DAT_80360208;
extern undefined4 DAT_80360232;
extern undefined4 DAT_80360234;
extern undefined4 DAT_80360236;
extern undefined4 DAT_80360238;
extern undefined4 DAT_8036023a;
extern undefined4 DAT_8036023c;
extern undefined4 DAT_8036023e;
extern undefined4 DAT_80360240;
extern undefined4 DAT_80360242;
extern undefined4 DAT_80360244;
extern undefined4 DAT_8036024e;
extern undefined4 DAT_80360250;
extern undefined4 DAT_80360252;
extern undefined4 DAT_80360254;
extern undefined4 DAT_80360318;
extern undefined4 DAT_80360390;
extern undefined DAT_803603a0;
extern undefined DAT_803704c0;
extern undefined DAT_803704e0;
extern undefined DAT_803784e0;
extern undefined2 DAT_803784f4;
extern short DAT_80378512;
extern undefined2 DAT_80378514;
extern undefined4 DAT_80378534;
extern undefined4 DAT_803785d4;
extern undefined4 DAT_80378600;
extern ushort DAT_80397240;
extern ushort DAT_80397330;
extern undefined4 DAT_80397480;
extern undefined4 DAT_803974e0;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc071;
extern undefined4 DAT_803dc218;
extern undefined4 DAT_803dc228;
extern undefined4 DAT_803dc22c;
extern undefined4 DAT_803dc22e;
extern undefined4 DAT_803dc230;
extern undefined4 DAT_803dc234;
extern undefined4 DAT_803dc23c;
extern undefined4 DAT_803dc248;
extern undefined4 DAT_803dc254;
extern undefined4 DAT_803dc258;
extern undefined4 DAT_803dd5d0;
extern undefined4* DAT_803dd71c;
extern undefined4 DAT_803dd8f0;
extern undefined4 DAT_803dd8f4;
extern undefined4 DAT_803dd8f8;
extern undefined4 DAT_803dd8fc;
extern undefined4 DAT_803dd900;
extern undefined4 DAT_803dd904;
extern undefined4 DAT_803dd908;
extern undefined4 DAT_803dd90c;
extern undefined4 DAT_803dd910;
extern undefined4 DAT_803dd912;
extern undefined4 DAT_803dd918;
extern undefined4 DAT_803dd920;
extern undefined4 DAT_803dd924;
extern undefined4 DAT_803dd925;
extern undefined4 DAT_803dd926;
extern undefined4 DAT_803dd927;
extern undefined4 DAT_803dd928;
extern undefined4 DAT_803dd929;
extern undefined4 DAT_803dd92a;
extern undefined4 DAT_803dd92c;
extern undefined4 DAT_803dd930;
extern undefined4 DAT_803dd938;
extern undefined4 DAT_803dd944;
extern undefined4 DAT_803dd94c;
extern undefined4 DAT_803dd950;
extern undefined4 DAT_803dd954;
extern undefined4* DAT_803dd958;
extern undefined4 DAT_803dd95c;
extern undefined4* DAT_803dd960;
extern undefined4 DAT_803dd964;
extern undefined4 DAT_803dd968;
extern undefined4 DAT_803dd96c;
extern undefined4* DAT_803dd970;
extern undefined4 DAT_803dd974;
extern undefined4 DAT_803dd978;
extern undefined4 DAT_803dd97c;
extern undefined4 DAT_803dd980;
extern undefined4 DAT_803dd988;
extern undefined4 DAT_803dd990;
extern undefined1 DAT_803dd998;
extern undefined DAT_803dd9a0;
extern undefined4 DAT_803dd9a8;
extern undefined4 DAT_803dd9ac;
extern undefined4 DAT_803dd9b0;
extern undefined4 DAT_803dd9b1;
extern undefined4 DAT_803dd9e8;
extern undefined4 DAT_803dd9e9;
extern undefined4 DAT_803dd9ea;
extern undefined4 DAT_803dd9eb;
extern undefined4 DAT_803dd9ec;
extern undefined4 DAT_803dd9f0;
extern undefined4 DAT_803dd9f4;
extern undefined4 DAT_803dd9f8;
extern undefined4 DAT_803dd9fc;
extern undefined4 DAT_803dda00;
extern undefined4 DAT_803dda04;
extern undefined4 DAT_803dda08;
extern undefined4 DAT_803dda0c;
extern undefined4 DAT_803dda10;
extern undefined4 DAT_803ddc80;
extern undefined4 DAT_803ddc82;
extern undefined4 DAT_803de288;
extern undefined4 DAT_803de6a8;
extern undefined4 DAT_803df730;
extern undefined4 DAT_803df734;
extern undefined4 DAT_803df738;
extern undefined4 DAT_803df73c;
extern undefined4 DAT_803df740;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803df700;
extern f64 DOUBLE_803df728;
extern f64 DOUBLE_803df7b0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803dc250;
extern f32 FLOAT_803dd934;
extern f32 FLOAT_803dd940;
extern f32 FLOAT_803dd9b4;
extern f32 FLOAT_803dd9b8;
extern f32 FLOAT_803dd9bc;
extern f32 FLOAT_803dd9c0;
extern f32 FLOAT_803dd9c4;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803df6f0;
extern f32 FLOAT_803df6f4;
extern f32 FLOAT_803df6f8;
extern f32 FLOAT_803df6fc;
extern f32 FLOAT_803df708;
extern f32 FLOAT_803df70c;
extern f32 FLOAT_803df710;
extern f32 FLOAT_803df714;
extern f32 FLOAT_803df718;
extern f32 FLOAT_803df71c;
extern f32 FLOAT_803df720;
extern f32 FLOAT_803df744;
extern f32 FLOAT_803df748;
extern f32 FLOAT_803df74c;
extern f32 FLOAT_803df750;
extern f32 FLOAT_803df754;
extern f32 FLOAT_803df75c;
extern f32 FLOAT_803df760;
extern f32 FLOAT_803df764;
extern f32 FLOAT_803df768;
extern f32 FLOAT_803df76c;
extern f32 FLOAT_803df770;
extern f32 FLOAT_803df774;
extern f32 FLOAT_803df778;
extern f32 FLOAT_803df77c;
extern f32 FLOAT_803df780;
extern f32 FLOAT_803df784;
extern f32 FLOAT_803df788;
extern f32 FLOAT_803df78c;
extern f32 FLOAT_803df790;
extern f32 FLOAT_803df794;
extern f32 FLOAT_803df798;
extern f32 FLOAT_803df79c;
extern f32 FLOAT_803df7a0;
extern f32 FLOAT_803df7a4;
extern f32 FLOAT_803df7a8;
extern f32 FLOAT_803df7ac;
extern f32 FLOAT_803df7b8;
extern f32 FLOAT_803df7bc;
extern f32 FLOAT_803df7c0;
extern void* PTR_LAB_802cd0ec;
extern undefined* PTR_s_AUDIO_tab_802cbecc;
extern void* PTR_s_animtest_802cc784;
extern void* PTR_s_frontend_802cc518;
extern undefined4 _DAT_00360048;
extern undefined4 _DAT_803dc24c;
extern char s_GP_appears_to_be_not_hung__waiti_8030d314[];
extern char s_GP_hang_due_to_XF_stall_bug__8030d2a8[];
extern char s_GP_hang_due_to_illegal_instructi_8030d2f0[];
extern char s_GP_hang_due_to_unterminated_prim_8030d2c8[];
extern char s_GP_is_in_unknown_state__8030d344[];
extern char s_Suspected_graphics_hang_or_infin_8030d260[];
extern char s__s_animcurv_bin_802ccf30[];
extern char s__s_animcurv_tab_802ccf40[];
extern char s__s_mod_d_tab_802ccf98[];
extern char s__s_mod_d_zlb_bin_802ccf84[];
extern char s__s_romlist_zlb_802cd0dc[];
extern char s__s_voxmap_bin_802ccf50[];
extern char s__s_voxmap_tab_802ccf74[];
extern char s_warlock_voxmap_bin_802ccf60[];
extern undefined4 uRam00000000;
extern undefined uRam803dc24f;

/*
 * --INFO--
 *
 * Function: FUN_80044510
 * EN v1.0 Address: 0x80044510
 * EN v1.0 Size: 56b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80044510(int param_1)
{
  if (DAT_803601f2 == param_1) {
    return 0;
  }
  if (DAT_80360236 == param_1) {
    return 1;
  }
  return 0xffffffff;
}

/*
 * --INFO--
 *
 * Function: FUN_80044548
 * EN v1.0 Address: 0x80044548
 * EN v1.0 Size: 8444b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80044548(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80046644
 * EN v1.0 Address: 0x80046644
 * EN v1.0 Size: 7400b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80046644(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint *param_13,
                 int param_14,uint param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8004832c
 * EN v1.0 Address: 0x8004832C
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8004832c(int param_1)
{
  if (0x4a < param_1) {
    return 5;
  }
  return (&DAT_802cc8a8)[param_1];
}

/*
 * --INFO--
 *
 * Function: FUN_80048350
 * EN v1.0 Address: 0x80048350
 * EN v1.0 Size: 340b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80048350(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800484a4
 * EN v1.0 Address: 0x800484A4
 * EN v1.0 Size: 436b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800484a4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined4 *puVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  undefined8 uVar6;
  char acStack_418 [1048];
  
  uVar6 = FUN_80286840();
  iVar4 = (int)uVar6;
  if ((param_11 == 0) && ((&DAT_8035fe68)[iVar4] == 0)) {
    uVar6 = FUN_8028fde8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)acStack_418,s__s_romlist_zlb_802cd0dc,
                         (&PTR_s_frontend_802cc518)[iVar4],param_12,param_13,param_14,param_15,
                         param_16);
    puVar1 = FUN_8002419c(DAT_803dd90c);
    iVar2 = FUN_80249300(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_418,
                         (int)puVar1);
    if (iVar2 != 0) {
      iVar2 = FUN_80023d8c(puVar1[0xd],0x7d7d7d7d);
      (&DAT_8035fe68)[iVar4] = iVar2;
      DAT_803dd8f4 = 1;
      FUN_80249610(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar1,
                   (&DAT_8035fe68)[iVar4],puVar1[0xd],0,FUN_800426d0,2,param_15,param_16);
    }
  }
  else {
    if ((&DAT_8035fe68)[iVar4] == 0) {
      uVar5 = FUN_8028fde8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (int)acStack_418,s__s_romlist_zlb_802cd0dc,
                           (&PTR_s_frontend_802cc518)[iVar4],param_12,param_13,param_14,param_15,
                           param_16);
      piVar3 = FUN_8002419c(DAT_803dd90c);
      iVar2 = FUN_80249300(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,acStack_418
                           ,(int)piVar3);
      if (iVar2 == 0) goto LAB_80048640;
      iVar2 = FUN_80023d8c(piVar3[0xd],0x7d7d7d7d);
      (&DAT_8035fe68)[iVar4] = iVar2;
      FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,piVar3,
                   (&DAT_8035fe68)[iVar4],piVar3[0xd],0,param_13,param_14,param_15,param_16);
      FUN_802493c8(piVar3);
      FUN_800241f8(DAT_803dd90c,piVar3);
    }
    piVar3 = (int *)(DAT_803600bc + (int)((ulonglong)uVar6 >> 0x20));
    if (*piVar3 == -0x5310113) {
      FUN_8004b7d4((&DAT_8035fe68)[iVar4] + 0x10,piVar3[3],param_11);
      FUN_80242114(param_11,piVar3[1]);
    }
  }
LAB_80048640:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80048658
 * EN v1.0 Address: 0x80048658
 * EN v1.0 Size: 720b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80048658(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 *param_11,undefined4 *param_12,
                 int param_13,uint param_14,int param_15,undefined4 param_16)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  undefined8 extraout_f1;
  undefined8 uVar9;
  int aiStack_68 [26];
  
  uVar1 = FUN_80286830();
  iVar8 = -1;
  if ((DAT_803600c8 != 0) || (DAT_80360174 != 0)) {
    iVar5 = param_13;
    uVar6 = param_14;
    iVar7 = param_15;
    uVar9 = extraout_f1;
    FUN_80243e74();
    uVar2 = DAT_803dd900;
    FUN_80243e9c();
    if (((uVar1 & 0x80000000) == 0) || ((uVar2 & 0x2000) != 0)) {
      if (((uVar1 & 0x40000000) == 0) || ((uVar2 & 0x1000) != 0)) {
        if ((DAT_803600cc == 0) || (((uVar2 & 0x1000) != 0 || (DAT_803600c8 == 0)))) {
          if ((DAT_80360178 != 0) && (((uVar2 & 0x2000) == 0 && (DAT_80360174 != 0)))) {
            iVar8 = 0x4b;
          }
        }
        else {
          iVar8 = 0x20;
        }
      }
      else {
        iVar8 = 0x20;
      }
    }
    else {
      iVar8 = 0x4b;
    }
    iVar3 = (&DAT_80360048)[iVar8];
    if (iVar3 == 0) {
      FUN_80249300(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (&PTR_s_AUDIO_tab_802cbecc)[iVar8],(int)aiStack_68);
      uVar2 = FUN_80023d8c(0x400,0x7f7f7fff);
      FUN_80015888(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_68,uVar2,
                   0x400,(uVar1 & 0xffffff) << 1,iVar5,uVar6,iVar7,param_16);
      FUN_802493c8(aiStack_68);
      FUN_80242114(uVar2,0x400);
      if ((param_15 == 1) && (param_14 != 0)) {
        iVar8 = uVar2 + *(int *)(param_14 + param_13 * 4) + 4;
        uVar4 = *(undefined4 *)(iVar8 + 4);
        *param_12 = *(undefined4 *)(iVar8 + 8);
        *param_11 = uVar4;
      }
      else if ((param_15 == 2) && (param_14 != 0)) {
        FUN_80003494(param_14,uVar2,(param_13 + 1) * 4);
      }
      else {
        uVar4 = *(undefined4 *)(uVar2 + 0xc);
        *param_11 = *(undefined4 *)(uVar2 + 8);
        iVar8 = FUN_80291d74(-0x7fc23ddc,uVar2,3);
        if (iVar8 == 0) {
          *param_12 = 0xffffffff;
        }
        else {
          *param_12 = uVar4;
        }
      }
      FUN_800238c4(uVar2);
    }
    else if ((param_15 == 1) && (param_14 != 0)) {
      iVar3 = iVar3 + (uVar1 & 0xffffff) * 2 + *(int *)(param_14 + param_13 * 4) + 4;
      uVar4 = *(undefined4 *)(iVar3 + 4);
      *param_12 = *(undefined4 *)(iVar3 + 8);
      *param_11 = uVar4;
    }
    else if ((param_15 == 2) && (param_14 != 0)) {
      FUN_80003494(param_14,iVar3 + (uVar1 & 0xffffff) * 2,(param_13 + 1) * 4);
    }
    else {
      iVar3 = iVar3 + (uVar1 & 0xffffff) * 2;
      uVar4 = *(undefined4 *)(iVar3 + 0xc);
      *param_11 = *(undefined4 *)(iVar3 + 8);
      iVar8 = FUN_80291d74(-0x7fc23ddc,iVar3,3);
      if (iVar8 == 0) {
        *param_12 = 0xffffffff;
      }
      else {
        *param_12 = uVar4;
      }
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80048928
 * EN v1.0 Address: 0x80048928
 * EN v1.0 Size: 440b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80048928(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 int param_5,uint param_6,int param_7)
{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  
  uVar2 = FUN_80286834();
  iVar4 = -1;
  if ((DAT_803600d4 != 0) || (DAT_8036017c != 0)) {
    FUN_80243e74();
    uVar1 = DAT_803dd900;
    FUN_80243e9c();
    if (((uVar2 & 0x80000000) == 0) || ((uVar1 & 0x200) != 0)) {
      if (((uVar2 & 0x40000000) == 0) || ((uVar1 & 0x100) != 0)) {
        if ((DAT_803600d8 == 0) || ((uVar1 & 0x100) != 0)) {
          if ((DAT_80360180 != 0) && ((uVar1 & 0x200) == 0)) {
            iVar4 = 0x4d;
          }
        }
        else {
          iVar4 = 0x23;
        }
      }
      else {
        iVar4 = 0x23;
      }
    }
    else {
      iVar4 = 0x4d;
    }
    if ((param_7 == 1) && (param_6 != 0)) {
      iVar4 = (&DAT_80360048)[iVar4] + (uVar2 & 0xffffff) * 2 + *(int *)(param_6 + param_5 * 4) + 4;
      uVar3 = *(undefined4 *)(iVar4 + 8);
      *param_3 = *(undefined4 *)(iVar4 + 4);
      *param_4 = uVar3;
    }
    else if ((param_7 == 2) && (param_6 != 0)) {
      FUN_80003494(param_6,(&DAT_80360048)[iVar4] + (uVar2 & 0xffffff) * 2,(param_5 + 1) * 4);
    }
    else {
      iVar4 = (&DAT_80360048)[iVar4] + (uVar2 & 0xffffff) * 2 + 4;
      uVar3 = *(undefined4 *)(iVar4 + 8);
      *param_3 = *(undefined4 *)(iVar4 + 4);
      *param_4 = uVar3;
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80048ae0
 * EN v1.0 Address: 0x80048AE0
 * EN v1.0 Size: 244b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80048ae0(uint param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 int param_5,uint param_6,int param_7)
{
  int iVar1;
  undefined4 uVar2;
  
  if (DAT_80360184 != 0) {
    if ((param_7 == 1) && (param_6 != 0)) {
      iVar1 = DAT_80360184 + (param_1 & 0xffffff) * 2 + *(int *)(param_6 + param_5 * 4) + 4;
      uVar2 = *(undefined4 *)(iVar1 + 8);
      *param_3 = *(undefined4 *)(iVar1 + 4);
      *param_4 = uVar2;
    }
    else if ((param_7 == 2) && (param_6 != 0)) {
      FUN_80003494(param_6,DAT_80360184 + (param_1 & 0xffffff) * 2,(param_5 + 1) * 4);
    }
    else {
      iVar1 = DAT_80360184 + (param_1 & 0xffffff) * 2;
      uVar2 = *(undefined4 *)(iVar1 + 0xc);
      *param_3 = *(undefined4 *)(iVar1 + 8);
      iVar1 = FUN_80291d74(-0x7fc23ddc,iVar1,3);
      if (iVar1 == 0) {
        *param_4 = 0xffffffff;
      }
      else {
        *param_4 = uVar2;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80048bd4
 * EN v1.0 Address: 0x80048BD4
 * EN v1.0 Size: 332b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80048bd4(undefined4 param_1,undefined4 param_2,undefined4 *param_3,undefined4 *param_4,
                 undefined4 *param_5)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  ulonglong uVar5;
  
  uVar5 = FUN_80286830();
  iVar2 = -1;
  if ((DAT_803600f4 != 0) || (DAT_80360160 != 0)) {
    FUN_80243e74();
    uVar1 = DAT_803dd900;
    FUN_80243e9c();
    iVar4 = 0;
    if (((uVar1 & 4) == 0) && ((uVar1 & 1) == 0)) {
      iVar4 = DAT_803600f0;
    }
    iVar3 = 0;
    if (((uVar1 & 8) == 0) && ((uVar1 & 2) == 0)) {
      iVar3 = DAT_8036015c;
    }
    if ((iVar3 == 0) || ((uVar5 & 0x2000000000000000) == 0)) {
      if ((iVar4 == 0) || ((uVar5 & 0x1000000000000000) == 0)) {
        if (iVar4 == 0) {
          if (iVar3 != 0) {
            iVar2 = 0x46;
          }
        }
        else {
          iVar2 = 0x2b;
        }
      }
      else {
        iVar2 = 0x2b;
      }
    }
    else {
      iVar2 = 0x46;
    }
    iVar2 = (&DAT_80360048)[iVar2] + ((uint)(uVar5 >> 0x20) & 0xfffffff);
    *param_4 = *(undefined4 *)(iVar2 + 0x18);
    *(undefined4 *)uVar5 = *(undefined4 *)(iVar2 + 0x1c);
    *param_3 = *(undefined4 *)(iVar2 + 0x20);
    *param_5 = *(undefined4 *)(iVar2 + 4);
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80048d20
 * EN v1.0 Address: 0x80048D20
 * EN v1.0 Size: 88b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80048d20(int param_1,int *param_2,int *param_3,undefined4 *param_4,int param_5)
{
  int iVar1;
  
  if (DAT_803600bc == 0) {
    return;
  }
  if (DAT_803600c0 == 0) {
    return;
  }
  iVar1 = DAT_803600bc + param_1;
  *param_2 = (int)*(short *)(iVar1 + 0x1c);
  *param_3 = (int)*(short *)(iVar1 + 0x1e);
  *param_4 = *(undefined4 *)(DAT_803600bc + *(int *)(DAT_803600c0 + param_5 * 4 + 0x18) + 4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80048d78
 * EN v1.0 Address: 0x80048D78
 * EN v1.0 Size: 380b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80048d78(undefined4 param_1,undefined4 param_2,undefined4 *param_3)
{
  uint uVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  ulonglong uVar6;
  
  uVar6 = FUN_80286840();
  puVar3 = (undefined4 *)uVar6;
  iVar5 = -1;
  if (((DAT_803600e0 == 0) || (DAT_803600dc == 0)) && ((DAT_80360168 == 0 || (DAT_80360164 == 0))))
  {
    *param_3 = 0;
    *puVar3 = 0;
  }
  else {
    FUN_80243e74();
    uVar1 = DAT_803dd900;
    FUN_80243e9c();
    if (((DAT_803600dc == 0) || ((uVar6 & 0x1000000000000000) == 0)) || ((uVar1 & 0x10000) != 0)) {
      if (((DAT_80360164 == 0) || ((uVar6 & 0x2000000000000000) == 0)) || ((uVar1 & 0x40000) != 0))
      {
        if ((DAT_803600dc == 0) || ((uVar1 & 0x10000) != 0)) {
          if ((DAT_80360164 != 0) && ((uVar1 & 0x40000) == 0)) {
            iVar5 = 0x47;
          }
        }
        else {
          iVar5 = 0x25;
        }
      }
      else {
        iVar5 = 0x47;
      }
    }
    else {
      iVar5 = 0x25;
    }
    iVar4 = (&DAT_80360048)[iVar5] + ((uint)(uVar6 >> 0x20) & 0xffffff);
    iVar5 = FUN_80291d74(iVar4,-0x7fc23de0,3);
    if (iVar5 == 0) {
      uVar2 = *(undefined4 *)(iVar4 + 0xc);
      *param_3 = *(undefined4 *)(iVar4 + 8);
      *puVar3 = uVar2;
    }
    else {
      *param_3 = 0;
      *puVar3 = 0;
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80048ef4
 * EN v1.0 Address: 0x80048EF4
 * EN v1.0 Size: 408b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80048ef4(undefined4 param_1,undefined4 param_2,undefined4 *param_3)
{
  uint uVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  ulonglong uVar6;
  
  uVar6 = FUN_80286840();
  puVar3 = (undefined4 *)uVar6;
  iVar5 = -1;
  if (((DAT_803600b0 == 0) || (DAT_803600b4 == 0)) && ((DAT_80360194 == 0 || (DAT_80360198 == 0))))
  {
    *param_3 = 0;
    *puVar3 = 0;
  }
  else {
    FUN_80243e74();
    uVar1 = DAT_803dd900;
    FUN_80243e9c();
    if (((DAT_803600b4 == 0) || ((uVar6 & 0x8000000000000000) == 0)) || ((uVar1 & 0x1000000) != 0))
    {
      if (((DAT_80360198 == 0) || ((uVar6 & 0x2000000000000000) == 0)) || ((uVar1 & 0x4000000) != 0)
         ) {
        if ((DAT_803600b4 == 0) || ((uVar1 & 0x1000000) != 0)) {
          if ((DAT_80360198 != 0) && ((uVar1 & 0x4000000) == 0)) {
            iVar5 = 0x54;
          }
        }
        else {
          iVar5 = 0x1b;
        }
      }
      else {
        iVar5 = 0x54;
      }
    }
    else {
      iVar5 = 0x1b;
    }
    if ((uVar6 & 0xf000000000000000) == 0) {
      *param_3 = 0;
      *puVar3 = 0;
    }
    else {
      iVar4 = (&DAT_80360048)[iVar5] + ((uint)(uVar6 >> 0x20) & 0xffffff);
      iVar5 = FUN_80291d74(iVar4,-0x7fc23de0,3);
      if (iVar5 == 0) {
        uVar2 = *(undefined4 *)(iVar4 + 0xc);
        *param_3 = *(undefined4 *)(iVar4 + 8);
        *puVar3 = uVar2;
      }
      else {
        *param_3 = 0;
        *puVar3 = 0;
      }
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004908c
 * EN v1.0 Address: 0x8004908C
 * EN v1.0 Size: 56b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8004908c(int param_1)
{
  if ((&DAT_80360048)[param_1] != 0) {
    return (&DAT_8035fd08)[param_1];
  }
  uRam00000000 = 0;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800490c4
 * EN v1.0 Address: 0x800490C4
 * EN v1.0 Size: 324b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800490c4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined8 extraout_f1;
  undefined8 uVar5;
  ulonglong uVar6;
  int aiStack_58 [22];
  
  uVar6 = FUN_80286840();
  iVar2 = (int)(uVar6 >> 0x20);
  uVar4 = (uint)uVar6;
  if (param_12 != 0) {
    if ((&DAT_80360048)[iVar2] == 0) {
      uVar5 = extraout_f1;
      FUN_80249300(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (&PTR_s_AUDIO_tab_802cbecc)[iVar2],(int)aiStack_58);
      if (((uVar6 & 0x1f) == 0) && ((param_12 & 0x1f) == 0)) {
        FUN_802420b0(uVar4,param_12);
        FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_58,uVar4,
                     param_12,param_11,param_13,param_14,param_15,param_16);
      }
      else {
        uVar1 = param_12 + 0x1f & 0xffffffe0;
        uVar3 = FUN_80023d8c(uVar1,0x7d7d7d7d);
        FUN_802420b0(uVar3,uVar1);
        FUN_80015888(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_58,uVar3,
                     uVar1,param_11,param_13,param_14,param_15,param_16);
        FUN_80003494(uVar4,uVar3,param_12);
        FUN_800238c4(uVar3);
      }
      FUN_802493c8(aiStack_58);
      FUN_80242114(uVar4,param_12);
    }
    else {
      FUN_80003494(uVar4,(&DAT_80360048)[iVar2] + param_11,param_12);
      FUN_80242114(uVar4,param_12);
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80049208
 * EN v1.0 Address: 0x80049208
 * EN v1.0 Size: 184b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80049208(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,uint param_10,undefined4 param_11,undefined4 param_12,
                undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int aiStack_58 [13];
  int local_24;
  
  if ((&DAT_80360048)[param_9] == 0) {
    FUN_80249300(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (&PTR_s_AUDIO_tab_802cbecc)[param_9],(int)aiStack_58);
    FUN_802420b0(param_10,local_24);
    FUN_80015888(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_58,param_10
                 ,local_24,0,param_13,param_14,param_15,param_16);
    FUN_802493c8(aiStack_58);
  }
  else {
    FUN_80003494(param_10,(&DAT_80360048)[param_9],(&DAT_8035fd08)[param_9]);
    FUN_80242114(param_10,(&DAT_8035fd08)[param_9]);
    local_24 = (&DAT_8035fd08)[param_9];
  }
  return local_24;
}

/*
 * --INFO--
 *
 * Function: FUN_800492c0
 * EN v1.0 Address: 0x800492C0
 * EN v1.0 Size: 188b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800492c0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9)
{
  int iVar1;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int aiStack_58 [13];
  undefined4 local_24;
  
  iVar1 = (&DAT_80360048)[param_9];
  if (iVar1 == 0) {
    FUN_80249300(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (&PTR_s_AUDIO_tab_802cbecc)[param_9],(int)aiStack_58);
    (&DAT_8035fd08)[param_9] = local_24;
    iVar1 = FUN_80023d8c((&DAT_8035fd08)[param_9] + 0x20,0x7d7d7d7d);
    (&DAT_80360048)[param_9] = iVar1;
    FUN_802420b0((&DAT_80360048)[param_9],(&DAT_8035fd08)[param_9]);
    FUN_80015888(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,aiStack_58,
                 (&DAT_80360048)[param_9],(&DAT_8035fd08)[param_9],0,in_r7,in_r8,in_r9,in_r10);
    FUN_802493c8(aiStack_58);
    iVar1 = (&DAT_80360048)[param_9];
  }
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_8004937c
 * EN v1.0 Address: 0x8004937C
 * EN v1.0 Size: 772b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004937c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80049680
 * EN v1.0 Address: 0x80049680
 * EN v1.0 Size: 76b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80049680(void)
{
  *(undefined2 *)((int)DAT_803dd970 + 0xe) = 0x294;
  *(short *)((int)DAT_803dd970 + 10) = *(short *)((int)DAT_803dd970 + 10) + -10;
  FUN_8024d51c(DAT_803dd970);
  FUN_8024dcb8();
  FUN_8024d054();
  FUN_8024d054();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800496cc
 * EN v1.0 Address: 0x800496CC
 * EN v1.0 Size: 836b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800496cc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80049a10
 * EN v1.0 Address: 0x80049A10
 * EN v1.0 Size: 340b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80049a10(void)
{
  bool bVar1;
  short sVar3;
  uint uVar2;
  undefined4 local_98 [3];
  uint auStack_8c [35];
  
  DAT_803dd920 = DAT_803dd920 + 1;
  sVar3 = FUN_80258c18();
  if (sVar3 == (short)(DAT_803dd92a + 1)) {
    bVar1 = DAT_803dd94c == DAT_803dd96c;
    DAT_803dd94c = DAT_803dd96c;
    if (bVar1) {
      DAT_803dd94c = DAT_803dd968;
    }
    DAT_803dd92a = sVar3;
    FUN_8024ddd4(DAT_803dd94c);
    FUN_8024dcb8();
    DAT_803dd929 = 1;
    DAT_803dc228 = DAT_803dd920;
    DAT_803dd920 = 0;
  }
  DAT_803dd92c = DAT_803dd92c + 1;
  if ((DAT_803dd930 != '\0') && (18000 < DAT_803dd92c)) {
    FUN_8004a724();
    FUN_80060cbc();
    FUN_800293b8();
    FUN_80258a94();
    FUN_8025665c((int *)auStack_8c,DAT_803dd950,0x10000);
    FUN_80256744(auStack_8c);
    FUN_80256854(auStack_8c);
    DAT_803dd954 = FUN_802554d0(DAT_803dd958,DAT_803dd964);
    uVar2 = FUN_8001377c((short *)&DAT_80360390);
    if (uVar2 == 0) {
      FUN_800137c8((short *)&DAT_80360390,(uint)local_98);
    }
    FUN_802472b0((int *)&DAT_803dd944);
    uVar2 = FUN_8001377c((short *)&DAT_80360390);
    if (uVar2 == 0) {
      FUN_8001378c(-0x7fc9fc70,(uint)local_98);
      FUN_80256c08(local_98[0]);
    }
    else {
      FUN_80256ca0();
      DAT_803dd927 = 0;
    }
    FUN_8004a8f8('\x01');
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80049b64
 * EN v1.0 Address: 0x80049B64
 * EN v1.0 Size: 324b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80049b64(void)
{
  uint uVar1;
  int iVar2;
  ushort *puVar3;
  ushort *puVar4;
  undefined4 local_28 [3];
  undefined auStack_1c [8];
  int local_14;
  
  if ((DAT_803de288 == 2) || (DAT_803de288 == 3)) {
    FUN_80118434();
  }
  FUN_8001378c(-0x7fc9fc70,(uint)auStack_1c);
  puVar4 = &DAT_80397330;
  puVar3 = &DAT_80397240;
  for (iVar2 = 0; iVar2 < (int)(uint)DAT_803ddc80; iVar2 = iVar2 + 1) {
    *puVar3 = *puVar4;
    puVar3[1] = puVar4[1];
    *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(puVar4 + 4);
    FUN_80258dac((uint)*puVar3,(uint)puVar3[1],(undefined4 *)(puVar3 + 2));
    puVar4 = puVar4 + 6;
    puVar3 = puVar3 + 6;
  }
  DAT_803ddc82 = DAT_803ddc80;
  DAT_803ddc80 = 0;
  if (local_14 == DAT_803dd94c) {
    DAT_803dd928 = 1;
    DAT_803dd929 = 0;
  }
  else {
    FUN_800137c8((short *)&DAT_80360390,(uint)local_28);
    DAT_803dd92c = 0;
    FUN_802472b0((int *)&DAT_803dd944);
    uVar1 = FUN_8001377c((short *)&DAT_80360390);
    if (uVar1 == 0) {
      FUN_8001378c(-0x7fc9fc70,(uint)local_28);
      FUN_80256c08(local_28[0]);
      DAT_803dd927 = 1;
    }
    else {
      FUN_80256ca0();
      DAT_803dd927 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80049ca8
 * EN v1.0 Address: 0x80049CA8
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80049ca8(void)
{
  FUN_80247dfc((double)FLOAT_803df6f0,(double)FLOAT_803df708,(double)FLOAT_803df6f0,
               (double)FLOAT_803df70c,(double)FLOAT_803df6f8,(double)FLOAT_803df710,
               (float *)&DAT_803974e0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80049ce8
 * EN v1.0 Address: 0x80049CE8
 * EN v1.0 Size: 2132b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80049ce8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8004a53c
 * EN v1.0 Address: 0x8004A53C
 * EN v1.0 Size: 20b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004a53c(undefined param_1,undefined param_2,undefined param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8004a550
 * EN v1.0 Address: 0x8004A550
 * EN v1.0 Size: 104b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004a550(void)
{
  if ((DAT_803dd970 == &DAT_8032f2b4) || (DAT_803dd970[0x18] != '\0')) {
    FUN_80259858(DAT_803dd970[0x19],DAT_803dd970 + 0x1a,'\0',DAT_803dd970 + 0x32);
  }
  else {
    FUN_80259858(DAT_803dd970[0x19],DAT_803dd970 + 0x1a,'\x01',&DAT_803dc234);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004a5b8
 * EN v1.0 Address: 0x8004A5B8
 * EN v1.0 Size: 304b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8004a5b8(char param_1)
{
  bool bVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined8 uVar4;
  undefined4 local_28;
  undefined4 uStack_24;
  undefined4 local_20;
  undefined4 local_1c;
  uint local_18;
  
  uVar2 = 1;
  FUN_8007048c(1,3,1);
  uVar4 = FUN_8025ce2c(1);
  FUN_80258a04((int)((ulonglong)uVar4 >> 0x20),(int)uVar4,uVar2);
  puVar3 = &local_28;
  FUN_80256b2c(DAT_803dd954,&uStack_24,puVar3);
  local_20 = local_28;
  local_1c = 0;
  local_18 = DAT_803dd950;
  FUN_80243e74();
  FUN_8001383c((short *)&DAT_80360390,(uint)&local_20);
  if (DAT_803dd927 == '\0') {
    FUN_80256c08(local_28);
    DAT_803dd927 = '\x01';
  }
  FUN_80243e9c();
  FUN_80258b60((uint)DAT_803dc22e);
  uVar4 = FUN_80259a9c(DAT_803dd950,1);
  FUN_80258a04((int)((ulonglong)uVar4 >> 0x20),(int)uVar4,(uint)puVar3);
  DAT_803dc22e = DAT_803dc22e + 1;
  bVar1 = DAT_803dd950 == DAT_803dd96c;
  DAT_803dd950 = DAT_803dd96c;
  if (bVar1) {
    DAT_803dd950 = DAT_803dd968;
  }
  if (((param_1 != '\0') && (DAT_803dc22c != '\0')) &&
     (DAT_803dc22c = DAT_803dc22c + -1, DAT_803dc22c == '\0')) {
    FUN_8024de40(0);
    DAT_803dc22c = '\0';
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8004a6e8
 * EN v1.0 Address: 0x8004A6E8
 * EN v1.0 Size: 60b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004a6e8(undefined param_1)
{
  FUN_8024de40(1);
  FUN_8024dcb8();
  DAT_803dc22c = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004a724
 * EN v1.0 Address: 0x8004A724
 * EN v1.0 Size: 468b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004a724(void)
{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  byte bStack_48;
  byte local_47;
  byte local_46 [2];
  int local_44;
  int local_40;
  int local_3c;
  int local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_28 [10];
  
  FUN_80286840();
  FUN_8025e520(&local_2c,local_28,&local_34,&local_30);
  FUN_8025e520(&local_3c,&local_38,&local_44,&local_40);
  uVar1 = countLeadingZeros(local_38 - local_28[0]);
  uVar1 = uVar1 >> 5;
  uVar2 = countLeadingZeros(local_3c - local_2c);
  uVar2 = uVar2 >> 5;
  uVar3 = -(local_40 - local_30) | local_40 - local_30;
  FUN_80256ac8(&bStack_48,&bStack_48,local_46,&local_47,&bStack_48);
  FUN_8007d858();
  if ((uVar2 == 0) && ((int)uVar3 < 0)) {
    FUN_8007d858();
  }
  else if ((uVar1 == 0) && ((uVar2 != 0 && ((int)uVar3 < 0)))) {
    FUN_8007d858();
  }
  else if ((local_47 == 0) && (((uVar1 != 0 && (uVar2 != 0)) && ((int)uVar3 < 0)))) {
    FUN_8007d858();
  }
  else if ((((local_46[0] == 0) || (local_47 == 0)) ||
           ((uVar1 == 0 || ((uVar2 == 0 || (-1 < (int)uVar3)))))) ||
          (-1 < (-(local_44 - local_34) | local_44 - local_34))) {
    FUN_8007d858();
  }
  else {
    FUN_8007d858();
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004a8f8
 * EN v1.0 Address: 0x8004A8F8
 * EN v1.0 Size: 192b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004a8f8(char param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8004a9b8
 * EN v1.0 Address: 0x8004A9B8
 * EN v1.0 Size: 44b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004a9b8(void)
{
  DAT_803dd930 = 0;
  FUN_8004a8f8('\0');
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004a9e4
 * EN v1.0 Address: 0x8004A9E4
 * EN v1.0 Size: 444b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004a9e4(void)
{
  uint uVar1;
  uint uVar2;
  double dVar3;
  undefined8 uVar4;
  
  FUN_802461cc(-0x7fc9fd20);
  uVar4 = FUN_80246298(-0x7fc9fd20);
  dVar3 = FUN_80286cd0((uint)((ulonglong)uVar4 >> 0x20),(uint)uVar4);
  FLOAT_803dd940 =
       (float)(dVar3 / (double)(float)((double)CONCAT44(0x43300000,DAT_800000f8 / 4000) -
                                      DOUBLE_803df700));
  FUN_80246308(-0x7fc9fd20);
  FUN_80246190(-0x7fc9fd20);
  FLOAT_803dc074 = FLOAT_803df71c * FLOAT_803df720 * FLOAT_803dd940;
  if (DAT_803dd5d0 != '\0') {
    FLOAT_803dc074 = FLOAT_803df6f0;
  }
  if (FLOAT_803df6f4 < FLOAT_803dc074) {
    FLOAT_803dc074 = FLOAT_803df6f4;
  }
  FLOAT_803dc078 = FLOAT_803df6f8;
  if (FLOAT_803df6fc < FLOAT_803dc074) {
    FLOAT_803dc078 = FLOAT_803df6f8 / FLOAT_803dc074;
  }
  uVar2 = (uint)(FLOAT_803dc074 + FLOAT_803dd934);
  uVar1 = uVar2 & 0xff;
  DAT_803dc071 = (undefined)uVar2;
  FLOAT_803dd934 =
       (FLOAT_803dc074 + FLOAT_803dd934) -
       (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803df700);
  DAT_803dc070 = DAT_803dc071;
  if (uVar1 == 0) {
    DAT_803dc070 = 1;
  }
  FUN_80243e74();
  DAT_803dd95c = FUN_802464ec();
  if (*(short *)(DAT_803dd95c + 0x2c8) != 2) {
    FUN_8007d858();
  }
  uVar2 = FUN_80013774((short *)&DAT_80360390);
  if (1 < uVar2) {
    DAT_803dd92c = 0;
    FUN_802471c4((int *)&DAT_803dd944);
  }
  FUN_80243e9c();
  FUN_8000f7a0();
  FUN_80258664();
  FUN_8025b210();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004aba0
 * EN v1.0 Address: 0x8004ABA0
 * EN v1.0 Size: 176b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8004aba0(int *param_1,int *param_2)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar4 = param_1[4];
  iVar3 = *param_2;
  if (*(char *)(iVar3 + 0x19) != '$') {
    uVar1 = countLeadingZeros(iVar3 - iVar4);
    return uVar1 >> 5;
  }
  if ((*(byte *)(param_2 + 3) & 0x80) == 0) {
    if (*(byte *)(iVar3 + 3) != 0) {
      uVar1 = countLeadingZeros((uint)*(byte *)(iVar3 + 3) - iVar4);
      return uVar1 >> 5;
    }
    iVar5 = *(int *)(*param_1 + (uint)*(byte *)(param_2 + 3) * 0x10);
    iVar6 = 0;
    iVar7 = 4;
    iVar2 = iVar5;
    do {
      if (*(int *)(iVar3 + 0x14) == *(int *)(iVar2 + 0x1c)) {
        uVar1 = countLeadingZeros((uint)*(byte *)(iVar6 + iVar5 + 4) - iVar4);
        return uVar1 >> 5;
      }
      iVar2 = iVar2 + 4;
      iVar6 = iVar6 + 1;
      iVar7 = iVar7 + -1;
    } while (iVar7 != 0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8004ac50
 * EN v1.0 Address: 0x8004AC50
 * EN v1.0 Size: 136b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004ac50(int param_1,int param_2,int param_3)
{
  undefined2 uVar1;
  uint *puVar2;
  uint uVar3;
  uint *puVar4;
  uint uVar5;
  int iVar6;
  
  uVar5 = *(uint *)(param_1 + param_3 * 8);
  uVar1 = *(undefined2 *)(param_1 + param_3 * 8 + 4);
  while (param_3 <= param_2 >> 1) {
    iVar6 = param_3 * 2;
    if ((iVar6 < param_2) && (puVar4 = (uint *)(param_1 + param_3 * 0x10), *puVar4 < puVar4[2])) {
      iVar6 = iVar6 + 1;
    }
    puVar4 = (uint *)(param_1 + iVar6 * 8);
    uVar3 = *puVar4;
    if (uVar3 <= uVar5) break;
    puVar2 = (uint *)(param_1 + param_3 * 8);
    *puVar2 = uVar3;
    *(undefined2 *)(puVar2 + 1) = *(undefined2 *)(puVar4 + 1);
    param_3 = iVar6;
  }
  *(uint *)(param_1 + param_3 * 8) = uVar5;
  *(undefined2 *)(param_1 + param_3 * 8 + 4) = uVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004acd8
 * EN v1.0 Address: 0x8004ACD8
 * EN v1.0 Size: 1092b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004acd8(undefined4 param_1,undefined4 param_2,undefined param_3,uint param_4,int param_5)
{
  short sVar1;
  undefined2 uVar2;
  short sVar3;
  int *piVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  uint *puVar9;
  uint uVar10;
  uint unaff_r29;
  int *piVar11;
  int iVar12;
  int unaff_r31;
  double dVar13;
  undefined8 uVar14;
  
  uVar14 = FUN_80286834();
  piVar4 = (int *)((ulonglong)uVar14 >> 0x20);
  uVar5 = FUN_8004aba0(piVar4,(int *)uVar14);
  if (uVar5 != 0) {
    sVar1 = *(short *)(piVar4 + 8);
    if (sVar1 != 0xfe) {
      *(short *)(piVar4 + 8) = sVar1 + 1;
      piVar11 = (int *)(*piVar4 + sVar1 * 0x10);
      *piVar11 = param_5;
      piVar11[2] = param_4;
      *(undefined *)(piVar11 + 3) = param_3;
      dVar13 = FUN_80021794((float *)(*piVar11 + 8),(float *)piVar4[3]);
      iVar6 = FUN_80286718(dVar13);
      piVar11[1] = iVar6;
    }
    puVar8 = (undefined4 *)piVar4[1];
    sVar3 = *(short *)((int)piVar4 + 0x22) + 1;
    *(short *)((int)piVar4 + 0x22) = sVar3;
    *(short *)(puVar8 + sVar3 * 2 + 1) = sVar1;
    puVar8[*(short *)((int)piVar4 + 0x22) * 2] = 0xfffffffe;
    iVar6 = (int)*(short *)((int)piVar4 + 0x22);
    uVar5 = puVar8[iVar6 * 2];
    uVar2 = *(undefined2 *)(puVar8 + iVar6 * 2 + 1);
    *puVar8 = 0xffffffff;
    while (iVar7 = iVar6 >> 1, (uint)puVar8[iVar7 * 2] < uVar5) {
      *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = *(undefined2 *)(puVar8 + iVar7 * 2 + 1);
      puVar8[iVar6 * 2] = puVar8[iVar7 * 2];
      iVar6 = iVar7;
    }
    puVar8[iVar6 * 2] = uVar5;
    *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = uVar2;
  }
  uVar5 = 0;
  iVar7 = 0;
  sVar1 = *(short *)(piVar4 + 8);
  iVar12 = (int)sVar1;
  iVar6 = iVar12;
  if (0 < iVar12) {
    do {
      if (*(int *)(*piVar4 + iVar7) == param_5) {
        unaff_r29 = (uint)*(byte *)(*piVar4 + iVar7 + 0xe);
        goto LAB_8004ae34;
      }
      iVar7 = iVar7 + 0x10;
      uVar5 = uVar5 + 1;
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
  }
  uVar5 = 0xffffffff;
LAB_8004ae34:
  if (((int)uVar5 < 0) || (unaff_r29 != 0)) {
    if ((int)uVar5 < 0) {
      if (iVar12 == 0xfe) {
        piVar11 = (int *)0x0;
      }
      else {
        sVar3 = *(short *)(piVar4 + 8);
        *(short *)(piVar4 + 8) = sVar3 + 1;
        piVar11 = (int *)(*piVar4 + sVar3 * 0x10);
        *piVar11 = param_5;
        piVar11[2] = param_4;
        *(undefined *)(piVar11 + 3) = param_3;
        dVar13 = FUN_80021794((float *)(*piVar11 + 8),(float *)piVar4[3]);
        iVar6 = FUN_80286718(dVar13);
        piVar11[1] = iVar6;
      }
      if (piVar11 != (int *)0x0) {
        uVar5 = piVar11[1];
        if ((uint)piVar4[9] < uVar5) {
          iVar6 = piVar11[2];
          puVar8 = (undefined4 *)piVar4[1];
          sVar3 = *(short *)((int)piVar4 + 0x22) + 1;
          *(short *)((int)piVar4 + 0x22) = sVar3;
          *(short *)(puVar8 + sVar3 * 2 + 1) = sVar1;
          puVar8[*(short *)((int)piVar4 + 0x22) * 2] = -1 - (uVar5 + iVar6);
          iVar6 = (int)*(short *)((int)piVar4 + 0x22);
          uVar5 = puVar8[iVar6 * 2];
          uVar2 = *(undefined2 *)(puVar8 + iVar6 * 2 + 1);
          *puVar8 = 0xffffffff;
          while (iVar7 = iVar6 >> 1, (uint)puVar8[iVar7 * 2] < uVar5) {
            *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = *(undefined2 *)(puVar8 + iVar7 * 2 + 1);
            puVar8[iVar6 * 2] = puVar8[iVar7 * 2];
            iVar6 = iVar7;
          }
          puVar8[iVar6 * 2] = uVar5;
          *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = uVar2;
        }
        else {
          if (uVar5 < (uint)piVar4[9]) {
            piVar4[9] = uVar5;
          }
          iVar7 = piVar11[1];
          iVar6 = piVar11[2];
          puVar8 = (undefined4 *)piVar4[1];
          sVar3 = *(short *)((int)piVar4 + 0x22) + 1;
          *(short *)((int)piVar4 + 0x22) = sVar3;
          *(short *)(puVar8 + sVar3 * 2 + 1) = sVar1;
          puVar8[*(short *)((int)piVar4 + 0x22) * 2] = -1 - (iVar7 + iVar6);
          iVar6 = (int)*(short *)((int)piVar4 + 0x22);
          uVar5 = puVar8[iVar6 * 2];
          uVar2 = *(undefined2 *)(puVar8 + iVar6 * 2 + 1);
          *puVar8 = 0xffffffff;
          while (iVar7 = iVar6 >> 1, (uint)puVar8[iVar7 * 2] < uVar5) {
            *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = *(undefined2 *)(puVar8 + iVar7 * 2 + 1);
            puVar8[iVar6 * 2] = puVar8[iVar7 * 2];
            iVar6 = iVar7;
          }
          puVar8[iVar6 * 2] = uVar5;
          *(undefined2 *)(puVar8 + iVar6 * 2 + 1) = uVar2;
        }
      }
    }
  }
  else {
    iVar6 = *piVar4 + uVar5 * 0x10;
    if (param_4 < *(uint *)(iVar6 + 8)) {
      *(undefined *)(iVar6 + 0xc) = param_3;
      *(uint *)(iVar6 + 8) = param_4;
      uVar10 = *(int *)(iVar6 + 4) + *(int *)(iVar6 + 8);
      iVar6 = (int)*(short *)((int)piVar4 + 0x22);
      puVar8 = (undefined4 *)piVar4[1];
      iVar7 = 0;
      while (iVar7 <= iVar6) {
        iVar12 = iVar7;
        if ((uVar5 & 0xffff) == (uint)*(ushort *)(puVar8 + iVar7 * 2 + 1)) {
          iVar12 = iVar6 + 1;
          unaff_r31 = iVar7;
        }
        iVar7 = iVar12 + 1;
      }
      puVar9 = puVar8 + unaff_r31 * 2;
      uVar5 = *puVar9;
      *puVar9 = uVar10;
      if (uVar10 < uVar5) {
        FUN_8004ac50((int)puVar8,iVar6,unaff_r31);
      }
      else if (uVar5 < uVar10) {
        uVar5 = *puVar9;
        uVar2 = *(undefined2 *)(puVar9 + 1);
        *puVar8 = 0xffffffff;
        while (iVar6 = unaff_r31 >> 1, (uint)puVar8[iVar6 * 2] < uVar5) {
          *(undefined2 *)(puVar8 + unaff_r31 * 2 + 1) = *(undefined2 *)(puVar8 + iVar6 * 2 + 1);
          puVar8[unaff_r31 * 2] = puVar8[iVar6 * 2];
          unaff_r31 = iVar6;
        }
        puVar8[unaff_r31 * 2] = uVar5;
        *(undefined2 *)(puVar8 + unaff_r31 * 2 + 1) = uVar2;
      }
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004b11c
 * EN v1.0 Address: 0x8004B11C
 * EN v1.0 Size: 376b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004b11c(undefined4 param_1,undefined4 param_2,undefined param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8004b294
 * EN v1.0 Address: 0x8004B294
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8004b294(int param_1)
{
  short sVar1;
  
  sVar1 = *(short *)(param_1 + 0x2c);
  if ((int)sVar1 < (int)*(short *)(param_1 + 0x2a)) {
    *(short *)(param_1 + 0x2c) = sVar1 + 1;
    return *(undefined4 *)(*(int *)(param_1 + 8) + sVar1 * 4);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8004b2c4
 * EN v1.0 Address: 0x8004B2C4
 * EN v1.0 Size: 208b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8004b2c4(int *param_1)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined4 *puVar5;
  
  uVar3 = param_1[7];
  iVar1 = *param_1 + uVar3 * 0x10;
  *(undefined *)(iVar1 + 0xd) = 0xff;
  while (uVar2 = (uint)*(byte *)(iVar1 + 0xc), uVar2 != 0xff) {
    iVar1 = *param_1 + uVar2 * 0x10;
    *(char *)(iVar1 + 0xd) = (char)uVar3;
    uVar3 = uVar2;
  }
  if (*(byte *)(iVar1 + 0xd) == 0xff) {
    puVar5 = (undefined4 *)0x0;
  }
  else {
    puVar5 = (undefined4 *)(*param_1 + (uint)*(byte *)(iVar1 + 0xd) * 0x10);
  }
  iVar4 = 0;
  iVar1 = 0;
  while (puVar5 != (undefined4 *)0x0) {
    *(undefined4 *)(param_1[2] + iVar1) = *puVar5;
    iVar1 = iVar1 + 4;
    iVar4 = iVar4 + 1;
    if (iVar4 < 100) {
      if (*(byte *)((int)puVar5 + 0xd) == 0xff) {
        puVar5 = (undefined4 *)0x0;
      }
      else {
        puVar5 = (undefined4 *)(*param_1 + (uint)*(byte *)((int)puVar5 + 0xd) * 0x10);
      }
    }
    else {
      puVar5 = (undefined4 *)0x0;
    }
  }
  *(short *)((int)param_1 + 0x2a) = (short)iVar4;
  *(undefined2 *)(param_1 + 0xb) = 0;
  return iVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_8004b394
 * EN v1.0 Address: 0x8004B394
 * EN v1.0 Size: 260b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004b394(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8004b498
 * EN v1.0 Address: 0x8004B498
 * EN v1.0 Size: 632b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8004b498(int *param_1,int param_2,int param_3,int param_4,byte param_5)
{
  undefined2 uVar1;
  short sVar2;
  int iVar3;
  undefined4 *puVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  int iVar9;
  double dVar10;
  
  iVar3 = 0;
  *(undefined2 *)((int)param_1 + 0x22) = 0;
  *(undefined2 *)(param_1 + 8) = 0;
  iVar6 = 0;
  iVar7 = 0;
  iVar9 = 0x1f;
  do {
    *(undefined4 *)(param_1[1] + iVar6) = 0;
    *(undefined *)(*param_1 + iVar7 + 0xe) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 8) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x1e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x10) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x2e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x18) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x3e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x20) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x4e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x28) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x5e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x30) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x6e) = 0;
    *(undefined4 *)(param_1[1] + iVar6 + 0x38) = 0;
    *(undefined *)(*param_1 + iVar7 + 0x7e) = 0;
    iVar6 = iVar6 + 0x40;
    iVar7 = iVar7 + 0x80;
    iVar3 = iVar3 + 8;
    iVar9 = iVar9 + -1;
  } while (iVar9 != 0);
  iVar6 = iVar3 * 8;
  iVar7 = iVar3 * 0x10;
  iVar9 = 0xfe - iVar3;
  if (iVar3 < 0xfe) {
    do {
      *(undefined4 *)(param_1[1] + iVar6) = 0;
      *(undefined *)(*param_1 + iVar7 + 0xe) = 0;
      iVar6 = iVar6 + 8;
      iVar7 = iVar7 + 0x10;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
  }
  param_1[6] = param_2;
  param_1[3] = param_3;
  param_1[4] = param_4;
  *(byte *)(param_1 + 10) = param_5 & 1;
  param_1[9] = 10000;
  sVar2 = *(short *)(param_1 + 8);
  if (sVar2 == 0xfe) {
    piVar8 = (int *)0x0;
  }
  else {
    *(short *)(param_1 + 8) = sVar2 + 1;
    piVar8 = (int *)(*param_1 + sVar2 * 0x10);
    *piVar8 = param_2;
    piVar8[2] = 0;
    *(undefined *)(piVar8 + 3) = 0xff;
    dVar10 = FUN_80021794((float *)(*piVar8 + 8),(float *)param_1[3]);
    iVar3 = FUN_80286718(dVar10);
    piVar8[1] = iVar3;
  }
  iVar6 = piVar8[1];
  iVar3 = piVar8[2];
  puVar4 = (undefined4 *)param_1[1];
  sVar2 = *(short *)((int)param_1 + 0x22) + 1;
  *(short *)((int)param_1 + 0x22) = sVar2;
  *(short *)(puVar4 + sVar2 * 2 + 1) = *(short *)(param_1 + 8) + -1;
  puVar4[*(short *)((int)param_1 + 0x22) * 2] = -1 - (iVar6 + iVar3);
  iVar3 = (int)*(short *)((int)param_1 + 0x22);
  uVar5 = puVar4[iVar3 * 2];
  uVar1 = *(undefined2 *)(puVar4 + iVar3 * 2 + 1);
  *puVar4 = 0xffffffff;
  while (iVar6 = iVar3 >> 1, (uint)puVar4[iVar6 * 2] < uVar5) {
    *(undefined2 *)(puVar4 + iVar3 * 2 + 1) = *(undefined2 *)(puVar4 + iVar6 * 2 + 1);
    puVar4[iVar3 * 2] = puVar4[iVar6 * 2];
    iVar3 = iVar6;
  }
  puVar4[iVar3 * 2] = uVar5;
  *(undefined2 *)(puVar4 + iVar3 * 2 + 1) = uVar1;
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8004b710
 * EN v1.0 Address: 0x8004B710
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004b710(uint *param_1)
{
  if (*param_1 != 0) {
    FUN_800238c4(*param_1);
    *param_1 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004b750
 * EN v1.0 Address: 0x8004B750
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004b750(int *param_1)
{
  int iVar1;
  
  iVar1 = FUN_80023d8c(0x1960,0x10);
  *param_1 = iVar1;
  param_1[1] = *param_1 + 0xfe0;
  param_1[2] = param_1[1] + 0x7f0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004b7a4
 * EN v1.0 Address: 0x8004B7A4
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004b7a4(void)
{
  DAT_803dd990 = FUN_80023d8c(0x20,0xff);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004b7d4
 * EN v1.0 Address: 0x8004B7D4
 * EN v1.0 Size: 2352b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8004b7d4(int param_1,undefined4 param_2,int param_3)
{
  byte bVar1;
  byte bVar2;
  byte bVar3;
  ushort uVar4;
  uint uVar5;
  ushort *puVar6;
  byte *pbVar7;
  ushort *puVar8;
  byte *pbVar9;
  uint uVar10;
  undefined *puVar11;
  int iVar12;
  int iVar13;
  undefined *puVar14;
  undefined *puVar15;
  int iVar16;
  uint uVar17;
  uint uVar18;
  undefined *puVar19;
  undefined2 *puVar20;
  short *psVar21;
  int iVar22;
  int iVar23;
  uint uVar24;
  int iVar25;
  uint uVar26;
  undefined1 *puVar27;
  undefined1 *puVar28;
  uint uVar29;
  uint uVar30;
  bool bVar31;
  
  pbVar9 = (byte *)(param_3 + -1);
  uVar10 = 0;
  uVar17 = 0;
  puVar6 = (ushort *)(param_1 + 2);
  do {
    bVar1 = *(byte *)puVar6;
    uVar5 = uVar17 & 0x1f;
    pbVar7 = (byte *)((int)puVar6 + ((int)(uVar10 + 1) >> 3));
    uVar10 = uVar10 + 1 & 7;
    uVar17 = 0x20 - uVar10 & 0x1f;
    uVar18 = ((uint)*pbVar7 << uVar17 & 0xff | (uint)(*pbVar7 >> 0x20 - uVar17) |
             (uint)pbVar7[1] << 8 - uVar10) & 3;
    puVar6 = (ushort *)(pbVar7 + ((int)(uVar10 + 2) >> 3));
    uVar10 = uVar10 + 2 & 7;
    bVar31 = uVar10 < 0x21;
    uVar17 = 0x20 - uVar10;
    if (uVar18 == 0) {
      if (uVar10 != 0) {
        puVar6 = (ushort *)((int)puVar6 + 1);
        uVar10 = 0;
      }
      uVar4 = *puVar6;
      puVar8 = (ushort *)((int)puVar6 + 1);
      puVar6 = puVar6 + 2;
      uVar18 = (uint)uVar4 | (uint)*puVar8 << 8;
      do {
        bVar2 = *(byte *)puVar6;
        puVar6 = (ushort *)((int)puVar6 + 1);
        pbVar9 = pbVar9 + 1;
        *pbVar9 = bVar2;
        uVar24 = (uint)bVar31;
        bVar31 = CARRY4(uVar18,uVar24 - 1);
        uVar18 = uVar18 + (uVar24 - 1);
      } while (uVar18 != 0);
    }
    else {
      if (uVar18 == 1) {
        puVar11 = &DAT_8030d440;
        iVar12 = -0x7fcf2aa0;
        iVar13 = 9;
        puVar14 = &DAT_8030d960;
        puVar15 = &DAT_8030d980;
        iVar16 = 5;
      }
      else {
        puVar11 = &DAT_803603a0;
        iVar12 = -0x7fc9fb40;
        puVar14 = &DAT_803704c0;
        puVar15 = &DAT_803704e0;
        iVar13 = 8;
        puVar19 = &DAT_803dd9a0;
        do {
          *puVar19 = 0;
          puVar19 = puVar19 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x13;
        puVar19 = &DAT_803784e0;
        do {
          *puVar19 = 0;
          puVar19 = puVar19 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x10;
        puVar20 = &DAT_803784f4;
        do {
          *puVar20 = 0;
          puVar20 = puVar20 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x120;
        puVar19 = puVar11;
        do {
          *puVar19 = 0;
          puVar19 = puVar19 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x10;
        puVar20 = &DAT_80378514;
        do {
          *puVar20 = 0;
          puVar20 = puVar20 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar13 = 0x20;
        puVar19 = puVar14;
        do {
          *puVar19 = 0;
          puVar19 = puVar19 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
        iVar16 = (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                   (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                  (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 0x1f) + 0x101;
        pbVar7 = (byte *)((int)puVar6 + ((int)(uVar10 + 5) >> 3));
        uVar10 = uVar10 + 5 & 7;
        uVar17 = 0x20 - uVar10 & 0x1f;
        iVar23 = (((uint)*pbVar7 << uVar17 & 0xff | (uint)(*pbVar7 >> 0x20 - uVar17) |
                  (uint)pbVar7[1] << 8 - uVar10) & 0x1f) + 1;
        pbVar7 = pbVar7 + ((int)(uVar10 + 5) >> 3);
        uVar24 = uVar10 + 5 & 7;
        bVar2 = pbVar7[1];
        bVar3 = *pbVar7;
        uVar18 = 0x20 - uVar24 & 0x1f;
        uVar10 = uVar24 + 4;
        puVar6 = (ushort *)(pbVar7 + ((int)uVar10 >> 3));
        puVar28 = &DAT_802c23d0;
        iVar13 = 0;
        while( true ) {
          uVar10 = uVar10 & 7;
          uVar17 = 0x20 - uVar10;
          if (iVar13 == (((uint)bVar3 << uVar18 & 0xff | (uint)(bVar3 >> 0x20 - uVar18) |
                         (uint)bVar2 << 8 - uVar24) & 0xf) + 4) break;
          uVar17 = ((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                    (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                   (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 7;
          (&DAT_803784e0)[(byte)(&DAT_802c23d0)[iVar13]] = (char)uVar17;
          uVar10 = uVar10 + 3;
          (&DAT_803dd9a0)[uVar17] = (&DAT_803dd9a0)[uVar17] + '\x01';
          puVar6 = (ushort *)((int)puVar6 + ((int)uVar10 >> 3));
          iVar13 = iVar13 + 1;
        }
        for (iVar13 = 7; (&DAT_803dd9a0)[iVar13] == '\0'; iVar13 = iVar13 + -1) {
        }
        iVar22 = 0;
        for (iVar25 = 1; iVar25 <= iVar13; iVar25 = iVar25 + 1) {
          if ((byte)(&DAT_803dd9a0)[iVar25] != 0) {
            (&DAT_803dd998)[iVar25] = (char)iVar22;
            iVar22 = iVar22 + ((uint)(byte)(&DAT_803dd9a0)[iVar25] << iVar13 - iVar25);
          }
        }
        for (iVar22 = 0; iVar22 < 0x13; iVar22 = iVar22 + 1) {
          puVar28 = &DAT_803dd998;
          uVar18 = (uint)(byte)(&DAT_803784e0)[iVar22];
          if (uVar18 != 0) {
            for (iVar25 = 0; iVar25 < 1 << iVar13 - uVar18; iVar25 = iVar25 + 1) {
              bVar2 = (&DAT_803dd998)[uVar18];
              (&DAT_803dd998)[uVar18] = bVar2 + 1;
              (&DAT_80378534)[bVar2] = (char)iVar22;
            }
          }
        }
        puVar20 = &DAT_803784f4;
        iVar22 = 0;
        puVar19 = puVar11;
        do {
          uVar18 = 0;
          if (8 - iVar13 < (int)uVar10) {
            uVar18 = (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10;
          }
          uVar24 = iVar13 + 0x18U & 0x1f;
          puVar27 = (undefined1 *)
                    (uint)(byte)(&DAT_80378534)
                                [(uint)(byte)(&DAT_8030d9a0)
                                             [((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                                               (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                                              uVar18) & (1 << iVar13) - 1U] << uVar24 & 0xff |
                                 (uint)((byte)(&DAT_8030d9a0)
                                              [((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                                                (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                                               uVar18) & (1 << iVar13) - 1U] >> 0x20 - uVar24)];
          puVar6 = (ushort *)
                   ((int)puVar6 + ((int)(uVar10 + (byte)(&DAT_803784e0)[(int)puVar27]) >> 3));
          uVar10 = uVar10 + (byte)(&DAT_803784e0)[(int)puVar27] & 7;
          bVar31 = uVar10 < 0x21;
          uVar17 = 0x20 - uVar10;
          if (puVar27 == (undefined1 *)0x10) {
            uVar18 = (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                       (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                      (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 3) + 3;
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + 2) >> 3));
            uVar10 = uVar10 + 2 & 7;
            bVar31 = uVar10 < 0x21;
            uVar17 = 0x20 - uVar10;
            puVar27 = puVar28;
          }
          else if (puVar27 == (undefined1 *)0x11) {
            puVar27 = (undefined1 *)0x0;
            uVar18 = (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                       (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                      (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 7) + 3;
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + 3) >> 3));
            uVar10 = uVar10 + 3 & 7;
            bVar31 = uVar10 < 0x21;
            uVar17 = 0x20 - uVar10;
          }
          else if (puVar27 == (undefined1 *)0x12) {
            puVar27 = (undefined1 *)0x0;
            uVar18 = (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                       (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                      (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & 0x7f) + 0xb;
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + 7) >> 3));
            uVar10 = uVar10 + 7 & 7;
            bVar31 = uVar10 < 0x21;
            uVar17 = 0x20 - uVar10;
          }
          else {
            uVar18 = 1;
          }
          do {
            puVar19[iVar22] = (char)puVar27;
            iVar22 = iVar22 + 1;
            puVar20[(int)puVar27] = puVar20[(int)puVar27] + 1;
            if ((puVar19 == &DAT_803603a0) && (iVar22 == iVar16)) {
              puVar20 = &DAT_80378514;
              iVar22 = 0;
              puVar19 = puVar14;
            }
            uVar24 = (uint)bVar31;
            bVar31 = CARRY4(uVar18,uVar24 - 1);
            uVar18 = uVar18 + (uVar24 - 1);
          } while (uVar18 != 0);
          puVar28 = puVar27;
        } while ((puVar19 == &DAT_803603a0) || (iVar22 < iVar23));
        iVar13 = 0xf;
        for (psVar21 = &DAT_80378512; *psVar21 == 0; psVar21 = psVar21 + -1) {
          iVar13 = iVar13 + -1;
        }
        iVar22 = 0;
        for (iVar25 = 1; iVar25 <= iVar13; iVar25 = iVar25 + 1) {
          uVar4 = (&DAT_803784f4)[iVar25];
          if (uVar4 != 0) {
            *(short *)(iVar25 * 2 + -0x7fc87a4c) = (short)iVar22;
            iVar22 = iVar22 + ((uint)uVar4 << iVar13 - iVar25);
          }
        }
        for (iVar22 = 0; iVar22 < iVar16; iVar22 = iVar22 + 1) {
          uVar18 = (uint)(byte)(&DAT_803603a0)[iVar22];
          if (uVar18 != 0) {
            for (iVar25 = 0; iVar25 < 1 << iVar13 - uVar18; iVar25 = iVar25 + 1) {
              puVar8 = (ushort *)(uVar18 * 2 + -0x7fc87a4c);
              uVar4 = *puVar8;
              *puVar8 = uVar4 + 1;
              *(short *)((uint)uVar4 * 2 + -0x7fc9fb40) = (short)iVar22;
            }
          }
        }
        for (iVar16 = 0xf; (&DAT_80378514)[iVar16] == 0; iVar16 = iVar16 + -1) {
        }
        iVar22 = 0;
        for (iVar25 = 1; iVar25 <= iVar16; iVar25 = iVar25 + 1) {
          if ((ushort)(&DAT_80378514)[iVar25] != 0) {
            (&DAT_803785d4)[iVar25] = (short)iVar22;
            iVar22 = iVar22 + ((uint)(ushort)(&DAT_80378514)[iVar25] << iVar16 - iVar25);
          }
        }
        for (iVar22 = 0; iVar22 < iVar23; iVar22 = iVar22 + 1) {
          uVar18 = (uint)(byte)(&DAT_803704c0)[iVar22];
          if (uVar18 != 0) {
            for (iVar25 = 0; iVar25 < 1 << iVar16 - uVar18; iVar25 = iVar25 + 1) {
              uVar4 = (&DAT_803785d4)[uVar18];
              (&DAT_803785d4)[uVar18] = uVar4 + 1;
              (&DAT_803704e0)[uVar4] = (char)iVar22;
            }
          }
        }
      }
      do {
        uVar24 = ((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                  (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                  (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10 |
                 (uint)*(byte *)(puVar6 + 1) << 0x10 - uVar10) & (1 << iVar13) - 1U;
        uVar17 = iVar13 - 8U & 0x1f;
        uVar18 = iVar13 + 0x10U & 0x1f;
        uVar4 = *(ushort *)
                 (iVar12 + ((uint)(byte)(&DAT_8030d9a0)[uVar24 & 0xff] << uVar17 & 0xffff |
                            (uint)((byte)(&DAT_8030d9a0)[uVar24 & 0xff] >> 0x20 - uVar17) |
                           (uint)(byte)(&DAT_8030d9a0)[uVar24 >> 8] << uVar18 & 0xff |
                           (uint)((byte)(&DAT_8030d9a0)[uVar24 >> 8] >> 0x20 - uVar18)) * 2);
        uVar18 = (uint)uVar4;
        puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + (byte)puVar11[uVar18]) >> 3));
        uVar10 = uVar10 + (byte)puVar11[uVar18] & 7;
        uVar17 = 0x20 - uVar10;
        if (uVar18 < 0x100) {
          pbVar9 = pbVar9 + 1;
          *pbVar9 = (byte)uVar4;
        }
        else {
          if (uVar18 == 0x100) break;
          iVar23 = (uVar18 - 0x101) * 4;
          uVar29 = (uint)*(ushort *)(&DAT_802c23e4 + iVar23);
          uVar24 = (uint)*(ushort *)(&DAT_802c23e6 + iVar23);
          if (uVar24 != 0) {
            uVar29 = uVar29 + (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                                (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                               (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10) & (1 << uVar24) - 1U)
            ;
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + uVar24) >> 3));
            uVar10 = uVar10 + uVar24 & 7;
            uVar17 = 0x20 - uVar10;
          }
          uVar26 = ((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                    (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                    (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10 |
                   (uint)*(byte *)(puVar6 + 1) << 0x10 - uVar10) & (1 << iVar16) - 1U;
          uVar24 = iVar16 - 8U & 0x1f;
          uVar30 = iVar16 + 0x10U & 0x1f;
          puVar6 = (ushort *)
                   ((int)puVar6 +
                   ((int)(uVar10 + (byte)puVar14[(byte)puVar15[(uint)(byte)(&DAT_8030d9a0)
                                                                           [uVar26 & 0xff] << uVar24
                                                               & 0xffff |
                                                               (uint)((byte)(&DAT_8030d9a0)
                                                                            [uVar26 & 0xff] >>
                                                                     0x20 - uVar24) |
                                                               (uint)(byte)(&DAT_8030d9a0)
                                                                           [uVar26 >> 8] << uVar30 &
                                                               0xff | (uint)((byte)(&DAT_8030d9a0)
                                                                                   [uVar26 >> 8] >>
                                                                            0x20 - uVar30)]]) >> 3))
          ;
          uVar10 = uVar10 + (byte)puVar14[(byte)puVar15[(uint)(byte)(&DAT_8030d9a0)[uVar26 & 0xff]
                                                        << uVar24 & 0xffff |
                                                        (uint)((byte)(&DAT_8030d9a0)[uVar26 & 0xff]
                                                              >> 0x20 - uVar24) |
                                                        (uint)(byte)(&DAT_8030d9a0)[uVar26 >> 8] <<
                                                        uVar30 & 0xff |
                                                        (uint)((byte)(&DAT_8030d9a0)[uVar26 >> 8] >>
                                                              0x20 - uVar30)]] & 7;
          uVar17 = 0x20 - uVar10;
          iVar23 = (uint)(byte)puVar15[(uint)(byte)(&DAT_8030d9a0)[uVar26 & 0xff] << uVar24 & 0xffff
                                       | (uint)((byte)(&DAT_8030d9a0)[uVar26 & 0xff] >>
                                               0x20 - uVar24) |
                                       (uint)(byte)(&DAT_8030d9a0)[uVar26 >> 8] << uVar30 & 0xff |
                                       (uint)((byte)(&DAT_8030d9a0)[uVar26 >> 8] >> 0x20 - uVar30)]
                   * 4;
          uVar30 = (uint)*(ushort *)(&DAT_802c2458 + iVar23);
          uVar24 = (uint)*(ushort *)(&DAT_802c245a + iVar23);
          if (uVar24 != 0) {
            uVar30 = uVar30 + (((uint)*(byte *)puVar6 << (uVar17 & 0x1f) & 0xff |
                                (uint)(*(byte *)puVar6 >> 0x20 - (uVar17 & 0x1f)) |
                                (uint)*(byte *)((int)puVar6 + 1) << 8 - uVar10 |
                               (uint)*(byte *)(puVar6 + 1) << 0x10 - uVar10) & (1 << uVar24) - 1U);
            puVar6 = (ushort *)((int)puVar6 + ((int)(uVar10 + uVar24) >> 3));
            uVar10 = uVar10 + uVar24 & 7;
            uVar17 = 0x20 - uVar10;
          }
          pbVar7 = pbVar9 + -uVar30;
          do {
            pbVar7 = pbVar7 + 1;
            pbVar9 = pbVar9 + 1;
            *pbVar9 = *pbVar7;
            uVar29 = uVar29 - 1;
          } while (uVar29 != 0);
        }
      } while (uVar18 != 0x100);
    }
    if ((((uint)bVar1 << uVar5 | (uint)(bVar1 >> 0x20 - uVar5)) & 1) != 0) {
      return 0;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_8004c104
 * EN v1.0 Address: 0x8004C104
 * EN v1.0 Size: 604b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004c104(char *param_1,char param_2,char param_3,undefined4 *param_4,undefined4 *param_5)
{
  char cVar1;
  bool bVar2;
  bool bVar3;
  undefined4 local_8 [2];
  
  bVar2 = false;
  bVar3 = false;
  if (param_2 == '\0') {
    bVar2 = true;
  }
  else {
    cVar1 = *param_1;
    if ((cVar1 == param_1[1]) && (cVar1 == param_1[2])) {
      if (cVar1 == -1) {
        *param_4 = 0;
        bVar2 = true;
      }
      else if (cVar1 == -0x20) {
        *param_4 = 1;
        bVar2 = true;
      }
      else if (cVar1 == -0x40) {
        *param_4 = 2;
        bVar2 = true;
      }
      else if (cVar1 == -0x60) {
        *param_4 = 3;
        bVar2 = true;
      }
      else if (cVar1 == -0x80) {
        *param_4 = 4;
        bVar2 = true;
      }
      else if (cVar1 == '`') {
        *param_4 = 5;
        bVar2 = true;
      }
      else if (cVar1 == '@') {
        *param_4 = 6;
        bVar2 = true;
      }
      else if (cVar1 == ' ') {
        *param_4 = 7;
        bVar2 = true;
      }
    }
    if (!bVar2) {
      *param_4 = DAT_803dd9f0;
    }
  }
  if (param_3 == '\0') {
    bVar3 = true;
  }
  else {
    cVar1 = param_1[3];
    if (cVar1 == -1) {
      *param_5 = 0;
      bVar3 = true;
    }
    else if (cVar1 == -0x20) {
      *param_5 = 1;
      bVar3 = true;
    }
    else if (cVar1 == -0x40) {
      *param_5 = 2;
      bVar3 = true;
    }
    else if (cVar1 == -0x60) {
      *param_5 = 3;
      bVar3 = true;
    }
    else if (cVar1 == -0x80) {
      *param_5 = 4;
      bVar3 = true;
    }
    else if (cVar1 == '`') {
      *param_5 = 5;
      bVar3 = true;
    }
    else if (cVar1 == '@') {
      *param_5 = 6;
      bVar3 = true;
    }
    else if (cVar1 == ' ') {
      *param_5 = 7;
      bVar3 = true;
    }
    if (!bVar3) {
      *param_5 = DAT_803dd9ec;
    }
  }
  if ((!bVar2) || (!bVar3)) {
    local_8[0] = *(undefined4 *)param_1;
    FUN_8025c510(DAT_803dd9f4,(byte *)local_8);
    DAT_803dd9f4 = DAT_803dd9f4 + 1;
    DAT_803dd9f0 = DAT_803dd9f0 + 1;
    DAT_803dd9ec = DAT_803dd9ec + 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004c360
 * EN v1.0 Address: 0x8004C360
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004c360(double param_1,undefined param_2)
{
  uRam803dc24f = param_2;
  FLOAT_803dc250 = (float)param_1;
  if (param_1 <= (double)FLOAT_803df748) {
    return;
  }
  FLOAT_803dc250 = FLOAT_803df748;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004c380
 * EN v1.0 Address: 0x8004C380
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004c380(void)
{
  DAT_803dd9a8 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004c38c
 * EN v1.0 Address: 0x8004C38C
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004c38c(double param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined param_6)
{
  DAT_803dd9a8 = 1;
  FLOAT_803dd9c4 = (float)param_1;
  FLOAT_803dd9c0 = (float)param_2;
  FLOAT_803dd9bc = (float)param_3;
  FLOAT_803dd9b8 = (float)param_4;
  FLOAT_803dd9b4 = (float)param_5;
  DAT_803dd9b1 = param_6;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004c3b0
 * EN v1.0 Address: 0x8004C3B0
 * EN v1.0 Size: 20b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004c3b0(undefined4 *param_1,undefined4 *param_2)
{
  *param_1 = FLOAT_803dd9c4;
  *param_2 = FLOAT_803dd9c0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004c3c4
 * EN v1.0 Address: 0x8004C3C4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_8004c3c4(void)
{
  return DAT_803dd9a8;
}

/*
 * --INFO--
 *
 * Function: FUN_8004c3cc
 * EN v1.0 Address: 0x8004C3CC
 * EN v1.0 Size: 20b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8004c3cc(int param_1,int param_2)
{
  return param_1 + param_2 * 8 + 0x24;
}

/*
 * --INFO--
 *
 * Function: FUN_8004c3e0
 * EN v1.0 Address: 0x8004C3E0
 * EN v1.0 Size: 128b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004c3e0(int param_1,int param_2)
{
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),param_2);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),param_2);
    }
    if (*(int *)(param_1 + 0x50) != 0) {
      FUN_80053dbc(param_1,(uint *)&DAT_80378600);
      FUN_8025b054((uint *)&DAT_80378600,1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004c460
 * EN v1.0 Address: 0x8004C460
 * EN v1.0 Size: 76b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004c460(int param_1,int param_2)
{
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),param_2);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),param_2);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004c4ac
 * EN v1.0 Address: 0x8004C4AC
 * EN v1.0 Size: 1148b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004c4ac(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8004c928
 * EN v1.0 Address: 0x8004C928
 * EN v1.0 Size: 1632b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004c928(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5)
{
  uint uVar1;
  uint uVar2;
  double dVar3;
  undefined8 uVar4;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  uint auStack_84 [8];
  uint auStack_64 [8];
  uint auStack_44 [17];
  
  uVar4 = FUN_80286840();
  if ((((DAT_803dd9ea < 0xc) && (DAT_803dd9e9 < 7)) && ((int)DAT_803dda0c < 6)) &&
     (DAT_803dd9f4 < 2)) {
    FUN_80258674(DAT_803dda08,1,4,0x3c,0,0x7d);
    FUN_80258674(DAT_803dda08 + 1,1,4,0x3c,0,0x7d);
    FUN_8025c828(DAT_803dda10,DAT_803dda08 + 1,DAT_803dda0c + 1,0xff);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c1a4(DAT_803dda10,0xf,8,0xe,2);
    FUN_8025c2a8(DAT_803dda10,0,0,0,0,2);
    FUN_8025c224(DAT_803dda10,7,4,6,1);
    FUN_8025c368(DAT_803dda10,1,0,0,0,2);
    FUN_8025c584(DAT_803dda10,DAT_803dd9f0);
    FUN_8025c5f0(DAT_803dda10,DAT_803dd9ec);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c + 2,0xff);
    FUN_8025be80(DAT_803dda10 + 1);
    FUN_8025c1a4(DAT_803dda10 + 1,0xf,8,0xe,4);
    FUN_8025c2a8(DAT_803dda10 + 1,0,0,1,0,2);
    FUN_8025c224(DAT_803dda10 + 1,7,4,6,2);
    FUN_8025c368(DAT_803dda10 + 1,1,0,0,0,2);
    FUN_8025c584(DAT_803dda10 + 1,DAT_803dd9f0 + 1);
    FUN_8025c5f0(DAT_803dda10 + 1,DAT_803dd9ec + 1);
    FUN_8025c65c(DAT_803dda10 + 1,0,0);
    FUN_8025c828(DAT_803dda10 + 2,DAT_803dda08,DAT_803dda0c,0xff);
    FUN_8025be80(DAT_803dda10 + 2);
    FUN_8025c1a4(DAT_803dda10 + 2,0xf,8,0xc,4);
    FUN_8025c2a8(DAT_803dda10 + 2,0,0,0,1,2);
    FUN_8025c224(DAT_803dda10 + 2,4,7,7,2);
    FUN_8025c368(DAT_803dda10 + 2,0,0,0,1,2);
    FUN_8025c65c(DAT_803dda10 + 2,0,0);
    FUN_8025c828(DAT_803dda10 + 3,0xff,0xff,0xff);
    FUN_8025be80(DAT_803dda10 + 3);
    FUN_8025c1a4(DAT_803dda10 + 3,5,4,0xe,0xf);
    FUN_8025c2a8(DAT_803dda10 + 3,0,0,0,1,2);
    FUN_8025c224(DAT_803dda10 + 3,7,7,7,7);
    FUN_8025c368(DAT_803dda10 + 3,0,0,0,1,2);
    FUN_8025c65c(DAT_803dda10 + 3,0,0);
    FUN_8025c584(DAT_803dda10 + 3,DAT_803dd9f0 + 2);
    FUN_8025c828(DAT_803dda10 + 4,0xff,0xff,0xff);
    FUN_8025be80(DAT_803dda10 + 4);
    FUN_8025c1a4(DAT_803dda10 + 4,0,4,0xe,0xf);
    FUN_8025c2a8(DAT_803dda10 + 4,0,0,0,1,0);
    FUN_8025c224(DAT_803dda10 + 4,7,7,7,0);
    FUN_8025c368(DAT_803dda10 + 4,0,0,0,1,0);
    FUN_8025c65c(DAT_803dda10 + 4,0,0);
    FUN_8025c584(DAT_803dda10 + 4,6);
    DAT_803dd9b0 = 1;
    local_8c = DAT_803df730;
    local_88 = DAT_803df734;
    FUN_8025c49c(1,(short *)&local_8c);
    local_90 = DAT_803df738;
    FUN_8025c510(DAT_803dd9f4,(byte *)&local_90);
    local_94 = DAT_803df73c;
    FUN_8025c510(DAT_803dd9f4 + 1,(byte *)&local_94);
    local_98 = DAT_803df740;
    FUN_8025c510(DAT_803dd9f4 + 2,(byte *)&local_98);
    FUN_8025aa74(auStack_44,(uint)((ulonglong)uVar4 >> 0x20),param_4 & 0xffff,param_5 & 0xffff,1,0,0
                 ,'\0');
    dVar3 = (double)FLOAT_803df74c;
    FUN_8025ace8(dVar3,dVar3,dVar3,auStack_44,0,0,0,'\0',0);
    FUN_8025b054(auStack_44,DAT_803dda0c);
    uVar2 = (int)(short)param_4 >> 1;
    uVar1 = (int)(short)param_5 >> 1;
    FUN_8025aa74(auStack_64,(uint)uVar4,uVar2 & 0xffff,uVar1 & 0xffff,1,0,0,'\0');
    dVar3 = (double)FLOAT_803df74c;
    FUN_8025ace8(dVar3,dVar3,dVar3,auStack_64,0,0,0,'\0',0);
    FUN_8025b054(auStack_64,DAT_803dda0c + 1);
    FUN_8025aa74(auStack_84,param_3,uVar2 & 0xffff,uVar1 & 0xffff,1,0,0,'\0');
    dVar3 = (double)FLOAT_803df74c;
    FUN_8025ace8(dVar3,dVar3,dVar3,auStack_84,0,0,0,'\0',0);
    FUN_8025b054(auStack_84,DAT_803dda0c + 2);
    DAT_803dda10 = DAT_803dda10 + 5;
    DAT_803dda08 = DAT_803dda08 + 2;
    DAT_803dda0c = DAT_803dda0c + 3;
    DAT_803dd9f4 = DAT_803dd9f4 + 3;
    DAT_803dd9f0 = DAT_803dd9f0 + 3;
    DAT_803dd9ec = DAT_803dd9ec + 3;
    DAT_803dd9ea = DAT_803dd9ea + 5;
    DAT_803dd9e9 = DAT_803dd9e9 + 2;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004cf88
 * EN v1.0 Address: 0x8004CF88
 * EN v1.0 Size: 1060b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004cf88(float *param_1)
{
  int local_80;
  int local_7c;
  float local_78;
  float local_74;
  float local_70 [5];
  float local_5c;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_8025be80(0);
  FUN_8025c828(0,0,0,4);
  FUN_8025c1a4(0,0xf,8,10,0xf);
  FUN_8025c224(0,4,7,5,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  local_40 = FLOAT_803df764;
  local_3c = FLOAT_803df74c;
  local_38 = FLOAT_803df74c;
  local_34 = FLOAT_803df74c;
  local_30 = FLOAT_803df74c;
  local_2c = FLOAT_803df74c;
  local_28 = FLOAT_803df764;
  local_24 = FLOAT_803df74c;
  FUN_8025d8c4(&local_40,0x1e,1);
  FUN_80258674(1,1,0,0x1e,0,0x7d);
  FUN_8006c760(&local_7c);
  if (local_7c != 0) {
    if (*(char *)(local_7c + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_7c + 0x20),2);
    }
    else {
      FUN_8025aeac((uint *)(local_7c + 0x20),*(uint **)(local_7c + 0x40),2);
    }
  }
  FUN_8006cc38(&local_74,&local_78);
  FUN_80247a48((double)(FLOAT_803df760 * local_74),(double)(FLOAT_803df760 * local_78),
               (double)FLOAT_803df74c,local_70);
  local_70[0] = FLOAT_803df768;
  local_5c = FLOAT_803df768;
  FUN_8025d8c4(local_70,0x21,1);
  FUN_80258674(2,1,0,0x21,0,0x7d);
  FUN_8025bd1c(0,2,2);
  FUN_8025bb48(0,0,0);
  FUN_8025b94c(1,0,0,7,1,0,0,0,0,0);
  FUN_8025c584(1,4);
  FUN_8025c828(1,1,1,0xff);
  FUN_8025c1a4(1,8,0xe,0,0);
  FUN_8025c224(1,7,4,0,7);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,1,1,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  FUN_8006c734(&local_80);
  if (local_80 != 0) {
    if (*(char *)(local_80 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_80 + 0x20),3);
    }
    else {
      FUN_8025aeac((uint *)(local_80 + 0x20),*(uint **)(local_80 + 0x40),3);
    }
  }
  local_40 = FLOAT_803df74c;
  local_3c = FLOAT_803df74c;
  local_38 = FLOAT_803df76c;
  local_34 = FLOAT_803df770;
  local_30 = FLOAT_803df74c;
  local_2c = FLOAT_803df74c;
  local_28 = FLOAT_803df74c;
  local_24 = FLOAT_803df74c;
  FUN_80247618(&local_40,param_1,&local_40);
  FUN_8025d8c4(&local_40,0x24,1);
  FUN_80258674(3,1,0,0x24,0,0x7d);
  FUN_8025be80(2);
  FUN_8025c828(2,3,3,0xff);
  FUN_8025c1a4(2,0xf,0xf,0xf,0);
  FUN_8025c224(2,7,4,0,7);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,0,0,0,1,0);
  DAT_803dda10 = 3;
  DAT_803dda08 = 4;
  DAT_803dda0c = 4;
  DAT_803dd9fc = 1;
  DAT_803dda04 = 0x27;
  DAT_803dd9ea = 3;
  DAT_803dd9e9 = 4;
  DAT_803dd9e8 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004d3ac
 * EN v1.0 Address: 0x8004D3AC
 * EN v1.0 Size: 900b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004d3ac(void)
{
  int iVar1;
  double dVar2;
  double dVar3;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float afStack_48 [17];
  
  iVar1 = FUN_8006c8d0();
  dVar3 = (double)FLOAT_803df75c;
  FUN_80247b70((double)FLOAT_803df774,(double)FLOAT_803df778,(double)FLOAT_803df778,
               (double)FLOAT_803df774,dVar3,dVar3,dVar3,dVar3,afStack_48);
  FUN_8025d8c4(afStack_48,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c6b4(1,0,0,0,1);
  FUN_8025c65c(DAT_803dda10,1,1);
  if (DAT_803dda10 == 0) {
    FUN_8025c1a4(0,0xf,0xf,0xf,0xf);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0);
  }
  FUN_8025c224(DAT_803dda10,7,7,7,4);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,2);
  DAT_803dd9b0 = 1;
  if (iVar1 != 0) {
    if (*(char *)(iVar1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(iVar1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(iVar1 + 0x20),*(uint **)(iVar1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  iVar1 = FUN_8002bac4();
  if (iVar1 == 0) {
    dVar3 = (double)FLOAT_803df77c;
  }
  else {
    dVar3 = (double)FUN_8000f4a0((double)*(float *)(iVar1 + 0x18),(double)*(float *)(iVar1 + 0x1c),
                                 (double)*(float *)(iVar1 + 0x20));
  }
  dVar2 = -(double)(FLOAT_803df748 /
                   (float)(dVar3 - (double)(float)(dVar3 - (double)FLOAT_803df780)));
  local_78 = FLOAT_803df74c;
  local_74 = FLOAT_803df74c;
  local_70 = (float)dVar2;
  local_6c = (float)(dVar2 * (double)(float)(dVar3 - (double)FLOAT_803df780));
  local_68 = FLOAT_803df74c;
  local_64 = FLOAT_803df74c;
  local_60 = FLOAT_803df74c;
  local_5c = FLOAT_803df74c;
  local_58 = FLOAT_803df74c;
  local_54 = FLOAT_803df74c;
  local_50 = FLOAT_803df74c;
  local_4c = FLOAT_803df74c;
  FUN_8025d8c4(&local_78,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c65c(DAT_803dda10,1,1);
  FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0);
  FUN_8025c5f0(DAT_803dda10,0);
  FUN_8025c224(DAT_803dda10,7,2,4,6);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,1,0,0,1,0);
  DAT_803dd9b0 = 1;
  iVar1 = FUN_8006c8c8();
  if (iVar1 != 0) {
    if (*(char *)(iVar1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(iVar1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(iVar1 + 0x20),*(uint **)(iVar1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9eb = 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x02';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x02';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004d730
 * EN v1.0 Address: 0x8004D730
 * EN v1.0 Size: 292b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004d730(int param_1)
{
  undefined uVar1;
  undefined4 local_8;
  undefined4 local_4;
  
  uVar1 = *(undefined *)(param_1 + 0x43);
  local_4 = CONCAT13(uVar1,CONCAT12(uVar1,CONCAT11(uVar1,(undefined)local_4)));
  local_8 = local_4;
  FUN_8025c510(DAT_803dd9f4,(byte *)&local_8);
  FUN_8025c584(DAT_803dda10,DAT_803dd9f0);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c1a4(DAT_803dda10,0,2,0xe,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dd9f4 = DAT_803dd9f4 + 1;
  DAT_803dd9f0 = DAT_803dd9f0 + 1;
  DAT_803dd9ec = DAT_803dd9ec + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004d854
 * EN v1.0 Address: 0x8004D854
 * EN v1.0 Size: 592b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004d854(void)
{
  double dVar1;
  int local_20;
  float local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  float local_8;
  
  local_1c = DAT_802c2590;
  local_18 = DAT_802c2594;
  local_14 = DAT_802c2598;
  local_10 = DAT_802c259c;
  local_c = DAT_802c25a0;
  local_8 = (float)DAT_802c25a4;
  dVar1 = FUN_8006c7ec();
  local_1c = (float)((double)FLOAT_803df75c * dVar1);
  local_8 = local_1c;
  if (DAT_803dda08 < 1) {
    FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08,DAT_803dda0c + 1);
  }
  else {
    FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08 + -1,DAT_803dda0c + 1);
  }
  FUN_8025bb48(DAT_803dd9fc,0,0);
  FUN_8025b9e8(2,&local_1c,-3);
  FUN_8025b94c(DAT_803dda10,DAT_803dd9fc,0,3,2,0,0,0,0,0);
  FUN_8006c760(&local_20);
  if (local_20 != 0) {
    if (*(char *)(local_20 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_20 + 0x20),DAT_803dda0c + 1);
    }
    else {
      FUN_8025aeac((uint *)(local_20 + 0x20),*(uint **)(local_20 + 0x40),DAT_803dda0c + 1);
    }
  }
  FUN_8025d8c4((float *)&DAT_80397480,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,8);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  FUN_8006c86c(DAT_803dda0c);
  DAT_803dd9fc = DAT_803dd9fc + 1;
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 2;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  DAT_803dd9e8 = DAT_803dd9e8 + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004daa4
 * EN v1.0 Address: 0x8004DAA4
 * EN v1.0 Size: 300b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004daa4(void)
{
  FUN_8006c8d8(DAT_803dda0c);
  FUN_80258674(DAT_803dda08,0,0,0x24,0,0x7d);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c584(DAT_803dda10,6);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c1a4(DAT_803dda10,0xf,8,0xe,0);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dda04 = 0x27;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004dbd0
 * EN v1.0 Address: 0x8004DBD0
 * EN v1.0 Size: 1704b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004dbd0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8004e278
 * EN v1.0 Address: 0x8004E278
 * EN v1.0 Size: 1788b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004e278(void)
{
  float *pfVar1;
  float local_210;
  float local_20c;
  int local_208;
  int local_204;
  float local_200;
  undefined4 local_1fc;
  undefined4 local_1f8;
  float local_1f4;
  undefined4 local_1f0;
  undefined4 local_1ec;
  float local_1e8;
  undefined4 local_1e4;
  undefined4 local_1e0;
  float local_1dc;
  undefined4 local_1d8;
  undefined4 local_1d4;
  float local_1d0;
  undefined4 local_1cc;
  undefined4 local_1c8;
  undefined4 local_1c4;
  undefined4 local_1c0;
  undefined4 local_1bc;
  float afStack_1b8 [12];
  float afStack_188 [12];
  float afStack_158 [12];
  float afStack_128 [12];
  float afStack_f8 [12];
  float local_c8;
  float local_c4;
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
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  
  local_1dc = DAT_802c2500;
  local_1d8 = DAT_802c2504;
  local_1d4 = DAT_802c2508;
  local_1e8 = DAT_802c250c;
  local_1e4 = DAT_802c2510;
  local_1e0 = DAT_802c2514;
  local_1f4 = DAT_802c2518;
  local_1f0 = DAT_802c251c;
  local_1ec = DAT_802c2520;
  local_200 = DAT_802c2524;
  local_1fc = DAT_802c2528;
  local_1f8 = DAT_802c252c;
  local_1d0 = DAT_802c2530;
  local_1cc = DAT_802c2534;
  local_1c8 = DAT_802c2538;
  local_1c4 = DAT_802c253c;
  local_1c0 = DAT_802c2540;
  local_1bc = DAT_802c2544;
  pfVar1 = (float *)FUN_8000f578();
  FUN_80247944((double)FLOAT_803df748,afStack_128,&local_1dc);
  FUN_80247944((double)FLOAT_803df748,afStack_158,&local_1e8);
  FUN_80247944((double)FLOAT_803df748,afStack_188,&local_1f4);
  FUN_80247944((double)FLOAT_803df748,afStack_1b8,&local_200);
  local_38 = FLOAT_803df79c;
  local_34 = FLOAT_803df74c;
  local_30 = FLOAT_803df74c;
  local_2c = FLOAT_803df750 * FLOAT_803df7a0 * FLOAT_803dda58;
  local_28 = FLOAT_803df74c;
  local_24 = FLOAT_803df79c;
  local_20 = FLOAT_803df74c;
  local_1c = FLOAT_803df74c;
  local_18 = FLOAT_803df74c;
  local_14 = FLOAT_803df74c;
  local_10 = FLOAT_803df79c;
  local_c = FLOAT_803df750 * FLOAT_803df7a0 * FLOAT_803dda5c;
  local_68 = FLOAT_803df7a4;
  local_64 = FLOAT_803df74c;
  local_60 = FLOAT_803df74c;
  local_5c = FLOAT_803df75c * FLOAT_803df7a0 * FLOAT_803dda58;
  local_58 = FLOAT_803df74c;
  local_54 = FLOAT_803df7a4;
  local_50 = FLOAT_803df74c;
  local_4c = FLOAT_803df74c;
  local_48 = FLOAT_803df74c;
  local_44 = FLOAT_803df74c;
  local_40 = FLOAT_803df7a4;
  local_3c = FLOAT_803df75c * FLOAT_803df7a0 * FLOAT_803dda5c;
  FUN_80247618(&local_38,pfVar1,&local_38);
  FUN_80247618(afStack_128,&local_38,&local_38);
  local_18 = FLOAT_803df74c;
  local_14 = FLOAT_803df74c;
  local_10 = FLOAT_803df74c;
  local_c = FLOAT_803df748;
  FUN_80247618(&local_68,pfVar1,&local_68);
  FUN_80247618(afStack_158,&local_68,&local_68);
  local_48 = FLOAT_803df74c;
  local_44 = FLOAT_803df74c;
  local_40 = FLOAT_803df74c;
  local_3c = FLOAT_803df748;
  FUN_8025d8c4(&local_38,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  FUN_8025d8c4(&local_68,DAT_803dda00 + 3,0);
  FUN_80258674(DAT_803dda08 + 1,0,0,0,0,DAT_803dda00 + 3);
  FUN_8006c68c(&local_204);
  if (local_204 != 0) {
    if (*(char *)(local_204 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_204 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(local_204 + 0x20),*(uint **)(local_204 + 0x40),DAT_803dda0c);
    }
  }
  FUN_8006cc38(&local_20c,&local_210);
  FUN_8025b9e8(2,&local_1d0,-1);
  FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08 + 2,DAT_803dda0c + 1);
  local_98 = FLOAT_803df7a0;
  local_94 = FLOAT_803df74c;
  local_90 = FLOAT_803df74c;
  local_8c = FLOAT_803df7a0 * FLOAT_803dda58 + local_20c;
  local_88 = FLOAT_803df74c;
  local_84 = FLOAT_803df7a0;
  local_80 = FLOAT_803df74c;
  local_7c = FLOAT_803df74c;
  local_78 = FLOAT_803df74c;
  local_74 = FLOAT_803df74c;
  local_70 = FLOAT_803df7a0;
  local_6c = FLOAT_803df7a0 * FLOAT_803dda5c;
  FUN_8024782c((double)FLOAT_803df7a8,afStack_f8,0x79);
  FUN_80247618(afStack_f8,&local_98,&local_98);
  FUN_80247618(&local_98,pfVar1,&local_98);
  FUN_80247618(afStack_188,&local_98,&local_98);
  local_78 = FLOAT_803df74c;
  local_74 = FLOAT_803df74c;
  local_70 = FLOAT_803df74c;
  local_6c = FLOAT_803df748;
  FUN_8025d8c4(&local_98,DAT_803dda00 + 6,0);
  FUN_80258674(DAT_803dda08 + 2,0,0,0,0,DAT_803dda00 + 6);
  FUN_8025b94c(DAT_803dda10,DAT_803dd9fc,0,2,2,0,0,0,0,0);
  FUN_8025bb48(DAT_803dd9fc,0,0);
  FUN_8025bd1c(DAT_803dd9fc + 1,DAT_803dda08 + 3,DAT_803dda0c + 1);
  local_c8 = FLOAT_803df7a0;
  local_c4 = FLOAT_803df74c;
  local_c0 = FLOAT_803df74c;
  local_bc = FLOAT_803df7a0 * FLOAT_803dda58;
  local_b8 = FLOAT_803df74c;
  local_b4 = FLOAT_803df7a0;
  local_b0 = FLOAT_803df74c;
  local_ac = FLOAT_803df74c;
  local_a8 = FLOAT_803df74c;
  local_a4 = FLOAT_803df74c;
  local_a0 = FLOAT_803df7a0;
  local_9c = FLOAT_803df7a0 * FLOAT_803dda5c + local_210;
  FUN_80247618(&local_c8,pfVar1,&local_c8);
  FUN_80247618(afStack_1b8,&local_c8,&local_c8);
  local_a8 = FLOAT_803df74c;
  local_a4 = FLOAT_803df74c;
  local_a0 = FLOAT_803df74c;
  local_9c = FLOAT_803df748;
  FUN_8025d8c4(&local_c8,DAT_803dda00 + 9,0);
  FUN_80258674(DAT_803dda08 + 3,0,0,0,0,DAT_803dda00 + 9);
  FUN_8025b94c(DAT_803dda10 + 1,DAT_803dd9fc + 1,0,2,2,0,0,1,0,0);
  FUN_8025bb48(DAT_803dd9fc + 1,0,0);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
  FUN_8025c1a4(DAT_803dda10,0xf,0xb,9,0);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c,4);
  FUN_8025c1a4(DAT_803dda10 + 1,0xf,0xb,9,0);
  FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 1,0,0);
  FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8006c760(&local_208);
  if (local_208 != 0) {
    if (*(char *)(local_208 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_208 + 0x20),DAT_803dda0c + 1);
    }
    else {
      FUN_8025aeac((uint *)(local_208 + 0x20),*(uint **)(local_208 + 0x40),DAT_803dda0c + 1);
    }
  }
  DAT_803dda08 = DAT_803dda08 + 4;
  DAT_803dda10 = DAT_803dda10 + 2;
  DAT_803dda0c = DAT_803dda0c + 2;
  DAT_803dda00 = DAT_803dda00 + 0xc;
  DAT_803dd9fc = DAT_803dd9fc + 2;
  DAT_803dd9ea = DAT_803dd9ea + '\x02';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x04';
  DAT_803dd9e8 = DAT_803dd9e8 + '\x02';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004e974
 * EN v1.0 Address: 0x8004E974
 * EN v1.0 Size: 1748b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004e974(undefined4 *param_1)
{
  float fVar1;
  float *pfVar2;
  undefined4 local_100;
  float local_fc;
  float local_f8;
  int local_f4;
  int local_f0;
  float local_ec;
  undefined4 local_e8;
  undefined4 local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  undefined4 local_d8;
  float afStack_d4 [12];
  float local_a4;
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
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  local_ec = DAT_802c24e8;
  local_e8 = DAT_802c24ec;
  local_e4 = DAT_802c24f0;
  local_e0 = DAT_802c24f4;
  local_dc = DAT_802c24f8;
  local_d8 = DAT_802c24fc;
  pfVar2 = (float *)FUN_8000f578();
  local_44 = FLOAT_803df74c;
  local_40 = FLOAT_803df74c;
  local_3c = FLOAT_803df744 / FLOAT_803dd9bc;
  local_38 = FLOAT_803dd9b8;
  fVar1 = FLOAT_803df744 / (FLOAT_803dd9c4 - FLOAT_803dd9c0);
  local_34 = fVar1 * pfVar2[4];
  local_30 = fVar1 * pfVar2[5];
  local_2c = fVar1 * pfVar2[6];
  local_28 = fVar1 * pfVar2[7] + -FLOAT_803dd9c4 * fVar1;
  local_24 = FLOAT_803df74c;
  local_20 = FLOAT_803df74c;
  local_1c = FLOAT_803df74c;
  local_18 = FLOAT_803df748;
  FUN_8025d8c4(&local_44,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  local_100 = *param_1;
  FUN_8025c510(DAT_803dd9f4,(byte *)&local_100);
  FUN_8006c6a4(&local_f0);
  if (local_f0 != 0) {
    if (*(char *)(local_f0 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_f0 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(local_f0 + 0x20),*(uint **)(local_f0 + 0x40),DAT_803dda0c);
    }
  }
  if (DAT_803dd9b1 == '\0') {
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
    FUN_8025c1a4(DAT_803dda10,0,0xe,9,0xf);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    DAT_803dd9b0 = 1;
    FUN_8025c584(DAT_803dda10,DAT_803dd9f0);
    DAT_803dda08 = DAT_803dda08 + 1;
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dda00 = DAT_803dda00 + 3;
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  }
  else {
    FUN_8006cc38(&local_f8,&local_fc);
    local_fc = local_fc * FLOAT_803df760;
    local_f8 = local_f8 * FLOAT_803df788;
    FUN_8025b9e8(2,&local_ec,-2);
    FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08 + 1,DAT_803dda0c + 1);
    local_74 = FLOAT_803dd9b4;
    local_70 = FLOAT_803df74c;
    local_6c = FLOAT_803df74c;
    local_68 = FLOAT_803dda58 * FLOAT_803dd9b4 + local_f8;
    local_64 = FLOAT_803df74c;
    local_60 = FLOAT_803dd9b4;
    local_5c = FLOAT_803df74c;
    local_58 = FLOAT_803df74c;
    local_54 = FLOAT_803df74c;
    local_50 = FLOAT_803df74c;
    local_4c = FLOAT_803df74c;
    local_48 = FLOAT_803df748;
    FUN_8024782c((double)FLOAT_803df7a8,afStack_d4,0x7a);
    FUN_80247618(afStack_d4,&local_74,&local_74);
    FUN_80247618(&local_74,pfVar2,&local_74);
    FUN_8025d8c4(&local_74,DAT_803dda00 + 3,0);
    FUN_80258674(DAT_803dda08 + 1,0,0,0,0,DAT_803dda00 + 3);
    FUN_8025b94c(DAT_803dda10,DAT_803dd9fc,0,2,2,6,6,0,0,0);
    FUN_8025bb48(DAT_803dd9fc,0,0);
    FUN_8025bd1c(DAT_803dd9fc + 1,DAT_803dda08 + 2,DAT_803dda0c + 1);
    local_a4 = FLOAT_803df74c;
    local_a0 = FLOAT_803df74c;
    local_9c = FLOAT_803dd9b4;
    local_98 = FLOAT_803dda5c * FLOAT_803dd9b4 + local_fc;
    local_94 = FLOAT_803df74c;
    local_90 = FLOAT_803dd9b4;
    local_8c = FLOAT_803df74c;
    local_88 = FLOAT_803df74c;
    local_84 = FLOAT_803df74c;
    local_80 = FLOAT_803df74c;
    local_7c = FLOAT_803df74c;
    local_78 = FLOAT_803df748;
    FUN_8024782c((double)FLOAT_803df7ac,afStack_d4,0x78);
    FUN_80247618(afStack_d4,&local_a4,&local_a4);
    FUN_80247618(&local_a4,pfVar2,&local_a4);
    FUN_8025d8c4(&local_a4,DAT_803dda00 + 6,0);
    FUN_80258674(DAT_803dda08 + 2,0,0,0,0,DAT_803dda00 + 6);
    FUN_8025b94c(DAT_803dda10 + 1,DAT_803dd9fc + 1,0,2,2,0,0,1,0,0);
    FUN_8025bb48(DAT_803dd9fc + 1,0,0);
    FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    DAT_803dd9b0 = 1;
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08,DAT_803dda0c,0xff);
    FUN_8025c1a4(DAT_803dda10 + 1,0,0xe,9,0xf);
    FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
    FUN_8025c65c(DAT_803dda10 + 1,0,0);
    FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
    FUN_8006c760(&local_f4);
    if (local_f4 != 0) {
      if (*(char *)(local_f4 + 0x48) == '\0') {
        FUN_8025b054((uint *)(local_f4 + 0x20),DAT_803dda0c + 1);
      }
      else {
        FUN_8025aeac((uint *)(local_f4 + 0x20),*(uint **)(local_f4 + 0x40),DAT_803dda0c + 1);
      }
    }
    FUN_8025c584(DAT_803dda10 + 1,DAT_803dd9f0);
    DAT_803dda08 = DAT_803dda08 + 3;
    DAT_803dda10 = DAT_803dda10 + 2;
    DAT_803dda0c = DAT_803dda0c + 2;
    DAT_803dda00 = DAT_803dda00 + 9;
    DAT_803dd9fc = DAT_803dd9fc + 2;
    DAT_803dd9ea = DAT_803dd9ea + '\x02';
    DAT_803dd9e9 = DAT_803dd9e9 + '\x03';
    DAT_803dd9e8 = DAT_803dd9e8 + '\x02';
  }
  DAT_803dd9f4 = DAT_803dd9f4 + 1;
  DAT_803dd9f0 = DAT_803dd9f0 + 1;
  DAT_803dd9ec = DAT_803dd9ec + 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004f048
 * EN v1.0 Address: 0x8004F048
 * EN v1.0 Size: 208b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004f048(void)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,4);
  FUN_8025c1a4(DAT_803dda10,0,0xf,0xb,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004f118
 * EN v1.0 Address: 0x8004F118
 * EN v1.0 Size: 228b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004f118(undefined4 *param_1)
{
  undefined4 local_8 [2];
  
  local_8[0] = *param_1;
  FUN_8025c428(2,(byte *)local_8);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
  FUN_8025c1a4(DAT_803dda10,0xf,0,4,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004f1fc
 * EN v1.0 Address: 0x8004F1FC
 * EN v1.0 Size: 560b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004f1fc(void)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
  FUN_8025c1a4(DAT_803dda10,0xf,0,4,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  FUN_8025be80(DAT_803dda10 + 1);
  FUN_8025c828(DAT_803dda10 + 1,0xff,0xff,0xff);
  FUN_8025c1a4(DAT_803dda10 + 1,4,0xf,0xf,0);
  FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 1,0,0);
  FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025be80(DAT_803dda10 + 2);
  FUN_8025c828(DAT_803dda10 + 2,0xff,0xff,4);
  FUN_8025c1a4(DAT_803dda10 + 2,0,6,0xb,0xf);
  FUN_8025c224(DAT_803dda10 + 2,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 2,0,0);
  FUN_8025c2a8(DAT_803dda10 + 2,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10 + 2,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 3;
  DAT_803dd9ea = DAT_803dd9ea + '\x03';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004f42c
 * EN v1.0 Address: 0x8004F42C
 * EN v1.0 Size: 208b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004f42c(void)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
  FUN_8025c1a4(DAT_803dda10,0xf,0,4,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004f4fc
 * EN v1.0 Address: 0x8004F4FC
 * EN v1.0 Size: 856b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004f4fc(double param_1,undefined4 *param_2,float *param_3)
{
  double dVar1;
  double dVar2;
  undefined4 local_78;
  int local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  if (((DAT_803dd9f4 < 4) && (DAT_803dd9ea < 0xc)) && (DAT_803dd9e9 < 7)) {
    dVar1 = (double)FLOAT_803df75c;
    local_6c = (float)(dVar1 / param_1);
    dVar2 = (double)local_6c;
    local_3c = FLOAT_803df74c;
    local_38 = FLOAT_803df74c;
    local_34 = (float)(-(double)*param_3 * dVar2 + dVar1);
    local_30 = FLOAT_803df74c;
    local_2c = FLOAT_803df74c;
    local_24 = (float)(-(double)param_3[2] * dVar2 + dVar1);
    local_20 = FLOAT_803df74c;
    local_1c = FLOAT_803df74c;
    local_18 = FLOAT_803df74c;
    local_14 = FLOAT_803df748;
    local_70 = FLOAT_803df74c;
    local_68 = FLOAT_803df74c;
    local_64 = (float)(-(double)param_3[1] * dVar2 + dVar1);
    local_60 = FLOAT_803df74c;
    local_5c = FLOAT_803df74c;
    local_58 = FLOAT_803df74c;
    local_54 = FLOAT_803df75c;
    local_50 = FLOAT_803df74c;
    local_4c = FLOAT_803df74c;
    local_48 = FLOAT_803df74c;
    local_44 = FLOAT_803df748;
    local_40 = local_6c;
    local_28 = local_6c;
    FUN_8006c6bc(&local_74);
    FUN_8025d8c4(&local_40,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
    FUN_8025d8c4(&local_70,DAT_803dda00 + 3,0);
    FUN_80258674(DAT_803dda08 + 1,0,0,0,0,DAT_803dda00 + 3);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
    local_78 = *param_2;
    FUN_8025c510(DAT_803dd9f4,(byte *)&local_78);
    FUN_8025c584(DAT_803dda10,DAT_803dd9f0);
    FUN_8025c1a4(DAT_803dda10,0xf,0xe,8,0xf);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    FUN_8025be80(DAT_803dda10 + 1);
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c,0xff);
    FUN_8025c1a4(DAT_803dda10 + 1,0xf,2,8,4);
    FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
    FUN_8025c65c(DAT_803dda10 + 1,0,0);
    FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,2);
    FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
    if (local_74 != 0) {
      if (*(char *)(local_74 + 0x48) == '\0') {
        FUN_8025b054((uint *)(local_74 + 0x20),DAT_803dda0c);
      }
      else {
        FUN_8025aeac((uint *)(local_74 + 0x20),*(uint **)(local_74 + 0x40),DAT_803dda0c);
      }
    }
    DAT_803dda10 = DAT_803dda10 + 2;
    DAT_803dda08 = DAT_803dda08 + 2;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9f4 = DAT_803dd9f4 + 1;
    DAT_803dd9f0 = DAT_803dd9f0 + 1;
    DAT_803dd9ec = DAT_803dd9ec + 1;
    DAT_803dda00 = DAT_803dda00 + 6;
    DAT_803dd9e9 = DAT_803dd9e9 + 2;
    DAT_803dd9ea = DAT_803dd9ea + 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004f854
 * EN v1.0 Address: 0x8004F854
 * EN v1.0 Size: 856b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004f854(double param_1,undefined4 *param_2,float *param_3)
{
  double dVar1;
  double dVar2;
  undefined4 local_78;
  int local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  if (((DAT_803dd9f4 < 4) && (DAT_803dd9ea < 0xc)) && (DAT_803dd9e9 < 7)) {
    dVar1 = (double)FLOAT_803df75c;
    local_6c = (float)(dVar1 / param_1);
    dVar2 = (double)local_6c;
    local_3c = FLOAT_803df74c;
    local_38 = FLOAT_803df74c;
    local_34 = (float)(-(double)*param_3 * dVar2 + dVar1);
    local_30 = FLOAT_803df74c;
    local_2c = FLOAT_803df74c;
    local_24 = (float)(-(double)param_3[2] * dVar2 + dVar1);
    local_20 = FLOAT_803df74c;
    local_1c = FLOAT_803df74c;
    local_18 = FLOAT_803df74c;
    local_14 = FLOAT_803df748;
    local_70 = FLOAT_803df74c;
    local_68 = FLOAT_803df74c;
    local_64 = (float)(-(double)param_3[1] * dVar2 + dVar1);
    local_60 = FLOAT_803df74c;
    local_5c = FLOAT_803df74c;
    local_58 = FLOAT_803df74c;
    local_54 = FLOAT_803df75c;
    local_50 = FLOAT_803df74c;
    local_4c = FLOAT_803df74c;
    local_48 = FLOAT_803df74c;
    local_44 = FLOAT_803df748;
    local_40 = local_6c;
    local_28 = local_6c;
    FUN_8006c6bc(&local_74);
    FUN_8025d8c4(&local_40,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
    FUN_8025d8c4(&local_70,DAT_803dda00 + 3,0);
    FUN_80258674(DAT_803dda08 + 1,0,0,0,0,DAT_803dda00 + 3);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
    local_78 = *param_2;
    FUN_8025c510(DAT_803dd9f4,(byte *)&local_78);
    FUN_8025c584(DAT_803dda10,DAT_803dd9f0);
    FUN_8025c1a4(DAT_803dda10,0xf,0xe,8,0xf);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    FUN_8025be80(DAT_803dda10 + 1);
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c,0xff);
    FUN_8025c1a4(DAT_803dda10 + 1,0xf,2,8,0xf);
    FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
    FUN_8025c65c(DAT_803dda10 + 1,0,0);
    FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,2);
    FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
    if (local_74 != 0) {
      if (*(char *)(local_74 + 0x48) == '\0') {
        FUN_8025b054((uint *)(local_74 + 0x20),DAT_803dda0c);
      }
      else {
        FUN_8025aeac((uint *)(local_74 + 0x20),*(uint **)(local_74 + 0x40),DAT_803dda0c);
      }
    }
    DAT_803dda10 = DAT_803dda10 + 2;
    DAT_803dda08 = DAT_803dda08 + 2;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9f4 = DAT_803dd9f4 + 1;
    DAT_803dd9f0 = DAT_803dd9f0 + 1;
    DAT_803dd9ec = DAT_803dd9ec + 1;
    DAT_803dda00 = DAT_803dda00 + 6;
    DAT_803dd9e9 = DAT_803dd9e9 + 2;
    DAT_803dd9ea = DAT_803dd9ea + 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004fbac
 * EN v1.0 Address: 0x8004FBAC
 * EN v1.0 Size: 880b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004fbac(double param_1,undefined4 *param_2,float *param_3)
{
  double dVar1;
  double dVar2;
  undefined4 local_78;
  int local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  if (((DAT_803dd9f4 < 4) && (DAT_803dd9ea < 0x10)) && (DAT_803dd9e9 < 7)) {
    if (param_1 < (double)FLOAT_803df764) {
      param_1 = (double)FLOAT_803df764;
    }
    dVar1 = (double)FLOAT_803df75c;
    local_6c = (float)(dVar1 / param_1);
    dVar2 = (double)local_6c;
    local_3c = FLOAT_803df74c;
    local_38 = FLOAT_803df74c;
    local_34 = (float)(-(double)*param_3 * dVar2 + dVar1);
    local_30 = FLOAT_803df74c;
    local_2c = FLOAT_803df74c;
    local_24 = (float)(-(double)param_3[2] * dVar2 + dVar1);
    local_20 = FLOAT_803df74c;
    local_1c = FLOAT_803df74c;
    local_18 = FLOAT_803df74c;
    local_14 = FLOAT_803df748;
    local_70 = FLOAT_803df74c;
    local_68 = FLOAT_803df74c;
    local_64 = (float)(-(double)param_3[1] * dVar2 + dVar1);
    local_60 = FLOAT_803df74c;
    local_5c = FLOAT_803df74c;
    local_58 = FLOAT_803df74c;
    local_54 = FLOAT_803df75c;
    local_50 = FLOAT_803df74c;
    local_4c = FLOAT_803df74c;
    local_48 = FLOAT_803df74c;
    local_44 = FLOAT_803df748;
    local_40 = local_6c;
    local_28 = local_6c;
    FUN_8006c6bc(&local_74);
    FUN_8025d8c4(&local_40,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
    FUN_8025d8c4(&local_70,DAT_803dda00 + 3,0);
    FUN_80258674(DAT_803dda08 + 1,0,0,0,0,DAT_803dda00 + 3);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
    local_78 = *param_2;
    FUN_8025c510(DAT_803dd9f4,(byte *)&local_78);
    FUN_8025c584(DAT_803dda10,DAT_803dd9f0);
    FUN_8025c1a4(DAT_803dda10,0xf,0xe,8,0xf);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    FUN_8025be80(DAT_803dda10 + 1);
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c,0xff);
    FUN_8025c1a4(DAT_803dda10 + 1,0xf,2,8,0);
    FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
    FUN_8025c65c(DAT_803dda10 + 1,0,0);
    FUN_8025c2a8(DAT_803dda10 + 1,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
    DAT_803dd9b0 = 1;
    if (local_74 != 0) {
      if (*(char *)(local_74 + 0x48) == '\0') {
        FUN_8025b054((uint *)(local_74 + 0x20),DAT_803dda0c);
      }
      else {
        FUN_8025aeac((uint *)(local_74 + 0x20),*(uint **)(local_74 + 0x40),DAT_803dda0c);
      }
    }
    DAT_803dda10 = DAT_803dda10 + 2;
    DAT_803dda08 = DAT_803dda08 + 2;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9f4 = DAT_803dd9f4 + 1;
    DAT_803dd9f0 = DAT_803dd9f0 + 1;
    DAT_803dd9ec = DAT_803dd9ec + 1;
    DAT_803dda00 = DAT_803dda00 + 6;
    DAT_803dd9e9 = DAT_803dd9e9 + 2;
    DAT_803dd9ea = DAT_803dd9ea + 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8004ff1c
 * EN v1.0 Address: 0x8004FF1C
 * EN v1.0 Size: 384b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8004ff1c(int param_1,float *param_2)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025d8c4(param_2,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c584(DAT_803dda10,4);
  FUN_8025c1a4(DAT_803dda10,0xe,9,0,0);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,1,1,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005009c
 * EN v1.0 Address: 0x8005009C
 * EN v1.0 Size: 508b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005009c(int param_1)
{
  if (param_1 != 0) {
    FUN_80258674(DAT_803dda08,1,1,0x1e,0,0x7d);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
    FUN_8025c1a4(DAT_803dda10,0xf,10,0xb,8);
    FUN_8025c224(DAT_803dda10,7,7,7,7);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    DAT_803dd9b0 = 1;
    if (param_1 != 0) {
      if (*(char *)(param_1 + 0x48) == '\0') {
        FUN_8025b054((uint *)(param_1 + 0x20),DAT_803dda0c);
      }
      else {
        FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),DAT_803dda0c);
      }
    }
    DAT_803dda08 = DAT_803dda08 + 1;
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,0xff,0xff,5);
    FUN_8025c1a4(DAT_803dda10,0xf,10,0xb,0);
    FUN_8025c224(DAT_803dda10,7,7,7,7);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80050298
 * EN v1.0 Address: 0x80050298
 * EN v1.0 Size: 1084b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80050298(float *param_1)
{
  float *pfVar1;
  float fVar2;
  int local_48;
  float afStack_44 [16];
  
  FUN_8025be80(DAT_803dda10);
  FUN_8025be80(DAT_803dda10 + 1);
  FUN_8025be80(DAT_803dda10 + 2);
  FUN_8025be80(DAT_803dda10 + 3);
  pfVar1 = (float *)FUN_8000f578();
  FUN_80247618(param_1 + 0xc,pfVar1,afStack_44);
  FUN_8025d8c4(afStack_44,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0x3c,0,DAT_803dda00);
  pfVar1 = (float *)FUN_8000f578();
  FUN_80247618(param_1,pfVar1,afStack_44);
  FUN_8025d8c4(afStack_44,DAT_803dda00 + 3,0);
  FUN_80258674(DAT_803dda08 + 1,0,0,0x3c,0,DAT_803dda00 + 3);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c + 1,0xff);
  FUN_8025c828(DAT_803dda10 + 2,DAT_803dda08 + 1,DAT_803dda0c + 1,0xff);
  FUN_8025c828(DAT_803dda10 + 3,DAT_803dda08 + 1,DAT_803dda0c + 1,0xff);
  FUN_8025c584(DAT_803dda10 + 2,6);
  FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,8);
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,1);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  FUN_8025c1a4(DAT_803dda10 + 1,2,8,0xc,0xf);
  FUN_8025c224(DAT_803dda10 + 1,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 1,0,0);
  FUN_8025c2a8(DAT_803dda10 + 1,8,0,0,1,1);
  FUN_8025c368(DAT_803dda10 + 1,0,0,0,1,0);
  FUN_8025c1a4(DAT_803dda10 + 2,4,0xe,2,0xf);
  FUN_8025c224(DAT_803dda10 + 2,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 2,0,0);
  FUN_8025c2a8(DAT_803dda10 + 2,0,0,0,1,2);
  FUN_8025c368(DAT_803dda10 + 2,0,0,0,1,0);
  FUN_8025c1a4(DAT_803dda10 + 3,6,0xf,2,0xf);
  FUN_8025c224(DAT_803dda10 + 3,7,7,7,0);
  FUN_8025c65c(DAT_803dda10 + 3,0,0);
  FUN_8025c2a8(DAT_803dda10 + 3,0,0,0,1,3);
  FUN_8025c368(DAT_803dda10 + 3,0,0,0,1,0);
  FUN_8006c734(&local_48);
  if (local_48 != 0) {
    if (*(char *)(local_48 + 0x48) == '\0') {
      FUN_8025b054((uint *)(local_48 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(local_48 + 0x20),*(uint **)(local_48 + 0x40),DAT_803dda0c);
    }
  }
  fVar2 = param_1[0x18];
  if (fVar2 != 0.0) {
    if (*(char *)((int)fVar2 + 0x48) == '\0') {
      FUN_8025b054((uint *)((int)fVar2 + 0x20),DAT_803dda0c + 1);
    }
    else {
      FUN_8025aeac((uint *)((int)fVar2 + 0x20),*(uint **)((int)fVar2 + 0x40),DAT_803dda0c + 1);
    }
  }
  DAT_803dda00 = DAT_803dda00 + 6;
  DAT_803dda08 = DAT_803dda08 + 2;
  DAT_803dda0c = DAT_803dda0c + 2;
  DAT_803dd9e9 = DAT_803dd9e9 + '\x02';
  DAT_803dd9ea = DAT_803dd9ea + '\x04';
  DAT_803dda10 = DAT_803dda10 + 4;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800506d4
 * EN v1.0 Address: 0x800506D4
 * EN v1.0 Size: 1232b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800506d4(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)
{
  int iVar1;
  uint uVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  FUN_8025be80(DAT_803dda10);
  FUN_8025d8c4((float *)uVar3,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,0,0,0,0,DAT_803dda00);
  if ((param_5 == 0) || (param_5 == 2)) {
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
  }
  else {
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,5);
  }
  if (DAT_803dda10 == 0) {
    uVar2 = 0xc;
  }
  else {
    uVar2 = 4;
  }
  if (param_3 == 0) {
    if (param_4 == 2) {
      FUN_8025c1a4(DAT_803dda10,0xf,uVar2,8,0xf);
    }
    else if (param_4 == 3) {
      FUN_8025c1a4(DAT_803dda10,uVar2,0xf,8,0xf);
    }
    else if (param_4 == 1) {
      FUN_8025c1a4(DAT_803dda10,0xf,0xf,8,uVar2);
    }
    else if ((param_5 == 0) || (param_5 == 1)) {
      FUN_8025c1a4(DAT_803dda10,0xf,10,8,uVar2);
    }
    else {
      FUN_8025c1a4(DAT_803dda10,0xf,0xb,8,uVar2);
    }
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c224(DAT_803dda10,7,7,7,7);
    if (param_4 == 1) {
      FUN_8025c2a8(DAT_803dda10,1,0,0,1,2);
      FUN_8025c368(DAT_803dda10,1,0,0,1,2);
    }
    else {
      FUN_8025c2a8(DAT_803dda10,0,0,0,1,2);
      FUN_8025c368(DAT_803dda10,0,0,0,1,2);
    }
  }
  else if (param_3 == 1) {
    if (param_4 == 2) {
      FUN_8025c1a4(DAT_803dda10,0xf,6,8,0xf);
    }
    else if (param_4 == 3) {
      FUN_8025c1a4(DAT_803dda10,6,0xf,8,0xf);
    }
    else if (param_4 == 1) {
      FUN_8025c1a4(DAT_803dda10,0xf,0xf,8,6);
    }
    else if ((param_5 == 0) || (param_5 == 1)) {
      FUN_8025c1a4(DAT_803dda10,0xf,10,8,6);
    }
    else {
      FUN_8025c1a4(DAT_803dda10,0xf,0xb,8,6);
    }
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c224(DAT_803dda10,7,7,7,7);
    if (param_4 == 1) {
      FUN_8025c2a8(DAT_803dda10,1,0,0,1,3);
      FUN_8025c368(DAT_803dda10,1,0,0,1,3);
    }
    else {
      FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
      FUN_8025c368(DAT_803dda10,0,0,0,1,3);
    }
  }
  else {
    DAT_803dd9eb = 1;
    DAT_803dd9b0 = 1;
    FUN_8025c6b4(1,0,0,0,1);
    FUN_8025c65c(DAT_803dda10,1,1);
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0xc);
    if (param_4 == 3) {
      FUN_8025c224(DAT_803dda10,7,5,4,6);
      FUN_8025c368(DAT_803dda10,1,0,0,1,0);
    }
    else {
      FUN_8025c224(DAT_803dda10,7,5,4,7);
      FUN_8025c368(DAT_803dda10,0,0,0,1,0);
    }
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  }
  if (iVar1 != 0) {
    if (*(char *)(iVar1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(iVar1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(iVar1 + 0x20),*(uint **)(iVar1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80050ba4
 * EN v1.0 Address: 0x80050BA4
 * EN v1.0 Size: 176b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80050ba4(uint param_1)
{
  float afStack_48 [11];
  float local_1c;
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  
  uStack_14 = param_1 ^ 0x80000000;
  local_18 = 0x43300000;
  local_10 = 0x43300000;
  uStack_c = uStack_14;
  FUN_80247a7c((double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803df7b0),
               (double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803df7b0),
               (double)FLOAT_803df74c,afStack_48);
  local_1c = FLOAT_803df748;
  FUN_8025d8c4(afStack_48,DAT_803dda00,0);
  FUN_80258674(DAT_803dda08,1,4,0x3c,0,DAT_803dda00);
  DAT_803dda00 = DAT_803dda00 + 3;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80050c54
 * EN v1.0 Address: 0x80050C54
 * EN v1.0 Size: 848b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80050c54(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4)
{
  int iVar1;
  uint uVar2;
  double dVar3;
  undefined8 uVar4;
  float local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  float afStack_58 [11];
  float local_2c;
  undefined4 local_28;
  uint uStack_24;
  
  uVar4 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  local_70 = DAT_802c24d0;
  local_6c = DAT_802c24d4;
  local_68 = DAT_802c24d8;
  local_64 = DAT_802c24dc;
  local_60 = DAT_802c24e0;
  local_5c = DAT_802c24e4;
  if ((DAT_803dc248 & 1) != 0) {
    FUN_8025b9e8(1,&local_70,'\0');
    FUN_8025bd1c(DAT_803dd9fc,DAT_803dda08 + (int)uVar4,DAT_803dda0c);
    if (param_4 != 0) {
      uVar2 = FUN_8005383c(param_4);
      uVar2 = (uint)*(ushort *)(uVar2 + 10) /
              ((uint)*(ushort *)(iVar1 + 10) * ((param_3 & 0xf) * 4 + 1));
      if (uVar2 != 0) {
        FUN_8025bb48(DAT_803dd9fc,*(uint *)(&DAT_8030da9c + uVar2 * 4),
                     *(uint *)(&DAT_8030da9c + uVar2 * 4));
      }
    }
    uStack_24 = (int)(param_3 & 0xf0) >> 4 ^ 0x80000000;
    local_28 = 0x43300000;
    dVar3 = (double)(FLOAT_803df75c *
                    FLOAT_803df7b8 *
                    ((float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803df7b0) /
                     FLOAT_803df7bc - FLOAT_803df748));
    FUN_80247a7c(dVar3,dVar3,(double)FLOAT_803df74c,afStack_58);
    local_2c = FLOAT_803df748;
    FUN_8025d8c4(afStack_58,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,2,0x1e,0,DAT_803dda00);
    FUN_80258674(DAT_803dda08 + 1,1,3,0x1e,0,DAT_803dda00);
    FUN_8025b94c(DAT_803dda10,DAT_803dd9fc,0,3,5,6,6,0,0,0);
    FUN_8025b94c(DAT_803dda10 + 1,DAT_803dd9fc,0,3,9,6,6,1,0,0);
    FUN_8025b94c(DAT_803dda10 + 2,DAT_803dd9fc,0,0,0,0,0,1,0,0);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c + 1 | 0x100,0xff);
    FUN_8025c000(DAT_803dda10,4);
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c + 1 | 0x100,0xff);
    FUN_8025c000(DAT_803dda10 + 1,4);
    if (iVar1 != 0) {
      if (*(char *)(iVar1 + 0x48) == '\0') {
        FUN_8025b054((uint *)(iVar1 + 0x20),DAT_803dda0c);
      }
      else {
        FUN_8025aeac((uint *)(iVar1 + 0x20),*(uint **)(iVar1 + 0x40),DAT_803dda0c);
      }
    }
    DAT_803dda00 = DAT_803dda00 + 3;
    DAT_803dd9fc = DAT_803dd9fc + 1;
    DAT_803dda08 = DAT_803dda08 + 2;
    DAT_803dda10 = DAT_803dda10 + 2;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9ea = DAT_803dd9ea + '\x02';
    DAT_803dd9e8 = DAT_803dd9e8 + '\x01';
    DAT_803dd9e9 = DAT_803dd9e9 + '\x02';
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80050fa4
 * EN v1.0 Address: 0x80050FA4
 * EN v1.0 Size: 260b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80050fa4(char param_1)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  if (param_1 == '\0') {
    FUN_8025c1a4(DAT_803dda10,0xf,0,10,6);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,0,4,6);
  }
  FUN_8025c224(DAT_803dda10,7,7,7,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800510a8
 * EN v1.0 Address: 0x800510A8
 * EN v1.0 Size: 200b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800510a8(void)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_8025c1a4(DAT_803dda10,0xf,6,8,0xf);
  FUN_8025c224(DAT_803dda10,7,7,7,7);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80051170
 * EN v1.0 Address: 0x80051170
 * EN v1.0 Size: 252b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80051170(char param_1)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  if (param_1 == '\0') {
    FUN_8025c1a4(DAT_803dda10,0xf,1,10,6);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,1,4,6);
  }
  FUN_8025c224(DAT_803dda10,7,7,7,7);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005126c
 * EN v1.0 Address: 0x8005126C
 * EN v1.0 Size: 600b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005126c(int param_1,char param_2,uint param_3)
{
  float afStack_78 [12];
  float afStack_48 [15];
  
  if (DAT_803dd9e8 == '\0') {
    FUN_8025be80(DAT_803dda10);
  }
  if (param_2 == '\0') {
    FUN_80247a7c((double)FLOAT_803df7c0,(double)FLOAT_803df7c0,(double)FLOAT_803df74c,afStack_78);
    FUN_80247a48((double)FLOAT_803df75c,(double)FLOAT_803df75c,(double)FLOAT_803df748,afStack_48);
    FUN_80247618(afStack_48,afStack_78,afStack_78);
    FUN_8025d8c4(afStack_78,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,1,0x1e,0,DAT_803dda00);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
    DAT_803dda00 = DAT_803dda00 + 3;
    DAT_803dda08 = DAT_803dda08 + 1;
    DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  }
  else {
    FUN_8025bec8(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08 + -1,DAT_803dda0c,0xff);
  }
  FUN_8025c224(DAT_803dda10,7,4,3,7);
  if (param_2 == '\0') {
    FUN_8025c1a4(DAT_803dda10,0xf,8,10,0xf);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,8,4,0xf);
  }
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,3);
  if ((param_3 & 1) == 0) {
    FUN_8025c6b4(3,0,0,0,1);
  }
  else {
    FUN_8025c6b4(3,2,2,2,1);
  }
  FUN_8025c65c(DAT_803dda10,0,3);
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800514c4
 * EN v1.0 Address: 0x800514C4
 * EN v1.0 Size: 480b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800514c4(int param_1,char param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800516a4
 * EN v1.0 Address: 0x800516A4
 * EN v1.0 Size: 832b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800516a4(int param_1,float *param_2)
{
}
