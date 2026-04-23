#include "ghidra_import.h"
#include "main/dll/modgfx.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80003494();
extern int FUN_80008b4c();
extern undefined4 FUN_8000b7dc();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000dd94();
extern undefined4 FUN_8000e840();
extern undefined4 FUN_8000f56c();
extern void* FUN_8000facc();
extern undefined4 FUN_80013e4c();
extern undefined4 FUN_80013ee8();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_800216cc();
extern uint FUN_80021884();
extern undefined4 FUN_80021b8c();
extern undefined4 FUN_80021fac();
extern uint FUN_80022264();
extern undefined4 FUN_80022790();
extern undefined4 FUN_800238c4();
extern uint FUN_80023d8c();
extern undefined4 FUN_80028630();
extern undefined4 FUN_8002b660();
extern int FUN_8002bac4();
extern void* FUN_8002becc();
extern undefined4 FUN_8002cc9c();
extern int FUN_8002e088();
extern uint FUN_8002e144();
extern undefined4 FUN_8002e1f4();
extern undefined4 FUN_8004c460();
extern undefined4 FUN_80054328();
extern undefined4 FUN_80054470();
extern undefined4 FUN_80054484();
extern undefined4 FUN_80054ed0();
extern void fn_8005D108();
extern undefined4 FUN_8005d264();
extern undefined4 FUN_8005d294();
extern undefined4 FUN_8006933c();
extern void trackDolphin_buildSweptBounds(uint *boundsOut,float *startPoints,float *endPoints,
                                          float *radii,int pointCount);
extern void trackDolphin_getCurrentTrackPoint(uint **param_1);
extern void trackDolphin_getCurrentIntersectionList(int *entryCountOut,undefined4 *entryListOut);
extern undefined4 FUN_80078bf8();
extern undefined4 FUN_80078cc8();
extern undefined4 FUN_80078f78();
extern undefined4 FUN_8007904c();
extern undefined4 FUN_800793d0();
extern undefined4 FUN_800794a4();
extern undefined4 FUN_8007986c();
extern undefined4 FUN_80079980();
extern undefined4 FUN_80079b3c();
extern undefined4 FUN_8007d858();
extern undefined4 FUN_80080100();
extern undefined4 FUN_80080404();
extern undefined4 FUN_80080610();
extern undefined4 FUN_80089b54();
extern void expgfx_initialise();
extern undefined4 FUN_80137cd0();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025d80c();
extern undefined8 FUN_80286818();
extern undefined4 FUN_80286820();
extern undefined4 FUN_80286824();
extern undefined4 FUN_80286828();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286864();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286874();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293544();
extern double FUN_80293900();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();

extern undefined DAT_80000100;
extern undefined DAT_80000108;
extern undefined4 DAT_80000119;
extern undefined4 DAT_80000200;
extern undefined DAT_80000201;
extern undefined4 DAT_802c28e0;
extern undefined4 DAT_802c28e4;
extern undefined4 DAT_802c28e8;
extern undefined4 DAT_802c28ec;
extern undefined2 DAT_80310488;
extern undefined DAT_80310528;
extern undefined4 DAT_803109a8;
extern undefined4 DAT_803109ac;
extern undefined4 DAT_803109b0;
extern undefined4 DAT_803109f8;
extern undefined4 DAT_80310a88;
extern undefined4 DAT_80310b18;
extern undefined2 DAT_80310ba8;
extern undefined4 DAT_80310bb2;
extern undefined4 DAT_80310f88;
extern undefined DAT_80310fac;
extern undefined4 DAT_80310fd0;
extern undefined4 DAT_8031105c;
extern undefined4 DAT_80311120;
extern undefined4 DAT_80311124;
extern undefined4 DAT_80311128;
extern undefined4 DAT_8031112c;
extern undefined4 DAT_80311130;
extern undefined4 DAT_80311134;
extern undefined4 DAT_80311138;
extern undefined4 DAT_8031113c;
extern undefined4 DAT_80311140;
extern undefined4 DAT_80311144;
extern undefined4 DAT_80311148;
extern undefined4 DAT_8031114c;
extern undefined4 DAT_80311150;
extern undefined4 DAT_80311154;
extern undefined4 DAT_80311158;
extern undefined4 DAT_8031115c;
extern undefined4 DAT_80311160;
extern undefined4 DAT_80311164;
extern undefined4 DAT_80311168;
extern undefined4 DAT_8031116c;
extern undefined4 DAT_80311170;
extern undefined4 DAT_80311174;
extern undefined4 DAT_80311178;
extern undefined4 DAT_8031117c;
extern undefined4 DAT_80311180;
extern undefined4 DAT_80311184;
extern undefined4 DAT_80311188;
extern undefined4 DAT_8031118c;
extern undefined4 DAT_80311190;
extern undefined4 DAT_80311194;
extern undefined4 DAT_80311198;
extern undefined4 DAT_8031119c;
extern undefined4 DAT_803111a0;
extern undefined4 DAT_803111a4;
extern undefined4 DAT_803111a8;
extern undefined4 DAT_803111ac;
extern undefined4 DAT_803111b0;
extern undefined4 DAT_803111b4;
extern undefined4 DAT_803111b6;
extern undefined4 DAT_803111b8;
extern undefined4 DAT_803111ba;
extern undefined4 DAT_803111bc;
extern undefined4 DAT_803111be;
extern undefined4 DAT_803111c0;
extern undefined4 DAT_803111c1;
extern undefined4 DAT_8031122c;
extern undefined DAT_80380209;
extern int DAT_8039b7b8;
extern undefined DAT_8039c638;
extern undefined4 DAT_8039c688;
extern undefined4 DAT_8039c7c8;
extern undefined4 DAT_8039c7cc;
extern undefined4 DAT_8039c7d0;
extern undefined4 DAT_8039c7d4;
extern undefined DAT_8039c828;
extern undefined4 DAT_8039c878;
extern uint DAT_8039c9b8;
extern undefined4* DAT_8039caf8;
extern undefined4 DAT_8039cafc;
extern undefined4 DAT_8039cb18;
extern undefined4 DAT_8039cb1c;
extern undefined4 DAT_8039cb20;
extern undefined4 DAT_8039cb24;
extern undefined4 DAT_8039cb28;
extern undefined4 DAT_8039cb2c;
extern undefined4 DAT_8039cb30;
extern undefined4 DAT_8039cb34;
extern undefined4 DAT_8039cb38;
extern undefined4 DAT_8039cb3c;
extern undefined4 DAT_8039cb4c;
extern undefined4 DAT_8039cb50;
extern undefined4 DAT_8039cb51;
extern undefined4 DAT_8039cb52;
extern undefined4 DAT_8039cb53;
extern undefined4 DAT_8039cb55;
extern undefined4 DAT_8039cb58;
extern uint DAT_8039ce58;
extern undefined4 DAT_8039ce5c;
extern undefined4 DAT_8039ce60;
extern undefined4 DAT_8039ce64;
extern undefined4 DAT_8039ce68;
extern undefined4 DAT_8039ce6c;
extern undefined4 DAT_8039ce70;
extern undefined4 DAT_8039ce74;
extern undefined4 DAT_8039ce78;
extern undefined4 DAT_8039ce7c;
extern undefined4 DAT_8039ce80;
extern undefined4 DAT_8039ce84;
extern undefined4 DAT_8039ce88;
extern undefined4 DAT_8039ce8c;
extern undefined4 DAT_8039ce90;
extern undefined4 DAT_8039ce94;
extern undefined4 DAT_8039ce98;
extern undefined4 DAT_8039ce9c;
extern undefined4 DAT_8039cea0;
extern undefined4 DAT_8039cea4;
extern undefined4 DAT_8039cea8;
extern undefined4 DAT_8039ceac;
extern undefined4 DAT_8039ceb0;
extern undefined4 DAT_8039ceb4;
extern undefined4 DAT_8039ceb8;
extern undefined4 DAT_8039cebc;
extern undefined4 DAT_8039cec0;
extern undefined4 DAT_8039cec4;
extern undefined4 DAT_8039cec8;
extern undefined4 DAT_8039cecc;
extern undefined4 DAT_8039ced0;
extern undefined4 DAT_8039ced4;
extern undefined4 DAT_8039ced8;
extern undefined4 DAT_8039cedc;
extern undefined4 DAT_8039cee0;
extern undefined4 DAT_8039cee4;
extern undefined4 DAT_8039cee8;
extern undefined4 DAT_8039ceec;
extern undefined4 DAT_8039cef0;
extern undefined4 DAT_8039cef4;
extern undefined4 DAT_8039cef8;
extern undefined4 DAT_8039cefc;
extern undefined4 DAT_8039cf00;
extern undefined4 DAT_8039cf04;
extern undefined4 DAT_8039cf08;
extern undefined4 DAT_8039cf0c;
extern undefined4 DAT_8039cf10;
extern undefined4 DAT_8039cf14;
extern undefined4 DAT_8039cf18;
extern int DAT_8039cf20;
extern undefined4 DAT_8039cf24;
extern undefined4 DAT_8039cf28;
extern undefined4 DAT_8039cf2c;
extern undefined4 DAT_8039cf30;
extern undefined4 DAT_8039cf34;
extern undefined4 DAT_8039cf38;
extern undefined4 DAT_8039cf40;
extern undefined4 DAT_8039cf42;
extern undefined4 DAT_8039cf44;
extern undefined4 DAT_8039cf46;
extern undefined4 DAT_8039cf48;
extern undefined4 DAT_8039cf4a;
extern undefined4 DAT_8039cf4c;
extern undefined4 DAT_8039cf4e;
extern undefined4 DAT_8039cf50;
extern undefined4 DAT_8039cf52;
extern undefined4 DAT_8039cf54;
extern undefined4 DAT_8039cf56;
extern undefined4 DAT_8039cf58;
extern undefined4 DAT_8039cf5a;
extern undefined4 DAT_8039cf5c;
extern undefined4 DAT_8039cf5e;
extern undefined4 DAT_8039cf60;
extern undefined4 DAT_8039cf62;
extern undefined4 DAT_8039cf64;
extern undefined4 DAT_8039cf66;
extern undefined2 DAT_8039cf68;
extern undefined4 DAT_8039cf6a;
extern undefined4 DAT_8039cf6c;
extern undefined4 DAT_8039cf6e;
extern undefined4 DAT_8039cf70;
extern undefined4 DAT_8039cf74;
extern undefined4 DAT_8039cf78;
extern undefined4 DAT_8039cf7c;
extern undefined4 DAT_8039cf80;
extern undefined4 DAT_8039cf82;
extern undefined4 DAT_8039cf84;
extern undefined4 DAT_8039cf88;
extern undefined4 DAT_8039cf8c;
extern undefined4 DAT_8039cf90;
extern undefined4 DAT_8039cf94;
extern undefined4 DAT_8039cf98;
extern undefined4 DAT_8039cf9a;
extern undefined4 DAT_8039cf9c;
extern undefined4 DAT_8039cfa0;
extern undefined4 DAT_8039cfa4;
extern undefined4 DAT_8039cfa8;
extern undefined4 DAT_8039cfac;
extern undefined4 DAT_8039cfb0;
extern undefined4 DAT_8039cfb2;
extern undefined4 DAT_8039cfb4;
extern undefined4 DAT_8039cfb8;
extern undefined4 DAT_8039cfbc;
extern undefined4 DAT_8039cfc0;
extern undefined4 DAT_8039cfc4;
extern undefined4 DAT_8039cfc8;
extern undefined4 DAT_8039cfca;
extern undefined4 DAT_8039cfcc;
extern undefined4 DAT_8039cfd0;
extern undefined4 DAT_8039cfd4;
extern undefined4 DAT_8039cfd8;
extern undefined4 DAT_8039cfdc;
extern undefined4 DAT_8039cfe0;
extern undefined4 DAT_8039cfe2;
extern undefined4 DAT_8039cfe4;
extern undefined4 DAT_8039cfe8;
extern undefined4 DAT_8039cfec;
extern undefined4 DAT_8039cff0;
extern undefined4 DAT_8039cff4;
extern undefined4 DAT_8039cff8;
extern undefined4 DAT_8039cffa;
extern undefined4 DAT_8039cffc;
extern undefined4 DAT_8039d000;
extern undefined4 DAT_8039d004;
extern undefined4 DAT_8039d008;
extern undefined4 DAT_8039d00c;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dd430;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4 DAT_803dded8;
extern undefined4 DAT_803ddf00;
extern undefined4 DAT_803ddf02;
extern undefined4 DAT_803ddf08;
extern undefined4 DAT_803ddf0c;
extern undefined4 DAT_803ddf10;
extern undefined4 DAT_803ddf18;
extern undefined4 DAT_803ddf1a;
extern undefined4 DAT_803ddf1c;
extern undefined4 DAT_803ddf20;
extern undefined4 DAT_803ddf24;
extern undefined4 DAT_803ddf28;
extern undefined4 DAT_803ddf30;
extern undefined4 DAT_803ddf34;
extern undefined4 DAT_803ddf38;
extern undefined4 DAT_803ddf3c;
extern undefined4 DAT_803ddf40;
extern undefined4 DAT_803ddf44;
extern undefined4* DAT_803ddf48;
extern undefined4* DAT_803ddf4c;
extern undefined4* DAT_803ddf50;
extern undefined4* DAT_803ddf54;
extern undefined4* DAT_803ddf58;
extern undefined4* DAT_803ddf5c;
extern undefined4* DAT_803ddf60;
extern undefined4* DAT_803ddf64;
extern undefined4* DAT_803ddf68;
extern undefined4* DAT_803ddf6c;
extern undefined4* DAT_803ddf70;
extern undefined4* DAT_803ddf74;
extern undefined4* DAT_803ddf78;
extern undefined4* DAT_803ddf7c;
extern undefined4* DAT_803ddf80;
extern undefined4* DAT_803ddf84;
extern undefined4* DAT_803ddf88;
extern undefined4* DAT_803ddf8c;
extern undefined4* DAT_803ddf90;
extern undefined4* DAT_803ddf94;
extern undefined4 DAT_803ddf98;
extern undefined4 DAT_803ddf9c;
extern undefined4 DAT_803ddfa8;
extern undefined4 DAT_803ddfac;
extern undefined4 DAT_803ddfb8;
extern undefined4 DAT_803ddfbc;
extern undefined4 DAT_803ddfc8;
extern undefined4 DAT_803ddfd0;
extern undefined4 DAT_803ddfd4;
extern undefined4 DAT_803ddfe0;
extern undefined4 DAT_803ddfe4;
extern undefined4 DAT_803ddff0;
extern undefined4 DAT_803ddff4;
extern undefined4 DAT_803de000;
extern undefined4 DAT_803de004;
extern undefined4 DAT_803de010;
extern undefined4 DAT_803de014;
extern undefined4 DAT_803de020;
extern undefined4 DAT_803de024;
extern f64 DOUBLE_803e00c0;
extern f64 DOUBLE_803e00c8;
extern f64 DOUBLE_803e0100;
extern f64 DOUBLE_803e0270;
extern f64 DOUBLE_803e0390;
extern f64 DOUBLE_803e04e0;
extern f64 DOUBLE_803e0640;
extern f64 DOUBLE_803e0700;
extern f64 DOUBLE_803e0850;
extern f64 DOUBLE_803e08f0;
extern f64 DOUBLE_803e0948;
extern f64 DOUBLE_803e0a08;
extern f64 DOUBLE_803e0a98;
extern f64 DOUBLE_803e0b28;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc3f8;
extern f32 FLOAT_803dc400;
extern f32 FLOAT_803dc404;
extern f32 FLOAT_803dc408;
extern f32 FLOAT_803dc40c;
extern f32 FLOAT_803dc410;
extern f32 FLOAT_803dc414;
extern f32 FLOAT_803dc418;
extern f32 FLOAT_803dc41c;
extern f32 FLOAT_803dc420;
extern f32 FLOAT_803dc424;
extern f32 FLOAT_803dc428;
extern f32 FLOAT_803dc42c;
extern f32 FLOAT_803dc430;
extern f32 FLOAT_803dc434;
extern f32 FLOAT_803dc438;
extern f32 FLOAT_803dc43c;
extern f32 FLOAT_803dc440;
extern f32 FLOAT_803dc444;
extern f32 FLOAT_803dc448;
extern f32 FLOAT_803dc44c;
extern f32 FLOAT_803dc450;
extern f32 FLOAT_803dc454;
extern f32 FLOAT_803dc458;
extern f32 FLOAT_803dc45c;
extern f32 FLOAT_803dc460;
extern f32 FLOAT_803dc464;
extern f32 FLOAT_803dc468;
extern f32 FLOAT_803dc46c;
extern f32 FLOAT_803dc470;
extern f32 FLOAT_803dc474;
extern f32 FLOAT_803dc478;
extern f32 FLOAT_803dc47c;
extern f32 FLOAT_803dc480;
extern f32 FLOAT_803dc484;
extern f32 FLOAT_803dc488;
extern f32 FLOAT_803dc48c;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803ddf04;
extern f32 FLOAT_803ddf2c;
extern f32 FLOAT_803ddfa0;
extern f32 FLOAT_803ddfa4;
extern f32 FLOAT_803ddfb0;
extern f32 FLOAT_803ddfb4;
extern f32 FLOAT_803ddfc0;
extern f32 FLOAT_803ddfc4;
extern f32 FLOAT_803ddfd8;
extern f32 FLOAT_803ddfdc;
extern f32 FLOAT_803ddfe8;
extern f32 FLOAT_803ddfec;
extern f32 FLOAT_803ddff8;
extern f32 FLOAT_803ddffc;
extern f32 FLOAT_803de008;
extern f32 FLOAT_803de00c;
extern f32 FLOAT_803de018;
extern f32 FLOAT_803de01c;
extern f32 FLOAT_803de028;
extern f32 FLOAT_803de02c;
extern f32 FLOAT_803e00b0;
extern f32 FLOAT_803e00b4;
extern f32 FLOAT_803e00b8;
extern f32 FLOAT_803e00bc;
extern f32 FLOAT_803e00d0;
extern f32 FLOAT_803e00d4;
extern f32 FLOAT_803e00d8;
extern f32 FLOAT_803e00dc;
extern f32 FLOAT_803e00e0;
extern f32 FLOAT_803e00e8;
extern f32 FLOAT_803e00ec;
extern f32 FLOAT_803e00f0;
extern f32 FLOAT_803e00f4;
extern f32 FLOAT_803e00f8;
extern f32 FLOAT_803e0108;
extern f32 FLOAT_803e010c;
extern f32 FLOAT_803e0110;
extern f32 FLOAT_803e0114;
extern f32 FLOAT_803e0118;
extern f32 FLOAT_803e011c;
extern f32 FLOAT_803e0120;
extern f32 FLOAT_803e0124;
extern f32 FLOAT_803e0128;
extern f32 FLOAT_803e012c;
extern f32 FLOAT_803e0130;
extern f32 FLOAT_803e0134;
extern f32 FLOAT_803e0138;
extern f32 FLOAT_803e013c;
extern f32 FLOAT_803e0140;
extern f32 FLOAT_803e0144;
extern f32 FLOAT_803e0148;
extern f32 FLOAT_803e014c;
extern f32 FLOAT_803e0150;
extern f32 FLOAT_803e0154;
extern f32 FLOAT_803e0158;
extern f32 FLOAT_803e015c;
extern f32 FLOAT_803e0160;
extern f32 FLOAT_803e0164;
extern f32 FLOAT_803e0168;
extern f32 FLOAT_803e016c;
extern f32 FLOAT_803e0170;
extern f32 FLOAT_803e0174;
extern f32 FLOAT_803e0178;
extern f32 FLOAT_803e017c;
extern f32 FLOAT_803e0180;
extern f32 FLOAT_803e0184;
extern f32 FLOAT_803e0188;
extern f32 FLOAT_803e018c;
extern f32 FLOAT_803e0190;
extern f32 FLOAT_803e0194;
extern f32 FLOAT_803e0198;
extern f32 FLOAT_803e019c;
extern f32 FLOAT_803e01a0;
extern f32 FLOAT_803e01a4;
extern f32 FLOAT_803e01a8;
extern f32 FLOAT_803e01ac;
extern f32 FLOAT_803e01b0;
extern f32 FLOAT_803e01b4;
extern f32 FLOAT_803e01b8;
extern f32 FLOAT_803e01bc;
extern f32 FLOAT_803e01c0;
extern f32 FLOAT_803e01c4;
extern f32 FLOAT_803e01c8;
extern f32 FLOAT_803e01cc;
extern f32 FLOAT_803e01d0;
extern f32 FLOAT_803e01d4;
extern f32 FLOAT_803e01d8;
extern f32 FLOAT_803e01dc;
extern f32 FLOAT_803e01e0;
extern f32 FLOAT_803e01e4;
extern f32 FLOAT_803e01e8;
extern f32 FLOAT_803e01ec;
extern f32 FLOAT_803e01f0;
extern f32 FLOAT_803e01f4;
extern f32 FLOAT_803e01f8;
extern f32 FLOAT_803e01fc;
extern f32 FLOAT_803e0200;
extern f32 FLOAT_803e0204;
extern f32 FLOAT_803e0208;
extern f32 FLOAT_803e020c;
extern f32 FLOAT_803e0210;
extern f32 FLOAT_803e0214;
extern f32 FLOAT_803e0218;
extern f32 FLOAT_803e021c;
extern f32 FLOAT_803e0220;
extern f32 FLOAT_803e0224;
extern f32 FLOAT_803e0228;
extern f32 FLOAT_803e022c;
extern f32 FLOAT_803e0230;
extern f32 FLOAT_803e0234;
extern f32 FLOAT_803e0238;
extern f32 FLOAT_803e023c;
extern f32 FLOAT_803e0240;
extern f32 FLOAT_803e0244;
extern f32 FLOAT_803e0248;
extern f32 FLOAT_803e024c;
extern f32 FLOAT_803e0250;
extern f32 FLOAT_803e0254;
extern f32 FLOAT_803e0258;
extern f32 FLOAT_803e025c;
extern f32 FLOAT_803e0260;
extern f32 FLOAT_803e0264;
extern f32 FLOAT_803e0268;
extern f32 FLOAT_803e026c;
extern f32 FLOAT_803e0278;
extern f32 FLOAT_803e027c;
extern f32 FLOAT_803e0280;
extern f32 FLOAT_803e0284;
extern f32 FLOAT_803e0288;
extern f32 FLOAT_803e028c;
extern f32 FLOAT_803e0290;
extern f32 FLOAT_803e0294;
extern f32 FLOAT_803e0298;
extern f32 FLOAT_803e029c;
extern f32 FLOAT_803e02a0;
extern f32 FLOAT_803e02a4;
extern f32 FLOAT_803e02a8;
extern f32 FLOAT_803e02ac;
extern f32 FLOAT_803e02b0;
extern f32 FLOAT_803e02b4;
extern f32 FLOAT_803e02b8;
extern f32 FLOAT_803e02bc;
extern f32 FLOAT_803e02c0;
extern f32 FLOAT_803e02c4;
extern f32 FLOAT_803e02c8;
extern f32 FLOAT_803e02cc;
extern f32 FLOAT_803e02d0;
extern f32 FLOAT_803e02d4;
extern f32 FLOAT_803e02d8;
extern f32 FLOAT_803e02dc;
extern f32 FLOAT_803e02e0;
extern f32 FLOAT_803e02e4;
extern f32 FLOAT_803e02e8;
extern f32 FLOAT_803e02ec;
extern f32 FLOAT_803e02f0;
extern f32 FLOAT_803e02f4;
extern f32 FLOAT_803e02f8;
extern f32 FLOAT_803e02fc;
extern f32 FLOAT_803e0300;
extern f32 FLOAT_803e0304;
extern f32 FLOAT_803e0308;
extern f32 FLOAT_803e030c;
extern f32 FLOAT_803e0310;
extern f32 FLOAT_803e0314;
extern f32 FLOAT_803e0318;
extern f32 FLOAT_803e031c;
extern f32 FLOAT_803e0320;
extern f32 FLOAT_803e0324;
extern f32 FLOAT_803e0328;
extern f32 FLOAT_803e032c;
extern f32 FLOAT_803e0330;
extern f32 FLOAT_803e0334;
extern f32 FLOAT_803e0338;
extern f32 FLOAT_803e033c;
extern f32 FLOAT_803e0340;
extern f32 FLOAT_803e0344;
extern f32 FLOAT_803e0348;
extern f32 FLOAT_803e034c;
extern f32 FLOAT_803e0350;
extern f32 FLOAT_803e0354;
extern f32 FLOAT_803e0358;
extern f32 FLOAT_803e035c;
extern f32 FLOAT_803e0360;
extern f32 FLOAT_803e0364;
extern f32 FLOAT_803e0368;
extern f32 FLOAT_803e036c;
extern f32 FLOAT_803e0370;
extern f32 FLOAT_803e0374;
extern f32 FLOAT_803e0378;
extern f32 FLOAT_803e037c;
extern f32 FLOAT_803e0380;
extern f32 FLOAT_803e0384;
extern f32 FLOAT_803e0388;
extern f32 FLOAT_803e03a0;
extern f32 FLOAT_803e03a4;
extern f32 FLOAT_803e03a8;
extern f32 FLOAT_803e03ac;
extern f32 FLOAT_803e03b0;
extern f32 FLOAT_803e03b4;
extern f32 FLOAT_803e03b8;
extern f32 FLOAT_803e03bc;
extern f32 FLOAT_803e03c0;
extern f32 FLOAT_803e03c4;
extern f32 FLOAT_803e03c8;
extern f32 FLOAT_803e03cc;
extern f32 FLOAT_803e03d0;
extern f32 FLOAT_803e03d4;
extern f32 FLOAT_803e03d8;
extern f32 FLOAT_803e03dc;
extern f32 FLOAT_803e03e0;
extern f32 FLOAT_803e03e4;
extern f32 FLOAT_803e03e8;
extern f32 FLOAT_803e03ec;
extern f32 FLOAT_803e03f0;
extern f32 FLOAT_803e03f4;
extern f32 FLOAT_803e03f8;
extern f32 FLOAT_803e03fc;
extern f32 FLOAT_803e0400;
extern f32 FLOAT_803e0404;
extern f32 FLOAT_803e0408;
extern f32 FLOAT_803e040c;
extern f32 FLOAT_803e0410;
extern f32 FLOAT_803e0414;
extern f32 FLOAT_803e0418;
extern f32 FLOAT_803e041c;
extern f32 FLOAT_803e0420;
extern f32 FLOAT_803e0424;
extern f32 FLOAT_803e0428;
extern f32 FLOAT_803e042c;
extern f32 FLOAT_803e0430;
extern f32 FLOAT_803e0434;
extern f32 FLOAT_803e0438;
extern f32 FLOAT_803e043c;
extern f32 FLOAT_803e0440;
extern f32 FLOAT_803e0444;
extern f32 FLOAT_803e0448;
extern f32 FLOAT_803e044c;
extern f32 FLOAT_803e0450;
extern f32 FLOAT_803e0454;
extern f32 FLOAT_803e0458;
extern f32 FLOAT_803e045c;
extern f32 FLOAT_803e0460;
extern f32 FLOAT_803e0464;
extern f32 FLOAT_803e0468;
extern f32 FLOAT_803e046c;
extern f32 FLOAT_803e0470;
extern f32 FLOAT_803e0474;
extern f32 FLOAT_803e0478;
extern f32 FLOAT_803e047c;
extern f32 FLOAT_803e0480;
extern f32 FLOAT_803e0484;
extern f32 FLOAT_803e0488;
extern f32 FLOAT_803e048c;
extern f32 FLOAT_803e0490;
extern f32 FLOAT_803e0494;
extern f32 FLOAT_803e0498;
extern f32 FLOAT_803e049c;
extern f32 FLOAT_803e04a0;
extern f32 FLOAT_803e04a4;
extern f32 FLOAT_803e04a8;
extern f32 FLOAT_803e04ac;
extern f32 FLOAT_803e04b0;
extern f32 FLOAT_803e04b4;
extern f32 FLOAT_803e04b8;
extern f32 FLOAT_803e04bc;
extern f32 FLOAT_803e04c0;
extern f32 FLOAT_803e04c4;
extern f32 FLOAT_803e04c8;
extern f32 FLOAT_803e04cc;
extern f32 FLOAT_803e04d0;
extern f32 FLOAT_803e04d4;
extern f32 FLOAT_803e04d8;
extern f32 FLOAT_803e04f0;
extern f32 FLOAT_803e04f4;
extern f32 FLOAT_803e04f8;
extern f32 FLOAT_803e04fc;
extern f32 FLOAT_803e0500;
extern f32 FLOAT_803e0504;
extern f32 FLOAT_803e0508;
extern f32 FLOAT_803e050c;
extern f32 FLOAT_803e0510;
extern f32 FLOAT_803e0514;
extern f32 FLOAT_803e0518;
extern f32 FLOAT_803e051c;
extern f32 FLOAT_803e0520;
extern f32 FLOAT_803e0524;
extern f32 FLOAT_803e0528;
extern f32 FLOAT_803e052c;
extern f32 FLOAT_803e0530;
extern f32 FLOAT_803e0534;
extern f32 FLOAT_803e0538;
extern f32 FLOAT_803e053c;
extern f32 FLOAT_803e0540;
extern f32 FLOAT_803e0544;
extern f32 FLOAT_803e0548;
extern f32 FLOAT_803e054c;
extern f32 FLOAT_803e0550;
extern f32 FLOAT_803e0554;
extern f32 FLOAT_803e0558;
extern f32 FLOAT_803e055c;
extern f32 FLOAT_803e0560;
extern f32 FLOAT_803e0564;
extern f32 FLOAT_803e0568;
extern f32 FLOAT_803e056c;
extern f32 FLOAT_803e0570;
extern f32 FLOAT_803e0574;
extern f32 FLOAT_803e0578;
extern f32 FLOAT_803e057c;
extern f32 FLOAT_803e0580;
extern f32 FLOAT_803e0584;
extern f32 FLOAT_803e0588;
extern f32 FLOAT_803e058c;
extern f32 FLOAT_803e0590;
extern f32 FLOAT_803e0594;
extern f32 FLOAT_803e0598;
extern f32 FLOAT_803e059c;
extern f32 FLOAT_803e05a0;
extern f32 FLOAT_803e05a4;
extern f32 FLOAT_803e05a8;
extern f32 FLOAT_803e05ac;
extern f32 FLOAT_803e05b0;
extern f32 FLOAT_803e05b4;
extern f32 FLOAT_803e05b8;
extern f32 FLOAT_803e05bc;
extern f32 FLOAT_803e05c0;
extern f32 FLOAT_803e05c4;
extern f32 FLOAT_803e05c8;
extern f32 FLOAT_803e05cc;
extern f32 FLOAT_803e05d0;
extern f32 FLOAT_803e05d4;
extern f32 FLOAT_803e05d8;
extern f32 FLOAT_803e05dc;
extern f32 FLOAT_803e05e0;
extern f32 FLOAT_803e05e4;
extern f32 FLOAT_803e05e8;
extern f32 FLOAT_803e05ec;
extern f32 FLOAT_803e05f0;
extern f32 FLOAT_803e05f4;
extern f32 FLOAT_803e05f8;
extern f32 FLOAT_803e05fc;
extern f32 FLOAT_803e0600;
extern f32 FLOAT_803e0604;
extern f32 FLOAT_803e0608;
extern f32 FLOAT_803e060c;
extern f32 FLOAT_803e0610;
extern f32 FLOAT_803e0614;
extern f32 FLOAT_803e0618;
extern f32 FLOAT_803e061c;
extern f32 FLOAT_803e0620;
extern f32 FLOAT_803e0624;
extern f32 FLOAT_803e0628;
extern f32 FLOAT_803e062c;
extern f32 FLOAT_803e0630;
extern f32 FLOAT_803e0634;
extern f32 FLOAT_803e0638;
extern f32 FLOAT_803e063c;
extern f32 FLOAT_803e0650;
extern f32 FLOAT_803e0654;
extern f32 FLOAT_803e0658;
extern f32 FLOAT_803e065c;
extern f32 FLOAT_803e0660;
extern f32 FLOAT_803e0664;
extern f32 FLOAT_803e0668;
extern f32 FLOAT_803e066c;
extern f32 FLOAT_803e0670;
extern f32 FLOAT_803e0674;
extern f32 FLOAT_803e0678;
extern f32 FLOAT_803e067c;
extern f32 FLOAT_803e0680;
extern f32 FLOAT_803e0684;
extern f32 FLOAT_803e0688;
extern f32 FLOAT_803e068c;
extern f32 FLOAT_803e0690;
extern f32 FLOAT_803e0694;
extern f32 FLOAT_803e0698;
extern f32 FLOAT_803e069c;
extern f32 FLOAT_803e06a0;
extern f32 FLOAT_803e06a4;
extern f32 FLOAT_803e06a8;
extern f32 FLOAT_803e06ac;
extern f32 FLOAT_803e06b0;
extern f32 FLOAT_803e06b4;
extern f32 FLOAT_803e06b8;
extern f32 FLOAT_803e06bc;
extern f32 FLOAT_803e06c0;
extern f32 FLOAT_803e06c4;
extern f32 FLOAT_803e06c8;
extern f32 FLOAT_803e06cc;
extern f32 FLOAT_803e06d0;
extern f32 FLOAT_803e06d4;
extern f32 FLOAT_803e06e0;
extern f32 FLOAT_803e06e4;
extern f32 FLOAT_803e06e8;
extern f32 FLOAT_803e06ec;
extern f32 FLOAT_803e06f0;
extern f32 FLOAT_803e06f4;
extern f32 FLOAT_803e06f8;
extern f32 FLOAT_803e0708;
extern f32 FLOAT_803e070c;
extern f32 FLOAT_803e0710;
extern f32 FLOAT_803e0714;
extern f32 FLOAT_803e0718;
extern f32 FLOAT_803e071c;
extern f32 FLOAT_803e0720;
extern f32 FLOAT_803e0724;
extern f32 FLOAT_803e0728;
extern f32 FLOAT_803e072c;
extern f32 FLOAT_803e0730;
extern f32 FLOAT_803e0734;
extern f32 FLOAT_803e0738;
extern f32 FLOAT_803e073c;
extern f32 FLOAT_803e0740;
extern f32 FLOAT_803e0744;
extern f32 FLOAT_803e0748;
extern f32 FLOAT_803e074c;
extern f32 FLOAT_803e0750;
extern f32 FLOAT_803e0754;
extern f32 FLOAT_803e0758;
extern f32 FLOAT_803e075c;
extern f32 FLOAT_803e0760;
extern f32 FLOAT_803e0764;
extern f32 FLOAT_803e0768;
extern f32 FLOAT_803e076c;
extern f32 FLOAT_803e0770;
extern f32 FLOAT_803e0774;
extern f32 FLOAT_803e0778;
extern f32 FLOAT_803e077c;
extern f32 FLOAT_803e0780;
extern f32 FLOAT_803e0784;
extern f32 FLOAT_803e0788;
extern f32 FLOAT_803e078c;
extern f32 FLOAT_803e0790;
extern f32 FLOAT_803e0794;
extern f32 FLOAT_803e0798;
extern f32 FLOAT_803e079c;
extern f32 FLOAT_803e07a0;
extern f32 FLOAT_803e07a4;
extern f32 FLOAT_803e07a8;
extern f32 FLOAT_803e07ac;
extern f32 FLOAT_803e07b0;
extern f32 FLOAT_803e07b4;
extern f32 FLOAT_803e07b8;
extern f32 FLOAT_803e07bc;
extern f32 FLOAT_803e07c0;
extern f32 FLOAT_803e07c4;
extern f32 FLOAT_803e07c8;
extern f32 FLOAT_803e07cc;
extern f32 FLOAT_803e07d0;
extern f32 FLOAT_803e07d4;
extern f32 FLOAT_803e07d8;
extern f32 FLOAT_803e07dc;
extern f32 FLOAT_803e07e0;
extern f32 FLOAT_803e07e4;
extern f32 FLOAT_803e07e8;
extern f32 FLOAT_803e07ec;
extern f32 FLOAT_803e07f0;
extern f32 FLOAT_803e07f4;
extern f32 FLOAT_803e07f8;
extern f32 FLOAT_803e07fc;
extern f32 FLOAT_803e0800;
extern f32 FLOAT_803e0804;
extern f32 FLOAT_803e0808;
extern f32 FLOAT_803e080c;
extern f32 FLOAT_803e0810;
extern f32 FLOAT_803e0814;
extern f32 FLOAT_803e0818;
extern f32 FLOAT_803e081c;
extern f32 FLOAT_803e0820;
extern f32 FLOAT_803e0824;
extern f32 FLOAT_803e0828;
extern f32 FLOAT_803e082c;
extern f32 FLOAT_803e0830;
extern f32 FLOAT_803e0834;
extern f32 FLOAT_803e0838;
extern f32 FLOAT_803e083c;
extern f32 FLOAT_803e0840;
extern f32 FLOAT_803e0844;
extern f32 FLOAT_803e0848;
extern f32 FLOAT_803e0860;
extern f32 FLOAT_803e0864;
extern f32 FLOAT_803e0868;
extern f32 FLOAT_803e086c;
extern f32 FLOAT_803e0870;
extern f32 FLOAT_803e0874;
extern f32 FLOAT_803e0878;
extern f32 FLOAT_803e087c;
extern f32 FLOAT_803e0880;
extern f32 FLOAT_803e0884;
extern f32 FLOAT_803e0888;
extern f32 FLOAT_803e088c;
extern f32 FLOAT_803e0890;
extern f32 FLOAT_803e0894;
extern f32 FLOAT_803e0898;
extern f32 FLOAT_803e089c;
extern f32 FLOAT_803e08a0;
extern f32 FLOAT_803e08a4;
extern f32 FLOAT_803e08a8;
extern f32 FLOAT_803e08ac;
extern f32 FLOAT_803e08b0;
extern f32 FLOAT_803e08b4;
extern f32 FLOAT_803e08b8;
extern f32 FLOAT_803e08bc;
extern f32 FLOAT_803e08c0;
extern f32 FLOAT_803e08c4;
extern f32 FLOAT_803e08c8;
extern f32 FLOAT_803e08cc;
extern f32 FLOAT_803e08d0;
extern f32 FLOAT_803e08d4;
extern f32 FLOAT_803e08d8;
extern f32 FLOAT_803e08dc;
extern f32 FLOAT_803e08e0;
extern f32 FLOAT_803e08e4;
extern f32 FLOAT_803e08e8;
extern f32 FLOAT_803e0900;
extern f32 FLOAT_803e0904;
extern f32 FLOAT_803e0908;
extern f32 FLOAT_803e090c;
extern f32 FLOAT_803e0910;
extern f32 FLOAT_803e0914;
extern f32 FLOAT_803e0918;
extern f32 FLOAT_803e091c;
extern f32 FLOAT_803e0920;
extern f32 FLOAT_803e0924;
extern f32 FLOAT_803e0928;
extern f32 FLOAT_803e092c;
extern f32 FLOAT_803e0930;
extern f32 FLOAT_803e0934;
extern f32 FLOAT_803e0938;
extern f32 FLOAT_803e093c;
extern f32 FLOAT_803e0940;
extern f32 FLOAT_803e0944;
extern f32 FLOAT_803e0958;
extern f32 FLOAT_803e095c;
extern f32 FLOAT_803e0960;
extern f32 FLOAT_803e0964;
extern f32 FLOAT_803e0968;
extern f32 FLOAT_803e096c;
extern f32 FLOAT_803e0970;
extern f32 FLOAT_803e0974;
extern f32 FLOAT_803e0978;
extern f32 FLOAT_803e097c;
extern f32 FLOAT_803e0980;
extern f32 FLOAT_803e0984;
extern f32 FLOAT_803e0988;
extern f32 FLOAT_803e098c;
extern f32 FLOAT_803e0990;
extern f32 FLOAT_803e0994;
extern f32 FLOAT_803e0998;
extern f32 FLOAT_803e099c;
extern f32 FLOAT_803e09a0;
extern f32 FLOAT_803e09a4;
extern f32 FLOAT_803e09a8;
extern f32 FLOAT_803e09ac;
extern f32 FLOAT_803e09b0;
extern f32 FLOAT_803e09b4;
extern f32 FLOAT_803e09b8;
extern f32 FLOAT_803e09bc;
extern f32 FLOAT_803e09c0;
extern f32 FLOAT_803e09c4;
extern f32 FLOAT_803e09c8;
extern f32 FLOAT_803e09cc;
extern f32 FLOAT_803e09d0;
extern f32 FLOAT_803e09d4;
extern f32 FLOAT_803e09d8;
extern f32 FLOAT_803e09dc;
extern f32 FLOAT_803e09e0;
extern f32 FLOAT_803e09e4;
extern f32 FLOAT_803e09e8;
extern f32 FLOAT_803e09ec;
extern f32 FLOAT_803e09f0;
extern f32 FLOAT_803e09f4;
extern f32 FLOAT_803e09f8;
extern f32 FLOAT_803e09fc;
extern f32 FLOAT_803e0a00;
extern f32 FLOAT_803e0a04;
extern f32 FLOAT_803e0a18;
extern f32 FLOAT_803e0a1c;
extern f32 FLOAT_803e0a20;
extern f32 FLOAT_803e0a24;
extern f32 FLOAT_803e0a28;
extern f32 FLOAT_803e0a2c;
extern f32 FLOAT_803e0a30;
extern f32 FLOAT_803e0a34;
extern f32 FLOAT_803e0a38;
extern f32 FLOAT_803e0a3c;
extern f32 FLOAT_803e0a40;
extern f32 FLOAT_803e0a44;
extern f32 FLOAT_803e0a48;
extern f32 FLOAT_803e0a4c;
extern f32 FLOAT_803e0a50;
extern f32 FLOAT_803e0a54;
extern f32 FLOAT_803e0a58;
extern f32 FLOAT_803e0a5c;
extern f32 FLOAT_803e0a60;
extern f32 FLOAT_803e0a64;
extern f32 FLOAT_803e0a68;
extern f32 FLOAT_803e0a6c;
extern f32 FLOAT_803e0a74;
extern f32 FLOAT_803e0a78;
extern f32 FLOAT_803e0a7c;
extern f32 FLOAT_803e0a80;
extern f32 FLOAT_803e0a84;
extern f32 FLOAT_803e0a88;
extern f32 FLOAT_803e0a8c;
extern f32 FLOAT_803e0a90;
extern f32 FLOAT_803e0aa8;
extern f32 FLOAT_803e0aac;
extern f32 FLOAT_803e0ab0;
extern f32 FLOAT_803e0ab4;
extern f32 FLOAT_803e0ab8;
extern f32 FLOAT_803e0abc;
extern f32 FLOAT_803e0ac0;
extern f32 FLOAT_803e0ac4;
extern f32 FLOAT_803e0ac8;
extern f32 FLOAT_803e0acc;
extern f32 FLOAT_803e0ad0;
extern f32 FLOAT_803e0ad4;
extern f32 FLOAT_803e0ad8;
extern f32 FLOAT_803e0adc;
extern f32 FLOAT_803e0ae0;
extern f32 FLOAT_803e0ae4;
extern f32 FLOAT_803e0ae8;
extern f32 FLOAT_803e0aec;
extern f32 FLOAT_803e0af0;
extern f32 FLOAT_803e0af4;
extern f32 FLOAT_803e0af8;
extern f32 FLOAT_803e0afc;
extern f32 FLOAT_803e0b00;
extern f32 FLOAT_803e0b04;
extern f32 FLOAT_803e0b08;
extern f32 FLOAT_803e0b0c;
extern f32 FLOAT_803e0b10;
extern f32 FLOAT_803e0b14;
extern f32 FLOAT_803e0b18;
extern f32 FLOAT_803e0b1c;
extern f32 FLOAT_803e0b20;
extern f32 FLOAT_803e0b24;
extern void* PTR_FUN_80310888;
extern void* PTR_FUN_80310894;
extern void* PTR_LAB_803108a0;

/*
 * --INFO--
 *
 * Function: FUN_8009ff68
 * EN v1.0 Address: 0x8009FF68
 * EN v1.0 Size: 416b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009ff68(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  undefined *puVar1;
  undefined4 *puVar2;
  undefined *puVar3;
  undefined2 *puVar4;
  undefined *puVar5;
  undefined4 *puVar6;
  int *piVar7;
  int iVar8;
  
  piVar7 = &DAT_8039b7b8;
  expgfx_initialise(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  puVar2 = &DAT_8039c878;
  puVar3 = &DAT_8039c828;
  puVar4 = &DAT_80310488;
  puVar1 = &DAT_80310528;
  puVar5 = &DAT_8039c638;
  puVar6 = &DAT_8039c688;
  iVar8 = 10;
  do {
    *puVar2 = 0;
    *puVar3 = 0;
    *puVar4 = 0xffff;
    *puVar1 = 0;
    *puVar5 = 0;
    *puVar6 = 0;
    puVar2[1] = 0;
    puVar3[1] = 0;
    puVar4[1] = 0xffff;
    puVar1[1] = 0;
    puVar5[1] = 0;
    puVar6[1] = 0;
    puVar2[2] = 0;
    puVar3[2] = 0;
    puVar4[2] = 0xffff;
    puVar1[2] = 0;
    puVar5[2] = 0;
    puVar6[2] = 0;
    puVar2[3] = 0;
    puVar3[3] = 0;
    puVar4[3] = 0xffff;
    puVar1[3] = 0;
    puVar5[3] = 0;
    puVar6[3] = 0;
    puVar2[4] = 0;
    puVar3[4] = 0;
    puVar4[4] = 0xffff;
    puVar1[4] = 0;
    puVar5[4] = 0;
    puVar6[4] = 0;
    puVar2[5] = 0;
    puVar3[5] = 0;
    puVar4[5] = 0xffff;
    puVar1[5] = 0;
    puVar5[5] = 0;
    puVar6[5] = 0;
    puVar2[6] = 0;
    puVar3[6] = 0;
    puVar4[6] = 0xffff;
    puVar1[6] = 0;
    puVar5[6] = 0;
    puVar6[6] = 0;
    puVar2[7] = 0;
    puVar3[7] = 0;
    puVar4[7] = 0xffff;
    puVar1[7] = 0;
    puVar5[7] = 0;
    puVar6[7] = 0;
    puVar2 = puVar2 + 8;
    puVar3 = puVar3 + 8;
    puVar4 = puVar4 + 8;
    puVar1 = puVar1 + 8;
    puVar5 = puVar5 + 8;
    puVar6 = puVar6 + 8;
    iVar8 = iVar8 + -1;
  } while (iVar8 != 0);
  DAT_8039c7cc = 0;
  DAT_8039c7c8 = 0;
  DAT_8039c7d4 = 0;
  DAT_8039c7d0 = 0;
  DAT_803dded8 = 1;
  iVar8 = 0;
  do {
    if (*piVar7 != 0) {
      FUN_80054484();
    }
    *piVar7 = 0;
    piVar7[2] = 0;
    piVar7[1] = 0;
    piVar7[3] = 0;
    piVar7 = piVar7 + 4;
    iVar8 = iVar8 + 1;
  } while (iVar8 < 0x20);
  DAT_803dded8 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a0108
 * EN v1.0 Address: 0x800A0108
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a0108(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  uint *puVar2;
  
  expgfx_initialise(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  iVar1 = 0;
  puVar2 = &DAT_8039c9b8;
  do {
    FUN_800238c4(*puVar2);
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x50);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a015c
 * EN v1.0 Address: 0x800A015C
 * EN v1.0 Size: 320b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a015c(void)
{
  undefined2 *puVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined *puVar4;
  int iVar5;
  uint *puVar6;
  int iVar7;
  
  puVar3 = &DAT_8039c878;
  puVar4 = &DAT_8039c828;
  puVar1 = &DAT_80310488;
  iVar7 = 10;
  do {
    iVar5 = 0;
    *puVar3 = 0;
    *puVar4 = 0;
    *puVar1 = 0xffff;
    puVar3[1] = 0;
    puVar4[1] = 0;
    puVar1[1] = 0xffff;
    puVar3[2] = 0;
    puVar4[2] = 0;
    puVar1[2] = 0xffff;
    puVar3[3] = 0;
    puVar4[3] = 0;
    puVar1[3] = 0xffff;
    puVar3[4] = 0;
    puVar4[4] = 0;
    puVar1[4] = 0xffff;
    puVar3[5] = 0;
    puVar4[5] = 0;
    puVar1[5] = 0xffff;
    puVar3[6] = 0;
    puVar4[6] = 0;
    puVar1[6] = 0xffff;
    puVar3[7] = 0;
    puVar4[7] = 0;
    puVar1[7] = 0xffff;
    puVar3 = puVar3 + 8;
    puVar4 = puVar4 + 8;
    puVar1 = puVar1 + 8;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  puVar6 = &DAT_8039c9b8;
  do {
    uVar2 = FUN_80023d8c(4000,0x14);
    *puVar6 = uVar2;
    FUN_800033a8(*puVar6,0,4000);
    FUN_802420e0(*puVar6,4000);
    puVar6 = puVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 0x50);
  FUN_800033a8(-0x7fc63ec8,0,0x500);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a029c
 * EN v1.0 Address: 0x800A029C
 * EN v1.0 Size: 336b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a029c(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
                 undefined2 *param_10,int param_11,undefined2 *param_12,int param_13,uint param_14,
                 int param_15)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a03ec
 * EN v1.0 Address: 0x800A03EC
 * EN v1.0 Size: 212b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a03ec(uint param_1)
{
  FUN_80003494(0x8039cb3e,param_1,0xe);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a04c0
 * EN v1.0 Address: 0x800A04C0
 * EN v1.0 Size: 168b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a04c0(undefined4 param_1,undefined4 param_2,undefined param_3,undefined4 param_4,
                 undefined4 param_5)
{
  undefined4 uVar1;
  ushort extraout_r4;
  
  uVar1 = FUN_80286840();
  FUN_800033a8(-0x7fc63508,0,0x60);
  DAT_8039cb50 = (undefined)extraout_r4;
  DAT_8039cb3c = extraout_r4 & 0xff;
  DAT_8039cb24 = FLOAT_803e00b0;
  DAT_8039cb28 = FLOAT_803e00b0;
  DAT_8039cb2c = FLOAT_803e00b0;
  DAT_8039cb18 = FLOAT_803e00b0;
  DAT_8039cb1c = FLOAT_803e00b0;
  DAT_8039cb20 = FLOAT_803e00b0;
  DAT_8039cb30 = FLOAT_803e00b4;
  DAT_8039cb52 = 0;
  DAT_8039cb53 = 0;
  DAT_8039cafc = uVar1;
  DAT_8039cb34 = param_5;
  DAT_8039cb38 = param_4;
  DAT_8039cb51 = param_3;
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a0568
 * EN v1.0 Address: 0x800A0568
 * EN v1.0 Size: 412b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a0568(int param_1,int param_2)
{
  short sVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  
  fVar2 = FLOAT_803e00b8 * *(float *)(param_2 + 4) * FLOAT_803ddf04;
  fVar3 = FLOAT_803e00b8 * *(float *)(param_2 + 8) * FLOAT_803ddf04;
  iVar5 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  iVar6 = *(int *)(param_1 + (1 - (uint)*(byte *)(param_1 + 0x130)) * 4 + 0x78);
  uVar7 = 0;
  uVar8 = 0;
  for (iVar4 = 0; iVar4 < *(short *)(param_1 + 0xea); iVar4 = iVar4 + 1) {
    *(undefined2 *)(iVar5 + 8) = *(undefined2 *)(iVar6 + 8);
    *(undefined2 *)(iVar5 + 10) = *(undefined2 *)(iVar6 + 10);
    *(short *)(iVar5 + 8) = *(short *)(iVar5 + 8) + (short)(int)fVar2;
    if (0x100 < *(short *)(iVar5 + 8)) {
      uVar7 = uVar7 + 1 & 0xff;
    }
    if (*(short *)(iVar5 + 8) < -0x100) {
      uVar7 = uVar7 + 1 & 0xff;
    }
    *(short *)(iVar5 + 10) = *(short *)(iVar5 + 10) + (short)(int)fVar3;
    if (0x100 < *(short *)(iVar5 + 10)) {
      uVar8 = uVar8 + 1 & 0xff;
    }
    if (*(short *)(iVar5 + 10) < -0x100) {
      uVar8 = uVar8 + 1 & 0xff;
    }
    iVar5 = iVar5 + 0x10;
    iVar6 = iVar6 + 0x10;
  }
  iVar4 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  for (iVar5 = 0; iVar5 < *(short *)(param_1 + 0xea); iVar5 = iVar5 + 1) {
    if (uVar7 == (int)*(short *)(param_1 + 0xea)) {
      sVar1 = *(short *)(iVar4 + 8);
      if (sVar1 < 0x101) {
        *(short *)(iVar4 + 8) = sVar1 + 0x100;
      }
      else {
        *(short *)(iVar4 + 8) = sVar1 + -0x100;
      }
    }
    if (uVar8 == (int)*(short *)(param_1 + 0xea)) {
      sVar1 = *(short *)(iVar4 + 10);
      if (sVar1 < 0x101) {
        *(short *)(iVar4 + 10) = sVar1 + 0x100;
      }
      else {
        *(short *)(iVar4 + 10) = sVar1 + -0x100;
      }
    }
    iVar4 = iVar4 + 0x10;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a0704
 * EN v1.0 Address: 0x800A0704
 * EN v1.0 Size: 172b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a0704(int param_1)
{
  float fVar1;
  float fVar2;
  int iVar3;
  undefined2 *puVar4;
  undefined2 *puVar5;
  
  puVar5 = *(undefined2 **)(param_1 + (1 - (uint)*(byte *)(param_1 + 0x130)) * 4 + 0x78);
  puVar4 = *(undefined2 **)(param_1 + 0x80);
  for (iVar3 = 0; fVar2 = FLOAT_803e00b4, iVar3 < *(short *)(param_1 + 0xea); iVar3 = iVar3 + 1) {
    *puVar4 = *puVar5;
    puVar4[1] = puVar5[1];
    puVar4[2] = puVar5[2];
    *(undefined *)(puVar4 + 6) = *(undefined *)(puVar5 + 6);
    *(undefined *)((int)puVar4 + 0xd) = *(undefined *)((int)puVar5 + 0xd);
    *(undefined *)(puVar4 + 7) = *(undefined *)(puVar5 + 7);
    *(undefined *)((int)puVar4 + 0xf) = *(undefined *)((int)puVar5 + 0xf);
    puVar4 = puVar4 + 8;
    puVar5 = puVar5 + 8;
  }
  *(float *)(param_1 + 0x30) = FLOAT_803e00b4;
  *(float *)(param_1 + 0x34) = fVar2;
  *(float *)(param_1 + 0x38) = fVar2;
  fVar1 = FLOAT_803e00b0;
  *(float *)(param_1 + 0x3c) = FLOAT_803e00b0;
  *(float *)(param_1 + 0x40) = fVar1;
  *(float *)(param_1 + 0x44) = fVar1;
  *(float *)(param_1 + 0x48) = fVar2;
  *(float *)(param_1 + 0x4c) = fVar2;
  *(float *)(param_1 + 0x50) = fVar2;
  *(float *)(param_1 + 0x54) = fVar1;
  *(float *)(param_1 + 0x58) = fVar1;
  *(float *)(param_1 + 0x5c) = fVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a07b0
 * EN v1.0 Address: 0x800A07B0
 * EN v1.0 Size: 760b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a07b0(int param_1,int param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 local_18;
  undefined8 local_10;
  undefined8 local_8;
  
  dVar4 = DOUBLE_803e00c0;
  iVar6 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  if (param_3 == 1) {
    fVar1 = *(float *)(param_2 + 4);
    fVar2 = *(float *)(param_2 + 8);
    fVar3 = *(float *)(param_2 + 0xc);
    if (*(short *)(param_1 + 0xfe) == 0) {
      *(float *)(param_1 + 0xbc) = fVar1;
      *(float *)(param_1 + 0xc0) = fVar2;
      *(float *)(param_1 + 0xc4) = fVar3;
      fVar1 = FLOAT_803e00b0;
      *(float *)(param_1 + 200) = FLOAT_803e00b0;
      *(float *)(param_1 + 0xcc) = fVar1;
      *(float *)(param_1 + 0xd0) = fVar1;
    }
    else {
      *(float *)(param_1 + 0xbc) =
           (float)((double)CONCAT44(0x43300000,
                                    (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 +
                                                   0xc)) - DOUBLE_803e00c0);
      *(float *)(param_1 + 0xc0) =
           (float)((double)CONCAT44(0x43300000,
                                    (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 +
                                                   0xd)) - dVar4);
      *(float *)(param_1 + 0xc4) =
           (float)((double)CONCAT44(0x43300000,
                                    (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 +
                                                   0xe)) - dVar4);
      dVar5 = DOUBLE_803e00c8;
      *(float *)(param_1 + 200) =
           (fVar1 - (float)((double)CONCAT44(0x43300000,
                                             (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) *
                                                                     0x10 + 0xc)) - dVar4)) /
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) -
                  DOUBLE_803e00c8);
      local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000);
      *(float *)(param_1 + 0xcc) =
           (fVar2 - (float)((double)CONCAT44(0x43300000,
                                             (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) *
                                                                     0x10 + 0xd)) - dVar4)) /
           (float)(local_18 - dVar5);
      local_10 = (double)CONCAT44(0x43300000,
                                  (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 + 0xe)
                                 );
      local_8 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000);
      *(float *)(param_1 + 0xd0) = (fVar3 - (float)(local_10 - dVar4)) / (float)(local_8 - dVar5);
    }
  }
  *(float *)(param_1 + 0xbc) = *(float *)(param_1 + 0xbc) + *(float *)(param_1 + 200);
  *(float *)(param_1 + 0xc0) = *(float *)(param_1 + 0xc0) + *(float *)(param_1 + 0xcc);
  *(float *)(param_1 + 0xc4) = *(float *)(param_1 + 0xc4) + *(float *)(param_1 + 0xd0);
  if (FLOAT_803e00b0 <= *(float *)(param_1 + 0xbc)) {
    if (FLOAT_803e00bc < *(float *)(param_1 + 0xbc)) {
      *(float *)(param_1 + 0xbc) = FLOAT_803e00bc;
    }
  }
  else {
    *(float *)(param_1 + 0xbc) = FLOAT_803e00b0;
  }
  if (FLOAT_803e00b0 <= *(float *)(param_1 + 0xc0)) {
    if (FLOAT_803e00bc < *(float *)(param_1 + 0xc0)) {
      *(float *)(param_1 + 0xc0) = FLOAT_803e00bc;
    }
  }
  else {
    *(float *)(param_1 + 0xc0) = FLOAT_803e00b0;
  }
  if (FLOAT_803e00b0 <= *(float *)(param_1 + 0xc4)) {
    if (FLOAT_803e00bc < *(float *)(param_1 + 0xc4)) {
      *(float *)(param_1 + 0xc4) = FLOAT_803e00bc;
    }
  }
  else {
    *(float *)(param_1 + 0xc4) = FLOAT_803e00b0;
  }
  iVar7 = 0;
  for (iVar8 = 0; iVar8 < *(short *)(param_2 + 0x14); iVar8 = iVar8 + 1) {
    *(char *)(iVar6 + *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xc) =
         (char)(int)*(float *)(param_1 + 0xbc);
    *(char *)(iVar6 + *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xd) =
         (char)(int)*(float *)(param_1 + 0xc0);
    *(char *)(iVar6 + *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xe) =
         (char)(int)*(float *)(param_1 + 0xc4);
    iVar7 = iVar7 + 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a0aa8
 * EN v1.0 Address: 0x800A0AA8
 * EN v1.0 Size: 424b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a0aa8(int param_1,int param_2,int param_3)
{
  double dVar1;
  ushort local_38;
  ushort local_36;
  ushort local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  dVar1 = DOUBLE_803e00c8;
  if (param_3 == 1) {
    if (*(short *)(param_1 + *(short *)(param_1 + 0xfc) * 2 + 0xee) == 0) {
      if (((*(uint *)(param_1 + 0xa4) & 4) != 0) || ((*(uint *)(param_1 + 0xa4) & 0x80000) != 0)) {
        local_2c = FLOAT_803e00b0;
        local_28 = FLOAT_803e00b0;
        local_24 = FLOAT_803e00b0;
        local_30 = FLOAT_803e00b4;
        local_38 = **(ushort **)(param_1 + 4);
        local_36 = local_38;
        local_34 = local_38;
        FUN_80021b8c(&local_38,(float *)(param_2 + 4));
      }
      *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(param_2 + 4);
      *(undefined4 *)(param_1 + 0x28) = *(undefined4 *)(param_2 + 8);
      *(undefined4 *)(param_1 + 0x2c) = *(undefined4 *)(param_2 + 0xc);
    }
    else {
      *(float *)(param_1 + 0x24) =
           *(float *)(param_2 + 4) /
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) -
                  DOUBLE_803e00c8);
      *(float *)(param_1 + 0x28) =
           *(float *)(param_2 + 8) /
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) - dVar1
                  );
      *(float *)(param_1 + 0x2c) =
           *(float *)(param_2 + 0xc) /
           (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) - dVar1
                  );
    }
    *(float *)(param_1 + 0x60) = *(float *)(param_1 + 0x60) + *(float *)(param_1 + 0x24);
    *(float *)(param_1 + 100) = *(float *)(param_1 + 100) + *(float *)(param_1 + 0x28);
    *(float *)(param_1 + 0x68) = *(float *)(param_1 + 0x68) + *(float *)(param_1 + 0x2c);
  }
  else {
    *(float *)(param_1 + 0x60) =
         *(float *)(param_1 + 0x24) * FLOAT_803ddf04 + *(float *)(param_1 + 0x60);
    *(float *)(param_1 + 100) =
         *(float *)(param_1 + 0x28) * FLOAT_803ddf04 + *(float *)(param_1 + 100);
    *(float *)(param_1 + 0x68) =
         *(float *)(param_1 + 0x2c) * FLOAT_803ddf04 + *(float *)(param_1 + 0x68);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a0c50
 * EN v1.0 Address: 0x800A0C50
 * EN v1.0 Size: 240b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a0c50(int param_1,int param_2,int param_3)
{
  short sVar1;
  short sVar2;
  short sVar3;
  
  if (param_3 == 1) {
    sVar1 = (short)(int)*(float *)(param_2 + 4);
    sVar2 = (short)(int)*(float *)(param_2 + 8);
    sVar3 = (short)(int)*(float *)(param_2 + 0xc);
    if (*(short *)(param_1 + 0xfe) == 0) {
      *(short *)(param_1 + 0x106) = sVar1;
      *(undefined2 *)(param_1 + 0x100) = 0;
      *(short *)(param_1 + 0x108) = sVar2;
      *(undefined2 *)(param_1 + 0x102) = 0;
      *(short *)(param_1 + 0x10a) = sVar3;
      *(undefined2 *)(param_1 + 0x104) = 0;
    }
    else {
      *(short *)(param_1 + 0x100) =
           (short)(((int)sVar1 - (int)*(short *)(param_1 + 0x106)) / (int)*(short *)(param_1 + 0xfe)
                  );
      *(short *)(param_1 + 0x102) =
           (short)(((int)sVar2 - (int)*(short *)(param_1 + 0x108)) / (int)*(short *)(param_1 + 0xfe)
                  );
      *(short *)(param_1 + 0x104) =
           (short)(((int)sVar3 - (int)*(short *)(param_1 + 0x10a)) / (int)*(short *)(param_1 + 0xfe)
                  );
    }
  }
  *(short *)(param_1 + 0x106) = *(short *)(param_1 + 0x106) + *(short *)(param_1 + 0x100);
  *(short *)(param_1 + 0x108) = *(short *)(param_1 + 0x108) + *(short *)(param_1 + 0x102);
  *(short *)(param_1 + 0x10a) = *(short *)(param_1 + 0x10a) + *(short *)(param_1 + 0x104);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a0d40
 * EN v1.0 Address: 0x800A0D40
 * EN v1.0 Size: 452b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a0d40(int param_1,int param_2,int param_3,uint param_4)
{
  float fVar1;
  double dVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined8 local_8;
  
  dVar2 = DOUBLE_803e00c0;
  iVar5 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  iVar6 = *(int *)(param_1 + 0x80);
  if (param_3 == 1) {
    fVar1 = *(float *)(param_2 + 4);
    if ((int)*(short *)(param_1 + 0xfe) == 0) {
      iVar7 = 0;
      for (iVar3 = 0; iVar3 < *(short *)(param_2 + 0x14); iVar3 = iVar3 + 1) {
        *(char *)(iVar6 + *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xf) =
             (char)(int)fVar1;
        iVar8 = *(short *)(*(int *)(param_2 + 0x10) + iVar7) * 0x10 + 0xf;
        *(undefined *)(iVar5 + iVar8) = *(undefined *)(iVar6 + iVar8);
        iVar7 = iVar7 + 2;
      }
      return;
    }
    iVar7 = param_1 + (param_4 & 0xff) * 8;
    *(float *)(iVar7 + 0xac) =
         (fVar1 - (float)((double)CONCAT44(0x43300000,
                                           (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) *
                                                                   0x10 + 0xf)) - DOUBLE_803e00c0))
         / (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) -
                  DOUBLE_803e00c8);
    local_8 = (double)CONCAT44(0x43300000,
                               (uint)*(byte *)(iVar6 + **(short **)(param_2 + 0x10) * 0x10 + 0xf));
    *(float *)(iVar7 + 0xb0) = (float)(local_8 - dVar2);
  }
  iVar7 = (param_4 & 0xff) * 8;
  iVar3 = param_1 + iVar7;
  *(float *)(iVar3 + 0xb0) = *(float *)(iVar3 + 0xac) * FLOAT_803ddf04 + *(float *)(iVar3 + 0xb0);
  if (FLOAT_803e00b0 <= *(float *)(iVar3 + 0xb0)) {
    if (FLOAT_803e00bc < *(float *)(iVar3 + 0xb0)) {
      *(float *)(iVar3 + 0xb0) = FLOAT_803e00bc;
    }
  }
  else {
    *(float *)(iVar3 + 0xb0) = FLOAT_803e00b0;
  }
  iVar3 = 0;
  for (iVar8 = 0; iVar8 < *(short *)(param_2 + 0x14); iVar8 = iVar8 + 1) {
    *(char *)(iVar5 + *(short *)(*(int *)(param_2 + 0x10) + iVar3) * 0x10 + 0xf) =
         (char)(int)*(float *)(param_1 + iVar7 + 0xb0);
    iVar4 = *(short *)(*(int *)(param_2 + 0x10) + iVar3) * 0x10 + 0xf;
    *(undefined *)(iVar6 + iVar4) = *(undefined *)(iVar5 + iVar4);
    iVar3 = iVar3 + 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a0f04
 * EN v1.0 Address: 0x800A0F04
 * EN v1.0 Size: 856b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a0f04(int param_1,int param_2,int param_3,uint param_4)
{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined8 local_30;
  undefined8 local_18;
  undefined8 local_10;
  
  dVar4 = DOUBLE_803e00c8;
  if (param_3 == 1) {
    fVar1 = *(float *)(param_2 + 4);
    fVar2 = *(float *)(param_2 + 8);
    fVar3 = *(float *)(param_2 + 0xc);
    if ((int)*(short *)(param_1 + 0xfe) == 0) {
      iVar8 = *(int *)(param_1 + 0x80);
      iVar7 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
      iVar6 = 0;
      for (iVar5 = 0; iVar5 < *(short *)(param_2 + 0x14); iVar5 = iVar5 + 1) {
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10;
        *(short *)(iVar8 + iVar10) =
             (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)*(short *)(iVar8 + iVar10) ^ 0x80000000) -
                                 dVar4) * fVar1);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10 + 2;
        *(short *)(iVar8 + iVar10) =
             (short)(int)((float)((double)CONCAT44(0x43300000,
                                                   (int)*(short *)(iVar8 + iVar10) ^ 0x80000000) -
                                 dVar4) * fVar2);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10 + 4;
        local_18 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + iVar10) ^ 0x80000000);
        *(short *)(iVar8 + iVar10) = (short)(int)((float)(local_18 - dVar4) * fVar3);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10;
        *(undefined2 *)(iVar7 + iVar10) = *(undefined2 *)(iVar8 + iVar10);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10 + 2;
        *(undefined2 *)(iVar7 + iVar10) = *(undefined2 *)(iVar8 + iVar10);
        iVar10 = *(short *)(*(int *)(param_2 + 0x10) + iVar6) * 0x10 + 4;
        *(undefined2 *)(iVar7 + iVar10) = *(undefined2 *)(iVar8 + iVar10);
        iVar6 = iVar6 + 2;
      }
      return;
    }
    iVar6 = param_1 + (param_4 & 0xff) * 0x18;
    *(float *)(iVar6 + 0x3c) =
         (fVar1 - *(float *)(iVar6 + 0x30)) /
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) -
                DOUBLE_803e00c8);
    local_30 = (double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000);
    *(float *)(iVar6 + 0x40) = (fVar2 - *(float *)(iVar6 + 0x34)) / (float)(local_30 - dVar4);
    *(float *)(iVar6 + 0x44) =
         (fVar3 - *(float *)(iVar6 + 0x38)) /
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xfe) ^ 0x80000000) - dVar4);
  }
  iVar5 = param_1 + (param_4 & 0xff) * 0x18;
  *(float *)(iVar5 + 0x30) = *(float *)(iVar5 + 0x3c) * FLOAT_803ddf04 + *(float *)(iVar5 + 0x30);
  *(float *)(iVar5 + 0x34) = *(float *)(iVar5 + 0x40) * FLOAT_803ddf04 + *(float *)(iVar5 + 0x34);
  *(float *)(iVar5 + 0x38) = *(float *)(iVar5 + 0x44) * FLOAT_803ddf04 + *(float *)(iVar5 + 0x38);
  fVar1 = FLOAT_803e00b4;
  iVar7 = *(int *)(param_1 + 0x80);
  iVar6 = *(int *)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  iVar10 = 0;
  for (iVar8 = 0; iVar8 < *(short *)(param_2 + 0x14); iVar8 = iVar8 + 1) {
    if (fVar1 != *(float *)(iVar5 + 0x30)) {
      iVar9 = *(short *)(*(int *)(param_2 + 0x10) + iVar10) * 0x10;
      local_10 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + iVar9) ^ 0x80000000);
      *(short *)(iVar6 + iVar9) =
           (short)(int)(*(float *)(iVar5 + 0x30) * (float)(local_10 - DOUBLE_803e00c8));
    }
    if (fVar1 != *(float *)(iVar5 + 0x34)) {
      iVar9 = *(short *)(*(int *)(param_2 + 0x10) + iVar10) * 0x10 + 2;
      local_10 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + iVar9) ^ 0x80000000);
      *(short *)(iVar6 + iVar9) =
           (short)(int)(*(float *)(iVar5 + 0x34) * (float)(local_10 - DOUBLE_803e00c8));
    }
    if (fVar1 != *(float *)(iVar5 + 0x38)) {
      iVar9 = *(short *)(*(int *)(param_2 + 0x10) + iVar10) * 0x10 + 4;
      local_10 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + iVar9) ^ 0x80000000);
      *(short *)(iVar6 + iVar9) =
           (short)(int)(*(float *)(iVar5 + 0x38) * (float)(local_10 - DOUBLE_803e00c8));
    }
    iVar10 = iVar10 + 2;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a125c
 * EN v1.0 Address: 0x800A125C
 * EN v1.0 Size: 112b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a125c(int param_1)
{
  int iVar1;
  undefined2 *puVar2;
  undefined2 *puVar3;
  
  puVar3 = *(undefined2 **)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  puVar2 = *(undefined2 **)(param_1 + 0x80);
  for (iVar1 = 0; iVar1 < *(short *)(param_1 + 0xea); iVar1 = iVar1 + 1) {
    *puVar3 = *puVar2;
    puVar3[1] = puVar2[1];
    puVar3[2] = puVar2[2];
    *(undefined *)(puVar3 + 6) = *(undefined *)(puVar2 + 6);
    *(undefined *)((int)puVar3 + 0xd) = *(undefined *)((int)puVar2 + 0xd);
    *(undefined *)(puVar3 + 7) = *(undefined *)(puVar2 + 7);
    *(undefined *)((int)puVar3 + 0xf) = *(undefined *)((int)puVar2 + 0xf);
    puVar3 = puVar3 + 8;
    puVar2 = puVar2 + 8;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a12cc
 * EN v1.0 Address: 0x800A12CC
 * EN v1.0 Size: 1156b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a12cc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short param_9,int param_10)
{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  
  iVar3 = 0;
  puVar2 = &DAT_8039ce58;
  do {
    uVar1 = *puVar2;
    if ((uVar1 != 0) && ((param_9 == *(short *)(uVar1 + 0x10c) || (param_10 != 0)))) {
      if (*(uint *)(uVar1 + 0xa0) != 0) {
        param_1 = FUN_800238c4(*(uint *)(uVar1 + 0xa0));
      }
      if (*(int *)*puVar2 != 0) {
        FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*(int *)*puVar2
                    );
      }
      *(undefined4 *)(*puVar2 + 300) = 0;
      if ((*(char *)(*puVar2 + 0x13f) == '\0') && (*(int *)(*puVar2 + 0x98) != 0)) {
        FUN_80054484();
      }
      if (*(char *)(*puVar2 + 0x13f) == '\0') {
        *(undefined4 *)(*puVar2 + 0x98) = 0;
      }
      param_1 = FUN_800238c4(*puVar2);
      *puVar2 = 0;
    }
    puVar2 = puVar2 + 1;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 0x32);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a1750
 * EN v1.0 Address: 0x800A1750
 * EN v1.0 Size: 2512b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a1750(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a2120
 * EN v1.0 Address: 0x800A2120
 * EN v1.0 Size: 372b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a2120(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a2294
 * EN v1.0 Address: 0x800A2294
 * EN v1.0 Size: 208b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a2294(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int *piVar1;
  int iVar2;
  uint *puVar3;
  
  iVar2 = 0;
  puVar3 = &DAT_8039ce58;
  do {
    piVar1 = (int *)*puVar3;
    if ((piVar1 != (int *)0x0) && (piVar1[1] == param_9)) {
      if (*piVar1 != 0) {
        FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar1);
      }
      *(undefined4 *)(*puVar3 + 300) = 0;
      if ((*(char *)(*puVar3 + 0x13f) == '\0') && (*(int *)(*puVar3 + 0x98) != 0)) {
        FUN_80054484();
      }
      if (*(char *)(*puVar3 + 0x13f) == '\0') {
        *(undefined4 *)(*puVar3 + 0x98) = 0;
      }
      param_1 = FUN_800238c4(*puVar3);
      *puVar3 = 0;
    }
    puVar3 = puVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 0x32);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a2364
 * EN v1.0 Address: 0x800A2364
 * EN v1.0 Size: 40b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a2364(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  FUN_800a12cc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a238c
 * EN v1.0 Address: 0x800A238C
 * EN v1.0 Size: 3420b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a238c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a30e8
 * EN v1.0 Address: 0x800A30E8
 * EN v1.0 Size: 2432b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a30e8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined2 *param_12,
                 int param_13,undefined2 *param_14,uint param_15,int param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a3a68
 * EN v1.0 Address: 0x800A3A68
 * EN v1.0 Size: 304b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a3a68(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  undefined4 *puVar2;
  
  FUN_800a12cc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,1);
  DAT_8039ce58 = 0;
  DAT_8039ce5c = 0;
  DAT_8039ce60 = 0;
  DAT_8039ce64 = 0;
  DAT_8039ce68 = 0;
  DAT_8039ce6c = 0;
  DAT_8039ce70 = 0;
  DAT_8039ce74 = 0;
  DAT_8039ce78 = 0;
  DAT_8039ce7c = 0;
  DAT_8039ce80 = 0;
  DAT_8039ce84 = 0;
  DAT_8039ce88 = 0;
  DAT_8039ce8c = 0;
  DAT_8039ce90 = 0;
  DAT_8039ce94 = 0;
  DAT_8039ce98 = 0;
  DAT_8039ce9c = 0;
  DAT_8039cea0 = 0;
  DAT_8039cea4 = 0;
  DAT_8039cea8 = 0;
  DAT_8039ceac = 0;
  DAT_8039ceb0 = 0;
  DAT_8039ceb4 = 0;
  DAT_8039ceb8 = 0;
  DAT_8039cebc = 0;
  DAT_8039cec0 = 0;
  DAT_8039cec4 = 0;
  DAT_8039cec8 = 0;
  DAT_8039cecc = 0;
  DAT_8039ced0 = 0;
  DAT_8039ced4 = 0;
  DAT_8039ced8 = 0;
  DAT_8039cedc = 0;
  DAT_8039cee0 = 0;
  DAT_8039cee4 = 0;
  DAT_8039cee8 = 0;
  DAT_8039ceec = 0;
  DAT_8039cef0 = 0;
  DAT_8039cef4 = 0;
  DAT_8039cef8 = 0;
  DAT_8039cefc = 0;
  DAT_8039cf00 = 0;
  DAT_8039cf04 = 0;
  DAT_8039cf08 = 0;
  DAT_8039cf0c = 0;
  DAT_8039cf10 = 0;
  DAT_8039cf14 = 0;
  puVar2 = &DAT_8039cf18;
  iVar1 = 2;
  do {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a3b98
 * EN v1.0 Address: 0x800A3B98
 * EN v1.0 Size: 308b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a3b98(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  FUN_800a12cc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a3ccc
 * EN v1.0 Address: 0x800A3CCC
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800a3ccc(void)
{
  FUN_8007d858();
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800a3cfc
 * EN v1.0 Address: 0x800A3CFC
 * EN v1.0 Size: 80b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800a3cfc(void)
{
  FUN_8007d858();
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800a3d4c
 * EN v1.0 Address: 0x800A3D4C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a3d4c(void)
{
  FUN_8007d858();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a3d7c
 * EN v1.0 Address: 0x800A3D7C
 * EN v1.0 Size: 1580b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a3d7c(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5)
{
  char cVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  undefined2 *puVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double extraout_f1;
  double in_f20;
  double dVar10;
  double in_f21;
  double in_f22;
  double dVar11;
  double dVar12;
  double in_f23;
  double dVar13;
  double dVar14;
  double in_f24;
  double dVar15;
  double dVar16;
  double in_f25;
  double dVar17;
  double in_f26;
  double dVar18;
  double in_f27;
  double dVar19;
  double in_f28;
  double dVar20;
  double in_f29;
  double dVar21;
  double in_f30;
  double dVar22;
  double in_f31;
  double dVar23;
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
  undefined8 uVar24;
  undefined2 local_148;
  undefined2 local_146;
  undefined2 local_144;
  float local_140;
  float local_13c;
  float local_138;
  float local_134;
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
  undefined4 local_f0;
  uint uStack_ec;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
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
  uVar24 = FUN_80286840();
  iVar9 = (int)((ulonglong)uVar24 >> 0x20);
  iVar7 = (int)uVar24;
  bVar4 = false;
  dVar10 = extraout_f1;
  puVar5 = FUN_8000facc();
  DAT_803ddf1c = puVar5[1];
  DAT_803ddf1a = *puVar5;
  dVar11 = (double)(*(float *)(puVar5 + 6) - *(float *)(param_5 + 0xc));
  dVar13 = (double)(*(float *)(puVar5 + 8) - *(float *)(param_5 + 0x10));
  dVar15 = (double)(*(float *)(puVar5 + 10) - *(float *)(param_5 + 0x14));
  for (iVar8 = 0; iVar8 < iVar7; iVar8 = iVar8 + 1) {
    cVar1 = *(char *)(iVar9 + iVar8 * 0x4c + 0x48);
    if ((((cVar1 == '\x12') || ((byte)(cVar1 - 0x10U) < 2)) || ((byte)(cVar1 - 0x14U) < 2)) ||
       (cVar1 == '\x17')) {
      DAT_803109a8 = (float)dVar11;
      DAT_803109ac = (float)dVar13;
      DAT_803109b0 = (float)dVar15;
      dVar12 = FUN_80293900((double)(float)(dVar15 * dVar15 +
                                           (double)(float)(dVar11 * dVar11 +
                                                          (double)(float)(dVar13 * dVar13))));
      dVar14 = (double)(float)((double)FLOAT_803e00e8 * dVar12);
      if ((double)FLOAT_803e00ec != dVar12) {
        dVar11 = (double)(float)(dVar11 / dVar12);
        dVar13 = (double)(float)(dVar13 / dVar12);
        dVar15 = (double)(float)(dVar15 / dVar12);
      }
      dVar11 = (double)(float)(dVar11 * dVar14);
      dVar13 = (double)(float)(dVar13 * dVar14);
      dVar15 = (double)(float)(dVar15 * dVar14);
      local_13c = FLOAT_803e00ec;
      local_138 = FLOAT_803e00ec;
      local_134 = FLOAT_803e00ec;
      local_140 = FLOAT_803e00f0;
      local_144 = 0;
      local_146 = 0;
      local_148 = 0;
      bVar4 = true;
      iVar8 = iVar7;
    }
  }
  if (bVar4) {
    for (iVar8 = 0; iVar8 < iVar7; iVar8 = iVar8 + 1) {
      cVar1 = *(char *)(iVar9 + 0x48);
      if (((cVar1 == '\x12') || ((byte)(cVar1 - 0x10U) < 2)) ||
         (((byte)(cVar1 - 0x14U) < 2 || (cVar1 == '\x17')))) {
        fVar2 = *(float *)(param_5 + 0xc);
        uStack_12c = (int)*(short *)(iVar9 + 0x10) ^ 0x80000000;
        local_130 = 0x43300000;
        dVar23 = (double)(fVar2 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_12c) -
                                                         DOUBLE_803e0100) - dVar10));
        uStack_124 = (int)*(short *)(iVar9 + 0x16) ^ 0x80000000;
        local_128 = 0x43300000;
        dVar22 = (double)(float)((double)CONCAT44(0x43300000,uStack_124) - DOUBLE_803e0100);
        fVar3 = *(float *)(param_5 + 0x14);
        uStack_11c = (int)*(short *)(iVar9 + 0x1c) ^ 0x80000000;
        local_120 = 0x43300000;
        dVar21 = (double)(fVar3 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_11c) -
                                                         DOUBLE_803e0100) - param_2));
        uStack_114 = (int)*(short *)(iVar9 + 0x12) ^ 0x80000000;
        local_118 = 0x43300000;
        dVar20 = (double)(fVar2 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_114) -
                                                         DOUBLE_803e0100) - dVar10));
        uStack_10c = (int)*(short *)(iVar9 + 0x18) ^ 0x80000000;
        local_110 = 0x43300000;
        dVar19 = (double)(float)((double)CONCAT44(0x43300000,uStack_10c) - DOUBLE_803e0100);
        uStack_104 = (int)*(short *)(iVar9 + 0x1e) ^ 0x80000000;
        local_108 = 0x43300000;
        dVar18 = (double)(fVar3 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_104) -
                                                         DOUBLE_803e0100) - param_2));
        uStack_fc = (int)*(short *)(iVar9 + 0x14) ^ 0x80000000;
        local_100 = 0x43300000;
        dVar17 = (double)(fVar2 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_fc) -
                                                         DOUBLE_803e0100) - dVar10));
        uStack_f4 = (int)*(short *)(iVar9 + 0x1a) ^ 0x80000000;
        local_f8 = 0x43300000;
        dVar16 = (double)(float)((double)CONCAT44(0x43300000,uStack_f4) - DOUBLE_803e0100);
        uStack_ec = (int)*(short *)(iVar9 + 0x20) ^ 0x80000000;
        local_f0 = 0x43300000;
        dVar14 = (double)(fVar3 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack_ec) -
                                                         DOUBLE_803e0100) - param_2));
        uStack_e4 = FUN_80022264(1,1000);
        uStack_e4 = uStack_e4 ^ 0x80000000;
        local_e8 = 0x43300000;
        dVar12 = (double)((float)((double)CONCAT44(0x43300000,uStack_e4) - DOUBLE_803e0100) /
                         FLOAT_803e00f4);
        uStack_dc = FUN_80022264(1,1000);
        uStack_dc = uStack_dc ^ 0x80000000;
        local_e0 = 0x43300000;
        dVar11 = FUN_80293900((double)((float)((double)CONCAT44(0x43300000,uStack_dc) -
                                              DOUBLE_803e0100) / FLOAT_803e00f4));
        dVar13 = (double)(float)((double)FLOAT_803e00f0 - dVar11);
        dVar15 = (double)(float)((double)(float)((double)FLOAT_803e00f0 - dVar12) * dVar11);
        dVar11 = (double)(float)(dVar12 * dVar11);
        local_13c = (float)(dVar11 * dVar17 +
                           (double)(float)(dVar13 * dVar23 + (double)(float)(dVar15 * dVar20)));
        local_134 = (float)(dVar11 * dVar14 +
                           (double)(float)(dVar13 * dVar21 + (double)(float)(dVar15 * dVar18)));
        local_138 = (float)(dVar11 * dVar16 +
                           (double)(float)(dVar13 * dVar22 + (double)(float)(dVar15 * dVar19))) +
                    FLOAT_803e00f8;
        cVar1 = *(char *)(iVar9 + 0x48);
        if ((cVar1 == '\x12') || (cVar1 == '\x10')) {
          uVar6 = FUN_80022264(0,0x1e);
          if (uVar6 == 1) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x72,&local_148,0x200001,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x11') {
          uVar6 = FUN_80022264(0,8);
          if (uVar6 == 2) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x14') {
          uVar6 = FUN_80022264(0,8);
          if (uVar6 == 2) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x15') {
          uVar6 = FUN_80022264(0,8);
          if (uVar6 == 2) {
            (**(code **)(*DAT_803dd708 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x17') {
          (**(code **)(*DAT_803dd708 + 8))(param_5,400,&local_148,0x111,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_5,400,&local_148,0x111,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(param_5,400,&local_148,0x111,0xffffffff,0);
        }
      }
      iVar9 = iVar9 + 0x4c;
    }
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a43a8
 * EN v1.0 Address: 0x800A43A8
 * EN v1.0 Size: 544b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a43a8(int param_1)
{
  undefined4 uVar1;
  int local_b8;
  undefined4 local_b4;
  uint *local_b0;
  float local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  uint auStack_9c [6];
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
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  local_ac = DAT_802c28e0;
  local_a8 = DAT_802c28e4;
  local_a4 = DAT_802c28e8;
  local_a0 = DAT_802c28ec;
  local_b4 = 0;
  if (DAT_803ddf18 != '\0') {
    local_6c = FLOAT_803e00ec;
    local_50 = FLOAT_803e00ec;
    switch(DAT_803ddf18) {
    case '\v':
      local_6c = FLOAT_803e0108;
      local_50 = FLOAT_803e0108;
      break;
    case '\f':
      local_6c = FLOAT_803e010c;
      local_50 = FLOAT_803e0110;
      break;
    case '\r':
      local_6c = FLOAT_803e0114;
      local_50 = FLOAT_803e0108;
      break;
    case '\x0e':
      local_6c = FLOAT_803e0114;
      local_50 = FLOAT_803e0108;
      break;
    case '\x0f':
      local_6c = FLOAT_803e0118;
      local_50 = FLOAT_803e0110;
      break;
    case '\x10':
      local_6c = FLOAT_803e011c;
      local_50 = FLOAT_803e0120;
      break;
    case '\x11':
      local_6c = FLOAT_803e0124;
      local_50 = FLOAT_803e0124;
    }
    local_84 = *(float *)(param_1 + 0xc) - local_6c;
    local_80 = *(float *)(param_1 + 0x10) + local_50;
    local_7c = *(float *)(param_1 + 0x14) - local_6c;
    local_70 = *(float *)(param_1 + 0x14) + local_6c;
    local_6c = *(float *)(param_1 + 0xc) + local_6c;
    local_50 = *(float *)(param_1 + 0x10) - local_50;
    local_78 = local_84;
    local_74 = local_80;
    local_68 = local_80;
    local_64 = local_70;
    local_60 = local_6c;
    local_5c = local_80;
    local_58 = local_7c;
    local_54 = local_84;
    local_4c = local_7c;
    local_48 = local_84;
    local_44 = local_50;
    local_40 = local_70;
    local_3c = local_6c;
    local_38 = local_50;
    local_34 = local_70;
    local_30 = local_6c;
    local_2c = local_50;
    local_28 = local_7c;
    trackDolphin_buildSweptBounds(auStack_9c,&local_84,&local_54,&local_ac,4);
    FUN_8006933c(param_1,auStack_9c,0x84,'\0');
    trackDolphin_getCurrentIntersectionList(&local_b8,&local_b4);
    uVar1 = local_b4;
    trackDolphin_getCurrentTrackPoint(&local_b0);
    uStack_1c = *local_b0 ^ 0x80000000;
    local_20 = 0x43300000;
    uStack_14 = local_b0[2] ^ 0x80000000;
    local_18 = 0x43300000;
    FUN_800a3d7c((double)(*(float *)(param_1 + 0xc) -
                         (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0100)),
                 (double)(*(float *)(param_1 + 0x14) -
                         (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0100)),uVar1,
                 local_b8,param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a45c8
 * EN v1.0 Address: 0x800A45C8
 * EN v1.0 Size: 1768b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a45c8(undefined4 param_1,undefined4 param_2,uint param_3)
{
  int iVar1;
  float fVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined *puVar8;
  float *pfVar9;
  float *pfVar10;
  float *pfVar11;
  float *pfVar12;
  int iVar13;
  short sVar14;
  short sVar15;
  int *piVar16;
  double in_f26;
  double in_f27;
  double dVar17;
  double dVar18;
  double in_f28;
  double dVar19;
  double in_f29;
  double dVar20;
  double in_f30;
  double dVar21;
  double in_f31;
  double dVar22;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar23;
  ushort local_e0 [4];
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  longlong local_c8;
  longlong local_c0;
  longlong local_b8;
  int local_b0;
  int *local_ac;
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
  uVar23 = FUN_80286818();
  uVar6 = (undefined4)((ulonglong)uVar23 >> 0x20);
  uVar7 = FUN_80020078(0x468);
  if (uVar7 != 0) {
    FUN_800201ac(0x468,0);
    DAT_803ddf3c = 0xf;
    FUN_8000bb38(param_3,0x281);
  }
  piVar16 = *(int **)(*(int *)(param_3 + 0x7c) + *(char *)(param_3 + 0xad) * 4);
  if (6 < DAT_803ddf34) {
    DAT_803ddf34 = 0;
  }
  if ((int)(*(byte *)(*piVar16 + 0xf3) - 1) < DAT_803ddf30) {
    DAT_803ddf30 = 0;
  }
  DAT_803ddf38 = DAT_803ddf38 + (uint)DAT_803dc070;
  if (0x1f < DAT_803ddf38) {
    DAT_803ddf38 = DAT_803ddf38 + -0x1f;
  }
  FLOAT_803ddf2c = FLOAT_803dc3f8 * FLOAT_803dc074 + FLOAT_803ddf2c;
  if (FLOAT_803ddf2c <= FLOAT_803e012c) {
    if (FLOAT_803ddf2c < FLOAT_803e0134) {
      FLOAT_803dc3f8 = FLOAT_803dc3f8 * FLOAT_803e0130;
      FLOAT_803ddf2c = FLOAT_803e0134;
      FUN_8000bb38(param_3,0x282);
    }
  }
  else {
    FLOAT_803dc3f8 = FLOAT_803dc3f8 * FLOAT_803e0130;
    FLOAT_803ddf2c = FLOAT_803e012c;
    FUN_8000bb38(param_3,0x282);
  }
  local_b0 = 0;
  piVar5 = &DAT_8039cf20;
  local_ac = &DAT_8039cf20;
  do {
    if (local_b0 != 5) {
      DAT_803ddf34 = (short)local_b0;
      iVar13 = 0;
      puVar8 = &DAT_80310fac;
      dVar20 = (double)FLOAT_803e0128;
      dVar21 = (double)FLOAT_803e0138;
      dVar22 = (double)FLOAT_803e013c;
      for (sVar15 = 0; sVar15 < 5; sVar15 = sVar15 + 1) {
        local_d4 = (float)dVar20;
        local_d0 = (float)dVar20;
        local_cc = (float)dVar20;
        local_d8 = (float)dVar21;
        local_e0[2] = 0;
        local_e0[1] = 0;
        local_e0[0] = 0;
        uVar7 = (uint)(byte)(&DAT_80310fac)[DAT_803ddf34 * 5 + (int)sVar15];
        pfVar12 = (float *)(piVar16[(*(ushort *)(piVar16 + 6) & 1) + 3] + uVar7 * 0x100);
        dVar17 = (double)(pfVar12[0xd] - *(float *)(param_3 + 0x10));
        dVar19 = (double)(float)((double)((pfVar12[0xc] + FLOAT_803dda58) -
                                         *(float *)(param_3 + 0xc)) * dVar22);
        if ((uVar7 == 0x1d) || (uVar7 == 0x1d)) {
          fVar2 = FLOAT_803e013c * (float)((double)FLOAT_803e0140 + dVar17);
        }
        else {
          fVar2 = (float)(dVar17 * dVar22);
        }
        dVar18 = (double)fVar2;
        dVar17 = (double)(float)((double)((pfVar12[0xe] + FLOAT_803dda5c) -
                                         *(float *)(param_3 + 0x14)) * dVar22);
        FUN_80022790((double)local_d4,(double)local_d0,(double)local_cc,pfVar12,&local_d4,&local_d0,
                     &local_cc);
        pfVar11 = (float *)&DAT_80310a88;
        pfVar9 = (float *)&DAT_80310b18;
        pfVar10 = (float *)&DAT_803109f8;
        for (sVar14 = 0; sVar14 < 4; sVar14 = sVar14 + 1) {
          uVar7 = (uint)(byte)puVar8[DAT_803ddf34 * 5];
          cVar3 = (&DAT_80310f88)[uVar7];
          if (cVar3 == '\0') {
            local_d4 = *pfVar11 * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_d0 = pfVar11[1] * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_cc = pfVar11[2] * *(float *)(&DAT_8031105c + uVar7 * 4);
          }
          else if (cVar3 == '\x01') {
            local_d4 = *pfVar10 * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_d0 = pfVar10[1] * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_cc = pfVar10[2] * *(float *)(&DAT_8031105c + uVar7 * 4);
          }
          else if (cVar3 == '\x02') {
            local_d4 = *pfVar9 * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_d0 = pfVar9[1] * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_cc = pfVar9[2] * *(float *)(&DAT_8031105c + uVar7 * 4);
          }
          FUN_80022790((double)local_d4,(double)local_d0,(double)local_cc,pfVar12,&local_d4,
                       &local_d0,&local_cc);
          local_d4 = local_d4 + FLOAT_803dda58;
          local_cc = local_cc + FLOAT_803dda5c;
          iVar1 = (int)(dVar19 + (double)(local_d4 - *(float *)(param_3 + 0xc)));
          local_c8 = (longlong)iVar1;
          iVar4 = (sVar14 + iVar13) * 0x10;
          *(short *)(*piVar5 + iVar4) = (short)iVar1;
          iVar1 = (int)(dVar18 + (double)(local_d0 - *(float *)(param_3 + 0x10)));
          local_c0 = (longlong)iVar1;
          *(short *)(*piVar5 + iVar4 + 2) = (short)iVar1;
          iVar1 = (int)(dVar17 + (double)(local_cc - *(float *)(param_3 + 0x14)));
          local_b8 = (longlong)iVar1;
          *(short *)(*piVar5 + iVar4 + 4) = (short)iVar1;
          *(undefined *)(*piVar5 + iVar4 + 0xf) = 0x9b;
          *(short *)(*piVar5 + iVar4 + 10) =
               (&DAT_80310bb2)[(sVar14 + iVar13) * 8] - (short)(DAT_803ddf38 << 2);
          pfVar11 = pfVar11 + 3;
          pfVar10 = pfVar10 + 3;
          pfVar9 = pfVar9 + 3;
        }
        iVar13 = iVar13 + 4;
        puVar8 = puVar8 + 1;
      }
    }
    piVar5 = piVar5 + 1;
    local_b0 = local_b0 + 1;
  } while (local_b0 < 7);
  local_d4 = *(float *)(param_3 + 0xc);
  local_d0 = *(float *)(param_3 + 0x10);
  local_cc = *(float *)(param_3 + 0x14);
  local_d8 = FLOAT_803e0144;
  FUN_8005d294(uVar6,0xff,0xff,0xff,0xff);
  if (DAT_803ddf3c == 0) {
    FUN_80054328(uVar6,DAT_803ddf24,(undefined4 *)0x0,0,0);
  }
  else {
    (**(code **)(*DAT_803dd708 + 8))(param_3,0x28c,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_3,0x28c,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_3,0x28c,0,1,0xffffffff,0);
    uVar7 = FUN_80022264(0,1);
    if (uVar7 == 0) {
      FUN_80054328(uVar6,DAT_803ddf28,(undefined4 *)0x0,0,0);
    }
    else {
      FUN_80054328(uVar6,DAT_803ddf24,(undefined4 *)0x0,0,0);
    }
    DAT_803ddf3c = DAT_803ddf3c - (ushort)DAT_803dc070;
    if (DAT_803ddf3c < 0) {
      DAT_803ddf3c = 0;
    }
  }
  FUN_8000e840((double)FLOAT_803e0138,uVar6,(int)uVar23,local_e0,(float *)0x0);
  FUN_80259288(0);
  FUN_8005d264(uVar6,0xff,0xff,0xff,0xff);
  FUN_80079b3c();
  FUN_8007986c();
  FUN_800793d0();
  FUN_80079980();
  FUN_80078cc8();
  iVar13 = 0;
  do {
    fn_8005D108(*local_ac,-0x7fcef318,0x20);
    local_ac = local_ac + 1;
    iVar13 = iVar13 + 1;
  } while (iVar13 < 7);
  DAT_803ddf20 = 1 - DAT_803ddf20;
  FUN_80286864();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a4cb0
 * EN v1.0 Address: 0x800A4CB0
 * EN v1.0 Size: 396b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a4cb0(undefined4 param_1,undefined4 param_2,undefined4 param_3,uint param_4,
                 undefined2 *param_5)
{
  int iVar1;
  int *piVar2;
  uint uVar3;
  float *pfVar4;
  int iVar5;
  undefined8 uVar6;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  uVar6 = FUN_80286834();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  piVar2 = (int *)FUN_8002b660(iVar1);
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(*piVar2 + 0xf3); iVar5 = iVar5 + 1) {
    uVar3 = FUN_80022264(1,100);
    if ((int)uVar3 <= (int)(param_4 & 0xff)) {
      local_2c = FLOAT_803e0128;
      local_28 = FLOAT_803e0128;
      local_24 = FLOAT_803e0128;
      local_30 = FLOAT_803e0138;
      local_34 = 0;
      local_36 = 0;
      local_38 = 0;
      pfVar4 = (float *)FUN_80028630(piVar2,iVar5);
      FUN_80247bf8(pfVar4,&local_2c,&local_2c);
      local_28 = local_28 - *(float *)(iVar1 + 0x1c);
      local_2c = (local_2c - *(float *)(iVar1 + 0x18)) + FLOAT_803dda58;
      local_24 = (local_24 - *(float *)(iVar1 + 0x20)) + FLOAT_803dda5c;
      if (param_5 == (undefined2 *)0x0) {
        local_30 = FLOAT_803e0138;
        local_38 = 0;
        local_34 = 0;
        local_36 = 0;
        local_32 = 0;
      }
      else {
        local_30 = *(float *)(param_5 + 4);
        local_38 = *param_5;
        local_34 = param_5[2];
        local_36 = param_5[1];
        local_32 = param_5[3];
      }
      (**(code **)(*DAT_803dd708 + 8))(iVar1,(int)uVar6,&local_38,2,0xffffffff,param_3);
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a4e3c
 * EN v1.0 Address: 0x800A4E3C
 * EN v1.0 Size: 136b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a4e3c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800a4ec4
 * EN v1.0 Address: 0x800A4EC4
 * EN v1.0 Size: 444b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a4ec4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  undefined2 *puVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  
  DAT_803ddf24 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x16b,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803ddf28 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x201,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_8039cf20 = FUN_80023d8c(0x140,0x15);
  DAT_8039cf24 = FUN_80023d8c(0x140,0x15);
  DAT_8039cf28 = FUN_80023d8c(0x140,0x15);
  DAT_8039cf2c = FUN_80023d8c(0x140,0x15);
  DAT_8039cf30 = FUN_80023d8c(0x140,0x15);
  DAT_8039cf34 = FUN_80023d8c(0x140,0x15);
  DAT_8039cf38 = FUN_80023d8c(0x140,0x15);
  piVar3 = &DAT_8039cf20;
  iVar4 = 0;
  do {
    iVar2 = 0;
    iVar5 = 0x14;
    puVar1 = &DAT_80310ba8;
    do {
      *(undefined2 *)(*piVar3 + iVar2) = *puVar1;
      *(undefined2 *)(*piVar3 + iVar2 + 2) = puVar1[1];
      *(undefined2 *)(*piVar3 + iVar2 + 4) = puVar1[2];
      *(undefined2 *)(*piVar3 + iVar2 + 8) = puVar1[4];
      *(undefined2 *)(*piVar3 + iVar2 + 10) = puVar1[5];
      *(undefined *)(*piVar3 + iVar2 + 0xc) = *(undefined *)(puVar1 + 6);
      *(undefined *)(*piVar3 + iVar2 + 0xd) = *(undefined *)((int)puVar1 + 0xd);
      *(undefined *)(*piVar3 + iVar2 + 0xe) = *(undefined *)(puVar1 + 7);
      *(undefined *)(*piVar3 + iVar2 + 0xf) = 0xff;
      puVar1 = puVar1 + 8;
      iVar2 = iVar2 + 0x10;
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
    piVar3 = piVar3 + 1;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 7);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800a5080
 * EN v1.0 Address: 0x800A5080
 * EN v1.0 Size: 40540b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800a5080(undefined4 param_1,undefined4 param_2,short *param_3,uint param_4,
                 undefined4 param_5,float *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800aeedc
 * EN v1.0 Address: 0x800AEEDC
 * EN v1.0 Size: 1996b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800aeedc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800af6a8
 * EN v1.0 Address: 0x800AF6A8
 * EN v1.0 Size: 620b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800af6a8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800af914
 * EN v1.0 Address: 0x800AF914
 * EN v1.0 Size: 14816b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800af914(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800b32f4
 * EN v1.0 Address: 0x800B32F4
 * EN v1.0 Size: 308b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800b32f4(void)
{
  double dVar1;
  
  FLOAT_803dc418 = FLOAT_803dc418 + FLOAT_803e03a0 * FLOAT_803dc074;
  if (FLOAT_803e03a8 < FLOAT_803dc418) {
    FLOAT_803dc418 = FLOAT_803e03a4;
  }
  FLOAT_803dc41c = FLOAT_803dc41c + FLOAT_803e03a0 * FLOAT_803dc074;
  if (FLOAT_803e03a8 < FLOAT_803dc41c) {
    FLOAT_803dc41c = FLOAT_803e03b0;
  }
  DAT_803ddfa8 = DAT_803ddfa8 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddfa8) {
    DAT_803ddfa8 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfb4 = (float)dVar1;
  DAT_803ddfac = DAT_803ddfac + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddfac) {
    DAT_803ddfac = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfb0 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800b3428
 * EN v1.0 Address: 0x800B3428
 * EN v1.0 Size: 15400b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800b3428(int param_1,int param_2,undefined2 *param_3,uint param_4,undefined param_5)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800b7050
 * EN v1.0 Address: 0x800B7050
 * EN v1.0 Size: 308b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800b7050(void)
{
  double dVar1;
  
  FLOAT_803dc428 = FLOAT_803dc428 + FLOAT_803e04f0 * FLOAT_803dc074;
  if (FLOAT_803e04f8 < FLOAT_803dc428) {
    FLOAT_803dc428 = FLOAT_803e04f4;
  }
  FLOAT_803dc42c = FLOAT_803dc42c + FLOAT_803e04f0 * FLOAT_803dc074;
  if (FLOAT_803e04f8 < FLOAT_803dc42c) {
    FLOAT_803dc42c = FLOAT_803e0500;
  }
  DAT_803ddfb8 = DAT_803ddfb8 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddfb8) {
    DAT_803ddfb8 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfc4 = (float)dVar1;
  DAT_803ddfbc = DAT_803ddfbc + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddfbc) {
    DAT_803ddfbc = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfc0 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800b7184
 * EN v1.0 Address: 0x800B7184
 * EN v1.0 Size: 7812b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800b7184(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800b9008
 * EN v1.0 Address: 0x800B9008
 * EN v1.0 Size: 13204b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800b9008(undefined4 param_1,undefined4 param_2,ushort *param_3,uint param_4,
                 undefined param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800bc39c
 * EN v1.0 Address: 0x800BC39C
 * EN v1.0 Size: 308b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800bc39c(void)
{
  double dVar1;
  
  FLOAT_803dc438 = FLOAT_803dc438 + FLOAT_803e0708 * FLOAT_803dc074;
  if (FLOAT_803e0710 < FLOAT_803dc438) {
    FLOAT_803dc438 = FLOAT_803e070c;
  }
  FLOAT_803dc43c = FLOAT_803dc43c + FLOAT_803e0708 * FLOAT_803dc074;
  if (FLOAT_803e0710 < FLOAT_803dc43c) {
    FLOAT_803dc43c = FLOAT_803e0718;
  }
  DAT_803ddfd0 = DAT_803ddfd0 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddfd0) {
    DAT_803ddfd0 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfdc = (float)dVar1;
  DAT_803ddfd4 = DAT_803ddfd4 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddfd4) {
    DAT_803ddfd4 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfd8 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800bc4d0
 * EN v1.0 Address: 0x800BC4D0
 * EN v1.0 Size: 4292b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800bc4d0(undefined4 param_1,undefined4 param_2,ushort *param_3,uint param_4,
                 undefined param_5)
{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  undefined8 uVar4;
  ushort local_d8 [4];
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  int local_c0 [3];
  ushort local_b4;
  ushort local_b2;
  ushort local_b0;
  undefined4 local_ac;
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
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  undefined local_62;
  undefined local_60;
  undefined local_5f;
  undefined local_5e;
  undefined8 local_58;
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
  undefined8 local_28;
  
  uVar4 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar4 >> 0x20);
  FLOAT_803dc440 = FLOAT_803dc440 + FLOAT_803e0860;
  if (FLOAT_803e0868 < FLOAT_803dc440) {
    FLOAT_803dc440 = FLOAT_803e0864;
  }
  FLOAT_803dc444 = FLOAT_803dc444 + FLOAT_803e086c;
  if (FLOAT_803e0868 < FLOAT_803dc444) {
    FLOAT_803dc444 = FLOAT_803e0870;
  }
  if (iVar2 != 0) {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (ushort *)0x0) goto LAB_800bd57c;
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      local_ac = *(undefined4 *)(param_3 + 4);
      local_b0 = param_3[2];
      local_b2 = param_3[1];
      local_b4 = *param_3;
      local_5e = param_5;
    }
    local_7c = 0;
    local_78 = 0;
    local_62 = (undefined)uVar4;
    local_90 = FLOAT_803e0874;
    local_8c = FLOAT_803e0874;
    local_88 = FLOAT_803e0874;
    local_9c = FLOAT_803e0874;
    local_98 = FLOAT_803e0874;
    local_94 = FLOAT_803e0874;
    local_84 = FLOAT_803e0874;
    local_c0[2] = 0;
    local_c0[1] = 0xffffffff;
    local_60 = 0xff;
    local_5f = 0;
    local_7e = 0;
    local_68 = 0xffff;
    local_66 = 0xffff;
    local_64 = 0xffff;
    local_74 = 0xffff;
    local_70 = 0xffff;
    local_6c = 0xffff;
    local_80 = 0;
    local_c0[0] = iVar2;
    switch((int)uVar4) {
    case 200:
      uVar3 = FUN_80022264(0xfffffffa,6);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = (float)(local_58 - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0xfffffffa,6);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(0xfffffffa,6);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_3c = FUN_80022264(4,8);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0878 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      local_c0[2] = 0x24;
      local_60 = 0x41;
      local_7c = 0x100111;
      local_7e = 0xc10;
      break;
    default:
      goto LAB_800bd57c;
    case 0xca:
      if (param_3 == (ushort *)0x0) goto LAB_800bd57c;
      uStack_3c = FUN_80022264(0xffffffec,0x14);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e087c * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(10,0x14);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803e087c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0x14,0x1e);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = FLOAT_803e0880 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      local_cc = FLOAT_803e0874;
      local_c8 = FLOAT_803e0874;
      local_c4 = FLOAT_803e0874;
      local_d0 = FLOAT_803e0868;
      local_d8[2] = 0;
      local_d8[1] = 0;
      local_d8[0] = *param_3;
      FUN_80021b8c(local_d8,&local_9c);
      uVar3 = FUN_80022264(4,8);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_84 = FLOAT_803e0884 * (float)(local_58 - DOUBLE_803e08f0);
      local_c0[2] = 0x46;
      local_60 = 100;
      local_5f = 0;
      local_7c = 0x180108;
      local_78 = 0x5000000;
      uVar1 = param_3[2];
      if (uVar1 == 0) {
        local_7e = 0x2b;
      }
      else if (uVar1 == 1) {
        local_7e = 0x1a1;
      }
      else if (uVar1 == 2) {
        local_7e = 0xc10;
        local_78 = 0x5000800;
      }
      else {
        local_7e = 0x2b;
      }
      break;
    case 0xcb:
      if (param_3 == (ushort *)0x0) goto LAB_800bd57c;
      uStack_3c = FUN_80022264(0xffffffec,0x14);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0888 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(10,0x14);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803e088c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0x14,0x1e);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = FLOAT_803e0888 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      local_cc = FLOAT_803e0874;
      local_c8 = FLOAT_803e0874;
      local_c4 = FLOAT_803e0874;
      local_d0 = FLOAT_803e0868;
      local_d8[2] = 0;
      local_d8[1] = 0;
      local_d8[0] = *param_3;
      FUN_80021b8c(local_d8,&local_9c);
      uVar3 = FUN_80022264(4,8);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_84 = FLOAT_803e0890 * (float)(local_58 - DOUBLE_803e08f0);
      local_c0[2] = 0x46;
      local_60 = 0xff;
      local_5f = 0;
      local_7c = 0x1080100;
      local_78 = 0x5000000;
      uVar1 = param_3[2];
      if (uVar1 == 0) {
        local_7e = 0x2b;
      }
      else if (uVar1 == 1) {
        local_7e = 0x1a1;
      }
      else if (uVar1 == 2) {
        local_7e = 0xc10;
        local_78 = 0x5000800;
      }
      else {
        local_7e = 0x2b;
      }
      break;
    case 0xcc:
      uStack_3c = FUN_80022264(0xffffffd8,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(1,2);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803e0894 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0xffffffd8,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      uVar3 = FUN_80022264(0xfffffff6,10);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_9c = FLOAT_803e0898 * (float)(local_58 - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e0898 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_2c = FUN_80022264(4,8);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e089c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      local_c0[2] = 0xfa;
      local_60 = 0xff;
      local_7c = 0x80108;
      local_7e = 0x5c;
      break;
    case 0xcd:
      uStack_2c = FUN_80022264(0,0xfa);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xfffffffb,5);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e08a0 + local_90 / FLOAT_803e08a0 +
                 (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      local_88 = FLOAT_803e08a4 * local_90;
      uStack_3c = FUN_80022264(0x28,0x50);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e08a8 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      local_c0[2] = 0xfa;
      local_60 = 0x7d;
      local_7c = 0x80080118;
      local_7e = 0x5c;
      break;
    case 0xce:
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = FLOAT_803e08ac + (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xfffffff8,8);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e08b0 + (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e08b4 + (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(0,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803e08b8 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0x28,0x50);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_84 = FLOAT_803e086c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      uVar3 = FUN_80022264(0,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_c0[2] = (int)(FLOAT_803e08bc + (float)(local_58 - DOUBLE_803e08f0));
      local_28 = (double)(longlong)local_c0[2];
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xcf:
      uVar3 = FUN_80022264(0,0xfa);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = -(float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80022264(0xfffffffb,5);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e08a0 + local_90 / FLOAT_803e08a0 +
                 (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      local_88 = -local_90;
      uStack_34 = FUN_80022264(0x28,0x50);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803e08a8 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      local_c0[2] = 0xfa;
      local_60 = 0x7d;
      local_7c = 0x80080118;
      local_7e = 0x5c;
      break;
    case 0xd0:
      uVar3 = FUN_80022264(0xfffffff6,10);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = FLOAT_803e08c0 + (float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80022264(0xfffffff8,8);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e08b0 + (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e08c4 + (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80022264(0,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803e08b8 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(0x28,0x50);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e086c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0,0x14);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_c0[2] = (int)(FLOAT_803e08bc +
                         (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0));
      local_58 = (double)(longlong)local_c0[2];
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xd1:
      uVar3 = FUN_80022264(0x46,0x50);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_84 = FLOAT_803e086c * (float)(local_28 - DOUBLE_803e08f0);
      uVar3 = FUN_80022264(0,0xf);
      local_c0[2] = uVar3 + 0x14;
      local_5f = 0;
      local_60 = 0xff;
      local_7c = 0x180210;
      local_7e = 0x159;
      break;
    case 0xd2:
      local_84 = FLOAT_803e087c;
      local_c0[2] = 0x50;
      local_7c = 0x400000;
      local_7e = 0x159;
      break;
    case 0xd3:
      uVar3 = FUN_80022264(0,0xfa);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = -(float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80022264(0xfffffffb,5);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e08c8 + (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xfffffffb,5);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80022264(0xfffffffb,5);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = FLOAT_803e0864 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(0x28,0x50);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e08cc * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      local_c0[2] = 0xa0;
      local_60 = 0x7d;
      local_7c = 0x180108;
      local_7e = 0x5c;
      break;
    case 0xd4:
      uVar3 = FUN_80022264(0xfffffff6,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = (float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80022264(0,0x1c);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80022264(0,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803e08d0 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(0x28,0x50);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e08d4 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0,0x14);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_c0[2] = (int)(FLOAT_803e08d8 +
                         (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0));
      local_58 = (double)(longlong)local_c0[2];
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xd5:
      local_84 = FLOAT_803e08dc;
      local_c0[1] = 0xd6;
      local_c0[2] = 100;
      local_60 = 0xff;
      local_7c = 0x80000;
      local_7e = 0x159;
      break;
    case 0xd6:
      local_84 = FLOAT_803e08dc;
      local_c0[2] = 0x28;
      local_60 = 0xff;
      local_7c = 0x80100;
      local_7e = 0x159;
      break;
    case 0xd7:
      uVar3 = FUN_80022264(0xffffff74,0x8c);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = FLOAT_803e08e0 * (float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80022264(0xffffffce,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e08e0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xffffff74,0x8c);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e08e0 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80022264(0xf,0x23);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803e08e4 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(1,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e08e8 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      local_c0[2] = 0x8c;
      local_60 = 0xff;
      local_7c = 0x80180100;
      local_7e = 0x5f;
    }
    local_7c = local_7c | param_4;
    if (((local_7c & 1) != 0) && ((param_4 & 2) != 0)) {
      local_7c = local_7c ^ 2;
    }
    if ((local_7c & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_c0[0] != 0) {
          local_90 = local_90 + *(float *)(local_c0[0] + 0x18);
          local_8c = local_8c + *(float *)(local_c0[0] + 0x1c);
          local_88 = local_88 + *(float *)(local_c0[0] + 0x20);
        }
      }
      else {
        local_90 = local_90 + local_a8;
        local_8c = local_8c + local_a4;
        local_88 = local_88 + local_a0;
      }
    }
    (**(code **)(*DAT_803dd6f8 + 8))(local_c0,0xffffffff,(int)uVar4,0);
  }
LAB_800bd57c:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800bd594
 * EN v1.0 Address: 0x800BD594
 * EN v1.0 Size: 308b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800bd594(void)
{
  double dVar1;
  
  FLOAT_803dc448 = FLOAT_803dc448 + FLOAT_803e0860 * FLOAT_803dc074;
  if (FLOAT_803e0868 < FLOAT_803dc448) {
    FLOAT_803dc448 = FLOAT_803e0864;
  }
  FLOAT_803dc44c = FLOAT_803dc44c + FLOAT_803e0860 * FLOAT_803dc074;
  if (FLOAT_803e0868 < FLOAT_803dc44c) {
    FLOAT_803dc44c = FLOAT_803e0870;
  }
  DAT_803ddfe0 = DAT_803ddfe0 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddfe0) {
    DAT_803ddfe0 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfec = (float)dVar1;
  DAT_803ddfe4 = DAT_803ddfe4 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddfe4) {
    DAT_803ddfe4 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddfe8 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800bd6c8
 * EN v1.0 Address: 0x800BD6C8
 * EN v1.0 Size: 2756b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800bd6c8(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5,
            undefined2 *param_6)
{
  undefined4 uVar1;
  uint uVar2;
  int local_b8 [3];
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
  uint local_68;
  uint local_64;
  undefined2 local_60;
  undefined2 local_5e;
  undefined2 local_5c;
  undefined local_5a;
  undefined local_58;
  undefined local_57;
  undefined local_56;
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
  undefined4 local_20;
  uint uStack_1c;
  
  FLOAT_803dc450 = FLOAT_803dc450 + FLOAT_803e0900;
  if (FLOAT_803e0908 < FLOAT_803dc450) {
    FLOAT_803dc450 = FLOAT_803e0904;
  }
  FLOAT_803dc454 = FLOAT_803dc454 + FLOAT_803e090c;
  if (FLOAT_803e0908 < FLOAT_803dc454) {
    FLOAT_803dc454 = FLOAT_803e0910;
  }
  if (param_1 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        return 0xffffffff;
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
    local_5a = (undefined)param_2;
    local_88 = FLOAT_803e0914;
    local_84 = FLOAT_803e0914;
    local_80 = FLOAT_803e0914;
    local_94 = FLOAT_803e0914;
    local_90 = FLOAT_803e0914;
    local_8c = FLOAT_803e0914;
    local_7c = FLOAT_803e0914;
    local_b8[2] = 0;
    local_b8[1] = 0xffffffff;
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
    local_b8[0] = param_1;
    switch(param_2) {
    case 0x422:
      if (param_6 == (undefined2 *)0x0) {
        return 0;
      }
      local_7c = FLOAT_803e0918;
      local_b8[2] = FUN_80022264(10,0xd);
      local_58 = (undefined)*param_6;
      local_74 = 0x80100;
      local_76 = 100;
      local_57 = 0x1e;
      break;
    case 0x423:
      uStack_4c = FUN_80022264(0xfffffff6,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = FLOAT_803e0910 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0948);
      uStack_44 = FUN_80022264(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e0910 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0948);
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_80 = FLOAT_803e0910 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0948);
      uStack_34 = FUN_80022264(5,0xb);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_7c = FLOAT_803e0900 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0948);
      local_b8[2] = 0x3c;
      local_74 = 0x80110;
      local_57 = 0x10;
      local_76 = 0xde;
      break;
    case 0x424:
      uStack_34 = FUN_80022264(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e0910 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0948);
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0910 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0948);
      uStack_44 = FUN_80022264(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = FLOAT_803e0910 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0948);
      uStack_4c = FUN_80022264(0xfffffffb,5);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = FLOAT_803e0904 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0948);
      uStack_2c = FUN_80022264(3,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = FLOAT_803e0904 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0948);
      uStack_24 = FUN_80022264(0xfffffffb,5);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803e0904 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948);
      uStack_1c = FUN_80022264(5,0xb);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_7c = FLOAT_803e091c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      local_b8[2] = 0x3c;
      local_74 = 0x1480200;
      local_57 = 0x10;
      local_76 = 0xde;
      break;
    case 0x425:
      uStack_1c = FUN_80022264(8,10);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_90 = FLOAT_803e0920 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      uVar2 = FUN_80022264(0,0x28);
      if (uVar2 == 0) {
        uStack_1c = FUN_80022264(0x15,0x29);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_7c = FLOAT_803e0900 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
        local_b8[2] = 0x1cc;
      }
      else {
        uStack_1c = FUN_80022264(8,0x14);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_7c = FLOAT_803e0900 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
        local_b8[2] = FUN_80022264(0x5a,0x78);
      }
      local_74 = 0x80180200;
      local_70 = 0x1000020;
      local_76 = 0xc0b;
      local_58 = 0x7f;
      local_5c = 0x3fff;
      local_5e = 0x3fff;
      local_60 = 0x3fff;
      local_64 = 0xffff;
      local_68 = 0xffff;
      local_6c = 0xffff;
      break;
    case 0x426:
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = FLOAT_803e0920 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      uStack_24 = FUN_80022264(8,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0920 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0920 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0948);
      local_7c = FLOAT_803e0924;
      local_b8[2] = 0x32;
      local_74 = 0x3000200;
      local_70 = 0x200020;
      local_76 = 0x33;
      local_58 = 0xff;
      local_60 = 0xffff;
      local_5e = 0xffff;
      local_5c = 0xffff;
      local_6c = 0xffff;
      local_68 = FUN_80022264(0,0x8000);
      local_64 = local_68;
      break;
    case 0x427:
      uStack_1c = FUN_80022264(0xffffff9c,100);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948) / FLOAT_803e0928;
      uStack_24 = FUN_80022264(0xffffffce,0x32);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_84 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948) / FLOAT_803e092c;
      uStack_2c = FUN_80022264(0xffffff9c,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0948) / FLOAT_803e0928;
      uStack_34 = FUN_80022264(1,4);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = FLOAT_803e0930 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0948);
      uStack_3c = FUN_80022264(0,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_7c = FLOAT_803e0938 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0948)
                 + FLOAT_803e0934;
      local_b8[2] = 0xa0;
      local_57 = 0;
      local_74 = 0x100200;
      local_76 = 0x33;
      break;
    default:
      return 0xffffffff;
    case 0x42b:
      if (param_6 == (undefined2 *)0x0) {
        return 0;
      }
      local_7c = FLOAT_803e093c;
      local_b8[2] = FUN_80022264(10,0xd);
      local_58 = (undefined)*param_6;
      local_74 = 0x80100;
      local_76 = 0xc7e;
      local_57 = 0x1e;
      break;
    case 0x42c:
      uStack_1c = FUN_80022264(0xfffffff6,10);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = FLOAT_803e0940 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      uStack_24 = FUN_80022264(10,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0918 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948);
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0940 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0948);
      local_7c = FLOAT_803e0944;
      local_b8[2] = 0x6e;
      local_74 = 0x8a100208;
      local_70 = 0x20;
      local_76 = 0x5f;
      local_60 = 0xffff;
      local_5e = 0xffff;
      local_5c = 0xffff;
      local_6c = 0x400;
      local_68 = 60000;
      local_64 = 0x1000;
      break;
    case 0x42d:
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = FLOAT_803e0944 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0948);
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803e0944 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0948);
      local_7c = FLOAT_803e0904;
      local_b8[2] = 600;
      local_58 = 0x7f;
      local_74 = 0xa100100;
      local_70 = 0x20;
      local_76 = 0x62;
      local_60 = 0x400;
      local_5e = 60000;
      local_5c = 0x1000;
      local_6c = 0;
      local_68 = 50000;
      local_64 = 0;
    }
    local_74 = local_74 | param_4;
    if (((local_74 & 1) != 0) && ((local_74 & 2) != 0)) {
      local_74 = local_74 ^ 2;
    }
    if ((local_74 & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_b8[0] != 0) {
          local_88 = local_88 + *(float *)(local_b8[0] + 0x18);
          local_84 = local_84 + *(float *)(local_b8[0] + 0x1c);
          local_80 = local_80 + *(float *)(local_b8[0] + 0x20);
        }
      }
      else {
        local_88 = local_88 + local_a0;
        local_84 = local_84 + local_9c;
        local_80 = local_80 + local_98;
      }
    }
    uVar1 = (**(code **)(*DAT_803dd6f8 + 8))(local_b8,0xffffffff,param_2,0);
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_800be18c
 * EN v1.0 Address: 0x800BE18C
 * EN v1.0 Size: 308b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800be18c(void)
{
  double dVar1;
  
  FLOAT_803dc458 = FLOAT_803dc458 + FLOAT_803e0900 * FLOAT_803dc074;
  if (FLOAT_803e0908 < FLOAT_803dc458) {
    FLOAT_803dc458 = FLOAT_803e0904;
  }
  FLOAT_803dc45c = FLOAT_803dc45c + FLOAT_803e0900 * FLOAT_803dc074;
  if (FLOAT_803e0908 < FLOAT_803dc45c) {
    FLOAT_803dc45c = FLOAT_803e0910;
  }
  DAT_803ddff0 = DAT_803ddff0 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803ddff0) {
    DAT_803ddff0 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddffc = (float)dVar1;
  DAT_803ddff4 = DAT_803ddff4 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803ddff4) {
    DAT_803ddff4 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803ddff8 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800be2c0
 * EN v1.0 Address: 0x800BE2C0
 * EN v1.0 Size: 6160b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800be2c0(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,int param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800bfad0
 * EN v1.0 Address: 0x800BFAD0
 * EN v1.0 Size: 308b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800bfad0(void)
{
  double dVar1;
  
  FLOAT_803dc468 = FLOAT_803dc468 + FLOAT_803e0958 * FLOAT_803dc074;
  if (FLOAT_803e0960 < FLOAT_803dc468) {
    FLOAT_803dc468 = FLOAT_803e095c;
  }
  FLOAT_803dc46c = FLOAT_803dc46c + FLOAT_803e0958 * FLOAT_803dc074;
  if (FLOAT_803e0960 < FLOAT_803dc46c) {
    FLOAT_803dc46c = FLOAT_803e0968;
  }
  DAT_803de000 = DAT_803de000 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de000) {
    DAT_803de000 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de00c = (float)dVar1;
  DAT_803de004 = DAT_803de004 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de004) {
    DAT_803de004 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de008 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800bfc04
 * EN v1.0 Address: 0x800BFC04
 * EN v1.0 Size: 5920b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800bfc04(int param_1,undefined4 param_2,short *param_3,uint param_4,undefined param_5)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800c1324
 * EN v1.0 Address: 0x800C1324
 * EN v1.0 Size: 308b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c1324(void)
{
  double dVar1;
  
  FLOAT_803dc478 = FLOAT_803dc478 + FLOAT_803e0a18 * FLOAT_803dc074;
  if (FLOAT_803e0a20 < FLOAT_803dc478) {
    FLOAT_803dc478 = FLOAT_803e0a1c;
  }
  FLOAT_803dc47c = FLOAT_803dc47c + FLOAT_803e0a18 * FLOAT_803dc074;
  if (FLOAT_803e0a20 < FLOAT_803dc47c) {
    FLOAT_803dc47c = FLOAT_803e0a28;
  }
  DAT_803de010 = DAT_803de010 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de010) {
    DAT_803de010 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de01c = (float)dVar1;
  DAT_803de014 = DAT_803de014 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de014) {
    DAT_803de014 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de018 = (float)dVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800c1458
 * EN v1.0 Address: 0x800C1458
 * EN v1.0 Size: 5660b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800c1458(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800c2a74
 * EN v1.0 Address: 0x800C2A74
 * EN v1.0 Size: 308b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800c2a74(void)
{
  double dVar1;
  
  FLOAT_803dc488 = FLOAT_803dc488 + FLOAT_803e0aa8 * FLOAT_803dc074;
  if (FLOAT_803e0ab0 < FLOAT_803dc488) {
    FLOAT_803dc488 = FLOAT_803e0aac;
  }
  FLOAT_803dc48c = FLOAT_803dc48c + FLOAT_803e0aa8 * FLOAT_803dc074;
  if (FLOAT_803e0ab0 < FLOAT_803dc48c) {
    FLOAT_803dc48c = FLOAT_803e0ab8;
  }
  DAT_803de020 = DAT_803de020 + (uint)DAT_803dc070 * 100;
  if (0x7fff < DAT_803de020) {
    DAT_803de020 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de02c = (float)dVar1;
  DAT_803de024 = DAT_803de024 + (uint)DAT_803dc070 * 0x32;
  if (0x7fff < DAT_803de024) {
    DAT_803de024 = 0;
  }
  dVar1 = (double)FUN_802945e0();
  FLOAT_803de028 = (float)dVar1;
  return;
}
