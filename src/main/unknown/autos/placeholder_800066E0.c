#include "ghidra_import.h"
#include "main/audio/inp_midi.h"
#include "main/audio/snd_core.h"
#include "main/unknown/autos/placeholder_800066E0.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_800033a8();
extern undefined4 FUN_80003494();
extern undefined4 FUN_80017438();
extern int FUN_80017458();
extern void* FUN_80017470();
extern undefined8 FUN_80017484();
extern int FUN_8001748c();
extern undefined4 FUN_80017494();
extern undefined8 FUN_800174b8();
extern undefined4 FUN_80017514();
extern undefined4 FUN_80017640();
extern undefined4 FUN_80017644();
extern uint FUN_80017690();
extern undefined4 FUN_800176a8();
extern int FUN_800176b8();
extern undefined4 FUN_800176c0();
extern undefined4 FUN_800176c8();
extern int FUN_800176d0();
extern undefined4 FUN_80017704();
extern undefined4 FUN_8001774c();
extern undefined4 FUN_80017750();
extern undefined4 FUN_80017754();
extern undefined4 FUN_80017768();
extern undefined4 FUN_80017770();
extern undefined4 FUN_80017774();
extern undefined4 FUN_80017778();
extern undefined4 FUN_800177a4();
extern uint FUN_800177bc();
extern undefined8 FUN_80017810();
extern undefined8 FUN_80017814();
extern undefined4 FUN_80017818();
extern uint FUN_80017830();
extern int FUN_80017a98();
extern uint FUN_80042838();
extern int FUN_80042c18();
extern undefined4 FUN_80044400();
extern undefined8 FUN_80045148();
extern undefined4 FUN_80045c4c();
extern undefined8 FUN_8004600c();
extern undefined4 FUN_800537a0();
extern undefined4 FUN_80053c34();
extern int FUN_80056cdc();
extern int coordsToMapCell();
extern uint FUN_8006f764();
extern undefined4 FUN_8006f79c();
extern undefined4 FUN_800723a0();
extern int FUN_8007f7c0();
extern void Movie_SetVolumeFade();
extern char FUN_8011e7b0();
extern undefined4 FUN_8012c9e8();
extern uint FUN_80132028();
extern undefined4 FUN_80135810();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_80242114();
extern bool FUN_80245dbc();
extern undefined4 FUN_80245e3c();
extern undefined4 FUN_802475e4();
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247aa4();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80247d2c();
extern undefined4 FUN_80247dfc();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double SeekTwiceBeforeRead();
extern int FUN_80249300();
extern int FUN_802493c8();
extern int FUN_80249610();
extern undefined4 FUN_8024983c();
extern int FUN_8024b73c();
extern undefined4 FUN_8024b7f8();
extern undefined4 FUN_8024b8b4();
extern undefined4 FUN_8024bad0();
extern undefined4 FUN_8024bb7c();
extern int FUN_8024bed4();
extern undefined4 FUN_8024e24c();
extern int FUN_8024ebb4();
extern undefined4 PADSetSpec();
extern undefined4 FUN_8024edb8();
extern uint FUN_8024efc8();
extern undefined4 FUN_8024f374();
extern undefined4 FUN_8024ff34();
extern undefined4 FUN_8025001c();
extern undefined4 FUN_802501f4();
extern undefined8 FUN_80250220();
extern undefined4 FUN_8025024c();
extern undefined4 FUN_802503b0();
extern undefined4 FUN_80250838();
extern undefined4 FUN_80251460();
extern undefined4 FUN_802514c8();
extern undefined4 FUN_8025d6ac();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d948();
extern undefined4 FUN_8025da64();
extern uint FUN_8026cb80();
extern undefined4 FUN_80272728();
extern undefined4 FUN_80272730();
extern undefined4 FUN_80272734();
extern undefined4 FUN_80272738();
extern undefined4 synthInitJobTable();
extern undefined4 FUN_80272eac();
extern undefined4 FUN_80272eb4();
extern uint FUN_80272ebc();
extern uint FUN_80272ec4();
extern undefined4 FUN_80272ecc();
extern undefined4 FUN_80272ed0();
extern undefined4 FUN_80272ed4();
extern undefined4 FUN_80272ed8();
extern int FUN_8027ba0c();
extern uint FUN_8027ba1c();
extern undefined4 FUN_80281340();
extern int FUN_8028133c();
extern undefined4 FUN_80284674();
extern undefined4 FUN_80285074();
extern undefined8 FUN_8028680c();
extern undefined8 FUN_80286810();
extern undefined4 FUN_80286820();
extern undefined8 FUN_80286824();
extern undefined8 FUN_8028682c();
extern ulonglong FUN_80286830();
extern undefined8 FUN_80286834();
extern ulonglong FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286858();
extern undefined4 TRKNubMainLoop();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined8 FUN_80286bac();
extern undefined8 FUN_80286bd0();
extern int FUN_8028f988();
extern undefined4 FUN_8028fa2c();
extern undefined4 FUN_8028fde8();
extern undefined4 FUN_80291edc();
extern undefined4 FUN_80291f4c();
extern double FUN_8029241c();
extern undefined4 FUN_802924c4();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern double FUN_80294a10();
extern undefined4 SUB42();
extern undefined4 SUB43();
extern uint countLeadingZeros();
extern longlong ldexpf();

extern undefined4 DAT_802c2040;
extern undefined4 DAT_802c21a4;
extern undefined4 DAT_802c21e8;
extern undefined4 DAT_802c21ec;
extern undefined4 DAT_802c21f0;
extern undefined4 DAT_802c21f4;
extern undefined4 DAT_802c21f8;
extern undefined4 DAT_802c21fc;
extern undefined4 DAT_802c2200;
extern undefined4 DAT_802c2204;
extern undefined DAT_802c3d00;
extern short DAT_802c5e80;
extern undefined4 DAT_802c64f8;
extern undefined4 DAT_802c64fa;
extern undefined4 DAT_802c6538;
extern undefined4 DAT_802c65a0;
extern undefined4 DAT_802c65a4;
extern undefined4 DAT_802c65a8;
extern undefined4 DAT_802c65ac;
extern undefined4 DAT_802c65b0;
extern undefined4 DAT_802c6650;
extern undefined4 DAT_802c6652;
extern undefined4 DAT_802c6658;
extern undefined4 DAT_802c665a;
extern undefined4 DAT_802c7588;
extern undefined4 DAT_802c75d0;
extern undefined4 DAT_802c7618;
extern undefined4 DAT_802c7718;
extern undefined4 DAT_802c7b54;
extern undefined DAT_802c7b80;
extern undefined4 DAT_802c7b88;
extern undefined4 DAT_802c7b8a;
extern undefined4 DAT_802c7b8c;
extern undefined4 DAT_802c7b90;
extern undefined4 DAT_802c7b92;
extern undefined4 DAT_802c7b94;
extern undefined4 DAT_802c7b96;
extern undefined4 DAT_802c7b98;
extern undefined4 DAT_802c7b9a;
extern undefined4 DAT_802c8e0a;
extern uint DAT_802c8e70;
extern ushort DAT_802c8fe0;
extern undefined4 DAT_803364a0;
extern undefined4 DAT_803364a4;
extern undefined4 DAT_803364a8;
extern undefined4 DAT_803364ac;
extern undefined4 DAT_803364b0;
extern undefined4 DAT_803364b4;
extern undefined4 DAT_803364b8;
extern undefined4 DAT_803364bc;
extern undefined4 DAT_803364c0;
extern undefined4 DAT_803364c4;
extern undefined DAT_803365a0;
extern undefined4 DAT_803365c0;
extern undefined4 DAT_803365c4;
extern undefined4 DAT_803365c8;
extern undefined4 DAT_803365cc;
extern undefined4 DAT_803368a0;
extern undefined4 DAT_803369dc;
extern undefined4 DAT_803369e0;
extern undefined4 DAT_803369e4;
extern undefined4 DAT_803369e8;
extern undefined4 DAT_803369ec;
extern undefined4 DAT_803369f0;
extern undefined4 DAT_803369f4;
extern int DAT_80336a20;
extern uint DAT_80336c60;
extern undefined4 DAT_803378a0;
extern undefined4 DAT_803378d0;
extern undefined4 DAT_80337900;
extern undefined4 DAT_80337930;
extern byte DAT_80337970;
extern ushort DAT_803379f0;
extern uint DAT_80337af0;
extern undefined4 DAT_80338c30;
extern undefined4 DAT_80338cb0;
extern undefined4 DAT_80338cf0;
extern undefined4 DAT_80338d70;
extern undefined4 DAT_80338df0;
extern undefined2 DAT_80338e30;
extern undefined4 DAT_80338e32;
extern undefined4 DAT_80338e34;
extern undefined4 DAT_80338e3c;
extern undefined4 DAT_80338e40;
extern undefined4 DAT_80338e44;
extern undefined4 DAT_80338e48;
extern undefined4 DAT_80338e50;
extern undefined4 DAT_80338e54;
extern undefined4 DAT_80338e58;
extern undefined4 DAT_80338e5c;
extern undefined4 DAT_80338e60;
extern undefined4 DAT_80338e64;
extern undefined4 DAT_80338e68;
extern undefined4 DAT_80338e6c;
extern undefined4 DAT_80338e70;
extern undefined4 DAT_80338e8a;
extern undefined4 DAT_80338e8c;
extern undefined4 DAT_80338e8d;
extern undefined4 DAT_80338ebc;
extern undefined4 DAT_80338eed;
extern undefined4 DAT_80338f1c;
extern undefined4 DAT_80338f4d;
extern undefined4 DAT_80338f7c;
extern undefined4 DAT_80338fad;
extern undefined4 DAT_80338fdc;
extern undefined4 DAT_8033900d;
extern undefined4 DAT_8033903c;
extern undefined4 DAT_8033906d;
extern undefined4 DAT_8033909c;
extern undefined4 DAT_803390cd;
extern undefined4 DAT_803390fc;
extern undefined4 DAT_8033912d;
extern undefined4 DAT_8033915c;
extern undefined4 DAT_8033918d;
extern undefined4 DAT_803391bc;
extern undefined4 DAT_803391ed;
extern undefined4 DAT_8033921c;
extern undefined4 DAT_8033924d;
extern undefined4 DAT_8033927c;
extern undefined4 DAT_803392ad;
extern undefined4 DAT_803392b0;
extern undefined4 DAT_803392bc;
extern undefined4 DAT_803392cc;
extern undefined4 DAT_803392dc;
extern undefined4 DAT_803392f0;
extern undefined4 DAT_803392fc;
extern undefined4 DAT_8033930c;
extern undefined4 DAT_8033931c;
extern undefined4 DAT_80339330;
extern undefined4 DAT_80339370;
extern undefined4 DAT_803393b0;
extern undefined4 DAT_803393b4;
extern undefined4 DAT_803393b8;
extern float* DAT_803393bc;
extern undefined4 DAT_803393c0;
extern undefined4 DAT_803393c4;
extern undefined4 DAT_803393c8;
extern float* DAT_803393cc;
extern undefined4 DAT_803393d0;
extern undefined4 DAT_803393d4;
extern undefined4 DAT_803393d8;
extern undefined4 DAT_803393dc;
extern undefined4 DAT_803393e0;
extern undefined4 DAT_803393e4;
extern undefined4 DAT_803393e8;
extern undefined4 DAT_803393ec;
extern undefined4 DAT_803393f0;
extern undefined4 DAT_803393f4;
extern undefined4 DAT_803393f8;
extern undefined4 DAT_803393fc;
extern undefined2 DAT_80339400;
extern undefined4 DAT_80339402;
extern undefined4 DAT_80339404;
extern undefined4 DAT_80339406;
extern undefined4 DAT_80339408;
extern undefined4 DAT_8033940a;
extern undefined4 DAT_8033940c;
extern undefined4 DAT_8033940e;
extern undefined4 DAT_80339410;
extern undefined4 DAT_80339412;
extern undefined4 DAT_80339414;
extern undefined4 DAT_80339416;
extern undefined4 DAT_80339418;
extern undefined4 DAT_8033941c;
extern undefined4 DAT_80339420;
extern undefined4 DAT_80339424;
extern undefined4 DAT_80339428;
extern undefined4 DAT_8033942c;
extern undefined4 DAT_80339430;
extern undefined4 DAT_80339434;
extern undefined4 DAT_80339438;
extern undefined4 DAT_8033943c;
extern undefined4 DAT_80339440;
extern undefined4 DAT_80339444;
extern undefined4 DAT_80339448;
extern undefined4 DAT_8033944c;
extern undefined4 DAT_80339450;
extern undefined4 DAT_80339454;
extern undefined4 DAT_80339458;
extern uint DAT_8033945c;
extern undefined4 DAT_80339460;
extern undefined4 DAT_80339464;
extern undefined4 DAT_80339468;
extern undefined4 DAT_8033946c;
extern undefined4 DAT_80339470;
extern undefined DAT_80339478;
extern undefined2 DAT_80339f7c;
extern undefined4 DAT_8033a500;
extern uint DAT_8033a510;
extern uint DAT_8033a520;
extern uint DAT_8033a530;
extern uint DAT_8033a540;
extern undefined DAT_8033a550;
extern undefined4 DAT_8033a552;
extern undefined4 DAT_8033a553;
extern undefined4 DAT_8033a554;
extern undefined4 DAT_8033a555;
extern undefined4 DAT_8033a556;
extern undefined4 DAT_8033a557;
extern undefined4 DAT_8033a5b0;
extern undefined4 DAT_8033a61c;
extern undefined4 DAT_8033b1a0;
extern undefined4 DAT_8033b1a4;
extern undefined4 DAT_8033b1a8;
extern undefined4 DAT_8033b1ac;
extern undefined4 DAT_8033b1b0;
extern undefined4 DAT_80397420;
extern undefined4 DAT_80397450;
extern undefined4 DAT_80397480;
extern undefined4 DAT_803974b0;
extern undefined4 DAT_803b15b8;
extern undefined4 DAT_803dbe48;
extern undefined4 DAT_803dbea8;
extern undefined4 DAT_803dbeb0;
extern undefined4 DAT_803dbeb1;
extern undefined4 DAT_803dbeb2;
extern undefined4 DAT_803dbeb3;
extern undefined DAT_803dbeb4;
extern undefined4 DAT_803dbed0;
extern undefined4 DAT_803dbed8;
extern undefined4 DAT_803dbedc;
extern undefined4 DAT_803dbee0;
extern undefined4 DAT_803dbee4;
extern undefined4 DAT_803dbee8;
extern undefined4 DAT_803dbeec;
extern undefined4 DAT_803dbef0;
extern undefined4 DAT_803dbef4;
extern undefined4 DAT_803dbefc;
extern undefined4 DAT_803dbf00;
extern undefined4 DAT_803dbf08;
extern undefined4 DAT_803dbfd8;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dd434;
extern undefined4 DAT_803dd438;
extern undefined4 DAT_803dd43c;
extern undefined4 DAT_803dd440;
extern undefined4 DAT_803dd444;
extern undefined4 DAT_803dd448;
extern undefined4 DAT_803dd44c;
extern undefined4 DAT_803dd44d;
extern undefined4 DAT_803dd44e;
extern undefined4 DAT_803dd44f;
extern undefined4 DAT_803dd450;
extern undefined4 DAT_803dd454;
extern undefined4 DAT_803dd458;
extern undefined4 DAT_803dd45c;
extern undefined4 DAT_803dd460;
extern undefined4 DAT_803dd464;
extern undefined4 DAT_803dd468;
extern undefined4 DAT_803dd46c;
extern undefined4 DAT_803dd470;
extern undefined4 DAT_803dd474;
extern undefined4 DAT_803dd478;
extern short* DAT_803dd480;
extern undefined4 DAT_803dd484;
extern undefined4 DAT_803dd488;
extern undefined4 DAT_803dd48c;
extern undefined4 DAT_803dd490;
extern undefined4 DAT_803dd494;
extern undefined4 DAT_803dd498;
extern undefined4 DAT_803dd49c;
extern undefined4 DAT_803dd4a0;
extern undefined4 DAT_803dd4a4;
extern undefined4 DAT_803dd4a8;
extern ushort* DAT_803dd4b0;
extern undefined4 DAT_803dd4b4;
extern undefined4 DAT_803dd4b8;
extern undefined4 DAT_803dd4bc;
extern undefined4 DAT_803dd4c0;
extern undefined4 DAT_803dd4c4;
extern undefined4 DAT_803dd4c8;
extern undefined4 DAT_803dd4c9;
extern ushort* DAT_803dd4d0;
extern undefined4 DAT_803dd4d4;
extern undefined4 DAT_803dd4dc;
extern undefined4 DAT_803dd4e0;
extern undefined4* DAT_803dd4e4;
extern undefined4 DAT_803dd4e8;
extern undefined4 DAT_803dd4ec;
extern undefined4 DAT_803dd4f0;
extern undefined4 DAT_803dd4f4;
extern undefined4 DAT_803dd4f8;
extern undefined4 DAT_803dd500;
extern undefined4 DAT_803dd502;
extern undefined4 DAT_803dd504;
extern undefined4 DAT_803dd506;
extern undefined4 DAT_803dd508;
extern undefined4 DAT_803dd50a;
extern undefined4 DAT_803dd50c;
extern undefined4 DAT_803dd50d;
extern undefined4 DAT_803dd510;
extern undefined4 DAT_803dd538;
extern undefined4 DAT_803dd540;
extern undefined4 DAT_803dd548;
extern undefined4 DAT_803dd54c;
extern undefined DAT_803dd550;
extern undefined4 DAT_803dd558;
extern undefined4 DAT_803dd55c;
extern int* DAT_803dd560;
extern undefined4* DAT_803dd568;
extern undefined4 DAT_803dd56c;
extern undefined4 DAT_803dd570;
extern undefined4 DAT_803dd574;
extern undefined4 DAT_803dd578;
extern undefined4 DAT_803dd579;
extern undefined4 DAT_803dd588;
extern undefined4 DAT_803dd589;
extern undefined4 DAT_803dd590;
extern undefined4 DAT_803dd594;
extern undefined4 DAT_803dd59c;
extern undefined4 DAT_803dd5a4;
extern undefined4 DAT_803dd5ac;
extern undefined DAT_803dd5b4;
extern undefined DAT_803dd5b8;
extern char DAT_803dd5bc;
extern char DAT_803dd5c0;
extern char DAT_803dd5c4;
extern char DAT_803dd5c8;
extern undefined4 DAT_803dd5cc;
extern undefined4 DAT_803dd5d0;
extern undefined4 DAT_803dd5d1;
extern undefined4* DAT_803dd5d4;
extern undefined4 DAT_803dd5d8;
extern undefined4 DAT_803dd5dc;
extern undefined4 DAT_803dd5e0;
extern undefined4 DAT_803dd5ec;
extern undefined4 DAT_803dd604;
extern undefined4 DAT_803dd610;
extern undefined4 DAT_803dd611;
extern undefined4 DAT_803dd612;
extern undefined4 DAT_803dd618;
extern undefined4 DAT_803dd61c;
extern undefined4 DAT_803dd624;
extern undefined4 DAT_803dd625;
extern undefined4 DAT_803dd626;
extern undefined4 DAT_803dd627;
extern undefined4 DAT_803dd628;
extern undefined4 DAT_803dd62a;
extern undefined4 DAT_803dd62c;
extern undefined4 DAT_803dd630;
extern undefined4 DAT_803dd634;
extern undefined4 DAT_803dd638;
extern undefined4 DAT_803dd63c;
extern undefined4 DAT_803dd640;
extern byte* DAT_803dd644;
extern undefined4 DAT_803dd648;
extern undefined* DAT_803dd64c;
extern undefined4 DAT_803dd664;
extern undefined4 DAT_803dd668;
extern undefined4* DAT_803dd66c;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6dc;
extern undefined4* DAT_803dd6e0;
extern undefined4* DAT_803dd6e4;
extern undefined4 DAT_803dd925;
extern undefined4 DAT_803dd93c;
extern undefined4 DAT_803dd970;
extern undefined4 DAT_803dda48;
extern undefined4 DAT_803dda4c;
extern undefined4 DAT_803de288;
extern undefined4 DAT_803de400;
extern undefined4 DAT_803df180;
extern undefined4 DAT_803df184;
extern undefined4 DAT_803df1c8;
extern undefined4 DAT_803df1cc;
extern f64 DOUBLE_803df200;
extern f64 DOUBLE_803df208;
extern f64 DOUBLE_803df240;
extern f64 DOUBLE_803df248;
extern f64 DOUBLE_803df260;
extern f64 DOUBLE_803df298;
extern f64 DOUBLE_803df2b8;
extern f64 DOUBLE_803df308;
extern f64 DOUBLE_803df328;
extern f64 DOUBLE_803df358;
extern f64 DOUBLE_803df370;
extern f64 DOUBLE_803df378;
extern f32 FLOAT_803dbec0;
extern f32 FLOAT_803dbec4;
extern f32 FLOAT_803dbec8;
extern f32 FLOAT_803dbecc;
extern f32 FLOAT_803dc030;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dd4cc;
extern f32 FLOAT_803dd4d8;
extern f32 FLOAT_803dd514;
extern f32 FLOAT_803dd518;
extern f32 FLOAT_803dd51c;
extern f32 FLOAT_803dd520;
extern f32 FLOAT_803dd524;
extern f32 FLOAT_803dd528;
extern f32 FLOAT_803dd52c;
extern f32 FLOAT_803dd530;
extern f32 FLOAT_803dd57c;
extern f32 FLOAT_803dd580;
extern f32 FLOAT_803dd58c;
extern f32 FLOAT_803dd614;
extern f32 FLOAT_803dd620;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803df18c;
extern f32 FLOAT_803df1a0;
extern f32 FLOAT_803df1a4;
extern f32 FLOAT_803df1a8;
extern f32 FLOAT_803df1ac;
extern f32 FLOAT_803df1b0;
extern f32 FLOAT_803df1b4;
extern f32 FLOAT_803df1b8;
extern f32 FLOAT_803df1bc;
extern f32 FLOAT_803df1c0;
extern f32 FLOAT_803df1c4;
extern f32 FLOAT_803df1d0;
extern f32 FLOAT_803df1d4;
extern f32 FLOAT_803df1d8;
extern f32 FLOAT_803df1dc;
extern f32 FLOAT_803df1e0;
extern f32 FLOAT_803df1e4;
extern f32 FLOAT_803df1e8;
extern f32 FLOAT_803df1f0;
extern f32 FLOAT_803df1f4;
extern f32 FLOAT_803df1f8;
extern f32 FLOAT_803df210;
extern f32 FLOAT_803df214;
extern f32 FLOAT_803df218;
extern f32 FLOAT_803df21c;
extern f32 FLOAT_803df220;
extern f32 FLOAT_803df224;
extern f32 FLOAT_803df228;
extern f32 FLOAT_803df234;
extern f32 FLOAT_803df238;
extern f32 FLOAT_803df250;
extern f32 FLOAT_803df254;
extern f32 FLOAT_803df258;
extern f32 FLOAT_803df268;
extern f32 FLOAT_803df270;
extern f32 FLOAT_803df274;
extern f32 FLOAT_803df284;
extern f32 FLOAT_803df288;
extern f32 FLOAT_803df28c;
extern f32 FLOAT_803df290;
extern f32 FLOAT_803df2a0;
extern f32 FLOAT_803df2a4;
extern f32 FLOAT_803df2a8;
extern f32 FLOAT_803df2ac;
extern f32 FLOAT_803df2b0;
extern f32 FLOAT_803df2c0;
extern f32 FLOAT_803df2c4;
extern f32 FLOAT_803df2c8;
extern f32 FLOAT_803df2cc;
extern f32 FLOAT_803df2d0;
extern f32 FLOAT_803df2d8;
extern f32 FLOAT_803df2dc;
extern f32 FLOAT_803df2e0;
extern f32 FLOAT_803df2e4;
extern f32 FLOAT_803df2e8;
extern f32 FLOAT_803df2ec;
extern f32 FLOAT_803df2f0;
extern f32 FLOAT_803df2f4;
extern f32 FLOAT_803df2f8;
extern f32 FLOAT_803df2fc;
extern f32 FLOAT_803df300;
extern f32 FLOAT_803df310;
extern f32 FLOAT_803df314;
extern f32 FLOAT_803df318;
extern f32 FLOAT_803df320;
extern f32 FLOAT_803df330;
extern f32 FLOAT_803df338;
extern f32 FLOAT_803df33c;
extern f32 FLOAT_803df340;
extern f32 FLOAT_803df344;
extern f32 FLOAT_803df348;
extern f32 FLOAT_803df34c;
extern f32 FLOAT_803df350;
extern f32 FLOAT_803df354;
extern f32 FLOAT_803df360;
extern f32 FLOAT_803df368;
extern f32 FLOAT_803df380;
extern f32 FLOAT_803df384;
extern f32 FLOAT_803df388;
extern void* PTR_DAT_802c6a80;
extern undefined cRam803dd551;
extern undefined2 cRam803dd552;
extern undefined cRam803dd553;
extern undefined4 cRam803dd554;
extern undefined cRam803dd555;
extern char s_Childnode_Null_802c6904[];
extern char s_VOXMAPS__route_nodes_list_overfl_802c68e0[];
extern char s__streams__802c6574[];
extern char s_curvesMove__There_must_be_a_mult_802c6880[];
extern char s_curvesMove__There_must_be_at_lea_802c6848[];
extern char s_curvesSetupMoveNetworkCurve__The_802c6790[];
extern char s_curvesSetupMoveNetworkCurve__The_802c67dc[];
extern undefined4 uRam803dd53c;
extern undefined4 uRam803dd544;
extern undefined uRam803dd551;
extern undefined2 uRam803dd552;
extern undefined uRam803dd553;
extern undefined4 uRam803dd554;
extern undefined uRam803dd555;

extern u32 gAudioResetting;
extern u32 gAudioManagedChannelMask;
extern u32 gAudioActiveChannelMask;
extern u8 gAudioInitStarted;
extern s32 lbl_803DD610;
extern u8 gAudioStreamDefaultVolume;
extern u8 gAudioStreamVolumeLeft;
extern u8 gAudioStreamVolumeRight;
extern u8 gAudioStreamDvdState;
extern u8 gAudioStreamPlaying;
extern u32 gAudioStreamMusicFadeFlagA;
extern u32 gAudioStreamMusicFadeFlagB;
extern void (*gAudioStreamPreparedCallback)(void);
extern s32 gAudioStreamCurrentId;
extern s32 gAudioStreamStartWhenPrepared;
extern s32 gAudioStreamPreparingId;
extern s32 gAudioStreamPreparedId;
extern u32 gAudioStreamPlayAddrCallbackResult;
extern u8 gAudioStreamPlayAddrCallbackDone;
extern f32 gAudioStreamEndPos;
extern f32 gAudioStreamPos;
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 lbl_803DE5D0;
extern f32 lbl_803DE5E8;
extern f32 lbl_803DE5F0;
extern f32 lbl_803DE5F4;
extern f32 lbl_803DE5F8;
extern f32 lbl_803DE5FC;
extern f32 lbl_803DE600;
extern f32 lbl_803DE604;
extern f32 lbl_803DE608;
extern f32 lbl_803DE610;
extern f32 lbl_803DE620;
extern f32 lbl_803DE624;
extern s8 gObjTransformMatrixSlot;
extern u8 lbl_80336C40[];
extern u8 lbl_80336C70[];
extern char lbl_802C5DC4[];
extern f32 gObjInverseYawTransformMatrices[][16];
extern f32 gObjYawTransformMatrices[][16];
typedef struct SfxLoopedObjectSoundTable {
    u8 flags[0x80];
    u16 ids[0x80];
    u32 objects[0x80];
} SfxLoopedObjectSoundTable;

typedef struct SfxObjectChannel {
    u32 handle;
    u8 hasPosition;
    u8 tracksObjectPosition;
    u8 paused;
    u8 volume;
    u8 pad08[0x04];
    f32 x;
    f32 y;
    f32 z;
    u32 object;
    u16 channelMask;
    u16 sfxId;
    u8 pad20[0x08];
    u8 globalCtrlDisabled;
    u8 pad29[0x07];
    u64 age;
} SfxObjectChannel;

typedef struct ObjMatrixBuildTransform {
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    u16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} ObjMatrixBuildTransform;

#define SFX_LOOPED_OBJECT_SOUND_COUNT 0x80
#define SFX_OBJECT_CHANNEL_COUNT 56
#define SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE 1
#define SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN 2
#define SFX_LOOPED_OBJECT_STOP_FLAG 0x40

extern SfxLoopedObjectSoundTable gSfxLoopedObjectSoundFlags;
extern u16 gSfxLoopedObjectSoundCount;
extern SfxObjectChannel gSfxObjectChannels[];
extern u8 lbl_803DC838;
extern u32 gSfxObjectChannelMatchCount;
extern u32 gSfxObjectChannelAgeHi;
extern u32 gSfxObjectChannelAgeLo;

extern void AIReset(void);
extern int sndFXKeyOff(u32 handle);
extern int sndFXCheck(u32 handle);
extern int sndFXCtrl(u32 handle, u32 ctrl, u32 value);
extern int sndFXCtrl14(u32 handle, u32 ctrl, u32 value);
extern void Music_Update(void);
extern void Sfx_UpdateObjectSounds(void);
extern void Sfx_StopAllObjectSounds(void);
extern void AudioStream_UpdateFadeTimer(void);
extern void AudioStream_StopCurrent(void);
extern void AudioStream_CancelPrepared(void);
extern void streamFn_8000a380(u32 channel, u32 mode, u32 time);
extern void Movie_SetVolumeFade(u32 volume, u32 fadeMs);
extern void AISetStreamPlayState(u32 state);
extern void AISetStreamVolLeft(u8 volume);
extern void AISetStreamVolRight(u8 volume);
extern s32 DVDCancelStreamAsync(void *streamInfo, void *callback);
extern void OSReport(char *message, ...);
extern s32 getGameState(void);
extern u32 GameBit_Get(u32 bit);
extern void AudioStream_CancelCallback(s32 result);
extern void fn_8000D0B4(void);
extern void Sfx_KeepAliveLoopedObjectSoundLimited(u32 obj, u16 sfxId, u16 limit);
extern s32 Sfx_IsPlayingFromObject(u32 obj, u32 sfxId);
extern void Sfx_StopFromObject(u32 obj, u32 sfxId);
extern void Sfx_PlayFromObject(u32 obj, u32 sfxId);
extern SfxObjectChannel* Sfx_FindObjectChannel(u32 obj, u32 channel, u32 sfxId, s32 mode);
extern void Sfx_PlayFromObjectEx(u32 obj, f32* pos, u32 channel, u32 sfxId);
extern void Sfx_UpdateObjectChannel3D(SfxObjectChannel* objectChannel);
extern f32 lbl_803DE570;
extern f32 lbl_803DE574;
extern f32 lbl_803DE578;
extern void Matrix_TransformVector(f32 *matrix, f32 *in, f32 *out);
extern void Matrix_TransformPoint(f32 *matrix, f64 x, f64 y, f64 z, f32 *outX, f32 *outY, f32 *outZ);
extern void setMatrixFromObjectPos(f32 *matrix, void *obj);
extern void mtxFn_80021ec0(f32 *matrix, f32 scale);
extern void mtxFn_80022404(f32 *dst, f32 *src, f32 *out);
extern void mtxRotateByVec3s(f32 *matrix, void *transform);
extern void mtx44Transpose(f32 *src, f32 *dst);
extern void PSMTXConcat(f32 *a, f32 *b, f32 *out);
extern void PSMTXCopy(f32 *src, f32 *dst);
extern void PSMTXMultVec(f32 *matrix, f32 *in, f32 *out);
extern void PSVECNormalize(f32 *in, f32 *out);
extern void PSVECScale(f32 *in, f32 *out, f32 scale);
extern void PSVECSubtract(f32 *a, f32 *b, f32 *out);
extern void GXLoadPosMtxImm(f32 *matrix, s32 slot);
extern void C_MTXOrtho(f32* matrix, f32 top, f32 bottom, f32 left, f32 right, f32 nearPlane, f32 farPlane);
extern void C_MTXPerspective(f32* matrix, f32 fovY, f32 aspect, f32 nearPlane, f32 farPlane);
extern void C_MTXLightPerspective(f32* matrix, f32 fovY, f32 aspect, f32 scaleS, f32 scaleT, f32 transS, f32 transT);
extern void GXSetProjection(f32* matrix, s32 projectionMode);
extern void GXSetViewport(f32 left, f32 top, f32 width, f32 height, f32 nearPlane, f32 farPlane);
extern void GXSetViewportJitter(f32 left, f32 top, f32 width, f32 height, f32 nearPlane, f32 farPlane, u32 field);
extern u8 pauseMenuGetState(void);
extern void matrixFn_8006ff0c(f32 fovY, f32 aspect, f32 nearPlane, f32 farPlane, f32 scale, f32* matrix, s16* out);
extern void copyMatrix44(f32* src, f32* dst);
extern void *memmove(void *dest, const void *src, u32 count);
extern void mm_free(void *ptr);
extern void *mmAlloc(u32 size, u32 tag, void *name);
extern void getTabEntry(void* dst, int kind, int offset, int size);

/*
 * --INFO--
 *
 * Function: getLActions
 * EN v1.0 Address: 0x800066E0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800066E0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int getLActions(int a, int b, u16 idx)
{
    void* buf = mmAlloc(0x28, -1, NULL);
    getTabEntry(buf, 0xc, idx * 0x28, 0x28);
    mm_free(buf);
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800066e8
 * EN v1.0 Address: 0x800066E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80006744
 * EN v1.1 Size: 984b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800066e8(undefined4 param_1,undefined4 param_2,int *param_3,int param_4,uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800066ec
 * EN v1.0 Address: 0x800066EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80006B1C
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800066ec(undefined4 param_1,undefined4 param_2,int param_3,int param_4,uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800066f0
 * EN v1.0 Address: 0x800066F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80006C6C
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800066f0(int *param_1,float *param_2,int param_3,undefined4 param_4,int param_5,int param_6
                 ,uint param_7,uint param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800066f4
 * EN v1.0 Address: 0x800066F4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80006E34
 * EN v1.1 Size: 1168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800066f4(int param_1,float *param_2,undefined4 param_3,undefined4 param_4,int param_5,
                 undefined4 param_6,uint param_7,uint param_8,undefined4 param_9,float param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800066f8
 * EN v1.0 Address: 0x800066F8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800072C4
 * EN v1.1 Size: 552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_800066f8(void)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006700
 * EN v1.0 Address: 0x80006700
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800074EC
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006700(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5,undefined param_6,undefined param_7,undefined param_8,
                 undefined param_9,float param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006704
 * EN v1.0 Address: 0x80006704
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80007738
 * EN v1.1 Size: 2112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006704(undefined param_1,undefined param_2,undefined param_3,undefined param_4,
                 undefined param_5,undefined param_6,undefined param_7,undefined param_8,
                 undefined param_9,undefined4 param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006708
 * EN v1.0 Address: 0x80006708
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80007F78
 * EN v1.1 Size: 2212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006708(undefined4 param_1,undefined4 param_2,short *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000670c
 * EN v1.0 Address: 0x8000670C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000881C
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000670c(uint *param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006710
 * EN v1.0 Address: 0x80006710
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800089AC
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006710(uint *param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006714
 * EN v1.0 Address: 0x80006714
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80008B4C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80006714(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8000671c
 * EN v1.0 Address: 0x8000671C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80008B6C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8000671c(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006724
 * EN v1.0 Address: 0x80006724
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80008B74
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006724(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006728
 * EN v1.0 Address: 0x80006728
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80008CBC
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006728(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

typedef struct EnvfxActEntry {
    u8 pad0[0x2a];
    u16 field_2a;
    u8 pad1[0x30];
    u8 kind;
    u8 pad2[3];
} EnvfxActEntry;

extern int *gNewCloudsInterface;
extern int *gSky2Interface;
extern int *gSHthorntailAnimationInterface;
extern int *gCloudActionInterface;

int getEnvfxActImmediately(int a, int b, u16 idx, int d)
{
    u8 raw[0x80];
    EnvfxActEntry *e = (EnvfxActEntry *)(((u32)raw + 0x1f) & ~0x1f);

    getTabEntry(e, 0x57, idx * 0x60, 0x60);
    if (e != NULL) {
        if (e->kind <= 2 || e->kind == 4) {
            (*(void (*)(int, int, EnvfxActEntry *, int))(*(int *)(*gNewCloudsInterface + 0x4)))(a, b, e, d);
        } else if (e->kind == 3) {
            e->field_2a = 0;
            (*(void (*)(int, int, EnvfxActEntry *, int, u16))(*(int *)(*gSky2Interface + 0x4)))(a, b, e, d, idx);
        } else if (e->kind == 5) {
            e->field_2a = 0;
            (*(void (*)(int, int, EnvfxActEntry *, int))(*(int *)(*gSHthorntailAnimationInterface + 0x4)))(a, b, e, d);
        } else if (e->kind == 6) {
            (*(void (*)(int, int, EnvfxActEntry *, int, u16))(*(int *)(*gCloudActionInterface + 0x4)))(a, b, e, d, idx);
        }
    }
    return 0;
}

int getEnvfxAct(int a, int b, u16 idx, int d)
{
    u8 raw[0x80];
    EnvfxActEntry *e = (EnvfxActEntry *)(((u32)raw + 0x1f) & ~0x1f);

    getTabEntry(e, 0x57, idx * 0x60, 0x60);
    if (e != NULL) {
        if (e->kind <= 2 || e->kind == 4) {
            (*(void (*)(int, int, EnvfxActEntry *, int))(*(int *)(*gNewCloudsInterface + 0x4)))(a, b, e, d);
        } else if (e->kind == 3) {
            (*(void (*)(int, int, EnvfxActEntry *, int, u16))(*(int *)(*gSky2Interface + 0x4)))(a, b, e, d, idx);
        } else if (e->kind == 5) {
            (*(void (*)(int, int, EnvfxActEntry *, int))(*(int *)(*gSHthorntailAnimationInterface + 0x4)))(a, b, e, d);
        } else if (e->kind == 6) {
            (*(void (*)(int, int, EnvfxActEntry *, int, u16))(*(int *)(*gCloudActionInterface + 0x4)))(a, b, e, d, idx);
        }
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8000672c
 * EN v1.0 Address: 0x8000672C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80008DF4
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000672c(undefined4 param_1,undefined4 param_2,uint *param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006730
 * EN v1.0 Address: 0x80006730
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80008EDC
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006730(undefined *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006734
 * EN v1.0 Address: 0x80006734
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80008F38
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006734(uint param_1,undefined4 param_2,uint param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006738
 * EN v1.0 Address: 0x80006738
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80009014
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006738(int param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000673c
 * EN v1.0 Address: 0x8000673C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800090C4
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000673c(int param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006740
 * EN v1.0 Address: 0x80006740
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80009174
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006740(int param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: modelRenderFn_80006744
 * EN v1.0 Address: 0x80006744
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80009224
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void modelRenderFn_80006744(int param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006748
 * EN v1.0 Address: 0x80006748
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800092D4
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006748(int param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000674c
 * EN v1.0 Address: 0x8000674C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80009384
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000674c(int param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006750
 * EN v1.0 Address: 0x80006750
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80009434
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006750(int param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006754
 * EN v1.0 Address: 0x80006754
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800094E4
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006754(int param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006758
 * EN v1.0 Address: 0x80006758
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80009594
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006758(int param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000675c
 * EN v1.0 Address: 0x8000675C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800096AC
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000675c(int param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006760
 * EN v1.0 Address: 0x80006760
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000975C
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006760(int param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006764
 * EN v1.0 Address: 0x80006764
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000980C
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006764(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006768
 * EN v1.0 Address: 0x80006768
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80009920
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006768(byte param_1,char param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000676c
 * EN v1.0 Address: 0x8000676C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80009A28
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000676c(uint param_1,uint param_2,int param_3,int param_4,int param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006770
 * EN v1.0 Address: 0x80006770
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80009A94
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void audioStopByMask(int mask)
{
    if ((mask & 4) != 0) {
        Sfx_StopAllObjectSounds();
    }
    if ((mask & 1) != 0) {
        streamFn_8000a380(1, 1, 0);
    }
    if ((mask & 2) != 0) {
        streamFn_8000a380(2, 1, 0);
    }
    if ((mask & 8) != 0) {
        AudioStream_StopCurrent();
    }
}

/*
 * --INFO--
 *
 * Function: FUN_80006774
 * EN v1.0 Address: 0x80006774
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80009B14
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void audioReset(void)
{
    if (gAudioInitStarted != 0) {
        sndQuit();
    }
    AIReset();
}

/*
 * --INFO--
 *
 * Function: FUN_80006778
 * EN v1.0 Address: 0x80006778
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80009B44
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 audioIsResetting(void)
{
    return gAudioResetting;
}

/*
 * --INFO--
 *
 * Function: FUN_80006780
 * EN v1.0 Address: 0x80006780
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80009B4C
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void audioStopAll(void)
{
    gAudioResetting = 1;
    Sfx_StopAllObjectSounds();
    streamFn_8000a380(1, 1, 0);
    streamFn_8000a380(2, 1, 0);
    AudioStream_StopCurrent();
    gAudioManagedChannelMask &= ~0xfU;
    gAudioResetting = 1;
    if ((lbl_803DD610 == 2) || (lbl_803DD610 == 3)) {
        Movie_SetVolumeFade(0, 500);
    }
    AudioStream_CancelPrepared();
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80006784
 * EN v1.0 Address: 0x80006784
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80009BD0
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void audioUpdate(void)
{
    Music_Update();
    Sfx_UpdateObjectSounds();
    AudioStream_UpdateFadeTimer();
}

/*
 * --INFO--
 *
 * Function: FUN_80006788
 * EN v1.0 Address: 0x80006788
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80009BF8
 * EN v1.1 Size: 1424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80006788(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006790
 * EN v1.0 Address: 0x80006790
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000A188
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma peephole off
u32 audioFlagFn_8000a188(u32 mask)
{
    s32 managed = gAudioManagedChannelMask & mask;
    if (managed == 0) {
        return 1;
    }
    return (gAudioActiveChannelMask & mask) != 0;
}
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_80006798
 * EN v1.0 Address: 0x80006798
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000A1B8
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void audioFree(void *ptr)
{
    mm_free(ptr);
}

/*
 * --INFO--
 *
 * Function: FUN_8000679c
 * EN v1.0 Address: 0x8000679C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000A1D8
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void *_audioAlloc(u32 size)
{
    return mmAlloc(size, 0xb, NULL);
}

/*
 * --INFO--
 *
 * Function: FUN_800067a4
 * EN v1.0 Address: 0x800067A4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000A220
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800067a4(int *param_1,undefined4 param_2,int *param_3,int param_4,int param_5)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800067ac
 * EN v1.0 Address: 0x800067AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000A284
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800067ac(int param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800067b0
 * EN v1.0 Address: 0x800067B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000A304
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800067b0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800067b4
 * EN v1.0 Address: 0x800067B4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000A398
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800067b4(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800067bc
 * EN v1.0 Address: 0x800067BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000A3A0
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800067bc(undefined4 param_1,undefined4 param_2,uint param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800067c0
 * EN v1.0 Address: 0x800067C0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000A538
 * EN v1.1 Size: 784b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int * FUN_800067c0(int *param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800067c8
 * EN v1.0 Address: 0x800067C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000A848
 * EN v1.1 Size: 1632b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800067c8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800067cc
 * EN v1.0 Address: 0x800067CC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000AEA8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800067cc(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800067d4
 * EN v1.0 Address: 0x800067D4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000AEB0
 * EN v1.1 Size: 576b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800067d4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800067dc
 * EN v1.0 Address: 0x800067DC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000B0F0
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800067dc(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800067e4
 * EN v1.0 Address: 0x800067E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000B390
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800067e4(int param_1,undefined4 *param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800067e8
 * EN v1.0 Address: 0x800067E8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000B4F0
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800067e8(uint param_1,ushort param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800067f0
 * EN v1.0 Address: 0x800067F0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000B598
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_800067f0(int param_1,ushort param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800067f8
 * EN v1.0 Address: 0x800067F8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000B5F0
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_800067f8(int param_1,short param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006800
 * EN v1.0 Address: 0x80006800
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000B644
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006800(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006804
 * EN v1.0 Address: 0x80006804
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000B6B4
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006804(char param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006808
 * EN v1.0 Address: 0x80006808
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000B734
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006808(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000680c
 * EN v1.0 Address: 0x8000680C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000B7DC
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000680c(int param_1,ushort param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006810
 * EN v1.0 Address: 0x80006810
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000B844
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006810(int param_1,short param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006814
 * EN v1.0 Address: 0x80006814
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000B8A8
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006814(double param_1,int param_2,ushort param_3,byte param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006818
 * EN v1.0 Address: 0x80006818
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000B9BC
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006818(double param_1,int param_2,short param_3,byte param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000681c
 * EN v1.0 Address: 0x8000681C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000BAD0
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000681c(uint param_1,uint param_2,ushort param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006820
 * EN v1.0 Address: 0x80006820
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000BB00
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006820(double param_1,double param_2,double param_3,uint param_4,ushort param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006824
 * EN v1.0 Address: 0x80006824
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000BB38
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006824(uint param_1,ushort param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006828
 * EN v1.0 Address: 0x80006828
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000BB64
 * EN v1.1 Size: 624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006828(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000682c
 * EN v1.0 Address: 0x8000682C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000BDD4
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000682c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006830
 * EN v1.0 Address: 0x80006830
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000BE80
 * EN v1.1 Size: 604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006830(uint param_1,float *param_2,uint param_3,ushort param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006834
 * EN v1.0 Address: 0x80006834
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000C0DC
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80006834(undefined4 *param_1,ushort *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8000683c
 * EN v1.0 Address: 0x8000683C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000C1C8
 * EN v1.1 Size: 600b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000683c(undefined4 param_1,undefined4 param_2,char *param_3,float *param_4,float *param_5,
                 float *param_6,uint *param_7,uint *param_8,uint *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006840
 * EN v1.0 Address: 0x80006840
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000C420
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
ushort * FUN_80006840(uint param_1)
{
    return 0;
}

typedef struct SfxTrigger {
    u16 id;
    u8 pad[0x1e];
} SfxTrigger;

typedef struct SfxTriggerCacheEntry {
    u16 key;
    u16 index;
} SfxTriggerCacheEntry;

extern void *gSfxTriggersData;
extern int gSfxTriggersCount;
extern SfxTriggerCacheEntry lbl_802C5D78[];

SfxTrigger *Sfx_FindTrigger(u16 id)
{
    SfxTrigger *low = (SfxTrigger *)gSfxTriggersData;
    SfxTrigger *high = (SfxTrigger *)gSfxTriggersData + gSfxTriggersCount;
    SfxTriggerCacheEntry *c = &lbl_802C5D78[id & 0xf];

    if (c->key == id) {
        return (SfxTrigger *)gSfxTriggersData + c->index;
    }
    while (low < high) {
        SfxTrigger *mid = low + (high - low) / 2;
        if (mid->id > id) {
            high = mid;
        } else if (mid->id < id) {
            low = mid + 1;
        } else {
            c->key = id;
            c->index = mid - (SfxTrigger *)gSfxTriggersData;
            return mid;
        }
    }
    return NULL;
}

/*
 * --INFO--
 *
 * Function: FUN_80006848
 * EN v1.0 Address: 0x80006848
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000C4D8
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006848(undefined4 param_1,undefined4 param_2,uint param_3,int param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000684c
 * EN v1.0 Address: 0x8000684C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000C6E0
 * EN v1.1 Size: 748b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000684c(uint *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006850
 * EN v1.0 Address: 0x80006850
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000C9CC
 * EN v1.1 Size: 532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006850(void)
{
}

extern void *Obj_GetPlayerObject(void);
extern int getCurSeqNo(void);
extern void *Camera_GetCurrentViewSlot(void);
extern void PSVECAdd(f32 *a, f32 *b, f32 *out);
extern f32 PSVECMag(f32 *v);
extern f32 lbl_803DE5B4;
extern f32 lbl_803DE5B8;
extern double lbl_803DE5C0;
extern double lbl_803DE5C8;

f32 Sfx_GetListenerRelativeDistance(f32 *soundPos, f32 *outDelta)
{
    f32 v[3];
    f32 t;
    f32 *listener;
    void *player = Obj_GetPlayerObject();
    void *slot = Camera_GetCurrentViewSlot();
    int seqNo = getCurSeqNo();

    if (player != NULL && seqNo == 0) {
        listener = (f32 *)((u8 *)player + 0x18);
    } else if (slot == NULL) {
        return lbl_803DE570;
    } else if (player == NULL) {
        listener = (f32 *)((u8 *)slot + 0x44);
    } else {
        PSVECSubtract((f32 *)((u8 *)slot + 0x44), (f32 *)((u8 *)player + 0x18), v);
        t = (PSVECMag(v) - lbl_803DE5B4) / lbl_803DE5B8;
        t = (t > lbl_803DE5C8 ? t : lbl_803DE5C8) > lbl_803DE5C0 ? lbl_803DE5C0
                                                                  : (t > lbl_803DE5C8 ? t : lbl_803DE5C8);
        PSVECScale(v, v, t);
        PSVECAdd((f32 *)((u8 *)player + 0x18), v, v);
        listener = v;
    }
    PSVECSubtract(listener, soundPos, outDelta);
    return PSVECMag(outDelta);
}

/*
 * --INFO--
 *
 * Function: FUN_80006854
 * EN v1.0 Address: 0x80006854
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000CBE0
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80006854(float *param_1,float *param_2)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_8000685c
 * EN v1.0 Address: 0x8000685C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000CD0C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int * FUN_8000685c(int param_1,ushort param_2,short param_3,int param_4)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006864
 * EN v1.0 Address: 0x80006864
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000CE74
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void AudioStream_StopAll(void)
{
    if (gAudioStreamDvdState != 0) {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        if (DVDCancelStreamAsync(lbl_80336C70, fn_8000D0B4) == 0) {
            OSReport(lbl_802C5DC4);
        }
        gAudioStreamPreparedId = 0;
        gAudioStreamPreparingId = 0;
        gAudioStreamCurrentId = 0;
        gAudioStreamStartWhenPrepared = 0;
        gAudioActiveChannelMask = 0;
        gAudioStreamMusicFadeFlagB = 0;
        gAudioStreamMusicFadeFlagA = 0;
    }

    if (gAudioStreamCurrentId != 0) {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        if (DVDCancelStreamAsync(lbl_80336C40, AudioStream_CancelCallback) == 0) {
            OSReport(lbl_802C5DC4);
            gAudioStreamPlaying = 0;
        }
    } else {
        gAudioStreamPlaying = 0;
    }

    gAudioStreamPreparedId = 0;
    gAudioStreamPreparingId = 0;
    gAudioStreamCurrentId = 0;
    gAudioStreamStartWhenPrepared = 0;
    gAudioActiveChannelMask = 0;
    gAudioStreamMusicFadeFlagB = 0;
    gAudioStreamMusicFadeFlagA = 0;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80006868
 * EN v1.0 Address: 0x80006868
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000CF74
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006868(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000686c
 * EN v1.0 Address: 0x8000686C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000CF78
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 AudioStream_GetMusicFadeFlagA(void)
{
    if (gAudioStreamPos > gAudioStreamEndPos) {
        return 0;
    }
    return gAudioStreamMusicFadeFlagA;
}

/*
 * --INFO--
 *
 * Function: FUN_80006874
 * EN v1.0 Address: 0x80006874
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000CF98
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 AudioStream_GetMusicFadeFlagB(void)
{
    if (gAudioStreamPos > gAudioStreamEndPos) {
        return 0;
    }
    return gAudioStreamMusicFadeFlagB;
}

/*
 * --INFO--
 *
 * Function: FUN_8000687c
 * EN v1.0 Address: 0x8000687C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000CFB8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 AudioStream_GetCurrentId(void)
{
    return gAudioStreamCurrentId;
}

/*
 * --INFO--
 *
 * Function: FUN_80006884
 * EN v1.0 Address: 0x80006884
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000CFC0
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u8 AudioStream_IsPreparing(void)
{
    return gAudioStreamDvdState;
}

/*
 * --INFO--
 *
 * Function: FUN_8000688c
 * EN v1.0 Address: 0x8000688C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000CFC8
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
#pragma scheduling off
void AudioStream_SetVolume(u8 volume)
{
    gAudioStreamVolumeLeft = volume;
    gAudioStreamVolumeRight = volume;
    AISetStreamVolLeft(volume);
    AISetStreamVolRight(volume);
}
#pragma scheduling reset
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: FUN_80006890
 * EN v1.0 Address: 0x80006890
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000D004
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void AudioStream_CancelCallback(s32 result)
{
    if (result == 0) {
        AISetStreamPlayState(0);
    }
    gAudioActiveChannelMask = 0;
    gAudioStreamPlaying = 0;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_80006894
 * EN v1.0 Address: 0x80006894
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000D03C
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void AudioStream_StopCurrent(void)
{
    if (gAudioStreamCurrentId != 0) {
        AISetStreamVolLeft(0);
        AISetStreamVolRight(0);
        if (DVDCancelStreamAsync(lbl_80336C40, AudioStream_CancelCallback) == 0) {
            OSReport(lbl_802C5DC4);
            gAudioStreamPlaying = 0;
        }
        gAudioStreamPreparedId = 0;
        gAudioStreamPreparingId = 0;
        gAudioStreamCurrentId = 0;
        gAudioStreamStartWhenPrepared = 0;
        gAudioActiveChannelMask = 0;
        gAudioStreamMusicFadeFlagB = 0;
        gAudioStreamMusicFadeFlagA = 0;
    } else {
        gAudioStreamPlaying = 0;
    }
}
#pragma scheduling reset

void fn_8000D0B4(void)
{
    gAudioStreamDvdState = 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006898
 * EN v1.0 Address: 0x80006898
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000D0E0
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void AudioStream_CancelPrepared(void)
{
    AISetStreamVolLeft(0);
    AISetStreamVolRight(0);
    if (DVDCancelStreamAsync(lbl_80336C70, fn_8000D0B4) == 0) {
        OSReport(lbl_802C5DC4);
    }
    gAudioStreamPreparedId = 0;
    gAudioStreamPreparingId = 0;
    gAudioStreamCurrentId = 0;
    gAudioStreamStartWhenPrepared = 0;
    gAudioActiveChannelMask = 0;
    gAudioStreamMusicFadeFlagB = 0;
    gAudioStreamMusicFadeFlagA = 0;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8000689c
 * EN v1.0 Address: 0x8000689C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000D158
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void AudioStream_StartPrepared(void)
{
    if (gAudioStreamPreparingId != 0) {
        gAudioStreamStartWhenPrepared = 1;
    } else if (gAudioStreamPreparedId != 0) {
        if (getGameState() == 1) {
            if (getGameState() == 1) {
                AISetStreamVolLeft(gAudioStreamVolumeLeft);
                AISetStreamVolRight(gAudioStreamVolumeRight);
                AISetStreamPlayState(1);
                gAudioStreamPlaying = 1;
                gAudioStreamPos = lbl_803DE5D0;
                gAudioStreamCurrentId = gAudioStreamPreparedId;
                gAudioStreamPreparedId = 0;
                gAudioStreamPreparingId = 0;
                gAudioStreamStartWhenPrepared = 0;
            } else {
                gAudioStreamPlaying = 0;
            }
        }
    } else if (gAudioStreamCurrentId == 0) {
        gAudioStreamMusicFadeFlagB = 0;
        gAudioStreamMusicFadeFlagA = 0;
        gAudioStreamStartWhenPrepared = 0;
        gAudioActiveChannelMask = 0;
    }
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800068a0
 * EN v1.0 Address: 0x800068A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000D220
 * EN v1.1 Size: 860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800068a0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800068a4
 * EN v1.0 Address: 0x800068A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000D57C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void AudioStream_UpdateFadeTimer(void)
{
    if (gAudioStreamCurrentId != 0) {
        f32 position = gAudioStreamPos;
        gAudioStreamPos = position + (timeDelta / lbl_803DE5E8);
    } else {
        gAudioStreamPos = lbl_803DE5D0;
    }
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800068a8
 * EN v1.0 Address: 0x800068A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000D5AC
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
void AudioStream_SetDefaultVolume(u8 volume)
{
    gAudioStreamDefaultVolume = volume;
}
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: FUN_800068ac
 * EN v1.0 Address: 0x800068AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000D5B4
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void AudioStream_Init(void)
{
    AISetStreamVolLeft(0);
    AISetStreamVolRight(0);
    gAudioStreamCurrentId = 0;
    gAudioStreamMusicFadeFlagA = 0;
    gAudioStreamMusicFadeFlagB = 0;
    gAudioStreamDefaultVolume = 0x7f;
    gAudioStreamStartWhenPrepared = 0;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800068b0
 * EN v1.0 Address: 0x800068B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000D5FC
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void AudioStream_PrepareCallback(void)
{
    if (getGameState() != 1) {
        gAudioStreamDvdState = 0;
        return;
    }
    gAudioStreamPreparedId = gAudioStreamPreparingId;
    gAudioStreamPreparingId = 0;
    if (gAudioStreamStartWhenPrepared != 0) {
        if (getGameState() == 1) {
            AISetStreamVolLeft(gAudioStreamVolumeLeft);
            AISetStreamVolRight(gAudioStreamVolumeRight);
            AISetStreamPlayState(1);
            gAudioStreamPlaying = 1;
            gAudioStreamPos = lbl_803DE5D0;
            gAudioStreamCurrentId = gAudioStreamPreparedId;
            gAudioStreamPreparedId = 0;
            gAudioStreamPreparingId = 0;
            gAudioStreamStartWhenPrepared = 0;
        } else {
            gAudioStreamPlaying = 0;
        }
    } else if (gAudioStreamPreparedCallback != NULL) {
        gAudioStreamPreparedCallback();
    }
    gAudioStreamDvdState = 0;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800068b4
 * EN v1.0 Address: 0x800068B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000D6C4
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void AudioStream_PlayAddrCallback(u32 result)
{
    if ((result & 0xff) == 0) {
        gAudioStreamPlaying = 0;
        if (gAudioStreamCurrentId != 0) {
            AISetStreamVolLeft(0);
            AISetStreamVolRight(0);
            gAudioStreamCurrentId = 0;
            gAudioActiveChannelMask = 0;
            AISetStreamPlayState(0);
            gAudioStreamMusicFadeFlagB = 0;
            gAudioStreamMusicFadeFlagA = 0;
        }
    }
    gAudioStreamPlayAddrCallbackResult = result;
    gAudioStreamPlayAddrCallbackDone = 1;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800068b8
 * EN v1.0 Address: 0x800068B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000D748
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Sfx_ClearLoopedObjectSounds(void)
{
    gSfxLoopedObjectSoundCount = 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800068bc
 * EN v1.0 Address: 0x800068BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000D754
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Sfx_UpdateLoopedObjectSounds(void)
{
    SfxLoopedObjectSoundTable *table = &gSfxLoopedObjectSoundFlags;
    u8 *flags = table->flags;
    u16 *ids = table->ids;
    u32 *objects = table->objects;
    s16 i;
    u32 obj;
    u16 sfxId;
    u16 oldCount;
    u16 index;
    u32 removeSound;

    for (i = (s16)(gSfxLoopedObjectSoundCount - 1); i >= 0; i--) {
        removeSound = 0;
        if (((flags[i] & SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE) != 0) &&
            ((flags[i] & SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN) == 0)) {
            removeSound = 1;
        }
        obj = objects[i];
        if (((obj != 0) && ((*(u16 *)(obj + 0xB0) & SFX_LOOPED_OBJECT_STOP_FLAG) != 0)) || removeSound) {
            Sfx_StopFromObject(obj, ids[i]);
            oldCount = gSfxLoopedObjectSoundCount;
            gSfxLoopedObjectSoundCount = (u16)(oldCount - 1);
            index = (u16)i;
            memmove(&objects[index], &objects[index + 1],
                    (((oldCount - 1) - index) * sizeof(u32)) & 0xFFFC);
            memmove(&ids[index], &ids[index + 1],
                    ((gSfxLoopedObjectSoundCount - index) * sizeof(u16)) & 0xFFFE);
            memmove(&flags[index], &flags[index + 1],
                    (gSfxLoopedObjectSoundCount - index) & 0xFFFF);
        } else {
            flags[i] &= ~SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
        }
    }

    for (i = 0; i < gSfxLoopedObjectSoundCount; i++) {
        obj = objects[i];
        sfxId = ids[i];
        if (Sfx_IsPlayingFromObject(obj, sfxId) == 0) {
            Sfx_PlayFromObject(obj, sfxId);
        }
    }
}

/*
 * --INFO--
 *
 * Function: FUN_800068c0
 * EN v1.0 Address: 0x800068C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000D904
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Sfx_KeepAliveLoopedObjectSoundLimited(u32 obj, u16 sfxId, u16 limit)
{
    SfxLoopedObjectSoundTable *table = &gSfxLoopedObjectSoundFlags;
    u8 *flags = table->flags;
    u16 *ids = table->ids;
    u32 *objects = table->objects;
    s16 i;
    u16 count = gSfxLoopedObjectSoundCount;
    u16 sameSfxCount = 0;
    u32 found;

    for (i = 0; i < count; i++) {
        if (sfxId == ids[i]) {
            if (limit != 0) {
                sameSfxCount++;
            }
            if (objects[i] == obj) {
                flags[i] |= SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE | SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
                return;
            }
        }
    }

    if (sameSfxCount <= limit) {
        found = 0;
        for (i = 0; i < count; i++) {
            if ((objects[i] == obj) && (sfxId == ids[i])) {
                found = 1;
                break;
            }
        }

        if ((found == 0) && (count != SFX_LOOPED_OBJECT_SOUND_COUNT)) {
            objects[count] = obj;
            ids[count] = sfxId;
            flags[count] = 0;
            gSfxLoopedObjectSoundCount++;
            Sfx_PlayFromObject(obj, sfxId);
        }
    }

    if (count != gSfxLoopedObjectSoundCount) {
        flags[count] |= SFX_LOOPED_OBJECT_SOUND_FLAG_ALIVE | SFX_LOOPED_OBJECT_SOUND_FLAG_SEEN;
    }
}

/*
 * --INFO--
 *
 * Function: FUN_800068c4
 * EN v1.0 Address: 0x800068C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000DA78
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void Sfx_KeepAliveLoopedObjectSound(u32 obj, u16 sfxId)
{
    Sfx_KeepAliveLoopedObjectSoundLimited(obj, sfxId, 0);
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800068c8
 * EN v1.0 Address: 0x800068C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000DA9C
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Sfx_RemoveLoopedObjectSoundForObject(u32 obj)
{
    SfxLoopedObjectSoundTable *table = &gSfxLoopedObjectSoundFlags;
    s16 i;
    u16 oldCount;
    u16 index;

    for (i = (s16)(gSfxLoopedObjectSoundCount - 1); i >= 0; i--) {
        if (table->objects[i] == obj) {
            Sfx_StopFromObject(obj, table->ids[i]);
            oldCount = gSfxLoopedObjectSoundCount;
            gSfxLoopedObjectSoundCount = (u16)(oldCount - 1);
            index = (u16)i;
            memmove(&table->objects[index], &table->objects[index + 1],
                    (((oldCount - 1) - index) * sizeof(u32)) & 0xFFFC);
            memmove(&table->ids[index], &table->ids[index + 1],
                    ((gSfxLoopedObjectSoundCount - index) * sizeof(u16)) & 0xFFFE);
            memmove(&table->flags[index], &table->flags[index + 1],
                    (gSfxLoopedObjectSoundCount - index) & 0xFFFF);
            return;
        }
    }
}

/*
 * --INFO--
 *
 * Function: FUN_800068cc
 * EN v1.0 Address: 0x800068CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000DBB0
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Sfx_RemoveLoopedObjectSound(u32 obj, u32 sfxId)
{
    SfxLoopedObjectSoundTable *table = &gSfxLoopedObjectSoundFlags;
    s16 i;
    u16 oldCount;
    u16 index;

    for (i = (s16)(gSfxLoopedObjectSoundCount - 1); i >= 0; i--) {
        if ((table->objects[i] == obj) && (table->ids[i] == (u16)sfxId)) {
            oldCount = gSfxLoopedObjectSoundCount;
            gSfxLoopedObjectSoundCount = (u16)(oldCount - 1);
            index = (u16)i;
            memmove(&table->objects[index], &table->objects[index + 1],
                    (((oldCount - 1) - index) * sizeof(u32)) & 0xFFFC);
            memmove(&table->ids[index], &table->ids[index + 1],
                    ((gSfxLoopedObjectSoundCount - index) * sizeof(u16)) & 0xFFFE);
            memmove(&table->flags[index], &table->flags[index + 1],
                    (gSfxLoopedObjectSoundCount - index) & 0xFFFF);
            Sfx_StopFromObject(obj, sfxId);
            return;
        }
    }
}

/*
 * --INFO--
 *
 * Function: FUN_800068d0
 * EN v1.0 Address: 0x800068D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000DCDC
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Sfx_AddLoopedObjectSound(u32 obj, u32 sfxId)
{
    SfxLoopedObjectSoundTable *table;
    u32* objectIt;
    u16* idIt;
    s16 i;
    u16 count;
    u32 found = 0;

    table = &gSfxLoopedObjectSoundFlags;
    i = 0;
    objectIt = table->objects;
    idIt = table->ids;
    count = gSfxLoopedObjectSoundCount;
    for (; i < count; i++) {
        if ((*objectIt == obj) && (*idIt == (u16)sfxId)) {
            found = 1;
            break;
        }
        objectIt++;
        idIt++;
    }

    if ((found == 0) && (count != SFX_LOOPED_OBJECT_SOUND_COUNT)) {
        table->objects[count] = obj;
        table->ids[count] = sfxId;
        table->flags[count] = 0;
        gSfxLoopedObjectSoundCount++;
        Sfx_PlayFromObject(obj, sfxId);
    }
}

/*
 * --INFO--
 *
 * Function: FUN_800068d4
 * EN v1.0 Address: 0x800068D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000DD94
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Obj_RotateLocalOffsetByYaw(f32 *local, f32 *out, s8 yawIndex)
{
    s32 matrixIndex;
    f32 *matrix;

    if (yawIndex < 0) {
        out[0] = local[0];
        out[1] = local[1];
        out[2] = local[2];
    } else {
        matrixIndex = yawIndex << 4;
        matrix = (f32 *)((u8 *)gObjYawTransformMatrices + (matrixIndex << 2));
        Matrix_TransformPoint(matrix, local[0], local[1], local[2], &out[0], &out[1], &out[2]);
    }
}

/*
 * --INFO--
 *
 * Function: FUN_800068d8
 * EN v1.0 Address: 0x800068D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000DE08
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void Obj_UpdateWorldTransform(s16 *obj)
{
    s16 *parent;
    s32 matrixIndex;
    f32 *matrix;

    parent = *(s16 **)(obj + 0x20);
    if (parent == (s16 *)0) {
        *(f32 *)(obj + 0x22) = *(f32 *)(obj + 6);
        *(f32 *)(obj + 0x24) = *(f32 *)(obj + 8);
        *(f32 *)(obj + 0x26) = *(f32 *)(obj + 10);
        obj[0x28] = obj[0];
        obj[0x29] = obj[1];
        obj[0x2A] = obj[2];
    } else {
        matrixIndex = *(s8 *)((u8 *)parent + 0x35) << 4;
        matrix = (f32 *)((u8 *)gObjYawTransformMatrices + (matrixIndex << 2));
        Matrix_TransformPoint(matrix, *(f32 *)(obj + 6), *(f32 *)(obj + 8), *(f32 *)(obj + 10),
                              (f32 *)(obj + 0x22), (f32 *)(obj + 0x24), (f32 *)(obj + 0x26));
        obj[0x28] = obj[0] - parent[0];
        obj[0x29] = obj[1];
        obj[0x2A] = obj[2];
    }
}

#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800068dc
 * EN v1.0 Address: 0x800068DC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000DED4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
s32 Angle_AddWrappedS16(s32 angle, s16 *delta)
{
    if ((angle += *delta) > 0x8000) {
        angle -= 0xFFFF;
    }
    if (angle >= -0x8000) {
        return angle;
    }
    return angle + 0xFFFF;
}

/*
 * --INFO--
 *
 * Function: FUN_800068e4
 * EN v1.0 Address: 0x800068E4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000DF08
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
s32 Angle_SubWrappedS16(s32 angle, s16 *delta)
{
    if ((angle -= *delta) > 0x8000) {
        angle -= 0xFFFF;
    }
    if (angle >= -0x8000) {
        return angle;
    }
    return angle + 0xFFFF;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800068ec
 * EN v1.0 Address: 0x800068EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000DF3C
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void Obj_TransformLocalVectorToWorld(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj)
{
    f32 vec[3];
    s32 matrixIndex;

    vec[0] = x;
    vec[1] = y;
    vec[2] = z;
    matrixIndex = *(s8 *)(obj + 0x35) << 4;
    Matrix_TransformVector((f32 *)((u8 *)gObjYawTransformMatrices + (matrixIndex << 2)), vec, vec);
    *outX = vec[0];
    *outY = vec[1];
    *outZ = vec[2];
}

/*
 * --INFO--
 *
 * Function: FUN_800068f0
 * EN v1.0 Address: 0x800068F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000DFC8
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Obj_TransformWorldVectorToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj)
{
    f32 vec[3];
    s32 matrixIndex;

    vec[0] = x;
    vec[1] = y;
    vec[2] = z;
    matrixIndex = *(s8 *)(obj + 0x35) << 4;
    Matrix_TransformVector((f32 *)((u8 *)gObjInverseYawTransformMatrices + (matrixIndex << 2)), vec, vec);
    *outX = vec[0];
    *outY = vec[1];
    *outZ = vec[2];
}

/*
 * --INFO--
 *
 * Function: FUN_800068f4
 * EN v1.0 Address: 0x800068F4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000E054
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Obj_TransformWorldPointToLocal(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj)
{
    s32 matrixIndex;

    if (obj != 0) {
        matrixIndex = *(s8 *)(obj + 0x35) << 4;
        Matrix_TransformPoint((f32 *)((u8 *)gObjInverseYawTransformMatrices + (matrixIndex << 2)), x, y, z, outX, outY,
                              outZ);
    } else {
        *outX = x;
        *outY = y;
        *outZ = z;
    }
}

/*
 * --INFO--
 *
 * Function: FUN_800068f8
 * EN v1.0 Address: 0x800068F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000E0C0
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Obj_TransformLocalPointToWorld(f32 x, f32 y, f32 z, f32 *outX, f32 *outY, f32 *outZ, u32 obj)
{
    s32 matrixIndex;

    if (obj != 0) {
        matrixIndex = *(s8 *)(obj + 0x35) << 4;
        Matrix_TransformPoint((f32 *)((u8 *)gObjYawTransformMatrices + (matrixIndex << 2)), x, y, z, outX, outY, outZ);
    } else {
        *outX = x;
        *outY = y;
        *outZ = z;
    }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800068fc
 * EN v1.0 Address: 0x800068FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000E12C
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Obj_GetWorldPosition(u32 obj, f32 *outX, f32 *outY, f32 *outZ)
{
    u32 parent;
    s32 matrixIndex;

    parent = *(u32 *)(obj + 0x30);
    if (parent == 0) {
        *outX = *(f32 *)(obj + 0x0C);
        *outY = *(f32 *)(obj + 0x10);
        *outZ = *(f32 *)(obj + 0x14);
    } else {
        matrixIndex = *(s8 *)(parent + 0x35) << 4;
        Matrix_TransformPoint((f32 *)((u8 *)gObjYawTransformMatrices + (matrixIndex << 2)), *(f32 *)(obj + 0x0C),
                              *(f32 *)(obj + 0x10), *(f32 *)(obj + 0x14), outX, outY, outZ);
    }
}

/*
 * --INFO--
 *
 * Function: FUN_80006900
 * EN v1.0 Address: 0x80006900
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000E1A0
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Obj_BuildTransformMatricesForYaw(u32 obj, s32 yawIndex)
{
    u32 ancestors[4];
    ObjMatrixBuildTransform inverseTransform;
    u32 current;
    s32 matrixIndex;
    f32 *yawMatrix;
    f32 *inverseYawMatrix;
    f32 savedScale;
    s8 ancestorCount;
    s32 hasParent;

    current = obj;
    matrixIndex = yawIndex << 4;
    inverseYawMatrix = (f32 *)((u8 *)gObjInverseYawTransformMatrices + (matrixIndex << 2));
    yawMatrix = (f32 *)((u8 *)gObjYawTransformMatrices + (matrixIndex << 2));
    hasParent = 0;
    ancestorCount = 0;
    while (current != 0) {
        ancestors[ancestorCount] = current;
        ancestorCount++;
        savedScale = *(f32 *)(current + 0x08);
        if ((*(u16 *)(current + 0xB0) & 8) == 0) {
            *(f32 *)(current + 0x08) = lbl_803DE5F0;
        }

        if (hasParent == 0) {
            setMatrixFromObjectPos(yawMatrix, (void *)current);
        } else {
            setMatrixFromObjectPos((f32 *)&DAT_80338c30, (void *)current);
            mtxFn_80022404(yawMatrix, (f32 *)&DAT_80338c30, yawMatrix);
        }

        *(f32 *)(current + 0x08) = savedScale;
        current = *(u32 *)(current + 0x30);
        hasParent = 1;
    }

    while (ancestorCount > 0) {
        ancestorCount--;
        current = ancestors[ancestorCount];
        inverseTransform.x = -*(f32 *)(current + 0x0C);
        inverseTransform.y = -*(f32 *)(current + 0x10);
        inverseTransform.z = -*(f32 *)(current + 0x14);
        if ((*(u16 *)(current + 0xB0) & 8) == 0) {
            inverseTransform.scale = lbl_803DE5F0;
        } else {
            inverseTransform.scale = lbl_803DE5F0 / *(f32 *)(current + 0x08);
        }
        inverseTransform.rotX = -*(s16 *)(current + 0x00);
        inverseTransform.rotY = -*(s16 *)(current + 0x02);
        inverseTransform.rotZ = -*(s16 *)(current + 0x04);
        mtxRotateByVec3s(inverseYawMatrix, &inverseTransform);
    }
}

/*
 * --INFO--
 *
 * Function: FUN_80006904
 * EN v1.0 Address: 0x80006904
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000E338
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Obj_BuildTransformMatrices(u32 obj)
{
    Obj_BuildTransformMatricesForYaw(obj, *(s8 *)(obj + 0x35));
}

/*
 * --INFO--
 *
 * Function: FUN_80006908
 * EN v1.0 Address: 0x80006908
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000E360
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
s32 Obj_BuildTransformMatrixSlot(u32 obj)
{
    Obj_BuildTransformMatricesForYaw(obj, gObjTransformMatrixSlot);
    gObjTransformMatrixSlot++;
    return gObjTransformMatrixSlot - 1;
}

/*
 * --INFO--
 *
 * Function: FUN_80006910
 * EN v1.0 Address: 0x80006910
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000E3A0
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006910(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006914
 * EN v1.0 Address: 0x80006914
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000E640
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80006914(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8000691c
 * EN v1.0 Address: 0x8000691C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000E670
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000691c(double param_1,double param_2,double param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006920
 * EN v1.0 Address: 0x80006920
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000E69C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006920(double param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006924
 * EN v1.0 Address: 0x80006924
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000E738
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006924(double param_1,double param_2,double param_3,double param_4,double param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006928
 * EN v1.0 Address: 0x80006928
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000E834
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined * FUN_80006928(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006930
 * EN v1.0 Address: 0x80006930
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000E840
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006930(double param_1,undefined4 param_2,undefined4 param_3,ushort *param_4,
                 float *param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006934
 * EN v1.0 Address: 0x80006934
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000E964
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006934(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006938
 * EN v1.0 Address: 0x80006938
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000EA98
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006938(double param_1,double param_2,double param_3,int *param_4,int *param_5,
                 int *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000693c
 * EN v1.0 Address: 0x8000693C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000EBA8
 * EN v1.1 Size: 548b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000693c(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,float *param_7,float *param_8,float *param_9,float *param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006940
 * EN v1.0 Address: 0x80006940
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000EDCC
 * EN v1.1 Size: 412b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006940(double param_1,double param_2,double param_3,double param_4,float *param_5,
                 float *param_6,float *param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006944
 * EN v1.0 Address: 0x80006944
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000EF68
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006944(double param_1,double param_2,double param_3,float *param_4,float *param_5,
                 float *param_6,float *param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006948
 * EN v1.0 Address: 0x80006948
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000F0D8
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006948(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000694c
 * EN v1.0 Address: 0x8000694C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000F11C
 * EN v1.1 Size: 732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000694c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006950
 * EN v1.0 Address: 0x80006950
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000F3F8
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006950(undefined4 *param_1,int *param_2,uint *param_3,int *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006954
 * EN v1.0 Address: 0x80006954
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000F478
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006954(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006958
 * EN v1.0 Address: 0x80006958
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000F4A0
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006958(double param_1,double param_2,double param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000695c
 * EN v1.0 Address: 0x8000695C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000F500
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000695c(undefined2 param_1,undefined2 param_2,undefined2 param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006960
 * EN v1.0 Address: 0x80006960
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000F530
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006960(double param_1,double param_2,double param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006964
 * EN v1.0 Address: 0x80006964
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000F554
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined * FUN_80006964(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8000696c
 * EN v1.0 Address: 0x8000696C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000F560
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined * FUN_8000696c(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006974
 * EN v1.0 Address: 0x80006974
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000F56C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined * FUN_80006974(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8000697c
 * EN v1.0 Address: 0x8000697C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000F578
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined * FUN_8000697c(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006984
 * EN v1.0 Address: 0x80006984
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000F584
 * EN v1.1 Size: 540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006984(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006988
 * EN v1.0 Address: 0x80006988
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000F7A0
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006988(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8000698c
 * EN v1.0 Address: 0x8000698C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000F85C
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8000698c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006990
 * EN v1.0 Address: 0x80006990
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000F918
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006990(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006994
 * EN v1.0 Address: 0x80006994
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000F9D4
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006994(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006998
 * EN v1.0 Address: 0x80006998
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000FA90
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 FUN_80006998(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800069a0
 * EN v1.0 Address: 0x800069A0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000FAB0
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 FUN_800069a0(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800069a8
 * EN v1.0 Address: 0x800069A8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000FACC
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 * FUN_800069a8(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800069b0
 * EN v1.0 Address: 0x800069B0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000FAE4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_800069b0(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800069b8
 * EN v1.0 Address: 0x800069B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000FAEC
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800069b8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800069bc
 * EN v1.0 Address: 0x800069BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000FAF8
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800069bc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800069c0
 * EN v1.0 Address: 0x800069C0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000FB04
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800069c0(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800069c8
 * EN v1.0 Address: 0x800069C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000FB0C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800069c8(undefined2 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800069cc
 * EN v1.0 Address: 0x800069CC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000FB14
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 * FUN_800069cc(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800069d4
 * EN v1.0 Address: 0x800069D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000FB20
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800069d4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800069d8
 * EN v1.0 Address: 0x800069D8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000FC08
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_800069d8(void)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_800069e0
 * EN v1.0 Address: 0x800069E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000FC10
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800069e0(double param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800069e4
 * EN v1.0 Address: 0x800069E4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000FC3C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_800069e4(void)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_800069ec
 * EN v1.0 Address: 0x800069EC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000FC44
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_800069ec(void)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_800069f4
 * EN v1.0 Address: 0x800069F4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000FC4C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800069f4(double param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800069f8
 * EN v1.0 Address: 0x800069F8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8000FC54
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_800069f8(void)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006a00
 * EN v1.0 Address: 0x80006A00
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000FC5C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a00(double param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a04
 * EN v1.0 Address: 0x80006A04
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000FC74
 * EN v1.1 Size: 568b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a04(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a08
 * EN v1.0 Address: 0x80006A08
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8000FEAC
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a08(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a0c
 * EN v1.0 Address: 0x80006A0C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80010038
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a0c(undefined4 param_1,undefined4 param_2,int param_3,float *param_4,float *param_5,
                 float *param_6,uint param_7,undefined *param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a10
 * EN v1.0 Address: 0x80006A10
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80010340
 * EN v1.1 Size: 1508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80006a10(double param_1,float *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006a18
 * EN v1.0 Address: 0x80006A18
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80010924
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a18(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a1c
 * EN v1.0 Address: 0x80006A1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80010A8C
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a1c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 float *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a20
 * EN v1.0 Address: 0x80006A20
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80010C70
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80006a20(double param_1,float *param_2)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006a28
 * EN v1.0 Address: 0x80006A28
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80010C84
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80006a28(double param_1,float *param_2,float *param_3)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006a30
 * EN v1.0 Address: 0x80006A30
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80010DE0
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80006a30(double param_1,float *param_2,float *param_3)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006a38
 * EN v1.0 Address: 0x80006A38
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80010F00
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80006a38(double param_1,float *param_2,float *param_3)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006a40
 * EN v1.0 Address: 0x80006A40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80010F8C
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a40(int param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a44
 * EN v1.0 Address: 0x80006A44
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80011014
 * EN v1.1 Size: 2296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a44(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,uint param_12,
                 short *param_13,byte *param_14,undefined2 *param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a48
 * EN v1.0 Address: 0x80006A48
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001190C
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a48(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,short *param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,byte *param_14,undefined2 *param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a4c
 * EN v1.0 Address: 0x80006A4C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80011A1C
 * EN v1.1 Size: 1204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a4c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 *param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a50
 * EN v1.0 Address: 0x80006A50
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80011ED0
 * EN v1.1 Size: 996b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a50(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a54
 * EN v1.0 Address: 0x80006A54
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800122B4
 * EN v1.1 Size: 1192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a54(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a58
 * EN v1.0 Address: 0x80006A58
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001275C
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a58(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a5c
 * EN v1.0 Address: 0x80006A5C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80012868
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a5c(uint *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a60
 * EN v1.0 Address: 0x80006A60
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800128A8
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a60(int *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a64
 * EN v1.0 Address: 0x80006A64
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800128FC
 * EN v1.1 Size: 1060b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a64(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 *param_11,undefined *param_12,
                 uint param_13)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a68
 * EN v1.0 Address: 0x80006A68
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80012D20
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a68(float *param_1,short *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a6c
 * EN v1.0 Address: 0x80006A6C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80012E2C
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a6c(float *param_1,short *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a70
 * EN v1.0 Address: 0x80006A70
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80012EE0
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80006a70(int param_1,int param_2,int param_3,uint param_4,int param_5,int param_6)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006a78
 * EN v1.0 Address: 0x80006A78
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80012FD8
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a78(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a7c
 * EN v1.0 Address: 0x80006A7C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800132E0
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80006a7c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006a84
 * EN v1.0 Address: 0x80006A84
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013454
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a84(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a88
 * EN v1.0 Address: 0x80006A88
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800134F4
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a88(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a8c
 * EN v1.0 Address: 0x80006A8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013590
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006a8c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006a90
 * EN v1.0 Address: 0x80006A90
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80013774
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80006a90(short *param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006a98
 * EN v1.0 Address: 0x80006A98
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001377C
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80006a98(short *param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006aa0
 * EN v1.0 Address: 0x80006AA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001378C
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006aa0(int param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006aa4
 * EN v1.0 Address: 0x80006AA4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800137C8
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006aa4(short *param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006aa8
 * EN v1.0 Address: 0x80006AA8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001383C
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006aa8(short *param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006aac
 * EN v1.0 Address: 0x80006AAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800138AC
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006aac(undefined2 *param_1,undefined4 param_2,undefined2 param_3,undefined2 param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006ab0
 * EN v1.0 Address: 0x80006AB0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800138D4
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80006ab0(short *param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006ab8
 * EN v1.0 Address: 0x80006AB8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800138E4
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80006ab8(short *param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006ac0
 * EN v1.0 Address: 0x80006AC0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013900
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006ac0(short *param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006ac4
 * EN v1.0 Address: 0x80006AC4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013978
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006ac4(short *param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006ac8
 * EN v1.0 Address: 0x80006AC8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800139E8
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006ac8(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006acc
 * EN v1.0 Address: 0x80006ACC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013A08
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006acc(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006ad0
 * EN v1.0 Address: 0x80006AD0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80013A74
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80006ad0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006ad8
 * EN v1.0 Address: 0x80006AD8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013A7C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006ad8(int param_1,undefined4 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006adc
 * EN v1.0 Address: 0x80006ADC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013A84
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006adc(undefined4 *param_1,undefined4 param_2,uint param_3,undefined4 param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006ae0
 * EN v1.0 Address: 0x80006AE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013ABC
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006ae0(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006ae4
 * EN v1.0 Address: 0x80006AE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013B40
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006ae4(short *param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006ae8
 * EN v1.0 Address: 0x80006AE8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013B8C
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006ae8(int param_1,undefined2 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006aec
 * EN v1.0 Address: 0x80006AEC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80013B9C
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80006aec(undefined4 *param_1,int param_2,int *param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006af4
 * EN v1.0 Address: 0x80006AF4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80013C30
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80006af4(undefined4 *param_1,int param_2,uint param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006afc
 * EN v1.0 Address: 0x80006AFC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013C98
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006afc(uint *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b00
 * EN v1.0 Address: 0x80006B00
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013D08
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b00(undefined4 *param_1,short param_2,uint param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b04
 * EN v1.0 Address: 0x80006B04
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80013D94
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int * FUN_80006b04(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006b0c
 * EN v1.0 Address: 0x80006B0C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80013E4C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80006b0c(undefined *param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006b14
 * EN v1.0 Address: 0x80006B14
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013EE8
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b14(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b18
 * EN v1.0 Address: 0x80006B18
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80013F88
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b18(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b1c
 * EN v1.0 Address: 0x80006B1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001406C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b1c(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b20
 * EN v1.0 Address: 0x80006B20
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014074
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_80006b20(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006b28
 * EN v1.0 Address: 0x80006B28
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014080
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b28(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b2c
 * EN v1.0 Address: 0x80006B2C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800140D4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b2c(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b30
 * EN v1.0 Address: 0x80006B30
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800140DC
 * EN v1.1 Size: 1388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b30(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b34
 * EN v1.0 Address: 0x80006B34
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014648
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80006b34(void)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006b3c
 * EN v1.0 Address: 0x80006B3C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014694
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80006b3c(void)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006b44
 * EN v1.0 Address: 0x80006B44
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001469C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_80006b44(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006b4c
 * EN v1.0 Address: 0x80006B4C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800146A8
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b4c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b50
 * EN v1.0 Address: 0x80006B50
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800146C8
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b50(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b54
 * EN v1.0 Address: 0x80006B54
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800146E8
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b54(byte param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b58
 * EN v1.0 Address: 0x80006B58
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014798
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b58(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b5c
 * EN v1.0 Address: 0x80006B5C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800147D0
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b5c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b60
 * EN v1.0 Address: 0x80006B60
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014888
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80006b60(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006b68
 * EN v1.0 Address: 0x80006B68
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014954
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b68(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b6c
 * EN v1.0 Address: 0x80006B6C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001495C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80006b6c(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006b74
 * EN v1.0 Address: 0x80006B74
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014964
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80006b74(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006b7c
 * EN v1.0 Address: 0x80006B7C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001496C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80006b7c(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006b84
 * EN v1.0 Address: 0x80006B84
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014974
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b84(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b88
 * EN v1.0 Address: 0x80006B88
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014A24
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b88(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b8c
 * EN v1.0 Address: 0x80006B8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014A54
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b8c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b90
 * EN v1.0 Address: 0x80006B90
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014A90
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b90(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b94
 * EN v1.0 Address: 0x80006B94
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014ACC
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b94(double param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b98
 * EN v1.0 Address: 0x80006B98
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014B38
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b98(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006b9c
 * EN v1.0 Address: 0x80006B9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014B44
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006b9c(undefined param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006ba0
 * EN v1.0 Address: 0x80006BA0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014B50
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80006ba0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006ba8
 * EN v1.0 Address: 0x80006BA8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014B68
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006ba8(int param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006bac
 * EN v1.0 Address: 0x80006BAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014B84
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006bac(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006bb0
 * EN v1.0 Address: 0x80006BB0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014B94
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006bb0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006bb4
 * EN v1.0 Address: 0x80006BB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014BA4
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006bb4(int param_1,undefined *param_2,undefined *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006bb8
 * EN v1.0 Address: 0x80006BB8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014BF0
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80006bb8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006bc0
 * EN v1.0 Address: 0x80006BC0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014C44
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80006bc0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006bc8
 * EN v1.0 Address: 0x80006BC8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014C98
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80006bc8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006bd0
 * EN v1.0 Address: 0x80006BD0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014CEC
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80006bd0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006bd8
 * EN v1.0 Address: 0x80006BD8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014D40
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80006bd8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006be0
 * EN v1.0 Address: 0x80006BE0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014D84
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80006be0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006be8
 * EN v1.0 Address: 0x80006BE8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014DC8
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 FUN_80006be8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006bf0
 * EN v1.0 Address: 0x80006BF0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014E04
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 FUN_80006bf0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006bf8
 * EN v1.0 Address: 0x80006BF8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014E40
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80006bf8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006c00
 * EN v1.0 Address: 0x80006C00
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014E9C
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80006c00(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006c08
 * EN v1.0 Address: 0x80006C08
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014EF0
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80006c08(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006c10
 * EN v1.0 Address: 0x80006C10
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80014F14
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80006c10(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006c18
 * EN v1.0 Address: 0x80006C18
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014F68
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c18(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c1c
 * EN v1.0 Address: 0x80006C1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80014F6C
 * EN v1.1 Size: 1380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c1c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c20
 * EN v1.0 Address: 0x80006C20
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800154D0
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c20(undefined param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c24
 * EN v1.0 Address: 0x80006C24
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800154D8
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c24(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c28
 * EN v1.0 Address: 0x80006C28
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80015650
 * EN v1.1 Size: 568b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80006c28(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006c30
 * EN v1.0 Address: 0x80006C30
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80015888
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c30(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,uint param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c34
 * EN v1.0 Address: 0x80006C34
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80015994
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c34(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c38
 * EN v1.0 Address: 0x80006C38
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001599C
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c38(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c3c
 * EN v1.0 Address: 0x80006C3C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80015AEC
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80006c3c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 char *param_9,int *param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006c44
 * EN v1.0 Address: 0x80006C44
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80015C00
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80006c44(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006c4c
 * EN v1.0 Address: 0x80006C4C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80015C28
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte * FUN_80006c4c(byte *param_1,byte *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006c54
 * EN v1.0 Address: 0x80006C54
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80015CF0
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80006c54(byte *param_1,int *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006c5c
 * EN v1.0 Address: 0x80006C5C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80015DA8
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80006c5c(uint param_1,uint *param_2,uint *param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006c64
 * EN v1.0 Address: 0x80006C64
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80015E00
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c64(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c68
 * EN v1.0 Address: 0x80006C68
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80015EBC
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c68(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c6c
 * EN v1.0 Address: 0x80006C6C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800161C4
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c6c(byte *param_1,undefined4 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c70
 * EN v1.0 Address: 0x80006C70
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80016258
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c70(byte *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c74
 * EN v1.0 Address: 0x80006C74
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800162C4
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c74(uint param_1,undefined4 param_2,undefined4 param_3,int *param_4,int *param_5,
                 int *param_6,int *param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c78
 * EN v1.0 Address: 0x80006C78
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800163FC
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c78(undefined4 param_1,undefined4 param_2,undefined2 param_3,undefined2 param_4,
                 int *param_5,int *param_6,int *param_7,int *param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c7c
 * EN v1.0 Address: 0x80006C7C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800164E8
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c7c(undefined4 param_1,undefined4 param_2,int *param_3,int *param_4,int *param_5,
                 int *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c80
 * EN v1.0 Address: 0x80006C80
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800165C4
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c80(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c84
 * EN v1.0 Address: 0x80006C84
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80016848
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c84(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c88
 * EN v1.0 Address: 0x80006C88
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800168A8
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c88(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c8c
 * EN v1.0 Address: 0x80006C8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80016914
 * EN v1.1 Size: 828b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c8c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c90
 * EN v1.0 Address: 0x80006C90
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80016C50
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c90(undefined4 param_1,undefined4 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c94
 * EN v1.0 Address: 0x80006C94
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80016C80
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c94(undefined4 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c98
 * EN v1.0 Address: 0x80006C98
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80016CD4
 * EN v1.1 Size: 1836b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80006c98(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 float *param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80006c9c
 * EN v1.0 Address: 0x80006C9C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80017400
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined * FUN_80006c9c(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80006ca4
 * EN v1.0 Address: 0x80006CA4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80017414
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80006ca4(void)
{
    return 0;
}

/* Pattern wrappers. */
int return0xFFFF_80008B6C(void) { return -0x1; }
int return0x64_8000A378(void) { return 0x64; }
void doNothing_8000CF54(void) {}
void doNothing_endOfFrame(void) {}

extern s32 gMusicActivePriority;
extern f32 gCameraViewRotationMatrix[16];
extern f32 gCameraInverseViewRotationMatrix[16];
extern f32 gCameraViewMatrix[16];
extern f32 gCameraInverseViewMatrix[16];
extern u8 gCameraCurrentViewIndex;
extern u8 lbl_803DC88C;
extern s16 lbl_803DC886;
extern s16 lbl_803DC884;
extern f32 gCameraProjectionMatrix[16];
extern f32 gCameraFarPlane;
extern f32 gCameraNearPlane;
extern f32 gCameraAspectRatio;
extern f32 gCameraFovY;
extern s32 gCameraProjectionMode;
extern s16 lbl_803DC880;
extern s16 lbl_803DC882;
extern f32 lbl_803DC8A8;
extern f32 lbl_803DC8AC;
extern f32 lbl_803DC894;
extern f32 lbl_803DC898;
extern f32 lbl_803DC89C;
extern f32 lbl_803DC8A0;
extern f32 lbl_803DE60C;
extern f32 lbl_803DE628;
extern f32 lbl_803DE62C;
extern f32 lbl_803DE630;
extern f32 lbl_803DE640;
extern f32 lbl_803DE644;
extern f32 lbl_803DE648;
extern f32 lbl_803DE64C;
extern f32 lbl_803DE650;
extern f32 lbl_803DE65C;
extern f32 lbl_803DE660;
extern f32 lbl_803DE664;
extern f32 lbl_803DE668;
extern f32 lbl_803DE66C;
extern f32 lbl_803DE670;
extern f32 lbl_803DE678;
extern f32 lbl_803DE694;
extern f32 lbl_803DE698;
extern f32 lbl_803DB26C;

typedef struct CameraRenderMode {
    u32 viTVMode;
    u16 fbWidth;
    u16 efbHeight;
    u16 xfbHeight;
    u8 pad0A[0x0E];
    u8 useViewportJitter;
} CameraRenderMode;

typedef struct CameraViewSlot {
    s16 pitch;
    s16 yaw;
    s16 roll;
    u8 pad06[6];
    f32 x;
    f32 y;
    f32 z;
    u8 pad18[0x14];
    f32 shakeMagnitude;
    f32 shakeMagnitudeTarget;
    f32 shakeDuration;
    f32 shakeTimer;
    f32 shakeFalloff;
    u8 pad40[0x1C];
    s8 shakeFlipTimer;
    s8 shakeActive;
    u8 pad5E[2];
} CameraViewSlot;

typedef struct CameraMatrixTransform {
    s16 pitch;
    s16 yaw;
    s16 roll;
    s16 pad06;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} CameraMatrixTransform;

extern CameraViewSlot gCameraShakeSlots[];
extern f32 sqrtf(f32 x);
extern f32 sin(f32 x);
extern f32 fabsf(f32 x);
extern u32 getScreenResolution(void);
extern void gxSetScissorRect(int p1, int p2, int x, int y, int x2, int y2);
extern u8 lbl_80338090[];
extern f32 lbl_80338190[16];
extern f32 lbl_803967C0[12];
extern f32 lbl_803967F0[12];
extern f32 lbl_80396820[12];
extern f32 lbl_80396850[12];
extern s16 lbl_802C5ED0[];
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern CameraRenderMode* lbl_803DCCF0;
extern u32 lbl_803DCCBC;
extern s16 lbl_803DC88A;
void Camera_ApplyCurrentViewport(void* viewportArg);

extern u8 lbl_802C5E00[];

/*
 * Function: Music_GetActivePriority
 * EN v1.0 Address: 0x8000AE88
 * EN v1.0 Size: 8b
 */
#pragma dont_inline on
s32 Music_GetActivePriority(void)
{
    return gMusicActivePriority;
}
#pragma dont_inline reset

/*
 * Function: Sfx_IsPlayingFromObjectChannel
 * EN v1.0 Address: 0x8000B578
 * EN v1.0 Size: 88b
 */
s32 Sfx_IsPlayingFromObjectChannel(u32 obj, u32 channel)
{
    SfxObjectChannel* objectChannel;

    if (((u8)channel == 0) || (obj == 0)) {
        objectChannel = NULL;
    } else {
        objectChannel = Sfx_FindObjectChannel(obj, channel, 0, 0);
    }

    if (objectChannel != NULL) {
        return 1;
    }
    return 0;
}

/*
 * Function: Sfx_IsPlayingFromObject
 * EN v1.0 Address: 0x8000B5D0
 * EN v1.0 Size: 84b
 */
s32 Sfx_IsPlayingFromObject(u32 obj, u32 sfxId)
{
    SfxObjectChannel* objectChannel;

    if ((u16)sfxId != 0) {
        objectChannel = Sfx_FindObjectChannel(obj, 0, sfxId, 0);
    } else {
        objectChannel = NULL;
    }

    if (objectChannel != NULL) {
        return 1;
    }
    return 0;
}

/*
 * Function: Sfx_StopAllObjectSounds
 * EN v1.0 Address: 0x8000B624
 * EN v1.0 Size: 112b
 */
void Sfx_StopAllObjectSounds(void)
{
    s32 i;
    SfxObjectChannel* objectChannel;

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do {
        if (objectChannel->handle != (u32)-1) {
            sndFXKeyOff(objectChannel->handle);
            objectChannel->handle = (u32)-1;
        }
        objectChannel++;
    } while (i-- != 0);
}

/*
 * Function: audioFn_8000b694
 * EN v1.0 Address: 0x8000B694
 * EN v1.0 Size: 128b
 */
void audioFn_8000b694(u32 value)
{
    s32 i;
    SfxObjectChannel* objectChannel;

    objectChannel = gSfxObjectChannels;
    lbl_803DC838 = (u8)(value * 5);
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do {
        if ((objectChannel->handle != (u32)-1) && (objectChannel->globalCtrlDisabled == 0)) {
            sndFXCtrl(objectChannel->handle, 0x5B, lbl_803DC838);
        }
        objectChannel++;
    } while (i-- != 0);
}

/*
 * Function: Sfx_SetObjectSoundsPaused
 * EN v1.0 Address: 0x8000B714
 * EN v1.0 Size: 168b
 */
void Sfx_SetObjectSoundsPaused(s32 paused)
{
    u8 pausedByte;
    s32 i;
    SfxObjectChannel* objectChannel;

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    pausedByte = paused;

    do {
        if (objectChannel->handle != (u32)-1) {
            if (paused != 0) {
                sndFXCtrl(objectChannel->handle, 7, 0);
            } else if (objectChannel->paused != 0) {
                sndFXCtrl(objectChannel->handle, 7, objectChannel->volume);
            }
            objectChannel->paused = pausedByte;
        }
        objectChannel++;
    } while (i-- != 0);
}

/*
 * Function: Sfx_StopObjectChannel
 * EN v1.0 Address: 0x8000B7BC
 * EN v1.0 Size: 104b
 */
void Sfx_StopObjectChannel(u32 obj, u32 channel)
{
    SfxObjectChannel* objectChannel;

    if (((u8)channel == 0) || (obj == 0)) {
        objectChannel = NULL;
    } else {
        objectChannel = Sfx_FindObjectChannel(obj, channel, 0, 0);
    }

    if (objectChannel != NULL) {
        sndFXKeyOff(objectChannel->handle);
        objectChannel->handle = (u32)-1;
    }
}

/*
 * Function: Sfx_StopFromObject
 * EN v1.0 Address: 0x8000B824
 * EN v1.0 Size: 100b
 */
void Sfx_StopFromObject(u32 obj, u32 sfxId)
{
    SfxObjectChannel* objectChannel;

    if ((u16)sfxId != 0) {
        objectChannel = Sfx_FindObjectChannel(obj, 0, sfxId, 0);
    } else {
        objectChannel = NULL;
    }

    if (objectChannel != NULL) {
        sndFXKeyOff(objectChannel->handle);
        objectChannel->handle = (u32)-1;
    }
}

/*
 * Function: Sfx_SetObjectChannelVolume
 * EN v1.0 Address: 0x8000B888
 * EN v1.0 Size: 276b
 */
void Sfx_SetObjectChannelVolume(f32 volumeScale, u32 obj, u32 channel, u8 volume)
{
    u8 volumeByte;
    SfxObjectChannel* objectChannel;

    volumeByte = volume;
    if (((u8)channel == 0) || (obj == 0)) {
        objectChannel = NULL;
    } else {
        objectChannel = Sfx_FindObjectChannel(obj, channel, 0, 2);
    }

    if (objectChannel != NULL) {
        if ((u8)volumeByte != 0xFE) {
            u32 ctrlVolume;

            if ((u8)volumeByte == 0xFF) {
                volumeByte = 100;
            }
            objectChannel->volume = volumeByte;
            if (objectChannel->hasPosition != 0) {
                Sfx_UpdateObjectChannel3D(objectChannel);
            } else {
                if (objectChannel->paused != 0) {
                    ctrlVolume = 0;
                } else {
                    ctrlVolume = volumeByte;
                }
                sndFXCtrl(objectChannel->handle, 7, (u8)ctrlVolume);
            }
        }

        if (volumeScale < lbl_803DE570) {
            volumeScale = lbl_803DE570;
        }
        if (volumeScale > lbl_803DE574) {
            volumeScale = lbl_803DE574;
        }
        sndFXCtrl14(objectChannel->handle, 0x80, (s32)(lbl_803DE578 * volumeScale));
    }
}

/*
 * Function: Sfx_SetObjectSfxVolume
 * EN v1.0 Address: 0x8000B99C
 * EN v1.0 Size: 276b
 */
void Sfx_SetObjectSfxVolume(f32 volumeScale, u32 obj, u32 sfxId, u8 volume)
{
    u8 volumeByte;
    SfxObjectChannel* objectChannel;

    volumeByte = volume;
    if ((u16)sfxId != 0) {
        objectChannel = Sfx_FindObjectChannel(obj, 0, sfxId, 2);
    } else {
        objectChannel = NULL;
    }

    if (objectChannel != NULL) {
        if ((u8)volumeByte != 0xFE) {
            u32 ctrlVolume;

            if ((u8)volumeByte == 0xFF) {
                volumeByte = 100;
            }
            objectChannel->volume = volumeByte;
            if (objectChannel->hasPosition != 0) {
                Sfx_UpdateObjectChannel3D(objectChannel);
            } else {
                if (objectChannel->paused != 0) {
                    ctrlVolume = 0;
                } else {
                    ctrlVolume = volumeByte;
                }
                sndFXCtrl(objectChannel->handle, 7, (u8)ctrlVolume);
            }
        }

        if (volumeScale < lbl_803DE570) {
            volumeScale = lbl_803DE570;
        }
        if (volumeScale > lbl_803DE574) {
            volumeScale = lbl_803DE574;
        }
        sndFXCtrl14(objectChannel->handle, 0x80, (s32)(lbl_803DE578 * volumeScale));
    }
}

/*
 * Function: Sfx_PlayFromObjectChannel
 * EN v1.0 Address: 0x8000BAB0
 * EN v1.0 Size: 48b
 */
void Sfx_PlayFromObjectChannel(u32 obj, u32 channel, u32 sfxId)
{
    Sfx_PlayFromObjectEx(obj, NULL, channel, sfxId);
}

/*
 * Function: Sfx_PlayAtPositionFromObject
 * EN v1.0 Address: 0x8000BAE0
 * EN v1.0 Size: 56b
 */
void Sfx_PlayAtPositionFromObject(f32 x, f32 y, f32 z, u32 obj, u32 sfxId)
{
    f32 pos[3];

    pos[0] = x;
    pos[1] = y;
    pos[2] = z;
    Sfx_PlayFromObjectEx(obj, pos, 0, sfxId);
}

/*
 * Function: Sfx_PlayFromObject
 * EN v1.0 Address: 0x8000BB18
 * EN v1.0 Size: 44b
 */
void Sfx_PlayFromObject(u32 obj, u32 sfxId)
{
    Sfx_PlayFromObjectEx(obj, NULL, 0, sfxId);
}

/*
 * Function: Sfx_UpdateObjectSounds
 * EN v1.0 Address: 0x8000BB44
 * EN v1.0 Size: 624b
 */
void Sfx_UpdateObjectSounds(void)
{
    SfxObjectChannel* objectChannel;
    s32 i;
    u32 globalCtrl;

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do {
        if ((objectChannel->handle != (u32)-1) && ((u32)sndFXCheck(objectChannel->handle) == (u32)-1)) {
            objectChannel->handle = (u32)-1;
        }
        objectChannel++;
    } while (i-- != 0);

    if (GameBit_Get(0xCBB) != 0) {
        globalCtrl = 0xE;
    } else if (GameBit_Get(0xEFA) != 0) {
        globalCtrl = 0xC;
    } else if (GameBit_Get(0xEFB) != 0) {
        globalCtrl = 0xD;
    } else if (GameBit_Get(0xEFD) != 0) {
        globalCtrl = 0xC;
    } else if (GameBit_Get(0xA7F) != 0) {
        globalCtrl = 0xC;
    } else if (GameBit_Get(0xEFC) != 0) {
        globalCtrl = 0xC;
    } else if (GameBit_Get(0xEFE) != 0) {
        globalCtrl = 0xC;
    } else if (GameBit_Get(0xDCF) != 0) {
        globalCtrl = 0xB;
    } else if (Music_GetActivePriority() <= 0x28) {
        globalCtrl = 0xC;
    } else {
        globalCtrl = 0;
    }

    if ((u8)globalCtrl != (s32)(lbl_803DC838 / 5)) {
        objectChannel = gSfxObjectChannels;
        lbl_803DC838 = (u8)(globalCtrl * 5);
        i = SFX_OBJECT_CHANNEL_COUNT - 1;
        do {
            if ((objectChannel->handle != (u32)-1) && (objectChannel->globalCtrlDisabled == 0)) {
                sndFXCtrl(objectChannel->handle, 0x5B, lbl_803DC838);
            }
            objectChannel++;
        } while (i-- != 0);
    }

    objectChannel = gSfxObjectChannels;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do {
        if ((objectChannel->handle != (u32)-1) && (objectChannel->hasPosition != 0)) {
            if (objectChannel->tracksObjectPosition != 0) {
                if ((*(u16*)(objectChannel->object + 0xB0) & SFX_LOOPED_OBJECT_STOP_FLAG) != 0) {
                    objectChannel->tracksObjectPosition = 0;
                } else {
                    objectChannel->x = *(f32*)(objectChannel->object + 0x18);
                    objectChannel->y = *(f32*)(objectChannel->object + 0x1C);
                    objectChannel->z = *(f32*)(objectChannel->object + 0x20);
                }
            }

            if ((objectChannel->tracksObjectPosition != 0) || (objectChannel->globalCtrlDisabled != 0)) {
                Sfx_UpdateObjectChannel3D(objectChannel);
            }
        }
        objectChannel++;
    } while (i-- != 0);
}

/*
 * Function: Sfx_InitObjectChannels
 * EN v1.0 Address: 0x8000BDB4
 * EN v1.0 Size: 172b
 */
void Sfx_InitObjectChannels(void)
{
    SfxObjectChannel* objectChannel;
    s32 i;

    i = SFX_OBJECT_CHANNEL_COUNT;
    objectChannel = &gSfxObjectChannels[SFX_OBJECT_CHANNEL_COUNT];
    goto checkNextChannel;
setChannelFree:
    objectChannel->handle = (u32)-1;
checkNextChannel:
    objectChannel--;
    if (i-- != 0) {
        goto setChannelFree;
    }

    gSfxObjectChannelAgeLo = 0;
    gSfxObjectChannelAgeHi = 0;
    objectChannel = gSfxObjectChannels;
    lbl_803DC838 = 0;
    i = SFX_OBJECT_CHANNEL_COUNT - 1;
    do {
        if ((objectChannel->handle != (u32)-1) && (objectChannel->globalCtrlDisabled == 0)) {
            sndFXCtrl(objectChannel->handle, 0x5B, lbl_803DC838);
        }
        objectChannel++;
    } while (i-- != 0);
}

/*
 * Function: Sfx_FindObjectChannel
 * EN v1.0 Address: 0x8000CCEC
 * EN v1.0 Size: 360b
 */
SfxObjectChannel* Sfx_FindObjectChannel(u32 obj, u32 channel, u32 sfxId, s32 mode)
{
    SfxObjectChannel* objectChannel = gSfxObjectChannels;
    SfxObjectChannel* bestChannel = NULL;
    u64 bestAge;
    u32 channelMask = (u8)channel;
    s32 i;

    if (mode == 2) {
        bestAge = 0;
    } else {
        bestAge = (u64)-1;
    }
    gSfxObjectChannelMatchCount = 0;

    for (i = SFX_OBJECT_CHANNEL_COUNT; i != 0; i--) {
        if ((objectChannel->handle != (u32)-1) &&
            ((obj == 0) || (objectChannel->object == obj)) &&
            ((channelMask == 0) || ((objectChannel->channelMask & channelMask) != 0)) &&
            (((u16)sfxId == 0) || (objectChannel->sfxId == (u16)sfxId))) {
            gSfxObjectChannelMatchCount++;

            switch (mode) {
            case 2:
                if (objectChannel->age > bestAge) {
                    bestChannel = objectChannel;
                    bestAge = objectChannel->age;
                }
                break;
            case 0:
                return objectChannel;
            case 1:
            case 3:
                if (objectChannel->age < bestAge) {
                    bestChannel = objectChannel;
                    bestAge = objectChannel->age;
                }
                break;
            }

            if ((mode != 3) && (gSfxObjectChannelMatchCount == 3)) {
                return bestChannel;
            }
        }
        objectChannel++;
    }

    return bestChannel;
}

/*
 * Function: Camera_GetViewRotationMatrix
 * EN v1.0 Address: 0x8000F534
 * EN v1.0 Size: 12b
 */
f32* Camera_GetViewRotationMatrix(void)
{
    return gCameraViewRotationMatrix;
}

/*
 * Function: Camera_GetInverseViewRotationMatrix
 * EN v1.0 Address: 0x8000F540
 * EN v1.0 Size: 12b
 */
f32* Camera_GetInverseViewRotationMatrix(void)
{
    return gCameraInverseViewRotationMatrix;
}

/*
 * Function: Camera_GetViewMatrix
 * EN v1.0 Address: 0x8000F54C
 * EN v1.0 Size: 12b
 */
f32* Camera_GetViewMatrix(void)
{
    return gCameraViewMatrix;
}

/*
 * Function: Camera_GetInverseViewMatrix
 * EN v1.0 Address: 0x8000F558
 * EN v1.0 Size: 12b
 */
f32* Camera_GetInverseViewMatrix(void)
{
    return gCameraInverseViewMatrix;
}

/*
 * Function: Camera_GetCurrentViewSlot
 * EN v1.0 Address: 0x8000FAAC
 * EN v1.0 Size: 24b
 */
void* Camera_GetCurrentViewSlot(void)
{
    return &gCameraShakeSlots[gCameraCurrentViewIndex];
}

/*
 * Function: CameraShake_IsActive
 * EN v1.0 Address: 0x8000E620
 * EN v1.0 Size: 48b
 */
u8 CameraShake_IsActive(void)
{
    s32 offset = gCameraCurrentViewIndex * sizeof(CameraViewSlot);
    CameraViewSlot* slot = (CameraViewSlot*)((u8*)gCameraShakeSlots + offset);

    return slot->shakeActive == 1;
}

/*
 * Function: CameraShake_Start
 * EN v1.0 Address: 0x8000E650
 * EN v1.0 Size: 44b
 */
void CameraShake_Start(f32 magnitude, f32 duration, f32 falloff)
{
    CameraViewSlot* slot = &gCameraShakeSlots[0];

    slot->shakeMagnitude = magnitude;
    slot->shakeMagnitudeTarget = magnitude;
    slot->shakeDuration = duration;
    slot->shakeTimer = lbl_803DE60C;
    slot->shakeFalloff = falloff;
    slot->shakeActive = 1;
}

/*
 * Function: CameraShake_SetAllMagnitudes
 * EN v1.0 Address: 0x8000E67C
 * EN v1.0 Size: 156b
 */
void CameraShake_SetAllMagnitudes(f32 magnitude)
{
    CameraViewSlot* slot = gCameraShakeSlots;

    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;

    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
    slot++;
    slot->shakeMagnitude = magnitude;
    slot->shakeActive = 0;
}

/*
 * Function: CameraShake_ApplyRadial
 * EN v1.0 Address: 0x8000E718
 * EN v1.0 Size: 252b
 */
void CameraShake_ApplyRadial(f32 x, f32 y, f32 z, f32 radius, f32 magnitude)
{
    CameraViewSlot* slot;
    s32 i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 distance;
    s8 inactive;

    i = 0;
    slot = gCameraShakeSlots;
    inactive = 0;
    do {
        dx = x - slot->x;
        dy = y - slot->y;
        dz = z - slot->z;
        distance = sqrtf(dx * dx + dy * dy + dz * dz);
        if (distance < radius) {
            slot->shakeMagnitude = (magnitude * (radius - distance)) / radius;
            slot->shakeActive = inactive;
        }
        slot++;
        i++;
    } while (i <= 7);
}

/*
 * Function: fn_8000E814
 * EN v1.0 Address: 0x8000E814
 * EN v1.0 Size: 12b
 */
void* fn_8000E814(void)
{
    return lbl_80338090;
}

/*
 * Function: Camera_LoadModelViewMatrix
 * EN v1.0 Address: 0x8000E820
 * EN v1.0 Size: 292b
 */
void Camera_LoadModelViewMatrix(f32 scale, void* unused0, void* unused1, CameraViewSlot* transform, f32* matrix)
{
    f32* modelMatrix;

    if (matrix != NULL) {
        modelMatrix = matrix;
    } else {
        modelMatrix = lbl_80338190;
    }

    transform->x -= playerMapOffsetX;
    transform->z -= playerMapOffsetZ;
    setMatrixFromObjectPos(modelMatrix, transform);
    if (lbl_803DE5F0 != scale) {
        mtxFn_80021ec0(modelMatrix, scale);
    }

    if (matrix == NULL) {
        mtx44Transpose(modelMatrix, lbl_803967C0);
    } else {
        mtx44Transpose(matrix, lbl_803967C0);
    }

    PSMTXConcat(gCameraViewMatrix, lbl_803967C0, lbl_803967C0);
    GXLoadPosMtxImm(lbl_803967C0, 0);
    transform->x += playerMapOffsetX;
    transform->z += playerMapOffsetZ;
}

/*
 * Function: Camera_NdcToScreen
 * EN v1.0 Address: 0x8000EA78
 * EN v1.0 Size: 272b
 */
void Camera_NdcToScreen(f32 ndcX, f32 ndcY, f32 ndcZ, s32* outX, s32* outY, s32* outZ)
{
    if (outX != NULL) {
        *outX = (s32)(ndcX * (f32)(lbl_802C5ED0[0] >> 2) + (f32)(lbl_802C5ED0[4] >> 2));
    }

    if (outY != NULL) {
        *outY = (s32)(ndcY * (f32)(lbl_802C5ED0[1] >> 2) + (f32)(lbl_802C5ED0[5] >> 2));
        *outY = 0x1E0 - *outY;
    }

    if (outZ != NULL) {
        *outZ = (s32)(lbl_803DE620 * (lbl_803DE5F0 + ndcZ));
    }
}

/*
 * Function: screenFn_8000e944
 * EN v1.0 Address: 0x8000E944
 * EN v1.0 Size: 308b
 */
void screenFn_8000e944(void* viewportArg)
{
    u32 resolution;
    u32 width;
    u32 height;
    u32* viewportFlags;
    u8 viewIndex;
    s16 halfWidth;
    s16 halfHeight;

    gCameraCurrentViewIndex = 4;
    resolution = getScreenResolution();
    width = resolution >> 16;
    height = resolution & 0xFFFF;
    viewportFlags = (u32*)(lbl_802C5E00 + 0x30);

    if ((*(u32*)((u8*)viewportFlags + gCameraCurrentViewIndex * 0x34) & 1) == 0) {
        gxSetScissorRect(0, 0, 0, 0, height - 1, width - 1);
        halfWidth = (s16)((height >> 1) << 2);
        viewIndex = gCameraCurrentViewIndex;
        if ((*(u32*)((u8*)viewportFlags + viewIndex * 0x34) & 1) == 0) {
            halfHeight = (s16)((width >> 1) << 2);
            lbl_802C5ED0[viewIndex * 8 + 4] = halfWidth;
            lbl_802C5ED0[viewIndex * 8 + 5] = halfHeight;
            lbl_802C5ED0[viewIndex * 8 + 0] = halfWidth;
            lbl_802C5ED0[viewIndex * 8 + 1] = halfHeight;
        }
    } else {
        Camera_ApplyCurrentViewport(viewportArg);
        viewIndex = gCameraCurrentViewIndex;
        if ((*(u32*)((u8*)viewportFlags + viewIndex * 0x34) & 1) == 0) {
            lbl_802C5ED0[viewIndex * 8 + 4] = 0;
            lbl_802C5ED0[viewIndex * 8 + 5] = 0;
            lbl_802C5ED0[viewIndex * 8 + 0] = 0;
            lbl_802C5ED0[viewIndex * 8 + 1] = 0;
        }
    }

    gCameraCurrentViewIndex = 0;
}

/*
 * Function: Camera_ProjectWorldPoint
 * EN v1.0 Address: 0x8000EF48
 * EN v1.0 Size: 368b
 */
void Camera_ProjectWorldPoint(f32 x, f32 y, f32 z, f32* outX, f32* outY, f32* outZ, f32* outViewZ)
{
    f32 pos[3];
    f32 w;
    f32 invW;

    pos[0] = x;
    pos[1] = y;
    pos[2] = z;
    PSMTXMultVec(gCameraViewMatrix, pos, pos);

    *outViewZ = pos[2];
    *outX = gCameraProjectionMatrix[3] +
            gCameraProjectionMatrix[2] * pos[2] +
            gCameraProjectionMatrix[0] * pos[0] +
            gCameraProjectionMatrix[1] * pos[1];
    *outY = gCameraProjectionMatrix[7] +
            gCameraProjectionMatrix[6] * pos[2] +
            gCameraProjectionMatrix[4] * pos[0] +
            gCameraProjectionMatrix[5] * pos[1];
    *outZ = gCameraProjectionMatrix[11] +
            gCameraProjectionMatrix[10] * pos[2] +
            gCameraProjectionMatrix[8] * pos[0] +
            gCameraProjectionMatrix[9] * pos[1];

    w = gCameraProjectionMatrix[15] +
        gCameraProjectionMatrix[14] * pos[2] +
        gCameraProjectionMatrix[12] * pos[0] +
        gCameraProjectionMatrix[13] * pos[1];
    if (w != lbl_803DE60C) {
        invW = lbl_803DE5F0 / w;
        *outX *= invW;
        *outY *= invW;
        *outZ *= invW;
    }
}

/*
 * Function: Camera_ProjectWorldPointWithOffset
 * EN v1.0 Address: 0x8000EDAC
 * EN v1.0 Size: 412b
 */
void Camera_ProjectWorldPointWithOffset(f32 x, f32 y, f32 z, f32 offset, f32* outX, f32* outY, f32* outZ)
{
    f32 pos[3];
    f32 offsetVec[3];
    f32 w;
    f32 invW;

    pos[0] = x;
    pos[1] = y;
    pos[2] = z;
    PSMTXMultVec(gCameraViewMatrix, pos, pos);
    PSVECNormalize(pos, offsetVec);
    PSVECScale(offsetVec, offsetVec, offset);
    PSVECSubtract(pos, offsetVec, pos);

    *outX = gCameraProjectionMatrix[3] +
            gCameraProjectionMatrix[2] * pos[2] +
            gCameraProjectionMatrix[0] * pos[0] +
            gCameraProjectionMatrix[1] * pos[1];
    *outY = gCameraProjectionMatrix[7] +
            gCameraProjectionMatrix[6] * pos[2] +
            gCameraProjectionMatrix[4] * pos[0] +
            gCameraProjectionMatrix[5] * pos[1];
    *outZ = gCameraProjectionMatrix[11] +
            gCameraProjectionMatrix[10] * pos[2] +
            gCameraProjectionMatrix[8] * pos[0] +
            gCameraProjectionMatrix[9] * pos[1];

    w = gCameraProjectionMatrix[15] +
        gCameraProjectionMatrix[14] * pos[2] +
        gCameraProjectionMatrix[12] * pos[0] +
        gCameraProjectionMatrix[13] * pos[1];
    if (w != lbl_803DE60C) {
        invW = lbl_803DE5F0 / w;
        *outX *= invW;
        *outY *= invW;
        *outZ *= invW;
    }
}

/*
 * Function: Camera_ProjectWorldSphere
 * EN v1.0 Address: 0x8000EB88
 * EN v1.0 Size: 548b
 */
void Camera_ProjectWorldSphere(
    f32 x,
    f32 y,
    f32 z,
    f32 radius,
    f32* outX,
    f32* outY,
    f32* outZ,
    f32* outRadiusX,
    f32* outRadiusY,
    f32* outRadiusZ)
{
    f32 pos[3];
    f32 w;
    f32 invW;

    pos[0] = x;
    pos[1] = y;
    pos[2] = z;
    PSMTXMultVec(gCameraViewMatrix, pos, pos);

    *outX = gCameraProjectionMatrix[3] +
            gCameraProjectionMatrix[2] * pos[2] +
            gCameraProjectionMatrix[0] * pos[0] +
            gCameraProjectionMatrix[1] * pos[1];
    *outY = gCameraProjectionMatrix[7] +
            gCameraProjectionMatrix[6] * pos[2] +
            gCameraProjectionMatrix[4] * pos[0] +
            gCameraProjectionMatrix[5] * pos[1];
    *outZ = gCameraProjectionMatrix[11] +
            gCameraProjectionMatrix[10] * pos[2] +
            gCameraProjectionMatrix[8] * pos[0] +
            gCameraProjectionMatrix[9] * pos[1];

    w = gCameraProjectionMatrix[15] +
        gCameraProjectionMatrix[14] * pos[2] +
        gCameraProjectionMatrix[12] * pos[0] +
        gCameraProjectionMatrix[13] * pos[1];
    if (w != lbl_803DE60C) {
        invW = lbl_803DE5F0 / w;
        *outX *= invW;
        *outY *= invW;
        *outZ *= invW;

        pos[2] += radius;
        if (pos[2] > lbl_803DE624) {
            pos[2] = lbl_803DE624;
        }

        w = gCameraProjectionMatrix[15] +
            gCameraProjectionMatrix[14] * pos[2] +
            gCameraProjectionMatrix[12] * pos[0] +
            gCameraProjectionMatrix[13] * pos[1];
        if (w != lbl_803DE60C) {
            invW = lbl_803DE5F0 / w;
            *outRadiusX = fabsf(invW * (radius * gCameraProjectionMatrix[0]));
            *outRadiusY = fabsf(invW * (radius * gCameraProjectionMatrix[5]));
            *outRadiusZ = fabsf(invW * (radius * gCameraProjectionMatrix[10]));
        }
    }
}

/*
 * Function: viewportEffectFn_8000e380
 * EN v1.0 Address: 0x8000E380
 * EN v1.0 Size: 672b
 */
void viewportEffectFn_8000e380(void)
{
    CameraViewSlot* slot;
    f32 falloffTime;
    f32 shakeTimer;
    f32 expTerm;
    f32 n;
    f32 term;
    f32 factorial;
    f32 one;
    f32 sinePhase;
    s32 i;

    lbl_803DC884 = lbl_803DC886;
    if (lbl_803DC880 != 0) {
        lbl_803DC880 -= framesThisStep;
        if (lbl_803DC880 < 0) {
            lbl_803DC880 = 0;
        }
        gCameraFarPlane = ((f32)lbl_803DC880 / (f32)lbl_803DC882) * (lbl_803DC8AC - lbl_803DC8A8) + lbl_803DC8A8;
    }

    gObjTransformMatrixSlot = 0;
    slot = &gCameraShakeSlots[gCameraCurrentViewIndex];

    if (slot->shakeActive == 0) {
        slot->shakeFlipTimer--;
        while (slot->shakeFlipTimer < 0) {
            slot->shakeFlipTimer++;
            slot->shakeMagnitude = lbl_803DE5F4 * -slot->shakeMagnitude;
        }
    } else if (slot->shakeActive == 1) {
        falloffTime = -slot->shakeFalloff;
        shakeTimer = slot->shakeTimer;
        falloffTime *= shakeTimer;
        expTerm = lbl_803DE5F0;
        n = expTerm;
        term = falloffTime;
        factorial = expTerm;
        one = expTerm;

        for (i = 0; i < 2; i++) {
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
            expTerm += term / factorial;
            n += one;
            term *= falloffTime;
            factorial *= n;
        }

        sinePhase = (lbl_803DE5F8 * (lbl_803DE5FC * slot->shakeDuration * shakeTimer)) / lbl_803DE600;
        slot->shakeMagnitude = slot->shakeMagnitudeTarget * expTerm * sin(sinePhase);
        if ((slot->shakeMagnitude < lbl_803DE604) && (slot->shakeMagnitude > lbl_803DE608)) {
            slot->shakeMagnitude = lbl_803DE60C;
            slot->shakeActive = -1;
        }
        slot->shakeTimer += timeDelta / lbl_803DE610;
    }
}

/*
 * Function: Camera_ApplyCurrentViewport
 * EN v1.0 Address: 0x8000F0B8
 * EN v1.0 Size: 68b
 */
#pragma dont_inline on
void Camera_ApplyCurrentViewport(void* viewportArg)
{
    u32 resolution = getScreenResolution();
    int width = resolution >> 16;
    int height = resolution & 0xffff;
    int viewportY = lbl_803DC884 + 6;

    gxSetScissorRect(0, 0, 0, viewportY, height, width - viewportY);
}
#pragma dont_inline reset

/*
 * Function: Camera_UpdateProjection
 * EN v1.0 Address: 0x8000F0FC
 * EN v1.0 Size: 732b
 */
void Camera_UpdateProjection(void* viewportArg)
{
    u8 viewIndex = gCameraCurrentViewIndex;
    u8 activeViewIndex;
    u32 resolution = getScreenResolution();
    u32 screenWidth = resolution >> 16;
    u32 screenHeight = resolution & 0xffff;
    u8* viewportEntry = lbl_802C5E00 + viewIndex * 0x34;

    if ((*(u32*)(viewportEntry + 0x30) & 1) != 0) {
        u8 savedViewIndex = gCameraCurrentViewIndex;

        gCameraCurrentViewIndex = viewIndex;
        gxSetScissorRect(0, 0,
                         *(s32*)(viewportEntry + 0x20),
                         *(s32*)(viewportEntry + 0x24),
                         *(s32*)(viewportEntry + 0x28),
                         *(s32*)(viewportEntry + 0x2c));

        activeViewIndex = gCameraCurrentViewIndex;
        viewportEntry = lbl_802C5E00 + activeViewIndex * 0x34;
        if ((*(u32*)(viewportEntry + 0x30) & 1) == 0) {
            lbl_802C5ED0[activeViewIndex * 8 + 4] = 0;
            lbl_802C5ED0[activeViewIndex * 8 + 5] = 0;
            lbl_802C5ED0[activeViewIndex * 8 + 0] = 0;
            lbl_802C5ED0[activeViewIndex * 8 + 1] = 0;
        }

        gCameraCurrentViewIndex = savedViewIndex;
        if (gCameraProjectionMode == 1) {
            C_MTXOrtho(gCameraProjectionMatrix, lbl_803DC8A0, lbl_803DC89C, lbl_803DC898,
                       lbl_803DC894, gCameraNearPlane, gCameraFarPlane);
        } else {
            C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio,
                             gCameraNearPlane, gCameraFarPlane);
            C_MTXLightPerspective(lbl_80396850, gCameraFovY, gCameraAspectRatio, lbl_803DE628,
                                  lbl_803DE628, lbl_803DE62C, lbl_803DE62C);
            C_MTXLightPerspective(lbl_803967F0, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                                  lbl_803DE62C, lbl_803DE62C, lbl_803DE62C);
            C_MTXLightPerspective(lbl_80396820, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                                  lbl_803DE630, lbl_803DE62C, lbl_803DE62C);
        }
        GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);
        gCameraCurrentViewIndex = viewIndex;
    } else {
        u32 halfScreenHeight = screenHeight >> 1;
        u32 halfScreenWidth = screenWidth >> 1;

        activeViewIndex = gCameraCurrentViewIndex;
        viewportEntry = lbl_802C5E00 + activeViewIndex * 0x34;
        if ((*(u32*)(viewportEntry + 0x30) & 1) == 0) {
            s16 scaledHalfHeight = (s16)(halfScreenHeight << 2);
            s16 scaledHalfWidth = (s16)(halfScreenWidth << 2);

            lbl_802C5ED0[activeViewIndex * 8 + 4] = scaledHalfHeight;
            lbl_802C5ED0[activeViewIndex * 8 + 5] = scaledHalfWidth;
            lbl_802C5ED0[activeViewIndex * 8 + 0] = scaledHalfHeight;
            lbl_802C5ED0[activeViewIndex * 8 + 1] = scaledHalfWidth;
        }

        if (gCameraProjectionMode == 1) {
            C_MTXOrtho(gCameraProjectionMatrix, lbl_803DC8A0, lbl_803DC89C, lbl_803DC898,
                       lbl_803DC894, gCameraNearPlane, gCameraFarPlane);
        } else {
            C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio,
                             gCameraNearPlane, gCameraFarPlane);
            C_MTXLightPerspective(lbl_80396850, gCameraFovY, gCameraAspectRatio, lbl_803DE628,
                                  lbl_803DE628, lbl_803DE62C, lbl_803DE62C);
            C_MTXLightPerspective(lbl_803967F0, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                                  lbl_803DE62C, lbl_803DE62C, lbl_803DE62C);
            C_MTXLightPerspective(lbl_80396820, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                                  lbl_803DE630, lbl_803DE62C, lbl_803DE62C);
        }
        GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);
        Camera_ApplyCurrentViewport(viewportArg);
        gCameraCurrentViewIndex = viewIndex;
    }
}

/*
 * Function: Camera_GetCurrentViewport
 * EN v1.0 Address: 0x8000F3D8
 * EN v1.0 Size: 128b
 */
void Camera_GetCurrentViewport(s32* outX, s32* outY, u32* outHeight, s32* outWidth)
{
    u32 resolution = getScreenResolution();

    *outX = 0;
    *outHeight = resolution & 0xffff;
    *outY = lbl_803DC884 + 6;
    *outWidth = (resolution >> 16) - (lbl_803DC884 + 6);
}

/*
 * Function: Camera_SetCurrentViewIndex
 * EN v1.0 Address: 0x8000F458
 * EN v1.0 Size: 40b
 */
void Camera_SetCurrentViewIndex(int index)
{
    if (index >= 0 && index < 4) {
        gCameraCurrentViewIndex = index;
        return;
    }
    gCameraCurrentViewIndex = 0;
}

/*
 * Function: Camera_DistanceToCurrentViewPosition
 * EN v1.0 Address: 0x8000F480
 * EN v1.0 Size: 96b
 */
f32 Camera_DistanceToCurrentViewPosition(f32 x, f32 y, f32 z)
{
    CameraViewSlot* slot = &gCameraShakeSlots[gCameraCurrentViewIndex];
    f32 dz = z - slot->z;
    f32 dx = x - slot->x;
    f32 dy = y - slot->y;

    return sqrtf(dx * dx + dy * dy + dz * dz);
}

/*
 * Function: Camera_SetCurrentViewRotation
 * EN v1.0 Address: 0x8000F4E0
 * EN v1.0 Size: 48b
 */
void Camera_SetCurrentViewRotation(int pitch, int yaw, int roll)
{
    CameraViewSlot* slot = &gCameraShakeSlots[gCameraCurrentViewIndex];

    slot->pitch = pitch;
    slot->yaw = yaw;
    slot->roll = roll;
}

/*
 * Function: Camera_SetCurrentViewPosition
 * EN v1.0 Address: 0x8000F510
 * EN v1.0 Size: 36b
 */
void Camera_SetCurrentViewPosition(f32 x, f32 y, f32 z)
{
    CameraViewSlot* slot = &gCameraShakeSlots[gCameraCurrentViewIndex];

    slot->x = x;
    slot->y = y;
    slot->z = z;
}

/*
 * Function: Camera_UpdateViewMatrices
 * EN v1.0 Address: 0x8000F564
 * EN v1.0 Size: 540b
 */
void Camera_UpdateViewMatrices(void)
{
    CameraViewSlot* slot = &gCameraShakeSlots[gCameraCurrentViewIndex];
    CameraMatrixTransform transform;
    f32 rotationMatrix[16];

    transform.x = -(slot->x - playerMapOffsetX);
    transform.y = -slot->y;
    transform.z = -(slot->z - playerMapOffsetZ);
    transform.pitch = slot->pitch - 0x8000;
    transform.yaw = slot->yaw;
    transform.roll = slot->roll;
    transform.scale = lbl_803DE5F0;
    if (pauseMenuGetState() == 0) {
        if (lbl_803DC88C != 0) {
            transform.y -= slot->shakeMagnitude;
        }
        transform.x += lbl_803DE60C;
        transform.y += lbl_803DE60C;
        transform.z += lbl_803DE60C;
    }

    mtxRotateByVec3s(rotationMatrix, &transform);
    mtx44Transpose(rotationMatrix, gCameraViewMatrix);

    transform.x = slot->x - playerMapOffsetX;
    transform.y = slot->y;
    transform.z = slot->z - playerMapOffsetZ;
    transform.pitch = -(slot->pitch - 0x8000);
    transform.yaw = -slot->yaw;
    transform.roll = -slot->roll;
    transform.scale = lbl_803DE5F0;
    if (pauseMenuGetState() == 0) {
        if (lbl_803DC88C != 0) {
            transform.y += slot->shakeMagnitude;
        }
        transform.x -= lbl_803DE60C;
        transform.y -= lbl_803DE60C;
        transform.z -= lbl_803DE60C;
    }

    setMatrixFromObjectPos((f32*)lbl_80338090, &transform);
    mtx44Transpose((f32*)lbl_80338090, gCameraInverseViewMatrix);
    PSMTXCopy(gCameraViewMatrix, gCameraViewRotationMatrix);
    gCameraViewRotationMatrix[3] = lbl_803DE60C;
    gCameraViewRotationMatrix[7] = lbl_803DE60C;
    gCameraViewRotationMatrix[11] = lbl_803DE60C;
    PSMTXCopy(gCameraInverseViewMatrix, gCameraInverseViewRotationMatrix);
    gCameraInverseViewRotationMatrix[3] = lbl_803DE60C;
    gCameraInverseViewRotationMatrix[7] = lbl_803DE60C;
    gCameraInverseViewRotationMatrix[11] = lbl_803DE60C;
}

/*
 * Function: Camera_ApplyFullViewport
 * EN v1.0 Address: 0x8000F780
 * EN v1.0 Size: 188b
 */
void Camera_ApplyFullViewport(void)
{
    CameraRenderMode* renderMode = lbl_803DCCF0;

    if (renderMode->useViewportJitter != 0) {
        GXSetViewportJitter(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                            (f32)renderMode->xfbHeight, lbl_803DE60C, lbl_803DE5F0,
                            lbl_803DCCBC);
    } else {
        GXSetViewport(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                      (f32)renderMode->xfbHeight, lbl_803DE60C, lbl_803DE5F0);
    }
}

/*
 * Function: fn_8000F83C
 * EN v1.0 Address: 0x8000F83C
 * EN v1.0 Size: 188b
 */
void fn_8000F83C(void)
{
    CameraRenderMode* renderMode = lbl_803DCCF0;

    if (renderMode->useViewportJitter != 0) {
        GXSetViewportJitter(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                            (f32)renderMode->xfbHeight, lbl_803DE640, lbl_803DE5F0,
                            lbl_803DCCBC);
    } else {
        GXSetViewport(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                      (f32)renderMode->xfbHeight, lbl_803DE640, lbl_803DB26C);
    }
}

/*
 * Function: fn_8000F8F8
 * EN v1.0 Address: 0x8000F8F8
 * EN v1.0 Size: 188b
 */
void fn_8000F8F8(void)
{
    CameraRenderMode* renderMode = lbl_803DCCF0;

    if (renderMode->useViewportJitter != 0) {
        GXSetViewportJitter(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                            (f32)renderMode->xfbHeight, lbl_803DE644, lbl_803DE5F0,
                            lbl_803DCCBC);
    } else {
        GXSetViewport(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                      (f32)renderMode->xfbHeight, lbl_803DE644, lbl_803DE5F0);
    }
}

/*
 * Function: fn_8000F9B4
 * EN v1.0 Address: 0x8000F9B4
 * EN v1.0 Size: 188b
 */
void fn_8000F9B4(void)
{
    CameraRenderMode* renderMode = lbl_803DCCF0;

    if (renderMode->useViewportJitter != 0) {
        GXSetViewportJitter(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                            (f32)renderMode->xfbHeight, lbl_803DE648, lbl_803DE5F0,
                            lbl_803DCCBC);
    } else {
        GXSetViewport(lbl_803DE60C, lbl_803DE60C, (f32)renderMode->fbWidth,
                      (f32)renderMode->xfbHeight, lbl_803DE648, lbl_803DE5F0);
    }
}

/*
 * Function: fn_8000FA70
 * EN v1.0 Address: 0x8000FA70
 * EN v1.0 Size: 32b
 */
u16 fn_8000FA70(void)
{
    return (u16)gCameraShakeSlots[gCameraCurrentViewIndex].yaw;
}

/*
 * Function: fn_8000FA90
 * EN v1.0 Address: 0x8000FA90
 * EN v1.0 Size: 28b
 */
u16 fn_8000FA90(void)
{
    return (u16)gCameraShakeSlots[gCameraCurrentViewIndex].pitch;
}

/*
 * Function: Camera_IsViewYOffsetEnabled
 * EN v1.0 Address: 0x8000FAC4
 * EN v1.0 Size: 8b
 */
u8 Camera_IsViewYOffsetEnabled(void)
{
    return lbl_803DC88C;
}

/*
 * Function: Camera_DisableViewYOffset
 * EN v1.0 Address: 0x8000FACC
 * EN v1.0 Size: 12b
 */
void Camera_DisableViewYOffset(void)
{
    lbl_803DC88C = 0;
}

/*
 * Function: Camera_EnableViewYOffset
 * EN v1.0 Address: 0x8000FAD8
 * EN v1.0 Size: 12b
 */
void Camera_EnableViewYOffset(void)
{
    lbl_803DC88C = 1;
}

/*
 * Function: Camera_GetViewportYOffset
 * EN v1.0 Address: 0x8000FAE4
 * EN v1.0 Size: 8b
 */
s16 Camera_GetViewportYOffset(void)
{
    return lbl_803DC886;
}

/*
 * Function: Camera_SetViewportYOffset
 * EN v1.0 Address: 0x8000FAEC
 * EN v1.0 Size: 8b
 */
void Camera_SetViewportYOffset(s16 yOffset)
{
    lbl_803DC886 = yOffset;
}

/*
 * Function: Camera_GetProjectionMatrix
 * EN v1.0 Address: 0x8000FAF4
 * EN v1.0 Size: 12b
 */
f32* Camera_GetProjectionMatrix(void)
{
    return gCameraProjectionMatrix;
}

/*
 * Function: Camera_RebuildProjectionMatrix
 * EN v1.0 Address: 0x8000FB00
 * EN v1.0 Size: 232b
 */
void Camera_RebuildProjectionMatrix(void)
{
    if (gCameraProjectionMode == 1) {
        C_MTXOrtho(gCameraProjectionMatrix, lbl_803DC8A0, lbl_803DC89C, lbl_803DC898,
                   lbl_803DC894, gCameraNearPlane, gCameraFarPlane);
    } else {
        C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio,
                         gCameraNearPlane, gCameraFarPlane);
        C_MTXLightPerspective(lbl_80396850, gCameraFovY, gCameraAspectRatio, lbl_803DE628,
                              lbl_803DE628, lbl_803DE62C, lbl_803DE62C);
        C_MTXLightPerspective(lbl_803967F0, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                              lbl_803DE62C, lbl_803DE62C, lbl_803DE62C);
        C_MTXLightPerspective(lbl_80396820, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                              lbl_803DE630, lbl_803DE62C, lbl_803DE62C);
    }
    GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);
}

/*
 * Function: Camera_GetFarPlane
 * EN v1.0 Address: 0x8000FBE8
 * EN v1.0 Size: 8b
 */
f32 Camera_GetFarPlane(void)
{
    return gCameraFarPlane;
}

/*
 * Function: Camera_SetFarPlane
 * EN v1.0 Address: 0x8000FBF0
 * EN v1.0 Size: 44b
 */
void Camera_SetFarPlane(f32 farPlane, int transitionFrames)
{
    if (transitionFrames != 0) {
        s16 frames = transitionFrames;
        lbl_803DC882 = frames;
        lbl_803DC880 = frames;
        lbl_803DC8AC = gCameraFarPlane;
        lbl_803DC8A8 = farPlane;
    } else {
        gCameraFarPlane = farPlane;
    }
}

/*
 * Function: Camera_GetNearPlane
 * EN v1.0 Address: 0x8000FC1C
 * EN v1.0 Size: 8b
 */
f32 Camera_GetNearPlane(void)
{
    return gCameraNearPlane;
}

/*
 * Function: Camera_GetAspectRatio
 * EN v1.0 Address: 0x8000FC24
 * EN v1.0 Size: 8b
 */
f32 Camera_GetAspectRatio(void)
{
    return gCameraAspectRatio;
}

/*
 * Function: Camera_SetAspectRatio
 * EN v1.0 Address: 0x8000FC2C
 * EN v1.0 Size: 8b
 */
void Camera_SetAspectRatio(f32 aspectRatio)
{
    gCameraAspectRatio = aspectRatio;
}

/*
 * Function: Camera_GetFovY
 * EN v1.0 Address: 0x8000FC34
 * EN v1.0 Size: 8b
 */
f32 Camera_GetFovY(void)
{
    return gCameraFovY;
}

/*
 * Function: Camera_SetFovY
 * EN v1.0 Address: 0x8000FC3C
 * EN v1.0 Size: 24b
 */
void Camera_SetFovY(f32 fovY)
{
    if (fovY == 0.0f) {
        fovY = 1.0f;
    }
    gCameraFovY = fovY;
}

/*
 * Function: Camera_InitState
 * EN v1.0 Address: 0x8000FC54
 * EN v1.0 Size: 568b
 */
void Camera_InitState(void)
{
    u32 i;
    CameraViewSlot* slot;
    f32* scaledProjection;
    f32* copiedProjection;

    for (i = 0; i < 12; i++) {
        slot = &gCameraShakeSlots[(u8)i];
        slot->roll = 0;
        slot->yaw = 0;
        slot->pitch = 0x7FF8;
        slot->x = lbl_803DE650;
        slot->y = lbl_803DE650;
        slot->z = lbl_803DE650;
        *(f32*)((u8*)slot + 0x20) = lbl_803DE60C;
        *(f32*)((u8*)slot + 0x24) = lbl_803DE60C;
        *(f32*)((u8*)slot + 0x28) = lbl_803DE60C;
        slot->shakeMagnitude = lbl_803DE60C;
        *(u32*)((u8*)slot + 0x40) = 0;
        *(s16*)((u8*)slot + 0x5A) = 0;
        *(f32*)((u8*)slot + 0x18) = lbl_803DE610;
    }

    gCameraCurrentViewIndex = 0;
    lbl_803DC88C = 0;
    gObjTransformMatrixSlot = 0;
    lbl_803DC884 = 0;
    lbl_803DC886 = 0;
    gCameraFarPlane = lbl_803DE64C;
    lbl_803DC880 = 0;
    gCameraFovY = lbl_803DE610;
    gCameraProjectionMode = 0;

    C_MTXPerspective(gCameraProjectionMatrix, gCameraFovY, gCameraAspectRatio, gCameraNearPlane,
                     gCameraFarPlane);
    C_MTXLightPerspective(lbl_80396850, gCameraFovY, gCameraAspectRatio, lbl_803DE628,
                          lbl_803DE628, lbl_803DE62C, lbl_803DE62C);
    C_MTXLightPerspective(lbl_803967F0, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                          lbl_803DE62C, lbl_803DE62C, lbl_803DE62C);
    C_MTXLightPerspective(lbl_80396820, gCameraFovY, gCameraAspectRatio, lbl_803DE62C,
                          lbl_803DE630, lbl_803DE62C, lbl_803DE62C);
    GXSetProjection(gCameraProjectionMatrix, gCameraProjectionMode);

    scaledProjection = (f32*)((u8*)gObjInverseYawTransformMatrices + 0x1080);
    copiedProjection = (f32*)((u8*)gObjInverseYawTransformMatrices + 0x0FC0);
    matrixFn_8006ff0c(gCameraFovY, gCameraAspectRatio, gCameraNearPlane, gCameraFarPlane,
                      lbl_803DE5F0, scaledProjection, &lbl_803DC88A);
    copyMatrix44(scaledProjection, copiedProjection);
}

/*
 * Function: fn_80010C50
 * EN v1.0 Address: 0x80010C50
 * EN v1.0 Size: 20b
 */
f32 fn_80010C50(f32 t, f32* values)
{
    return t * (values[1] - values[0]) + values[0];
}

/*
 * Function: mathFn_80010c64
 * EN v1.0 Address: 0x80010C64
 * EN v1.0 Size: 128b
 */
f32 mathFn_80010c64(f32 t, f32* values, f32* outTangent)
{
    f32 a = values[3] + (lbl_803DE668 * values[2] + (lbl_803DE664 * values[1] - values[0]));
    f32 b = (lbl_803DE65C * values[2] + (lbl_803DE660 * values[0] + lbl_803DE694 * values[1])) - values[3];
    f32 c = -values[0] + values[2];
    f32 d = lbl_803DE660 * values[1];

    if (outTangent != NULL) {
        *outTangent = t * (lbl_803DE660 * b + (lbl_803DE664 * a) * t) + c;
    }
    return lbl_803DE678 * (t * (t * (a * t + b) + c) + d);
}

/*
 * Function: curveFn_80010ce4
 * EN v1.0 Address: 0x80010CE4
 * EN v1.0 Size: 112b
 */
f32 curveFn_80010ce4(f32 t, f32* values, f32* outTangent)
{
    f32 a = values[3] + (lbl_803DE668 * values[2] + (lbl_803DE664 * values[1] - values[0]));
    f32 b = lbl_803DE664 * values[2] +
            (lbl_803DE664 * values[0] + lbl_803DE66C * values[1]);
    f32 c = lbl_803DE668 * values[0] + lbl_803DE664 * values[1];

    if (outTangent != NULL) {
        *outTangent = t * (lbl_803DE660 * b + (lbl_803DE664 * a) * t) + c;
    }
    return t * (t * (a * t + b) + c) + values[0];
}

/*
 * Function: curveFn_80010d54
 * EN v1.0 Address: 0x80010D54
 * EN v1.0 Size: 108b
 */
void curveFn_80010d54(f32* values, f32* coefficients)
{
    coefficients[0] = values[3] + (values[2] + (lbl_803DE660 * values[0] + lbl_803DE698 * values[1]));
    coefficients[1] = (lbl_803DE668 * values[0] + lbl_803DE664 * values[1] +
                       lbl_803DE698 * values[2]) -
                      values[3];
    coefficients[2] = values[2];
    coefficients[3] = values[0];
}

/*
 * Function: curveFn_80010dc0
 * EN v1.0 Address: 0x80010DC0
 * EN v1.0 Size: 108b
 */
f32 curveFn_80010dc0(f32 t, f32* values, f32* outTangent)
{
    f32 a = values[3] + (values[2] + (lbl_803DE660 * values[0] + lbl_803DE698 * values[1]));
    f32 b = (lbl_803DE698 * values[2] + (lbl_803DE668 * values[0] + lbl_803DE664 * values[1])) - values[3];

    if (outTangent != NULL) {
        *outTangent = t * (lbl_803DE660 * b + (lbl_803DE664 * a) * t) + values[2];
    }
    return t * (t * (a * t + b) + values[2]) + values[0];
}

/*
 * Function: fn_80010E2C
 * EN v1.0 Address: 0x80010E2C
 * EN v1.0 Size: 180b
 */
void fn_80010E2C(f32* values, f32* coefficients)
{
    f32 scale;

    coefficients[0] = values[3] + (lbl_803DE668 * values[2] + (lbl_803DE664 * values[1] - values[0]));
    coefficients[1] = lbl_803DE664 * values[2] +
                      (lbl_803DE664 * values[0] + lbl_803DE66C * values[1]);
    coefficients[2] = lbl_803DE668 * values[0] + lbl_803DE664 * values[2];
    coefficients[3] = values[2] + (values[0] + lbl_803DE65C * values[1]);

    scale = lbl_803DE670;
    coefficients[0] *= scale;
    coefficients[1] *= scale;
    coefficients[2] *= scale;
    coefficients[3] *= scale;
}

/*
 * Function: mathFn_80010ee0
 * EN v1.0 Address: 0x80010EE0
 * EN v1.0 Size: 140b
 */
f32 mathFn_80010ee0(f32 t, f32* values, f32* outTangent)
{
    f32 a = values[3] + (lbl_803DE668 * values[2] + (lbl_803DE664 * values[1] - values[0]));
    f32 b = lbl_803DE664 * values[2] +
            (lbl_803DE664 * values[0] + lbl_803DE66C * values[1]);
    f32 c = lbl_803DE668 * values[0] + lbl_803DE664 * values[2];
    f32 d = values[2] + (values[0] + lbl_803DE65C * values[1]);

    if (outTangent != NULL) {
        *outTangent = lbl_803DE670 *
                      (t * (lbl_803DE660 * b + (lbl_803DE664 * a) * t) + c);
    }
    return lbl_803DE670 * (t * (t * (a * t + b) + c) + d);
}

typedef struct CurveHeapNode {
    u16 priority;
    u16 value;
} CurveHeapNode;

/*
 * Function: fn_80010F6C
 * EN v1.0 Address: 0x80010F6C
 * EN v1.0 Size: 136b
 */
void fn_80010F6C(CurveHeapNode* heap, s32 count, s32 index)
{
    u16 priority = heap[index].priority;
    u16 value = heap[index].value;

    while (index <= count >> 1) {
        s32 child = index * 2;

        if ((child < count) && (heap[child].priority < heap[child + 1].priority)) {
            child++;
        }

        if (heap[child].priority <= priority) {
            break;
        }

        heap[index].priority = heap[child].priority;
        heap[index].value = heap[child].value;
        index = child;
    }

    heap[index].priority = priority;
    heap[index].value = value;
}

typedef struct RingBufferQueue {
    s16 count;
    s16 capacity;
    s16 elemSize;
    s16 unused;
    s16 writeIndex;
    s16 readIndex;
    void* data;
} RingBufferQueue;

typedef struct ModelRenderInstrsState {
    void* instrs;
    s32 byteCount;
    s32 bitCount;
    s32 fieldC;
    s32 bit;
} ModelRenderInstrsState;

typedef struct ObjLinkedList {
    s16 count;
    s16 nextOffset;
    int head;
} ObjLinkedList;

typedef struct ModelList {
    s16* entries;
    s16* end;
    s16* capacityEnd;
    u8 dataSize;
    u8 strideShorts;
    u8 pad0E[6];
} ModelList;

typedef struct ResourceDescriptor {
    u8 pad00[0x10];
    void (*acquire)(struct ResourceDescriptor* descriptor);
    void (*release)(void);
    u8 data[0];
} ResourceDescriptor;

typedef struct UiDllVTable {
    void* field0;
    int (*frameStart)(void);
    void (*frameEnd)(void);
    void (*draw)(void);
} UiDllVTable;

extern int memcmp(const void* lhs, const void* rhs, u32 size);
extern void* memcpy(void* dst, const void* src, u32 size);
extern void* memset(void* dst, int value, u32 size);
extern ResourceDescriptor* gResourceDescriptors[];
extern void* gResourceLoadedHandles[];
extern u16 gResourceRefCounts[];

/*
 * Function: Queue_GetCount
 * EN v1.0 Address: 0x80013754
 * EN v1.0 Size: 8b
 */
s16 Queue_GetCount(RingBufferQueue* queue)
{
    return queue->count;
}

/*
 * Function: Queue_IsEmpty
 * EN v1.0 Address: 0x8001375C
 * EN v1.0 Size: 16b
 */
BOOL Queue_IsEmpty(RingBufferQueue* queue)
{
    return queue->count == 0;
}

/*
 * Function: Queue_Peek
 * EN v1.0 Address: 0x8001376C
 * EN v1.0 Size: 60b
 */
void Queue_Peek(RingBufferQueue* queue, void* dst)
{
    memcpy(dst, (u8*)queue->data + queue->readIndex * queue->elemSize, queue->elemSize);
}

/*
 * Function: Queue_Pop
 * EN v1.0 Address: 0x800137A8
 * EN v1.0 Size: 116b
 */
void Queue_Pop(RingBufferQueue* queue, void* dst)
{
    s16 readIndex;

    memcpy(dst, (u8*)queue->data + queue->readIndex * queue->elemSize, queue->elemSize);
    readIndex = queue->readIndex + 1;
    queue->readIndex = readIndex;
    if (readIndex == queue->capacity) {
        queue->readIndex = 0;
    }
    queue->count--;
}

/*
 * Function: Queue_Push
 * EN v1.0 Address: 0x8001381C
 * EN v1.0 Size: 112b
 */
void Queue_Push(RingBufferQueue* queue, void* src)
{
    s16 writeIndex;

    memcpy((u8*)queue->data + queue->writeIndex * queue->elemSize, src, queue->elemSize);
    writeIndex = queue->writeIndex + 1;
    queue->writeIndex = writeIndex;
    if (writeIndex == queue->capacity) {
        queue->writeIndex = 0;
    }
    queue->count++;
}

/*
 * Function: Queue_Init
 * EN v1.0 Address: 0x8001388C
 * EN v1.0 Size: 40b
 */
void Queue_Init(RingBufferQueue* queue, void* data, int capacity, int elemSize)
{
    queue->data = data;
    queue->count = 0;
    queue->capacity = capacity;
    queue->elemSize = elemSize;
    queue->writeIndex = 0;
    queue->readIndex = 0;
}

/*
 * Function: Stack_IsEmpty
 * EN v1.0 Address: 0x800138B4
 * EN v1.0 Size: 16b
 */
BOOL Stack_IsEmpty(RingBufferQueue* stack)
{
    return stack->count == 0;
}

/*
 * Function: Stack_IsFull
 * EN v1.0 Address: 0x800138C4
 * EN v1.0 Size: 28b
 */
BOOL Stack_IsFull(RingBufferQueue* stack)
{
    return stack->count == stack->capacity - 1;
}

/*
 * Function: Stack_Pop
 * EN v1.0 Address: 0x800138E0
 * EN v1.0 Size: 120b
 */
void Stack_Pop(RingBufferQueue* stack, void* dst)
{
    s16 writeIndex = stack->writeIndex - 1;

    stack->writeIndex = writeIndex;
    if (writeIndex < 0) {
        writeIndex = stack->capacity - 1;
        stack->writeIndex = writeIndex;
    }
    memcpy(dst, (u8*)stack->data + stack->writeIndex * stack->elemSize, stack->elemSize);
    stack->count--;
}

/*
 * Function: Stack_Push
 * EN v1.0 Address: 0x80013958
 * EN v1.0 Size: 112b
 */
void Stack_Push(RingBufferQueue* stack, void* src)
{
    s16 writeIndex;

    memcpy((u8*)stack->data + stack->writeIndex * stack->elemSize, src, stack->elemSize);
    writeIndex = stack->writeIndex + 1;
    stack->writeIndex = writeIndex;
    if (writeIndex == stack->capacity) {
        stack->writeIndex = 0;
    }
    stack->count++;
}

/*
 * Function: Stack_Free
 * EN v1.0 Address: 0x800139C8
 * EN v1.0 Size: 32b
 */
void Stack_Free(RingBufferQueue* stack)
{
    mm_free(stack);
}

/*
 * Function: allocModelStruct_800139e8
 * EN v1.0 Address: 0x800139E8
 * EN v1.0 Size: 108b
 */
RingBufferQueue* allocModelStruct_800139e8(int capacity, int elemSize)
{
    RingBufferQueue* queue = mmAlloc(elemSize * capacity + sizeof(RingBufferQueue), 0x1a, NULL);
    queue->data = (u8*)queue + sizeof(RingBufferQueue);
    queue->count = 0;
    queue->capacity = capacity;
    queue->elemSize = elemSize;
    queue->writeIndex = 0;
    return queue;
}

/*
 * Function: modelRenderInstrsState_getBit
 * EN v1.0 Address: 0x80013A54
 * EN v1.0 Size: 8b
 */
s32 modelRenderInstrsState_getBit(ModelRenderInstrsState* state)
{
    return state->bit;
}

/*
 * Function: modelRenderInstrsState_setBit
 * EN v1.0 Address: 0x80013A5C
 * EN v1.0 Size: 8b
 */
void modelRenderInstrsState_setBit(ModelRenderInstrsState* state, s32 bit)
{
    state->bit = bit;
}

/*
 * Function: modelRenderInstrsState_init
 * EN v1.0 Address: 0x80013A64
 * EN v1.0 Size: 56b
 */
void modelRenderInstrsState_init(ModelRenderInstrsState* state, void* instrs, int bitCount, int fieldC)
{
    state->byteCount = bitCount >> 3;
    if ((bitCount & 7) != 0) {
        state->byteCount++;
    }
    state->bitCount = bitCount;
    state->fieldC = fieldC;
    state->instrs = instrs;
    state->bit = 0;
}

/*
 * Function: objList_remove
 * EN v1.0 Address: 0x80013A9C
 * EN v1.0 Size: 132b
 */
void objList_remove(ObjLinkedList* list, int item)
{
    int head;
    int prev;
    int current;
    int next;

    head = list->head;
    if (head == item) {
        list->head = *(int*)(head + list->nextOffset);
        list->count--;
        return;
    }

    current = head;
    prev = head;
    while (current != 0 && current != item) {
        prev = current;
        current = *(int*)(current + list->nextOffset);
    }

    if (current == 0) {
        return;
    }

    next = *(int*)(current + list->nextOffset);
    if (current == head) {
        list->head = next;
    } else {
        *(int*)(prev + list->nextOffset) = next;
    }
    list->count--;
}

/*
 * Function: objListAdd
 * EN v1.0 Address: 0x80013B20
 * EN v1.0 Size: 76b
 */
void objListAdd(ObjLinkedList* list, int prev, int item)
{
    int next;

    if (list->head == 0) {
        list->head = item;
    } else {
        if (prev == 0) {
            next = list->head;
            list->head = item;
        } else {
            next = *(int*)(prev + list->nextOffset);
            *(int*)(prev + list->nextOffset) = item;
        }
        *(int*)(item + list->nextOffset) = next;
    }
    list->count++;
}

/*
 * Function: fn_80013B6C
 * EN v1.0 Address: 0x80013B6C
 * EN v1.0 Size: 16b
 */
void fn_80013B6C(ObjLinkedList* list, s16 nextOffset)
{
    list->head = 0;
    list->nextOffset = nextOffset;
}

/*
 * Function: model_findIdxInModelList
 * EN v1.0 Address: 0x80013B7C
 * EN v1.0 Size: 148b
 */
BOOL model_findIdxInModelList(ModelList* list, void* header, int* outIndex)
{
    s16* entry;

    entry = list->entries;
    while (entry < list->end) {
        if (memcmp(entry + 1, header, list->dataSize) == 0) {
            *outIndex = *entry;
            return TRUE;
        }
        entry += list->strideShorts;
    }
    return FALSE;
}

/*
 * Function: ModelList_getHeader
 * EN v1.0 Address: 0x80013C10
 * EN v1.0 Size: 104b
 */
BOOL ModelList_getHeader(ModelList* list, int index, void* outHeader)
{
    s16* entry;

    entry = list->entries;
    while (entry < list->end) {
        if (*entry == index) {
            memcpy(outHeader, entry + 1, list->dataSize);
            return TRUE;
        }
        entry += list->strideShorts;
    }
    return FALSE;
}

/*
 * Function: model_adjustModelList
 * EN v1.0 Address: 0x80013C78
 * EN v1.0 Size: 112b
 */
void model_adjustModelList(ModelList* list, int index)
{
    s16* entry;

    entry = list->entries;
    while (entry < list->end) {
        if (*entry == index) {
            *entry = -1;
            break;
        }
        entry += list->strideShorts;
    }

    goto checkTail;
trimTail:
    list->end = (s16*)((u8*)list->end - list->strideShorts * 2);
checkTail:
    if (list->end <= list->entries) {
        return;
    }
    if (list->end[-1] == -1) {
        goto trimTail;
    }
    return;
}

/*
 * Function: modelInitModelList
 * EN v1.0 Address: 0x80013CE8
 * EN v1.0 Size: 140b
 */
void modelInitModelList(ModelList* list, s16 index, void* header)
{
    s16* entry;

    for (entry = list->entries; entry < list->end; entry += list->strideShorts) {
        if (*entry == -1) {
            break;
        }
    }

    *entry = index;
    memcpy(entry + 1, header, list->dataSize);
    if (entry == list->end) {
        list->end += list->strideShorts;
    }
}

/*
 * Function: allocModelStruct
 * EN v1.0 Address: 0x80013D74
 * EN v1.0 Size: 184b
 */
ModelList* allocModelStruct(int capacity, int dataSize)
{
    ModelList* list;
    int entryBytes;

    entryBytes = dataSize + 2;
    list = mmAlloc(capacity * entryBytes + sizeof(ModelList), 0x1a, NULL);
    list->entries = (s16*)((u8*)list + sizeof(ModelList));
    list->dataSize = dataSize;
    list->strideShorts = entryBytes >> 1;
    list->end = list->entries;
    list->capacityEnd = list->entries + capacity * list->strideShorts;
    memset(list->entries, -1, capacity * list->strideShorts * 2);
    return list;
}

/*
 * Function: Resource_Release
 * EN v1.0 Address: 0x80013E2C
 * EN v1.0 Size: 156b
 */
#pragma dont_inline on
BOOL Resource_Release(void* handleSlot)
{
    s32 i;
    ResourceDescriptor* descriptor;
    void** loadedHandle;

    i = 0;
    descriptor = (ResourceDescriptor*)handleSlot;
    loadedHandle = gResourceLoadedHandles;
    while (i < 0x2c1) {
        if ((void*)loadedHandle == handleSlot) {
            descriptor = gResourceDescriptors[i];
            break;
        }
        loadedHandle++;
        i++;
    }

    gResourceRefCounts[i]--;
    if (gResourceRefCounts[i] == 0) {
        if (descriptor->release != NULL) {
            descriptor->release();
        }
        return TRUE;
    }
    return FALSE;
}

/*
 * Function: Resource_Acquire
 * EN v1.0 Address: 0x80013EC8
 * EN v1.0 Size: 160b
 */
void* Resource_Acquire(u32 id, int unused)
{
    u32 index;
    ResourceDescriptor* descriptor;

    index = id & 0xffff;
    descriptor = gResourceDescriptors[index];
    if (gResourceRefCounts[index] == 0 && descriptor->acquire != NULL) {
        descriptor->acquire(descriptor);
    }
    gResourceRefCounts[index]++;
    gResourceLoadedHandles[index] = descriptor->data;
    return &gResourceLoadedHandles[index];
}
#pragma dont_inline reset

/*
 * Function: Resource_ResetRefCounts
 * EN v1.0 Address: 0x80013F68
 * EN v1.0 Size: 228b
 */
void Resource_ResetRefCounts(void)
{
    s32 i;

    for (i = 0; i < 0x2c1; i++) {
        gResourceRefCounts[i] = 0;
    }
}

extern u8 lbl_803DC8F8;
extern s8 lbl_803DC8F9;
extern UiDllVTable** lbl_803DC8E8;
extern int lbl_803DC8EC;
extern int lbl_803DC8F0;
extern int lbl_803DC8F4;
extern f32 lbl_803DC8FC;
extern f32 lbl_803DC900;
extern f32 lbl_803DC90C;
extern u8 lbl_803DC908;
extern u8 lbl_803DC909;
extern u32 lbl_803DC910;
extern u8 lbl_803DB2A8;
extern s32 lbl_803DB278;
extern s32 lbl_803DB28C;
extern char lbl_803DB290;
extern char lbl_803398A0[];
extern u32 lbl_802C6E50[];
extern u8 lbl_803DC934;
extern u8 lbl_803DC938;
extern u8 lbl_803DC93C;
extern u8 lbl_803DC940;
extern u8 lbl_803DC944;
extern u8 lbl_803DC948;
extern u16 lbl_803DC914;
extern u16 lbl_803DC91C;
extern u16 lbl_803DC924;
extern u16 lbl_803DC92C;
extern u8 lbl_803DC94C;
extern u8 lbl_803DC950;
extern u32 lbl_803398B0[];
extern u32 lbl_803398C0[];
extern u32 lbl_803398D0[];
extern u32 lbl_803398E0[];
extern u8 lbl_803398F0[];
extern s32 lbl_802C6E08[];
extern u8 lbl_802C7400[];
extern void* lbl_803DC954;
extern volatile int lbl_803DC958;
extern void* lbl_803DC9CC;
extern f32 lbl_803DE6B8;
extern f32 lbl_803DE6D4;
extern f64 lbl_803DE6D8;
extern f32 lbl_803DE6E0;
extern f32 lbl_803DE6E8;
extern volatile int lbl_803DC7BC;
extern int lbl_803DC7B8;
extern int gRenderMode;
extern int lbl_803DC9C8;
extern u8 lbl_8033A540[];
extern void ARQPostRequest(void* req, u32 owner, u32 type, u32 prio, u32 src, u32 dst, u32 size, void (*cb)(void*));

extern int sprintf(char* buf, const char* fmt, ...);
extern char* strcpy(char* dst, const char* src);
extern char* strcat(char* dst, const char* src);
extern void gameTextShowStr(char* text, int box, int arg2, int arg3);
extern void PADControlMotor(s32 chan, u32 command);
extern int PADInit(void);
extern int PADRecalibrate(u32 mask);
extern int PADReset(u32 mask);

typedef struct PadStatusLite {
    u16 buttons;
    s8 stickX;
    s8 stickY;
    s8 substickX;
    s8 substickY;
    u8 triggerLeft;
    u8 triggerRight;
    u8 analogA;
    u8 analogB;
    s8 error;
} PadStatusLite;

/*
 * Function: concatThreeStrings
 * EN v1.0 Address: 0x8000A200
 * EN v1.0 Size: 100b
 */
int concatThreeStrings(char* dst, void* unused, const char* first, const char* second, const char* third)
{
    strcpy(dst, first);
    strcat(dst, second);
    strcat(dst, third);
    return 1;
}

/*
 * Function: fn_8001404C
 * EN v1.0 Address: 0x8001404C
 * EN v1.0 Size: 8b
 */
void fn_8001404C(s32 value)
{
    lbl_803DB28C = value;
}

/*
 * Function: gameTimerIsRunning
 * EN v1.0 Address: 0x80014054
 * EN v1.0 Size: 12b
 */
u32 gameTimerIsRunning(void)
{
    return lbl_803DC8F8 & 4;
}

/*
 * Function: hudNumberFn_80014060
 * EN v1.0 Address: 0x80014060
 * EN v1.0 Size: 84b
 */
void hudNumberFn_80014060(void)
{
    if (lbl_803DB278 != -1) {
        sprintf(lbl_803398A0, &lbl_803DB290, lbl_803DB278);
        gameTextShowStr(lbl_803398A0, 13, 0, 0);
    }
}

/*
 * Function: set_hudNumber_803db278
 * EN v1.0 Address: 0x800140B4
 * EN v1.0 Size: 8b
 */
void set_hudNumber_803db278(s32 value)
{
    lbl_803DB278 = value;
}

/*
 * Function: isGameTimerDisabled
 * EN v1.0 Address: 0x80014670
 * EN v1.0 Size: 12b
 */
u32 isGameTimerDisabled(void)
{
    return lbl_803DC8F8 & 2;
}

/*
 * Function: gameTimerStop
 * EN v1.0 Address: 0x8001467C
 * EN v1.0 Size: 32b
 */
void gameTimerStop(void)
{
    lbl_803DC8F8 &= ~4;
    lbl_803DC8F8 |= 2;
}

/*
 * Function: fn_8001461C
 * EN v1.0 Address: 0x8001461C
 * EN v1.0 Size: 76b
 */
f32 fn_8001461C(void)
{
    if (((s8)lbl_803DC8F9 & 1) != 0) {
        return lbl_803DE6E0 * ((lbl_803DC8FC - lbl_803DC900) / lbl_803DE6D4);
    }
    return lbl_803DE6E0 * (lbl_803DC900 / lbl_803DE6D4);
}

/*
 * Function: fn_80014668
 * EN v1.0 Address: 0x80014668
 * EN v1.0 Size: 8b
 */
f32 fn_80014668(void)
{
    return lbl_803DC900;
}

/*
 * Function: timerSetToCountUp
 * EN v1.0 Address: 0x8001469C
 * EN v1.0 Size: 32b
 */
void timerSetToCountUp(void)
{
    if ((lbl_803DC8F8 & 1) != 0) {
        lbl_803DC8F8 &= ~1;
    }
}

/*
 * Function: gameTimerInit
 * EN v1.0 Address: 0x800146BC
 * EN v1.0 Size: 176b
 */
void gameTimerInit(s8 flags, int minutes)
{
    lbl_803DC8F9 = flags;
    if ((flags & 1) != 0) {
        lbl_803DC900 = minutes * 60;
    } else {
        lbl_803DC900 = lbl_803DE6B8;
    }
    lbl_803DC8FC = minutes * 60;
    lbl_803DC8F8 |= 1;
    lbl_803DC8F8 &= ~2;
    if ((flags & 3) != 0) {
        lbl_803DC8F8 |= 4;
    } else {
        lbl_803DC8F8 &= ~4;
    }
}

/*
 * Function: curUiDllDraw
 * EN v1.0 Address: 0x8001476C
 * EN v1.0 Size: 56b
 */
void curUiDllDraw(void)
{
    UiDllVTable* callbacks;

    if (lbl_803DC8E8 != NULL) {
        callbacks = *lbl_803DC8E8;
        callbacks->draw();
    }
}

/*
 * Function: uiDll_runFrameEndAndLoadNext
 * EN v1.0 Address: 0x800147A4
 * EN v1.0 Size: 184b
 */
void uiDll_runFrameEndAndLoadNext(void)
{
    UiDllVTable* callbacks;
    s32 resourceId;

    if (lbl_803DC8E8 != NULL) {
        callbacks = *lbl_803DC8E8;
        callbacks->frameEnd();
    }

    if (lbl_803DC8EC != 0) {
        lbl_803DC8EC--;
        lbl_803DC8F4 = lbl_803DC8F0;
        if (lbl_803DC8E8 != NULL) {
            Resource_Release(lbl_803DC8E8);
            lbl_803DC8E8 = NULL;
        }

        resourceId = lbl_802C6E08[lbl_803DC8EC];
        if (resourceId != -1) {
            lbl_803DC8E8 = Resource_Acquire(resourceId, 1);
        } else {
            lbl_803DC8E8 = NULL;
            lbl_803DC8EC = 0;
        }
        lbl_803DC8F0 = lbl_803DC8EC;
        lbl_803DC8EC = 0;
    }
}

/*
 * Function: uiDll_runFrameStartAndLoadNext
 * EN v1.0 Address: 0x8001485C
 * EN v1.0 Size: 204b
 */
int uiDll_runFrameStartAndLoadNext(void)
{
    UiDllVTable* callbacks;
    int result;
    s32 resourceId;

    result = 0;
    if (lbl_803DC8E8 != NULL) {
        callbacks = *lbl_803DC8E8;
        result = callbacks->frameStart();
    }

    if (lbl_803DC8EC != 0) {
        lbl_803DC8EC--;
        lbl_803DC8F4 = lbl_803DC8F0;
        if (lbl_803DC8E8 != NULL) {
            Resource_Release(lbl_803DC8E8);
            lbl_803DC8E8 = NULL;
        }

        resourceId = lbl_802C6E08[lbl_803DC8EC];
        if (resourceId != -1) {
            lbl_803DC8E8 = Resource_Acquire(resourceId, 1);
        } else {
            lbl_803DC8E8 = NULL;
            lbl_803DC8EC = 0;
        }
        lbl_803DC8F0 = lbl_803DC8EC;
        lbl_803DC8EC = 0;
    }
    return result;
}

/*
 * Function: set_uiDllIdx_803dc8f0
 * EN v1.0 Address: 0x80014928
 * EN v1.0 Size: 8b
 */
void set_uiDllIdx_803dc8f0(int idx)
{
    lbl_803DC8F0 = idx;
}

/*
 * Function: getUiDllFn_80014930
 * EN v1.0 Address: 0x80014930
 * EN v1.0 Size: 8b
 */
int getUiDllFn_80014930(void)
{
    return lbl_803DC8F4;
}

/*
 * Function: getCurUiDll
 * EN v1.0 Address: 0x80014940
 * EN v1.0 Size: 8b
 */
int getCurUiDll(void)
{
    return lbl_803DC8F0;
}

/*
 * Function: getDLL16
 * EN v1.0 Address: 0x80014938
 * EN v1.0 Size: 8b
 */
void* getDLL16(void)
{
    return lbl_803DC8E8;
}

/*
 * Function: loadUiDll
 * EN v1.0 Address: 0x80014948
 * EN v1.0 Size: 176b
 */
void loadUiDll(int index)
{
    s32 current;
    s32 next;
    s32 resourceId;

    current = lbl_803DC8F0;
    if (index != current) {
        next = index + 1;
        lbl_803DC8EC = next;
        if (lbl_803DC8E8 == NULL && next != 0) {
            lbl_803DC8EC = next - 1;
            lbl_803DC8F4 = current;
            if (lbl_803DC8E8 != NULL) {
                Resource_Release(lbl_803DC8E8);
                lbl_803DC8E8 = NULL;
            }

            resourceId = lbl_802C6E08[lbl_803DC8EC];
            if (resourceId != -1) {
                lbl_803DC8E8 = Resource_Acquire(resourceId, 1);
            } else {
                lbl_803DC8E8 = NULL;
                lbl_803DC8EC = 0;
            }
            lbl_803DC8F0 = lbl_803DC8EC;
            lbl_803DC8EC = 0;
        }
    }
}

/*
 * Function: initGameTimer
 * EN v1.0 Address: 0x800149F8
 * EN v1.0 Size: 48b
 */
void initGameTimer(void)
{
    lbl_803DC8E8 = NULL;
    lbl_803DC8EC = 0;
    lbl_803DC8F4 = 0;
    lbl_803DC8F0 = 0;
    lbl_803DC8F8 = 2;
    lbl_803DC8F9 = 0;
    lbl_803DC900 = 0.0f;
    lbl_803DC8FC = 0.0f;
}

/*
 * Function: setJoypadDisabled
 * EN v1.0 Address: 0x80014B0C
 * EN v1.0 Size: 12b
 */
void setJoypadDisabled(void)
{
    lbl_803DC908 = 1;
}

/*
 * Function: padFn_80014b18
 * EN v1.0 Address: 0x80014B18
 * EN v1.0 Size: 12b
 */
void padFn_80014b18(int value)
{
    lbl_803DB2A8 = (u8)value;
}

/*
 * Function: buttonGetDisabled
 * EN v1.0 Address: 0x80014B24
 * EN v1.0 Size: 24b
 */
u32 buttonGetDisabled(int port)
{
    return ~lbl_802C6E50[port];
}

/*
 * Function: buttonDisable
 * EN v1.0 Address: 0x80014B3C
 * EN v1.0 Size: 28b
 */
void buttonDisable(int port, u32 mask)
{
    lbl_802C6E50[port] &= ~mask;
}

/*
 * Function: padClearAnalogInputY
 * EN v1.0 Address: 0x80014B58
 * EN v1.0 Size: 16b
 */
void padClearAnalogInputY(int port)
{
    (&lbl_803DC934)[port] = 0;
}

/*
 * Function: padClearAnalogInputX
 * EN v1.0 Address: 0x80014B68
 * EN v1.0 Size: 16b
 */
void padClearAnalogInputX(int port)
{
    (&lbl_803DC938)[port] = 0;
}

/*
 * Function: stopRumble2
 * EN v1.0 Address: 0x80014A28
 * EN v1.0 Size: 60b
 */
void stopRumble2(void)
{
    if (lbl_803DC909 != 0) {
        PADControlMotor(0, 2);
        lbl_803DC90C = lbl_803DE6E8;
    }
}

/*
 * Function: stopRumble
 * EN v1.0 Address: 0x80014A64
 * EN v1.0 Size: 60b
 */
void stopRumble(void)
{
    if (lbl_803DC909 != 0) {
        PADControlMotor(0, 0);
        lbl_803DC90C = lbl_803DE6E8;
    }
}

/*
 * Function: doRumble
 * EN v1.0 Address: 0x80014AA0
 * EN v1.0 Size: 108b
 */
void doRumble(f32 duration)
{
    if (lbl_803DC909 != 0 && getGameState() == 1) {
        f32 rumbleTimer;

        PADControlMotor(0, 1);
        rumbleTimer = lbl_803DC90C;
        if (rumbleTimer <= duration) {
            rumbleTimer = duration;
        }
        lbl_803DC90C = rumbleTimer;
    }
}

/*
 * Function: setRumbleEnabled
 * EN v1.0 Address: 0x800154A4
 * EN v1.0 Size: 8b
 */
void setRumbleEnabled(u8 enabled)
{
    lbl_803DC909 = enabled;
}

/*
 * Function: fileReadCb_80015954
 * EN v1.0 Address: 0x80015954
 * EN v1.0 Size: 8b
 */
void fileReadCb_80015954(void* result)
{
    lbl_803DC958 = (int)result;
}

/*
 * Function: setFileInfo
 * EN v1.0 Address: 0x8001595C
 * EN v1.0 Size: 8b
 */
void setFileInfo(void* fileInfo)
{
    lbl_803DC954 = fileInfo;
}

/*
 * Function: isSpace
 * EN v1.0 Address: 0x80015BC8
 * EN v1.0 Size: 40b
 */
int isSpace(u32 c)
{
    int result = 0;

    if (c == 0x20 || c == 0x3000 || c == 0x303F) {
        result = 1;
    }
    return result;
}

/*
 * Function: padGetAnalogInput
 * EN v1.0 Address: 0x80014B78
 * EN v1.0 Size: 76b
 */
void padGetAnalogInput(int port, u8* x, u8* y)
{
    if (lbl_803DC908 != 0 || port > 0 || lbl_803DC950 != 0) {
        *x = 0;
        *y = 0;
        return;
    }
    *x = (&lbl_803DC938)[port];
    *y = (&lbl_803DC934)[port];
}

/*
 * Function: padGetCY
 * EN v1.0 Address: 0x80014BC4
 * EN v1.0 Size: 84b
 */
u8 padGetCY(int port)
{
    PadStatusLite* statuses;

    if (port > 0) {
        return 0;
    }
    if (lbl_803DC908 != 0 || lbl_803DC950 != 0) {
        return 0;
    }
    statuses = (PadStatusLite*)lbl_803398F0;
    return statuses[lbl_803DC94C * 4 + port].substickY;
}

/*
 * Function: padGetCX
 * EN v1.0 Address: 0x80014C18
 * EN v1.0 Size: 84b
 */
u8 padGetCX(int port)
{
    PadStatusLite* statuses;

    if (port > 0) {
        return 0;
    }
    if (lbl_803DC908 != 0 || lbl_803DC950 != 0) {
        return 0;
    }
    statuses = (PadStatusLite*)lbl_803398F0;
    return statuses[lbl_803DC94C * 4 + port].substickX;
}

/*
 * Function: padGetStickY
 * EN v1.0 Address: 0x80014C6C
 * EN v1.0 Size: 84b
 */
u8 padGetStickY(int port)
{
    PadStatusLite* statuses;

    if (port > 0) {
        return 0;
    }
    if (lbl_803DC908 != 0 || lbl_803DC950 != 0) {
        return 0;
    }
    statuses = (PadStatusLite*)lbl_803398F0;
    return statuses[lbl_803DC94C * 4 + port].stickY;
}

/*
 * Function: padGetStickX
 * EN v1.0 Address: 0x80014CC0
 * EN v1.0 Size: 84b
 */
u8 padGetStickX(int port)
{
    PadStatusLite* statuses;

    if (port > 0) {
        return 0;
    }
    if (lbl_803DC908 != 0 || lbl_803DC950 != 0) {
        return 0;
    }
    statuses = (PadStatusLite*)lbl_803398F0;
    return statuses[lbl_803DC94C * 4 + port].stickX;
}

/*
 * Function: padGetLTrigger
 * EN v1.0 Address: 0x80014D14
 * EN v1.0 Size: 68b
 */
u8 padGetLTrigger(int port)
{
    PadStatusLite* statuses;

    if (lbl_803DC908 != 0 || lbl_803DC950 != 0) {
        return 0;
    }
    statuses = (PadStatusLite*)lbl_803398F0;
    return statuses[lbl_803DC94C * 4 + port].triggerLeft;
}

/*
 * Function: padGetRTrigger
 * EN v1.0 Address: 0x80014D58
 * EN v1.0 Size: 68b
 */
u8 padGetRTrigger(int port)
{
    PadStatusLite* statuses;

    if (lbl_803DC908 != 0 || lbl_803DC950 != 0) {
        return 0;
    }
    statuses = (PadStatusLite*)lbl_803398F0;
    return statuses[lbl_803DC94C * 4 + port].triggerRight;
}

/*
 * Function: getPadFn_80014d9c
 * EN v1.0 Address: 0x80014D9C
 * EN v1.0 Size: 60b
 */
u16 getPadFn_80014d9c(int port)
{
    if (port > 0) {
        port = 0;
    }
    if (lbl_803DC908 != 0 || lbl_803DC950 != 0) {
        return 0;
    }
    return (&lbl_803DC92C)[port];
}

/*
 * Function: getButtons_80014dd8
 * EN v1.0 Address: 0x80014DD8
 * EN v1.0 Size: 60b
 */
u16 getButtons_80014dd8(int port)
{
    if (port > 0) {
        port = 0;
    }
    if (lbl_803DC908 != 0 || lbl_803DC950 != 0) {
        return 0;
    }
    return (&lbl_803DC91C)[port];
}

/*
 * Function: getButtonsJustPressedIfNotBusy
 * EN v1.0 Address: 0x80014E14
 * EN v1.0 Size: 92b
 */
u32 getButtonsJustPressedIfNotBusy(int port)
{
    if (port > 0) {
        return 0;
    }
    if (lbl_803DC950 != 0) {
        return 0;
    }
    if (lbl_803DC908 != 0) {
        return -1;
    }
    return lbl_803398D0[port] & lbl_802C6E50[port];
}

/*
 * Function: getButtonsJustPressed
 * EN v1.0 Address: 0x80014E70
 * EN v1.0 Size: 84b
 */
u32 getButtonsJustPressed(int port)
{
    if (port > 0) {
        return 0;
    }
    if (lbl_803DC908 != 0 || lbl_803DC950 != 0) {
        return 0;
    }
    return lbl_803398E0[port] & lbl_802C6E50[port];
}

/*
 * Function: getNewInputs
 * EN v1.0 Address: 0x80014EC4
 * EN v1.0 Size: 36b
 */
u32 getNewInputs(int port)
{
    if (port > 0) {
        return 0;
    }
    return lbl_803398C0[port];
}

/*
 * Function: getButtonsHeld
 * EN v1.0 Address: 0x80014EE8
 * EN v1.0 Size: 84b
 */
u32 getButtonsHeld(int port)
{
    if (port > 0) {
        return 0;
    }
    if (lbl_803DC908 != 0 || lbl_803DC950 != 0) {
        return 0;
    }
    return lbl_803398C0[port] & lbl_802C6E50[port];
}

/*
 * Function: initControllers
 * EN v1.0 Address: 0x800154AC
 * EN v1.0 Size: 376b
 */
int initControllers(void)
{
    s32 i;
    u32* padStateBlock;
    u32* heldButtons;
    u32* buttonsPressed;
    u32* buttonsReleased;
    u8* prevStickY;
    u8* prevStickX;
    u8* repeatY;
    u8* repeatX;
    u8* analogY;
    u8* analogX;
    u16* prevTriggers;
    u16* triggers;
    u16* triggersReleased;
    u16* triggersPressed;
    PadStatusLite* statuses;

    padStateBlock = lbl_803398B0;
    statuses = (PadStatusLite*)((u8*)padStateBlock + 0x40);
    lbl_803DC910 = 0xF0000000;
    PADInit();
    PADRecalibrate(lbl_803DC910);
    if (PADReset(lbl_803DC910) != 0) {
        lbl_803DC910 = 0;
    }

    prevStickY = &lbl_803DC944;
    prevStickX = &lbl_803DC948;
    repeatY = &lbl_803DC93C;
    repeatX = &lbl_803DC940;
    analogY = &lbl_803DC934;
    analogX = &lbl_803DC938;
    heldButtons = padStateBlock;
    buttonsPressed = padStateBlock + 4;
    buttonsReleased = padStateBlock + 8;
    prevTriggers = &lbl_803DC914;
    triggers = &lbl_803DC91C;
    triggersReleased = &lbl_803DC924;
    triggersPressed = &lbl_803DC92C;

    for (i = 0; i < 4; i++) {
        *prevStickY = 0;
        *prevStickX = 0;
        *repeatY = 0;
        *repeatX = 0;
        *analogY = 0;
        *analogX = 0;
        *heldButtons = 0;
        *buttonsPressed = 0;
        *buttonsReleased = 0;
        *padStateBlock = 0;
        *prevTriggers = 0;
        *triggers = 0;
        *triggersReleased = 0;
        *triggersPressed = 0;
        memset(statuses, 0, sizeof(PadStatusLite));
        memset(statuses + 4, 0, sizeof(PadStatusLite));

        prevStickY++;
        prevStickX++;
        repeatY++;
        repeatX++;
        analogY++;
        analogX++;
        heldButtons++;
        buttonsPressed++;
        buttonsReleased++;
        padStateBlock++;
        prevTriggers++;
        triggers++;
        triggersReleased++;
        triggersPressed++;
        statuses++;
    }

    lbl_803DC94C = 0;
    lbl_803DC909 = 1;
    PADControlMotor(0, 2);
    lbl_803DC90C = lbl_803DE6E8;
    return 0;
}

/*
 * Function: gameTextGetBox
 * EN v1.0 Address: 0x800173C8
 * EN v1.0 Size: 20b
 */
void* gameTextGetBox(int box)
{
    return &lbl_802C7400[box * 0x20];
}

/*
 * Function: gameTextGetCurBox
 * EN v1.0 Address: 0x800173DC
 * EN v1.0 Size: 8b
 */
void* gameTextGetCurBox(void)
{
    return lbl_803DC9CC;
}

/*
 * Function: fn_80009008
 * EN v1.0 Address: 0x80009008
 * EN v1.0 Size: 12b
 */
void fn_80009008(void)
{
    lbl_803DC7BC = 1;
}

/*
 * Function: renderModeSetOrGet
 * EN v1.0 Address: 0x80008B4C
 * EN v1.0 Size: 32b
 */
s16 renderModeSetOrGet(int mode)
{
    if (mode != -1) {
        gRenderMode = mode;
        return mode;
    }
    return gRenderMode;
}

/*
 * Function: gameTextFn_80016c18
 * EN v1.0 Address: 0x80016C18
 * EN v1.0 Size: 48b
 */
void gameTextFn_80016c18(int a, int b)
{
    int i = lbl_803DC9C8++;
    int* e = (int*)&lbl_8033A540[i * 0x14];
    e[0] = 1;
    e[1] = a;
    e[2] = b;
}

/*
 * Function: voxmaps_freeRouteWork
 * EN v1.0 Address: 0x80012848
 * EN v1.0 Size: 64b
 */
void voxmaps_freeRouteWork(void** p)
{
    if (p[0] != NULL) {
        mm_free(p[0]);
        p[0] = NULL;
    }
}

/*
 * Function: voxmaps_allocRouteWork
 * EN v1.0 Address: 0x80012888
 * EN v1.0 Size: 84b
 */
void voxmaps_allocRouteWork(void** p)
{
    p[0] = mmAlloc(0xe88, 0x10, NULL);
    p[1] = (u8*)p[0] + 0xaf0;
    p[2] = (u8*)p[1] + 0x320;
}

/*
 * Function: gameTextFreePhrase
 * EN v1.0 Address: 0x80016C48
 * EN v1.0 Size: 84b
 */
void gameTextFreePhrase(int* p)
{
    p[0] = 0;
    p[1] = 0;
    p[2] = 0;
    p[3] = 0;
    if (((void**)p)[5] != NULL) {
        mm_free(((void**)p)[5]);
        ((void**)p)[5] = NULL;
    }
}

extern void* gameTextDrawFunc;
extern char* lbl_803DC9C4;
extern char* gameStrcpy(char* dst, char* src);
extern void gameTextFn_8001658c(int a, int b, int c);

typedef struct {
    u8 pad[0x20];
    void (*fn)(int, int, int);
    int a;
    int b;
    int c;
} TextCallbackEntry;

extern TextCallbackEntry lbl_80335940[];

typedef struct {
    u16 a;
    u16 b;
    u16 key;
} TaskTextEntry;

extern TaskTextEntry lbl_802C8860[];

/*
 * Function: fn_80008EDC
 * EN v1.0 Address: 0x80008EDC
 * EN v1.0 Size: 92b
 */
void fn_80008EDC(TextCallbackEntry* p)
{
    int i;
    TextCallbackEntry* e = lbl_80335940;
    for (i = 0; i < 16; i++) {
        if (p == e) {
            e->fn(e->a, e->b, e->c);
            return;
        }
        e++;
    }
}

/*
 * Function: gameTextFn_80016810
 * EN v1.0 Address: 0x80016810
 * EN v1.0 Size: 96b
 */
void gameTextFn_80016810(int a, int b, int c)
{
    int i;
    int* e;
    if (gameTextDrawFunc != NULL) {
        gameTextFn_8001658c(a, b, c);
    } else {
        i = lbl_803DC9C8++;
        e = (int*)&lbl_8033A540[i * 0x14];
        e[0] = 2;
        e[1] = a;
        e[2] = b;
        e[3] = c;
    }
}

/*
 * Function: gameTextGetTaskText
 * EN v1.0 Address: 0x80015D70
 * EN v1.0 Size: 88b
 */
int gameTextGetTaskText(int id, int* outA, int* outB)
{
    int i;
    TaskTextEntry* e = lbl_802C8860;
    for (i = 0; i < 0x7a; i++) {
        if (e->key == id) {
            if (outA != NULL) {
                *outA = e->a;
            }
            if (outB != NULL) {
                *outB = e->b;
            }
            return 1;
        }
        e++;
    }
    return 0;
}

/*
 * Function: gameTextShowTimeStr
 * EN v1.0 Address: 0x80016220
 * EN v1.0 Size: 108b
 */
void gameTextShowTimeStr(char* str)
{
    int i;
    int* e;
    char* buf;
    i = lbl_803DC9C8++;
    e = (int*)&lbl_8033A540[i * 0x14];
    e[0] = 5;
    buf = lbl_803DC9C4;
    lbl_803DC9C4 = gameStrcpy(buf, str) + 1;
    e[1] = (int)buf;
}

/*
 * Function: gameTextShow
 * EN v1.0 Address: 0x80016870
 * EN v1.0 Size: 104b
 */
void gameTextShow(int a)
{
    int i;
    int* e;
    if (gameTextDrawFunc != NULL) {
        gameTextFn_8001658c(a, 0, 0);
    } else {
        i = lbl_803DC9C8++;
        e = (int*)&lbl_8033A540[i * 0x14];
        e[0] = 2;
        e[1] = a;
        e[2] = 0;
        e[3] = 0;
    }
}

extern void sndMasterVolume(u8 volume, u16 time, u8 musicFlag, u8 fxFlag);
extern u32 gAudioPendingLoadFlags;
extern u32 gAudioCompletedLoadFlags;
extern char sMidiWadLoadedCallbackLoadError[];
extern void gameTextRenderStrs(char* str, int arg2);

/*
 * Function: audioSetVolumes
 * EN v1.0 Address: 0x80009A28
 * EN v1.0 Size: 108b
 */
void audioSetVolumes(u8 volume, u16 time, int musicFlag, int fxFlag, int streamFlag)
{
    if (musicFlag != 0 || fxFlag != 0) {
        sndMasterVolume(volume, time, musicFlag, fxFlag);
    }
    if (streamFlag != 0) {
        AudioStream_SetVolume(volume);
        AudioStream_SetDefaultVolume(volume);
    }
}

/*
 * Function: MIDIWADLoadedCallback
 * EN v1.0 Address: 0x8000A264
 * EN v1.0 Size: 128b
 */
void MIDIWADLoadedCallback(int status, void* fileInfo)
{
    if (status == -1) {
        OSReport(sMidiWadLoadedCallbackLoadError);
        DVDClose(fileInfo);
        mm_free(fileInfo);
    } else {
        DVDClose(fileInfo);
        mm_free(fileInfo);
        gAudioPendingLoadFlags &= ~0x800;
        gAudioCompletedLoadFlags |= 0x800;
    }
}

/*
 * Function: gameTextAppendStr
 * EN v1.0 Address: 0x8001618C
 * EN v1.0 Size: 144b
 */
void gameTextAppendStr(char* str, int arg2)
{
    int i;
    int* e;
    char* buf;
    if (gameTextDrawFunc != NULL) {
        gameTextRenderStrs(str, arg2);
    } else {
        i = lbl_803DC9C8++;
        e = (int*)&lbl_8033A540[i * 0x14];
        e[0] = 6;
        buf = lbl_803DC9C4;
        lbl_803DC9C4 = gameStrcpy(buf, str) + 1;
        e[1] = (int)buf;
        e[2] = arg2;
    }
}

extern uint mmSetFreeDelay(uint delay);
extern char sPoolDataMLoadedCallbackLoadError[];

/*
 * Function: poolDataMLoadedCallback
 * EN v1.0 Address: 0x800094E4
 * EN v1.0 Size: 176b
 */
void poolDataMLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sPoolDataMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x8;
        gAudioCompletedLoadFlags |= 0x8;
    }
}

extern char sPoolDataSLoadedCallbackLoadError[];
extern char sProjectDataMLoadedCallbackLoadError[];
extern char sProjectDataSLoadedCallbackLoadError[];
extern char sSampleBufferMLoadedCallbackLoadError[];
extern char sSampleBufferSLoadedCallbackLoadError[];
extern char sSampleDirectoryMLoadedCallbackLoadError[];
extern char sSampleDirectorySLoadedCallbackLoadError[];
extern char sSfxTriggersLoadedCallbackLoadError[];
extern char sMusicTriggersLoadedCallbackLoadError[];
extern char sStreamsLoadedCallbackLoadError[];

/*
 * Function: poolDataSLoadedCallback
 * EN v1.0 Address: 0x80009210
 * EN v1.0 Size: 176b
 */
void poolDataSLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sPoolDataSLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x80;
        gAudioCompletedLoadFlags |= 0x80;
    }
}

/*
 * Function: projectDataMLoadedCallback
 * EN v1.0 Address: 0x80009420
 * EN v1.0 Size: 176b
 */
void projectDataMLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sProjectDataMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x10;
        gAudioCompletedLoadFlags |= 0x10;
    }
}

/*
 * Function: projectDataSLoadedCallback
 * EN v1.0 Address: 0x80009160
 * EN v1.0 Size: 176b
 */
void projectDataSLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sProjectDataSLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x100;
        gAudioCompletedLoadFlags |= 0x100;
    }
}

/*
 * Function: sampleBufferMLoadedCallback
 * EN v1.0 Address: 0x800092D4
 * EN v1.0 Size: 172b
 */
void sampleBufferMLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sSampleBufferMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x40;
        gAudioCompletedLoadFlags |= 0x40;
    }
}

/*
 * Function: sampleBufferSLoadedCallback
 * EN v1.0 Address: 0x80009000
 * EN v1.0 Size: 176b
 */
void sampleBufferSLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sSampleBufferSLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x400;
        gAudioCompletedLoadFlags |= 0x400;
    }
}

/*
 * Function: sampleDirectoryMLoadedCallback
 * EN v1.0 Address: 0x80009384
 * EN v1.0 Size: 176b
 */
void sampleDirectoryMLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sSampleDirectoryMLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x20;
        gAudioCompletedLoadFlags |= 0x20;
    }
}

/*
 * Function: sampleDirectorySLoadedCallback
 * EN v1.0 Address: 0x800090C4
 * EN v1.0 Size: 176b
 */
void sampleDirectorySLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sSampleDirectorySLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x200;
        gAudioCompletedLoadFlags |= 0x200;
    }
}

/*
 * Function: sfxTriggersLoadedCallback
 * EN v1.0 Address: 0x800096AC
 * EN v1.0 Size: 176b
 */
void sfxTriggersLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sSfxTriggersLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x2;
        gAudioCompletedLoadFlags |= 0x2;
    }
}

/*
 * Function: musicTriggersLoadedCallback
 * EN v1.0 Address: 0x8000977C
 * EN v1.0 Size: 176b
 */
void musicTriggersLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sMusicTriggersLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x1;
        gAudioCompletedLoadFlags |= 0x1;
    }
}

typedef struct {
    u8 pad[0x15];
    u8 flag;
} StreamEntry;

extern StreamEntry* gStreamsData;
extern int gStreamsCount;

/*
 * Function: streamsLoadedCallback
 * EN v1.0 Address: 0x80009594
 * EN v1.0 Size: 276b
 */
void streamsLoadedCallback(int status, void* fileInfo)
{
    uint saved;
    if (status < 0) {
        OSReport(sStreamsLoadedCallbackLoadError);
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
    } else {
        StreamEntry* s;
        int count;
        int i;
        DVDClose(fileInfo);
        saved = mmSetFreeDelay(0);
        mm_free(fileInfo);
        mmSetFreeDelay(saved);
        gAudioPendingLoadFlags &= ~0x4;
        gAudioCompletedLoadFlags |= 0x4;
        s = gStreamsData;
        count = gStreamsCount;
        for (i = 0; i < count; i++) {
            s->flag = 0;
            s++;
        }
    }
}

extern int lbl_803387B8[];

/*
 * Function: voxmaps_updateTimers
 * EN v1.0 Address: 0x80013434
 * EN v1.0 Size: 160b
 */
void voxmaps_updateTimers(void)
{
    int* p = lbl_803387B8;
    int i;
    for (i = 0; i < 6; i++) {
        if (*p < 0x3FFFFFFF) {
            (*p)++;
        }
        p++;
    }
}

extern u32 lbl_803DC8CC;

/*
 * Function: voxmaps_gridToWorld
 * EN v1.0 Address: 0x80012E0C
 * EN v1.0 Size: 180b
 */
void voxmaps_gridToWorld(f32* out, s16* grid)
{
    int v;
    v = grid[0] * 10 + 5;
    out[0] = (f32)v;
    v = grid[1] * 10 + 5;
    out[1] = (f32)v;
    v = grid[2] * 10 + 5;
    out[2] = (f32)v;
    if (lbl_803DC8CC != 0) {
        Obj_TransformLocalPointToWorld(out[0], out[1], out[2], out, &out[1], &out[2], lbl_803DC8CC);
    }
}

/*
 * Function: fn_80008F38
 * EN v1.0 Address: 0x80008F38
 * EN v1.0 Size: 204b
 */
void fn_80008F38(void* addr, u32 dest, u32 size)
{
    int idx;
    TextCallbackEntry* entry;
    idx = lbl_803DC7B8;
    lbl_803DC7B8 = idx + 1;
    entry = &lbl_80335940[idx];
    if (idx + 1 >= 0x10) {
        lbl_803DC7B8 = 0;
    }
    if ((size & 0x1f) != 0) {
        size = (size | 0x1f) + 1;
    }
    DCFlushRange(addr, size);
    lbl_803DC7BC = 0;
    ARQPostRequest(entry, 0x64, 0, 1, (u32)addr, dest, size, (void (*)(void*))fn_80009008);
    while (lbl_803DC7BC == 0) {
    }
}

/*
 * Function: audioAllocFn_80008df4
 * EN v1.0 Address: 0x80008DF4
 * EN v1.0 Size: 232b
 */
void audioAllocFn_80008df4(void* source, u32 size, void** outBuf, u32 cb, u32 p5, u32 p6, u32 p7)
{
    int idx;
    TextCallbackEntry* entry;
    void* buf;
    idx = lbl_803DC7B8;
    lbl_803DC7B8 = idx + 1;
    entry = &lbl_80335940[idx];
    if (idx + 1 >= 0x10) {
        lbl_803DC7B8 = 0;
    }
    if ((size & 0x1f) != 0) {
        size = (size | 0x1f) + 1;
    }
    buf = mmAlloc(size, 0, NULL);
    *outBuf = buf;
    entry->fn = (void (*)(int, int, int))cb;
    entry->a = p5;
    entry->b = p6;
    entry->c = p7;
    DCFlushRange(buf, size);
    lbl_803DC7BC = 0;
    ARQPostRequest(entry, 0x64, 1, 1, (u32)source, (u32)buf, size, (void (*)(void*))fn_80008EDC);
}

extern void Music_Trigger(int id, int arg);

/*
 * Function: Sfx_ResolveObjectSfxId
 * EN v1.0 Address: 0x8000C0BC
 * EN v1.0 Size: 232b
 */
int Sfx_ResolveObjectSfxId(int* outChannel, u16* sfxId)
{
    switch (*sfxId) {
    case 0x170:
    case 0xca:
    case 0x109:
        *sfxId = 0x409;
    case 0x409:
        *outChannel = 0;
        return 1;
    case 0x7e:
    case 0x487:
        *outChannel = 0;
        return 1;
    case 0x420:
        Music_Trigger(0xe7, 0);
        Music_Trigger(0xe7, 1);
        return 0;
    case 0x38c:
        return !(gAudioActiveChannelMask & 4);
    case 0x0:
        return 0;
    default:
        return 1;
    }
}

extern f32 lbl_803DE6B0;

/*
 * Function: voxmaps_worldToGrid
 * EN v1.0 Address: 0x80012D00
 * EN v1.0 Size: 264b
 */
void voxmaps_worldToGrid(f32* in, s16* out)
{
    f32 sx, sy, sz;
    int ix, iy, iz;
    sx = in[0];
    sy = in[1];
    sz = in[2];
    if (lbl_803DC8CC != 0) {
        Obj_TransformWorldPointToLocal(sx, sy, sz, &sx, &sy, &sz, lbl_803DC8CC);
    }
    ix = (int)sx;
    iy = (int)sy;
    iz = (int)sz;
    if (sx < lbl_803DE6B0) {
        ix -= 10;
    }
    if (sy < lbl_803DE6B0) {
        iy -= 10;
    }
    if (sz < lbl_803DE6B0) {
        iz -= 10;
    }
    out[0] = ix / 10;
    out[1] = iy / 10;
    out[2] = iz / 10;
}

extern int lbl_803DC9AC;
extern int lbl_803DC9B0;
extern int lbl_803DC9B4;
extern int lbl_803DC9B8;
extern int lbl_803DC9BC;

/*
 * Function: gameTextBoxFn_800164b0
 * EN v1.0 Address: 0x800164B0
 * EN v1.0 Size: 220b
 */
void gameTextBoxFn_800164b0(char* str, int boxIdx, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY)
{
    u8* box = &lbl_802C7400[boxIdx * 0x20];
    s16 savedX = *(s16*)(box + 0x18);
    s16 savedY = *(s16*)(box + 0x1a);
    lbl_803DC9BC = 1;
    lbl_803DC9B0 = 0x7FFFFFFF;
    lbl_803DC9AC = 0;
    lbl_803DC9B8 = 0x7FFFFFFF;
    lbl_803DC9B4 = 0;
    gameTextRenderStrs(str, boxIdx);
    lbl_803DC9BC = 0;
    if (outMinX != NULL) {
        *outMinX = lbl_803DC9B8 >> 2;
    }
    if (outMinY != NULL) {
        *outMinY = lbl_803DC9B4 >> 2;
    }
    if (outMaxX != NULL) {
        *outMaxX = lbl_803DC9B0 >> 2;
    }
    if (outMaxY != NULL) {
        *outMaxY = lbl_803DC9AC >> 2;
    }
    *(s16*)(box + 0x18) = savedX;
    *(s16*)(box + 0x1a) = savedY;
}

/*
 * Function: gameTextMeasureFn_800163c4
 * EN v1.0 Address: 0x800163C4
 * EN v1.0 Size: 236b
 */
void gameTextMeasureFn_800163c4(char* str, int boxIdx, int x, int y, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY)
{
    u8* box = &lbl_802C7400[boxIdx * 0x20];
    s16 savedX = *(s16*)(box + 0x18);
    s16 savedY = *(s16*)(box + 0x1a);
    lbl_803DC9BC = 1;
    lbl_803DC9B0 = 0x7FFFFFFF;
    lbl_803DC9AC = 0;
    lbl_803DC9B8 = 0x7FFFFFFF;
    lbl_803DC9B4 = 0;
    *(s16*)(box + 0x18) = (s16)x;
    *(s16*)(box + 0x1a) = (s16)y;
    gameTextRenderStrs(str, boxIdx);
    lbl_803DC9BC = 0;
    if (outMinX != NULL) {
        *outMinX = lbl_803DC9B8 >> 2;
    }
    if (outMinY != NULL) {
        *outMinY = lbl_803DC9B4 >> 2;
    }
    if (outMaxX != NULL) {
        *outMaxX = lbl_803DC9B0 >> 2;
    }
    if (outMaxY != NULL) {
        *outMaxY = lbl_803DC9AC >> 2;
    }
    *(s16*)(box + 0x18) = savedX;
    *(s16*)(box + 0x1a) = savedY;
}

/*
 * Function: Sfx_PlayFromObjectLimited
 * EN v1.0 Address: 0x8000B4D0
 * EN v1.0 Size: 168b
 */
u32 Sfx_PlayFromObjectLimited(u32 obj, u32 sfxId, int limit)
{
    SfxObjectChannel* ch = Sfx_FindObjectChannel(0, 0, sfxId, 3);
    if (ch != NULL && (int)gSfxObjectChannelMatchCount > limit) {
        sndFXKeyOff(*(s32*)ch);
        *(s32*)ch = -1;
    }
    if ((int)gSfxObjectChannelMatchCount < limit) {
        Sfx_PlayFromObjectEx(obj, NULL, 0, sfxId);
    }
    return gSfxObjectChannelMatchCount;
}

extern int DVDRead(void* fileInfo, void* buf, int size, int offset);
extern int DVDOpen(char* path, void* fileInfo);
extern void DVDSetAutoInvalidation(int autoInval);
extern void DCStoreRange(void* addr, u32 nBytes);

/*
 * Function: loadFileByPath
 * EN v1.0 Address: 0x80015AB4
 * EN v1.0 Size: 276b
 */
void* loadFileByPath(char* path, int* outSize)
{
    u8 fileInfo[0x3c];
    int size;
    u32 alignedSize;
    void* buf;
    if (outSize != NULL) {
        *outSize = 0;
    }
    DVDSetAutoInvalidation(1);
    if (DVDOpen(path, fileInfo) == 0) {
        return NULL;
    }
    size = *(u32*)(fileInfo + 0x34);
    alignedSize = (size + 0x1f) & ~0x1f;
    buf = mmAlloc(alignedSize, 0x7d7d7d7d, NULL);
    if (buf == NULL) {
        return NULL;
    }
    if (DVDRead(fileInfo, buf, alignedSize, 0) == -1) {
        mm_free(buf);
        return NULL;
    }
    if (DVDClose(fileInfo) == 0) {
        mm_free(buf);
        return NULL;
    }
    DCStoreRange(buf, size);
    if (outSize != NULL) {
        *outSize = size;
    }
    return buf;
}

extern int DVDReadAsyncPrio(void* fileInfo, void* buf, int size, int offset, void (*cb)(void*), int prio);
extern void checkReset(void);
extern void waitNextFrame(void);
extern void mmFreeTick(int arg);
extern void GXFlush_(int a, int b);
extern void padUpdate(void);
extern void dvdCheckError(void);
extern void gameTextRun(void);

/*
 * Function: DVDRead
 * EN v1.0 Address: 0x80015850
 * EN v1.0 Size: 284b
 */
int DVDRead(void* fileInfo, void* buf, int size, int offset)
{
    u8 resetSeen = 0;
    lbl_803DC958 = 0;
    while (lbl_803DC958 == 0 || lbl_803DC958 == -1 || lbl_803DC958 == -3) {
        DVDReadAsyncPrio(fileInfo, buf, size, offset, fileReadCb_80015954, 2);
        while (lbl_803DC958 == 0 || lbl_803DC958 == -1) {
            padUpdate();
            checkReset();
            if (resetSeen) {
                waitNextFrame();
            }
            dvdCheckError();
            if (resetSeen) {
                mmFreeTick(0);
                gameTextRun();
                GXFlush_(1, 0);
            }
            if (lbl_803DC950 != 0) {
                resetSeen = 1;
            }
        }
    }
    return lbl_803DC958;
}

typedef struct {
    u16 id;
    u16 track;
    u8 pad[0xc];
} MusicTrigger;

extern MusicTrigger* gMusicTriggersData;
extern int gMusicTriggersCount;
extern s16 sMusicTrackTable[];

/*
 * Function: Music_PlayTrackByIndex
 * EN v1.0 Address: 0x8000A2E4
 * EN v1.0 Size: 148b
 */
void Music_PlayTrackByIndex(int index)
{
    MusicTrigger* trigger = gMusicTriggersData;
    int count = gMusicTriggersCount;
    while (count != 0) {
        if ((int)trigger->id == 0xec) {
            goto found;
        }
        trigger++;
        count--;
    }
    trigger = NULL;
found:
    streamFn_8000a380(3, 1, 0);
    trigger->track = *(s16*)((u8*)sMusicTrackTable + (index << 4));
    Music_Trigger(0xec, 1);
}

typedef struct {
    u16 a;
    u16 b;
} VoxXY;

typedef struct {
    VoxXY xy[6];
    int timer[6];
    int f30[6];
    u8 gap[0x14];
    void* buf[6];
} VoxMaps;

extern VoxMaps lbl_803387A0;
extern u8 lbl_803DC8D0[];

/*
 * Function: voxmaps_resetLoadedMaps
 * EN v1.0 Address: 0x800134D4
 * EN v1.0 Size: 156b
 */
void voxmaps_resetLoadedMaps(void)
{
    VoxXY* xy = lbl_803387A0.xy;
    u8* b = lbl_803DC8D0;
    int* timer = lbl_803387A0.timer;
    int* f30 = lbl_803387A0.f30;
    void** buf = lbl_803387A0.buf;
    int i;
    for (i = 0; i < 6; i++) {
        if (*buf != NULL) {
            mm_free(*buf);
            *buf = NULL;
        }
        *f30 = -2;
        *timer = 0x40000000;
        *b = 0;
        xy->a = 0;
        xy->b = 0;
        buf++;
        f30++;
        timer++;
        b++;
        xy++;
    }
}

extern s8 gAudioSoundMode;
extern void sndOutputMode(int mode);
extern u32 OSGetSoundMode(void);
extern void OSSetSoundMode(int mode);

/*
 * Function: audioSetSoundMode
 * EN v1.0 Address: 0x80009920
 * EN v1.0 Size: 264b
 */
void audioSetSoundMode(int mode, u8 forceFlag)
{
    if (forceFlag == 0) {
        if (OSGetSoundMode() != 1) {
            return;
        }
    }
    if ((u8)mode != gAudioSoundMode) {
        switch ((u8)mode) {
        case 0:
            sndOutputMode(1);
            break;
        case 1:
            sndOutputMode(2);
            break;
        case 2:
            sndOutputMode(0);
            break;
        case 3:
            sndOutputMode(1);
            break;
        }
    }
    if ((u8)mode == 2) {
        if (gAudioSoundMode != 2) {
            OSSetSoundMode(0);
        }
    } else {
        if (gAudioSoundMode == 2) {
            OSSetSoundMode(1);
        }
    }
    gAudioSoundMode = (s8)mode;
}

extern u8 lbl_802C6E98[];
extern int lbl_802C6F98[];

/*
 * Function: utf8GetNextChar
 * EN v1.0 Address: 0x80015CB8
 * EN v1.0 Size: 184b
 */
int utf8GetNextChar(u8* str, int* outLen)
{
    u8 first = *str;
    int cls = lbl_802C6E98[first];
    u32 acc = 0;
    switch (cls) {
    case 5:
        str++;
        acc = first << 6;
    case 4:
        acc = (acc + *str++) << 6;
    case 3:
        acc = (acc + *str++) << 6;
    case 2:
        acc = (acc + *str++) << 6;
    case 1:
        acc = (acc + *str++) << 6;
    case 0:
        acc += *str;
    default:
        break;
    }
    *outLen = cls + 1;
    return acc - lbl_802C6F98[cls];
}

typedef struct {
    s16 f0;
    s16 f2;
    s16 f4;
    s16 pad6;
    u16 f8;
} VoxBoxArg;

extern void voxmapsFn_80010ff4(int a1, VoxBoxArg* a2, int a3, u16 count, s16* box);

/*
 * Function: fn_800118EC
 * EN v1.0 Address: 0x800118EC
 * EN v1.0 Size: 272b
 */
void fn_800118EC(int a1, VoxBoxArg* a2, int a3)
{
    s16 box[3];
    u16 count = a2->f8 + 1;
    box[0] = a2->f0;
    box[1] = a2->f2;
    box[2] = a2->f4;
    box[0] = a2->f0 + 2;
    voxmapsFn_80010ff4(a1, a2, a3, count, box);
    box[0] = box[0] - 4;
    box[1] = a2->f2;
    voxmapsFn_80010ff4(a1, a2, a3, count, box);
    box[0] = box[0] + 2;
    box[2] = box[2] + 2;
    box[1] = a2->f2;
    voxmapsFn_80010ff4(a1, a2, a3, count, box);
    box[2] = box[2] - 4;
    box[1] = a2->f2;
    voxmapsFn_80010ff4(a1, a2, a3, count, box);
}

typedef struct {
    u16 id;
    u8 pad[0xa];
} GlyphEntry;

typedef struct {
    int field0;
    GlyphEntry* entries;
    int field8;
    int count;
    u8 pad[0x10];
    int mode;
} GameTextFont;

extern GameTextFont* gameTextFonts;

/*
 * Function: gameTextFn_8001628c
 * EN v1.0 Address: 0x8001628C
 * EN v1.0 Size: 312b
 */
void gameTextFn_8001628c(int id, int a, int b, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY)
{
    GameTextFont* font = gameTextFonts;
    int found = 0;
    if (font->mode == 2) {
        GlyphEntry* e = font->entries;
        int count = font->count;
        int i;
        for (i = 0; i < count; i++) {
            if (e->id == id) {
                found = 1;
                break;
            }
            e++;
        }
    }
    if (!found) {
        *outMaxX = 0;
        *outMaxY = 0;
        *outMinX = 0;
        *outMinY = 0;
        return;
    }
    lbl_803DC9BC = 1;
    lbl_803DC9B0 = 0x7FFFFFFF;
    lbl_803DC9AC = 0;
    lbl_803DC9B8 = 0x7FFFFFFF;
    lbl_803DC9B4 = 0;
    gameTextFn_8001658c(id, a, b);
    lbl_803DC9BC = 0;
    if (outMinX != NULL) {
        *outMinX = lbl_803DC9B8 >> 2;
    }
    if (outMinY != NULL) {
        *outMinY = lbl_803DC9B4 >> 2;
    }
    if (outMaxX != NULL) {
        *outMaxX = lbl_803DC9B0 >> 2;
    }
    if (outMaxY != NULL) {
        *outMaxY = lbl_803DC9AC >> 2;
    }
}

extern u8 testAndSet_onlyUseHeap3(int arg);

/*
 * Function: loadFileByPathAsync
 * EN v1.0 Address: 0x80015964
 * EN v1.0 Size: 332b
 */
#pragma dont_inline on
void* loadFileByPathAsync(char* path, int* outSize, int unused, void (*cb)(void*))
{
    void* fileInfo;
    int size;
    u32 alignedSize;
    void* buf;
    int guard;
    if (outSize != NULL) {
        *outSize = 0;
    }
    DVDSetAutoInvalidation(1);
    if (lbl_803DC954 != NULL) {
        fileInfo = lbl_803DC954;
    } else {
        guard = testAndSet_onlyUseHeap3(0);
        fileInfo = mmAlloc(0x3c, 0xFACEFEED, NULL);
        testAndSet_onlyUseHeap3(guard);
    }
    if (DVDOpen(path, fileInfo) == 0) {
        mm_free(fileInfo);
        return NULL;
    }
    size = *(int*)((u8*)fileInfo + 0x34);
    alignedSize = (size + 0x1f) & ~0x1f;
    guard = testAndSet_onlyUseHeap3(0);
    buf = mmAlloc(alignedSize, 0x7d7d7d7d, NULL);
    testAndSet_onlyUseHeap3(guard);
    if (buf == NULL) {
        mm_free(fileInfo);
        return NULL;
    }
    if (DVDReadAsyncPrio(fileInfo, buf, alignedSize, 0, cb, 2) != 0) {
        if (outSize != NULL) {
            *outSize = size;
        }
        return buf;
    }
    mm_free(buf);
    mm_free(fileInfo);
    return NULL;
}
#pragma dont_inline reset

extern void* gSfxTriggersData;
extern int gSfxTriggersCount;

/*
 * Function: audioLoadTriggerData
 * EN v1.0 Address: 0x8000980C
 * EN v1.0 Size: 276b
 */
void audioLoadTriggerData(void)
{
    char* base = sSampleBufferSLoadedCallbackLoadError;
    int info;
    int delay;
    if (gMusicTriggersData != NULL) {
        delay = mmSetFreeDelay(0);
        mm_free(gMusicTriggersData);
        mm_free(gSfxTriggersData);
        mm_free(gStreamsData);
        mmSetFreeDelay(delay);
    }
    gAudioPendingLoadFlags |= 0x1;
    gMusicTriggersData = loadFileByPathAsync(base + 0x1b4, &info, 1, (void (*)(void*))musicTriggersLoadedCallback);
    gMusicTriggersCount = (u32)info >> 4;
    gAudioPendingLoadFlags |= 0x2;
    gSfxTriggersData = loadFileByPathAsync(base + 0x1cc, &info, 1, (void (*)(void*))sfxTriggersLoadedCallback);
    gSfxTriggersCount = (u32)info >> 5;
    gAudioPendingLoadFlags |= 0x4;
    gStreamsData = loadFileByPathAsync(base + 0x1e0, &info, 1, (void (*)(void*))streamsLoadedCallback);
    gStreamsCount = (u32)info / 0xb0;
}