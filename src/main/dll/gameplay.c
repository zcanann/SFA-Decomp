#include "ghidra_import.h"
#include "main/dll/gameplay.h"

extern undefined4 FUN_800033a8();
extern undefined8 FUN_80003494();
extern undefined4 FUN_80006768();
extern undefined4 FUN_8000676c();
extern undefined4 FUN_80006770();
extern undefined4 FUN_80006824();
extern int FUN_80006b7c();
extern undefined4 FUN_80006b84();
extern undefined4 FUN_80006b8c();
extern uint FUN_80006ba0();
extern undefined4 FUN_80006ba8();
extern uint FUN_80006c00();
extern undefined4 FUN_80006c20();
extern undefined4 FUN_80017460();
extern undefined4 FUN_80017470();
extern undefined4 FUN_80017488();
extern undefined4 FUN_80017498();
extern undefined4 FUN_80017500();
extern undefined4 FUN_80017640();
extern undefined8 FUN_80017644();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_800176cc();
extern undefined4 FUN_800176dc();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern undefined8 FUN_80017814();
extern undefined4 FUN_80017830();
extern int FUN_80017a98();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 FUN_80042b9c();
extern uint FUN_80053078();
extern undefined4 FUN_8005d018();
extern int FUN_800632f4();
extern undefined4 FUN_80072564();
extern int FUN_80072600();
extern int FUN_8007269c();
extern undefined4 FUN_800d783c();
extern undefined4 FUN_8011e80c();
extern undefined4 FUN_80135810();
extern undefined4 FUN_80244e58();
extern int FUN_80286718();
extern undefined8 FUN_80286810();
extern undefined8 FUN_80286820();
extern int FUN_80286824();
extern longlong FUN_80286830();
extern uint FUN_80286834();
extern undefined8 FUN_80286838();
extern uint FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028685c();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286870();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern uint FUN_80294bec();
extern undefined4 FUN_80294ce0();
extern undefined4 FUN_80294d00();
extern int FUN_80294d58();
extern undefined4 FUN_80294d60();
extern uint countLeadingZeros();

extern undefined4 DAT_802c28f0;
extern undefined4 DAT_802c28f4;
extern undefined4 DAT_802c28f8;
extern short DAT_80312370;
extern short DAT_80312460;
extern undefined4 DAT_80312630;
extern short DAT_80312632;
extern undefined4 DAT_803128a8;
extern undefined4 DAT_80312954;
extern undefined DAT_80312984;
extern undefined DAT_803129a8;
extern undefined4 DAT_803129c8;
extern undefined4 DAT_803129ca;
extern undefined4 DAT_803129cc;
extern undefined4 DAT_803129ce;
extern undefined4 DAT_803129d0;
extern undefined4 DAT_803129d2;
extern undefined4 DAT_803129d4;
extern undefined DAT_80312a18;
extern undefined DAT_80312a40;
extern undefined4 DAT_80312a4c;
extern undefined4 DAT_80312a4e;
extern undefined4 DAT_80312a50;
extern undefined4 DAT_80312a52;
extern undefined4 DAT_80312a54;
extern undefined4 DAT_80312a56;
extern undefined4 DAT_80312a58;
extern undefined4 DAT_80312a80;
extern undefined4 DAT_80312aa8;
extern undefined4 DAT_80312ac0;
extern undefined4 DAT_80312ac2;
extern undefined4 DAT_80312ac4;
extern undefined4 DAT_80312ac6;
extern undefined4 DAT_80312ac8;
extern undefined4 DAT_80312aca;
extern undefined4 DAT_80312acc;
extern undefined4 DAT_80312b70;
extern undefined4 DAT_80312c44;
extern undefined DAT_80312ce4;
extern undefined DAT_80312d20;
extern undefined4 DAT_80312d4c;
extern undefined4 DAT_80312d4e;
extern undefined4 DAT_80312d50;
extern undefined4 DAT_80312d52;
extern undefined4 DAT_80312d54;
extern undefined4 DAT_80312d56;
extern undefined4 DAT_80312d58;
extern undefined4 DAT_80312d80;
extern undefined4 DAT_80312e54;
extern undefined DAT_80312ef4;
extern undefined DAT_80312f30;
extern undefined4 DAT_80312f5c;
extern undefined4 DAT_80312f5e;
extern undefined4 DAT_80312f60;
extern undefined4 DAT_80312f62;
extern undefined4 DAT_80312f64;
extern undefined4 DAT_80312f66;
extern undefined4 DAT_80312f68;
extern undefined4 DAT_80312f90;
extern undefined4 DAT_803130f8;
extern undefined4 DAT_80313158;
extern undefined4 DAT_8031316c;
extern undefined4 DAT_80313180;
extern undefined4 DAT_80313194;
extern undefined4 DAT_803131f0;
extern undefined4 DAT_80313238;
extern undefined4 DAT_8031325c;
extern undefined4 DAT_803132a0;
extern undefined4 DAT_8031332c;
extern undefined DAT_80313374;
extern undefined DAT_80313390;
extern undefined DAT_803133a0;
extern undefined4 DAT_803133b0;
extern undefined4 DAT_803133b2;
extern undefined4 DAT_803133b4;
extern undefined4 DAT_803133b6;
extern undefined4 DAT_803133b8;
extern undefined4 DAT_803133ba;
extern undefined4 DAT_803133bc;
extern undefined4 DAT_803133e0;
extern undefined4 DAT_8031346c;
extern undefined DAT_803134d4;
extern undefined DAT_803134f0;
extern undefined4 DAT_80313504;
extern undefined4 DAT_80313506;
extern undefined4 DAT_80313508;
extern undefined4 DAT_8031350a;
extern undefined4 DAT_8031350c;
extern undefined4 DAT_8031350e;
extern undefined4 DAT_80313510;
extern undefined4 DAT_80313538;
extern undefined4 DAT_80313594;
extern undefined DAT_803135c4;
extern undefined DAT_803135d8;
extern undefined4 DAT_803135e8;
extern undefined4 DAT_803135ea;
extern undefined4 DAT_803135ec;
extern undefined4 DAT_803135ee;
extern undefined4 DAT_803135f0;
extern undefined4 DAT_803135f2;
extern undefined4 DAT_803135f4;
extern undefined4 DAT_80313618;
extern undefined4 DAT_803136ec;
extern undefined DAT_8031378c;
extern undefined DAT_8031379c;
extern undefined DAT_803137ac;
extern undefined DAT_803137c8;
extern undefined4 DAT_803137f4;
extern undefined4 DAT_803137f6;
extern undefined4 DAT_803137f8;
extern undefined4 DAT_803137fa;
extern undefined4 DAT_803137fc;
extern undefined4 DAT_803137fe;
extern undefined4 DAT_80313800;
extern short DAT_80313828;
extern undefined4 DAT_803138b4;
extern undefined DAT_803138fc;
extern undefined DAT_80313918;
extern undefined DAT_80313928;
extern undefined4 DAT_80313938;
extern undefined4 DAT_8031393a;
extern undefined4 DAT_8031393c;
extern undefined4 DAT_8031393e;
extern undefined4 DAT_80313940;
extern undefined4 DAT_80313942;
extern undefined4 DAT_80313944;
extern undefined4 DAT_80313968;
extern undefined4 DAT_803139f4;
extern undefined DAT_80313a3c;
extern undefined DAT_80313a58;
extern undefined DAT_80313a68;
extern undefined4 DAT_80313a78;
extern undefined4 DAT_80313a7a;
extern undefined4 DAT_80313a7c;
extern undefined4 DAT_80313a7e;
extern undefined4 DAT_80313a80;
extern undefined4 DAT_80313a82;
extern undefined4 DAT_80313a84;
extern undefined4 DAT_80313aa8;
extern undefined4 DAT_80313b34;
extern undefined DAT_80313b7c;
extern undefined DAT_80313b98;
extern undefined DAT_80313ba8;
extern undefined4 DAT_80313bb8;
extern undefined4 DAT_80313bba;
extern undefined4 DAT_80313bbc;
extern undefined4 DAT_80313bbe;
extern undefined4 DAT_80313bc0;
extern undefined4 DAT_80313bc2;
extern undefined4 DAT_80313bc4;
extern undefined4 DAT_80313be8;
extern undefined4 DAT_80313cbc;
extern undefined DAT_80313d5c;
extern undefined DAT_80313d6c;
extern undefined DAT_80313d7c;
extern undefined DAT_80313d98;
extern undefined4 DAT_80313dc4;
extern undefined4 DAT_80313dc6;
extern undefined4 DAT_80313dc8;
extern undefined4 DAT_80313dca;
extern undefined4 DAT_80313dcc;
extern undefined4 DAT_80313dce;
extern undefined4 DAT_80313dd0;
extern undefined4 DAT_80313df8;
extern undefined4 DAT_80313ecc;
extern undefined DAT_80313f6c;
extern undefined DAT_80313fa8;
extern undefined4 DAT_80313fd4;
extern undefined4 DAT_80313fd6;
extern undefined4 DAT_80313fd8;
extern undefined4 DAT_80313fda;
extern undefined4 DAT_80313fdc;
extern undefined4 DAT_80313fde;
extern undefined4 DAT_80313fe0;
extern undefined4 DAT_80314008;
extern undefined4 DAT_803140dc;
extern undefined DAT_8031417c;
extern undefined DAT_803141b8;
extern undefined4 DAT_803141e4;
extern undefined4 DAT_803141e6;
extern undefined4 DAT_803141e8;
extern undefined4 DAT_803141ea;
extern undefined4 DAT_803141ec;
extern undefined4 DAT_803141ee;
extern undefined4 DAT_803141f0;
extern undefined4 DAT_80314218;
extern undefined4 DAT_803142ec;
extern undefined DAT_8031437c;
extern undefined DAT_8031438c;
extern undefined DAT_803143c8;
extern undefined4 DAT_803143f4;
extern undefined4 DAT_803143f6;
extern undefined4 DAT_803143f8;
extern undefined4 DAT_803143fa;
extern undefined4 DAT_803143fc;
extern undefined4 DAT_803143fe;
extern undefined4 DAT_80314400;
extern undefined4 DAT_80314448;
extern undefined4 DAT_80314498;
extern undefined DAT_803144b0;
extern undefined4 DAT_803144c0;
extern undefined4 DAT_803144c2;
extern undefined4 DAT_803144c4;
extern undefined4 DAT_803144c6;
extern undefined4 DAT_803144c8;
extern undefined4 DAT_803144ca;
extern undefined4 DAT_803144cc;
extern undefined4 DAT_803144f0;
extern undefined4 DAT_803145a4;
extern undefined DAT_80314604;
extern undefined DAT_80314618;
extern undefined4 DAT_80314650;
extern undefined4 DAT_80314652;
extern undefined4 DAT_80314654;
extern undefined4 DAT_80314656;
extern undefined4 DAT_80314658;
extern undefined4 DAT_8031465a;
extern undefined4 DAT_8031465c;
extern undefined4 DAT_80314660;
extern undefined4 DAT_80314661;
extern undefined4 DAT_80314662;
extern undefined4 DAT_80314690;
extern undefined4 DAT_803146c4;
extern undefined DAT_803146e4;
extern undefined4 DAT_803146f0;
extern undefined4 DAT_803146f2;
extern undefined4 DAT_803146f4;
extern undefined4 DAT_803146f6;
extern undefined4 DAT_803146f8;
extern undefined4 DAT_803146fa;
extern undefined4 DAT_803146fc;
extern undefined4 DAT_80314740;
extern undefined4 DAT_803147cc;
extern undefined DAT_80314814;
extern undefined DAT_80314830;
extern undefined DAT_80314840;
extern undefined4 DAT_80314850;
extern undefined4 DAT_80314852;
extern undefined4 DAT_80314854;
extern undefined4 DAT_80314856;
extern undefined4 DAT_80314858;
extern undefined4 DAT_8031485a;
extern undefined4 DAT_8031485c;
extern undefined4 DAT_80314880;
extern undefined4 DAT_803148b4;
extern undefined DAT_803148d4;
extern undefined4 DAT_803148e0;
extern undefined4 DAT_803148e2;
extern undefined4 DAT_803148e4;
extern undefined4 DAT_803148e6;
extern undefined4 DAT_803148e8;
extern undefined4 DAT_803148ea;
extern undefined4 DAT_803148ec;
extern undefined4 DAT_80314910;
extern undefined4 DAT_80314a00;
extern undefined DAT_80314a60;
extern undefined DAT_80314a90;
extern undefined DAT_80314aa0;
extern undefined4 DAT_80314ab8;
extern undefined4 DAT_80314aba;
extern undefined4 DAT_80314abc;
extern undefined4 DAT_80314abe;
extern undefined4 DAT_80314ac0;
extern undefined4 DAT_80314ac2;
extern undefined4 DAT_80314ac4;
extern undefined4 DAT_80314ae8;
extern undefined4 DAT_80314b9c;
extern undefined DAT_80314bfc;
extern undefined DAT_80314c10;
extern undefined DAT_80314c38;
extern undefined DAT_80314c70;
extern undefined4 DAT_80314c7c;
extern undefined4 DAT_80314c7e;
extern undefined4 DAT_80314c80;
extern undefined4 DAT_80314c82;
extern undefined4 DAT_80314c84;
extern undefined4 DAT_80314c86;
extern undefined4 DAT_80314c88;
extern undefined4 DAT_80314cb0;
extern undefined4 DAT_80314d84;
extern undefined DAT_80314e60;
extern undefined DAT_80314e8c;
extern undefined4 DAT_80314ea8;
extern undefined4 DAT_80314eaa;
extern undefined4 DAT_80314eac;
extern undefined4 DAT_80314eae;
extern undefined4 DAT_80314eb0;
extern undefined4 DAT_80314eb2;
extern undefined4 DAT_80314eb4;
extern undefined4 DAT_80314ed8;
extern undefined4 DAT_80314fac;
extern undefined DAT_80315088;
extern undefined DAT_803150b4;
extern undefined4 DAT_803150d0;
extern undefined4 DAT_803150d2;
extern undefined4 DAT_803150d4;
extern undefined4 DAT_803150d6;
extern undefined4 DAT_803150d8;
extern undefined4 DAT_803150da;
extern undefined4 DAT_803150dc;
extern undefined4 DAT_80315100;
extern undefined4 DAT_803151d4;
extern undefined DAT_803152b0;
extern undefined DAT_803152dc;
extern undefined4 DAT_803152f8;
extern undefined4 DAT_803152fa;
extern undefined4 DAT_803152fc;
extern undefined4 DAT_803152fe;
extern undefined4 DAT_80315300;
extern undefined4 DAT_80315302;
extern undefined4 DAT_80315304;
extern undefined4 DAT_80315328;
extern undefined4 DAT_803153fc;
extern undefined DAT_8031548c;
extern undefined DAT_8031549c;
extern undefined DAT_803154d8;
extern undefined DAT_80315520;
extern undefined4 DAT_8031553c;
extern undefined4 DAT_8031553e;
extern undefined4 DAT_80315540;
extern undefined4 DAT_80315542;
extern undefined4 DAT_80315544;
extern undefined4 DAT_80315546;
extern undefined4 DAT_80315548;
extern undefined4 DAT_80315570;
extern undefined4 DAT_80315572;
extern undefined4 DAT_80315574;
extern undefined4 DAT_80315576;
extern undefined4 DAT_80315578;
extern undefined4 DAT_8031557a;
extern undefined4 DAT_8031557c;
extern undefined4 DAT_803155a0;
extern undefined4 DAT_803155a2;
extern undefined4 DAT_803155a4;
extern undefined4 DAT_803155a6;
extern undefined4 DAT_803155a8;
extern undefined4 DAT_803155aa;
extern undefined4 DAT_803155ac;
extern undefined4 DAT_803155d0;
extern undefined4 DAT_803155d2;
extern undefined4 DAT_803155d4;
extern undefined4 DAT_803155d6;
extern undefined4 DAT_803155d8;
extern undefined4 DAT_803155da;
extern undefined4 DAT_803155dc;
extern undefined4 DAT_80315600;
extern undefined4 DAT_8031568c;
extern undefined DAT_803156d4;
extern undefined DAT_803156f0;
extern undefined DAT_80315700;
extern undefined4 DAT_80315710;
extern undefined4 DAT_80315712;
extern undefined4 DAT_80315714;
extern undefined4 DAT_80315716;
extern undefined4 DAT_80315718;
extern undefined4 DAT_8031571a;
extern undefined4 DAT_8031571c;
extern undefined4 DAT_80315740;
extern undefined4 DAT_8031579c;
extern undefined DAT_803157cc;
extern undefined DAT_803157e0;
extern undefined4 DAT_803157f0;
extern undefined4 DAT_803157f2;
extern undefined4 DAT_803157f4;
extern undefined4 DAT_803157f6;
extern undefined4 DAT_803157f8;
extern undefined4 DAT_803157fa;
extern undefined4 DAT_803157fc;
extern undefined4 DAT_80315820;
extern undefined4 DAT_8031587c;
extern undefined DAT_803158ac;
extern undefined DAT_803158c0;
extern undefined4 DAT_803158d0;
extern undefined4 DAT_803158d2;
extern undefined4 DAT_803158d4;
extern undefined4 DAT_803158d6;
extern undefined4 DAT_803158d8;
extern undefined4 DAT_803158da;
extern undefined4 DAT_803158dc;
extern undefined4 DAT_80315900;
extern undefined4 DAT_8031598c;
extern undefined DAT_803159f4;
extern undefined4 DAT_80315a10;
extern undefined4 DAT_80315a24;
extern undefined4 DAT_80315a26;
extern undefined4 DAT_80315a28;
extern undefined4 DAT_80315a2a;
extern undefined4 DAT_80315a2c;
extern undefined4 DAT_80315a2e;
extern undefined4 DAT_80315a30;
extern char DAT_803a3be0;
extern undefined4 DAT_803a3be1;
extern undefined4 DAT_803a3be2;
extern undefined4 DAT_803a3be3;
extern undefined4 DAT_803a3be6;
extern undefined4 DAT_803a3be9;
extern undefined4 DAT_803a3bec;
extern undefined4 DAT_803a3bef;
extern undefined4 DAT_803a3bf2;
extern undefined4 DAT_803a3bf5;
extern undefined4 DAT_803a3bf8;
extern undefined4 DAT_803a3bfb;
extern undefined4 DAT_803a3bfe;
extern undefined4 DAT_803a3c01;
extern undefined4 DAT_803a3c04;
extern undefined4 DAT_803a3c07;
extern undefined4 DAT_803a3c0a;
extern undefined4 DAT_803a3c0d;
extern undefined4 DAT_803a3c10;
extern undefined4 DAT_803a3c13;
extern undefined4 DAT_803a3c16;
extern undefined4 DAT_803a3c19;
extern uint DAT_803a3c1c;
extern undefined4 DAT_803a3dac;
extern undefined1 gGameplayPreviewSettings;
extern undefined4 DAT_803a3e26;
extern undefined4 DAT_803a3e27;
extern undefined4 DAT_803a3e28;
extern undefined4 DAT_803a3e2a;
extern undefined4 DAT_803a3e2c;
extern undefined4 DAT_803a3e2d;
extern undefined4 gGameplayPreviewColorRed;
extern undefined4 gGameplayPreviewColorGreen;
extern undefined4 gGameplayPreviewColorBlue;
extern undefined4 gGameplayRegisteredDebugOptions;
extern undefined4 gGameplayEnabledDebugOptions;
extern undefined4 DAT_803a3e40;
extern undefined DAT_803a3e44;
extern undefined1 DAT_803a3f08;
extern undefined4 DAT_803a3f09;
extern undefined4 DAT_803a3f0c;
extern undefined4 DAT_803a3f0e;
extern undefined4 DAT_803a3f12;
extern undefined4 DAT_803a3f14;
extern undefined4 DAT_803a3f15;
extern undefined4 DAT_803a3f18;
extern undefined4 DAT_803a3f1a;
extern undefined4 DAT_803a3f1e;
extern undefined4 DAT_803a3f21;
extern char DAT_803a3f24;
extern undefined4 DAT_803a3f25;
extern undefined4 DAT_803a3f26;
extern undefined4 DAT_803a3f27;
extern undefined4 DAT_803a3f28;
extern undefined4 DAT_803a3f29;
extern undefined4 DAT_803a3f2a;
extern undefined4 DAT_803a3f2b;
extern undefined4 DAT_803a4070;
extern undefined4 DAT_803a4074;
extern undefined4 DAT_803a4078;
extern undefined4 DAT_803a407c;
extern undefined4 DAT_803a4460;
extern undefined4 DAT_803a4465;
extern undefined4 DAT_803a4468;
extern undefined4 DAT_803a458c;
extern undefined4 DAT_803a4590;
extern undefined4 DAT_803a4594;
extern undefined4 DAT_803a4598;
extern undefined4 DAT_803a4599;
extern undefined4 DAT_803a459a;
extern undefined4 DAT_803a45aa;
extern undefined4 DAT_803a45ac;
extern undefined4 DAT_803a45b0;
extern undefined4 DAT_803a45b4;
extern undefined4 DAT_803a45b6;
extern undefined4 DAT_803a45ba;
extern undefined4 DAT_803a45bc;
extern undefined4 DAT_803a45be;
extern undefined4 DAT_803a45c0;
extern undefined4 DAT_803a45c2;
extern undefined4 DAT_803a45f0;
extern undefined4 DAT_803a45f1;
extern undefined4 DAT_803a45f2;
extern undefined4 DAT_803a45f3;
extern undefined4 DAT_803a4e48;
extern undefined4 DAT_803a4e78;
extern undefined4 DAT_803c4060;
extern undefined4 DAT_803dc4f0;
extern undefined DAT_803dc4f8;
extern undefined DAT_803dc500;
extern undefined DAT_803dc508;
extern undefined DAT_803dc510;
extern undefined DAT_803dc514;
extern undefined DAT_803dc520;
extern undefined DAT_803dc528;
extern undefined DAT_803dc530;
extern undefined4 DAT_803dc538;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de100;
extern undefined4 DAT_803de104;
extern undefined4 DAT_803de10c;
extern undefined4* DAT_803de110;
extern undefined4 DAT_803de114;
extern undefined4 DAT_803de118;
extern undefined4 DAT_803de11c;
extern undefined4 DAT_803de120;
extern undefined4 DAT_803de124;
extern undefined4 DAT_803e13b0;
extern f64 DOUBLE_803e13a8;
extern f64 DOUBLE_803e13d8;
extern f64 DOUBLE_803e14d0;
extern f64 DOUBLE_803e1510;
extern f64 DOUBLE_803e1540;
extern f64 DOUBLE_803e1580;
extern f64 DOUBLE_803e15a8;
extern f64 DOUBLE_803e15e0;
extern f64 DOUBLE_803e1608;
extern f64 DOUBLE_803e16a0;
extern f64 DOUBLE_803e16d0;
extern f64 DOUBLE_803e1830;
extern f64 DOUBLE_803e1928;
extern f64 DOUBLE_803e1980;
extern f64 DOUBLE_803e19b0;
extern f64 DOUBLE_803e1a00;
extern f32 lbl_803DC074;
extern f32 lbl_803E1348;
extern f32 lbl_803E134C;
extern f32 lbl_803E1358;
extern f32 lbl_803E135C;
extern f32 lbl_803E1360;
extern f32 lbl_803E1364;
extern f32 lbl_803E1368;
extern f32 lbl_803E1370;
extern f32 lbl_803E1374;
extern f32 lbl_803E1378;
extern f32 lbl_803E137C;
extern f32 lbl_803E1380;
extern f32 lbl_803E1384;
extern f32 lbl_803E1388;
extern f32 lbl_803E138C;
extern f32 lbl_803E1390;
extern f32 lbl_803E1394;
extern f32 lbl_803E1398;
extern f32 lbl_803E139C;
extern f32 lbl_803E13A0;
extern f32 lbl_803E13B4;
extern f32 lbl_803E13B8;
extern f32 lbl_803E13BC;
extern f32 lbl_803E13C0;
extern f32 lbl_803E13C4;
extern f32 lbl_803E13C8;
extern f32 lbl_803E13CC;
extern f32 lbl_803E13D0;
extern f32 lbl_803E13D4;
extern f32 lbl_803E13E0;
extern f32 lbl_803E13E4;
extern f32 lbl_803E13E8;
extern f32 lbl_803E13EC;
extern f32 lbl_803E13F0;
extern f32 lbl_803E13F4;
extern f32 lbl_803E13F8;
extern f32 lbl_803E13FC;
extern f32 lbl_803E1400;
extern f32 lbl_803E1404;
extern f32 lbl_803E1408;
extern f32 lbl_803E140C;
extern f32 lbl_803E1410;
extern f32 lbl_803E1414;
extern f32 lbl_803E1418;
extern f32 lbl_803E141C;
extern f32 lbl_803E1420;
extern f32 lbl_803E1424;
extern f32 lbl_803E1428;
extern f32 lbl_803E142C;
extern f32 lbl_803E1430;
extern f32 lbl_803E1434;
extern f32 lbl_803E1438;
extern f32 lbl_803E143C;
extern f32 lbl_803E1440;
extern f32 lbl_803E1444;
extern f32 lbl_803E1448;
extern f32 lbl_803E144C;
extern f32 lbl_803E1450;
extern f32 lbl_803E1454;
extern f32 lbl_803E1458;
extern f32 lbl_803E145C;
extern f32 lbl_803E1460;
extern f32 lbl_803E1464;
extern f32 lbl_803E1468;
extern f32 lbl_803E146C;
extern f32 lbl_803E1470;
extern f32 lbl_803E1474;
extern f32 lbl_803E1478;
extern f32 lbl_803E1480;
extern f32 lbl_803E1484;
extern f32 lbl_803E1488;
extern f32 lbl_803E148C;
extern f32 lbl_803E1490;
extern f32 lbl_803E1494;
extern f32 lbl_803E1498;
extern f32 lbl_803E149C;
extern f32 lbl_803E14A0;
extern f32 lbl_803E14A4;
extern f32 lbl_803E14A8;
extern f32 lbl_803E14B0;
extern f32 lbl_803E14B4;
extern f32 lbl_803E14B8;
extern f32 lbl_803E14BC;
extern f32 lbl_803E14C0;
extern f32 lbl_803E14C4;
extern f32 lbl_803E14C8;
extern f32 lbl_803E14CC;
extern f32 lbl_803E14D8;
extern f32 lbl_803E14DC;
extern f32 lbl_803E14E0;
extern f32 lbl_803E14E4;
extern f32 lbl_803E14E8;
extern f32 lbl_803E14EC;
extern f32 lbl_803E14F0;
extern f32 lbl_803E14F4;
extern f32 lbl_803E14F8;
extern f32 lbl_803E14FC;
extern f32 lbl_803E1500;
extern f32 lbl_803E1504;
extern f32 lbl_803E1508;
extern f32 lbl_803E150C;
extern f32 lbl_803E1518;
extern f32 lbl_803E151C;
extern f32 lbl_803E1520;
extern f32 lbl_803E1524;
extern f32 lbl_803E1528;
extern f32 lbl_803E152C;
extern f32 lbl_803E1530;
extern f32 lbl_803E1534;
extern f32 lbl_803E1538;
extern f32 lbl_803E1548;
extern f32 lbl_803E154C;
extern f32 lbl_803E1550;
extern f32 lbl_803E1554;
extern f32 lbl_803E1558;
extern f32 lbl_803E155C;
extern f32 lbl_803E1560;
extern f32 lbl_803E1564;
extern f32 lbl_803E1568;
extern f32 lbl_803E156C;
extern f32 lbl_803E1570;
extern f32 lbl_803E1574;
extern f32 lbl_803E1578;
extern f32 lbl_803E157C;
extern f32 lbl_803E1588;
extern f32 lbl_803E158C;
extern f32 lbl_803E1590;
extern f32 lbl_803E1594;
extern f32 lbl_803E1598;
extern f32 lbl_803E159C;
extern f32 lbl_803E15A0;
extern f32 lbl_803E15A4;
extern f32 lbl_803E15B0;
extern f32 lbl_803E15B4;
extern f32 lbl_803E15B8;
extern f32 lbl_803E15BC;
extern f32 lbl_803E15C0;
extern f32 lbl_803E15C4;
extern f32 lbl_803E15C8;
extern f32 lbl_803E15CC;
extern f32 lbl_803E15D0;
extern f32 lbl_803E15D4;
extern f32 lbl_803E15D8;
extern f32 lbl_803E15DC;
extern f32 lbl_803E15E8;
extern f32 lbl_803E15EC;
extern f32 lbl_803E15F0;
extern f32 lbl_803E15F4;
extern f32 lbl_803E15F8;
extern f32 lbl_803E15FC;
extern f32 lbl_803E1600;
extern f32 lbl_803E1604;
extern f32 lbl_803E1610;
extern f32 lbl_803E1614;
extern f32 lbl_803E1618;
extern f32 lbl_803E161C;
extern f32 lbl_803E1620;
extern f32 lbl_803E1624;
extern f32 lbl_803E1628;
extern f32 lbl_803E162C;
extern f32 lbl_803E1630;
extern f32 lbl_803E1634;
extern f32 lbl_803E1638;
extern f32 lbl_803E163C;
extern f32 lbl_803E1640;
extern f32 lbl_803E1648;
extern f32 lbl_803E164C;
extern f32 lbl_803E1650;
extern f32 lbl_803E1654;
extern f32 lbl_803E1658;
extern f32 lbl_803E165C;
extern f32 lbl_803E1660;
extern f32 lbl_803E1664;
extern f32 lbl_803E1668;
extern f32 lbl_803E166C;
extern f32 lbl_803E1670;
extern f32 lbl_803E1674;
extern f32 lbl_803E1678;
extern f32 lbl_803E1680;
extern f32 lbl_803E1684;
extern f32 lbl_803E1688;
extern f32 lbl_803E168C;
extern f32 lbl_803E1690;
extern f32 lbl_803E1694;
extern f32 lbl_803E1698;
extern f32 lbl_803E16A8;
extern f32 lbl_803E16AC;
extern f32 lbl_803E16B0;
extern f32 lbl_803E16B4;
extern f32 lbl_803E16B8;
extern f32 lbl_803E16BC;
extern f32 lbl_803E16C0;
extern f32 lbl_803E16C4;
extern f32 lbl_803E16C8;
extern f32 lbl_803E16CC;
extern f32 lbl_803E16D8;
extern f32 lbl_803E16DC;
extern f32 lbl_803E16E0;
extern f32 lbl_803E16E4;
extern f32 lbl_803E16E8;
extern f32 lbl_803E16EC;
extern f32 lbl_803E16F0;
extern f32 lbl_803E16F8;
extern f32 lbl_803E16FC;
extern f32 lbl_803E1700;
extern f32 lbl_803E1704;
extern f32 lbl_803E1708;
extern f32 lbl_803E170C;
extern f32 lbl_803E1710;
extern f32 lbl_803E1718;
extern f32 lbl_803E171C;
extern f32 lbl_803E1720;
extern f32 lbl_803E1724;
extern f32 lbl_803E1728;
extern f32 lbl_803E172C;
extern f32 lbl_803E1730;
extern f32 lbl_803E1738;
extern f32 lbl_803E173C;
extern f32 lbl_803E1740;
extern f32 lbl_803E1744;
extern f32 lbl_803E1748;
extern f32 lbl_803E174C;
extern f32 lbl_803E1750;
extern f32 lbl_803E1754;
extern f32 lbl_803E1758;
extern f32 lbl_803E175C;
extern f32 lbl_803E1760;
extern f32 lbl_803E1764;
extern f32 lbl_803E1768;
extern f32 lbl_803E176C;
extern f32 lbl_803E1770;
extern f32 lbl_803E1778;
extern f32 lbl_803E177C;
extern f32 lbl_803E1780;
extern f32 lbl_803E1784;
extern f32 lbl_803E1788;
extern f32 lbl_803E178C;
extern f32 lbl_803E1790;
extern f32 lbl_803E1794;
extern f32 lbl_803E1798;
extern f32 lbl_803E179C;
extern f32 lbl_803E17A0;
extern f32 lbl_803E17A4;
extern f32 lbl_803E17A8;
extern f32 lbl_803E17AC;
extern f32 lbl_803E17B0;
extern f32 lbl_803E17B8;
extern f32 lbl_803E17BC;
extern f32 lbl_803E17C0;
extern f32 lbl_803E17C4;
extern f32 lbl_803E17C8;
extern f32 lbl_803E17CC;
extern f32 lbl_803E17D0;
extern f32 lbl_803E17D4;
extern f32 lbl_803E17D8;
extern f32 lbl_803E17E0;
extern f32 lbl_803E17E4;
extern f32 lbl_803E17E8;
extern f32 lbl_803E17EC;
extern f32 lbl_803E17F0;
extern f32 lbl_803E17F4;
extern f32 lbl_803E17F8;
extern f32 lbl_803E17FC;
extern f32 lbl_803E1800;
extern f32 lbl_803E1804;
extern f32 lbl_803E1808;
extern f32 lbl_803E180C;
extern f32 lbl_803E1810;
extern f32 lbl_803E1814;
extern f32 lbl_803E1818;
extern f32 lbl_803E181C;
extern f32 lbl_803E1820;
extern f32 lbl_803E1824;
extern f32 lbl_803E1828;
extern f32 lbl_803E182C;
extern f32 lbl_803E1838;
extern f32 lbl_803E183C;
extern f32 lbl_803E1840;
extern f32 lbl_803E1844;
extern f32 lbl_803E1848;
extern f32 lbl_803E184C;
extern f32 lbl_803E1850;
extern f32 lbl_803E1854;
extern f32 lbl_803E1858;
extern f32 lbl_803E185C;
extern f32 lbl_803E1860;
extern f32 lbl_803E1864;
extern f32 lbl_803E1868;
extern f32 lbl_803E186C;
extern f32 lbl_803E1870;
extern f32 lbl_803E1874;
extern f32 lbl_803E1878;
extern f32 lbl_803E187C;
extern f32 lbl_803E1880;
extern f32 lbl_803E1884;
extern f32 lbl_803E1888;
extern f32 lbl_803E188C;
extern f32 lbl_803E1890;
extern f32 lbl_803E1894;
extern f32 lbl_803E1898;
extern f32 lbl_803E189C;
extern f32 lbl_803E18A0;
extern f32 lbl_803E18A4;
extern f32 lbl_803E18A8;
extern f32 lbl_803E18AC;
extern f32 lbl_803E18B0;
extern f32 lbl_803E18B4;
extern f32 lbl_803E18B8;
extern f32 lbl_803E18BC;
extern f32 lbl_803E18C0;
extern f32 lbl_803E18C4;
extern f32 lbl_803E18C8;
extern f32 lbl_803E18CC;
extern f32 lbl_803E18D0;
extern f32 lbl_803E18D4;
extern f32 lbl_803E18D8;
extern f32 lbl_803E18DC;
extern f32 lbl_803E18E0;
extern f32 lbl_803E18E4;
extern f32 lbl_803E18E8;
extern f32 lbl_803E18EC;
extern f32 lbl_803E18F0;
extern f32 lbl_803E18F4;
extern f32 lbl_803E18F8;
extern f32 lbl_803E18FC;
extern f32 lbl_803E1900;
extern f32 lbl_803E1904;
extern f32 lbl_803E1908;
extern f32 lbl_803E190C;
extern f32 lbl_803E1910;
extern f32 lbl_803E1914;
extern f32 lbl_803E1918;
extern f32 lbl_803E191C;
extern f32 lbl_803E1920;
extern f32 lbl_803E1930;
extern f32 lbl_803E1934;
extern f32 lbl_803E1938;
extern f32 lbl_803E193C;
extern f32 lbl_803E1940;
extern f32 lbl_803E1944;
extern f32 lbl_803E1948;
extern f32 lbl_803E194C;
extern f32 lbl_803E1950;
extern f32 lbl_803E1954;
extern f32 lbl_803E1958;
extern f32 lbl_803E195C;
extern f32 lbl_803E1960;
extern f32 lbl_803E1964;
extern f32 lbl_803E1968;
extern f32 lbl_803E196C;
extern f32 lbl_803E1970;
extern f32 lbl_803E1974;
extern f32 lbl_803E1978;
extern f32 lbl_803E197C;
extern f32 lbl_803E1988;
extern f32 lbl_803E198C;
extern f32 lbl_803E1990;
extern f32 lbl_803E1994;
extern f32 lbl_803E1998;
extern f32 lbl_803E199C;
extern f32 lbl_803E19A0;
extern f32 lbl_803E19A4;
extern f32 lbl_803E19A8;
extern f32 lbl_803E19AC;
extern f32 lbl_803E19B8;
extern f32 lbl_803E19BC;
extern f32 lbl_803E19C0;
extern f32 lbl_803E19C4;
extern f32 lbl_803E19C8;
extern f32 lbl_803E19CC;
extern f32 lbl_803E19D0;
extern f32 lbl_803E19D4;
extern f32 lbl_803E19D8;
extern f32 lbl_803E19DC;
extern f32 lbl_803E19E0;
extern f32 lbl_803E19E4;
extern f32 lbl_803E19E8;
extern f32 lbl_803E19EC;
extern f32 lbl_803E19F0;
extern f32 lbl_803E19F4;
extern f32 lbl_803E19F8;
extern char s______This_modgfx_needs_an_owner_o_80312af0[];
extern undefined4 uRam803de108;
extern undefined uRam803de10d;

/*
 * --INFO--
 *
 * Function: gameplay_isDebugOptionEnabled
 * EN v1.0 Address: 0x800E8100
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x800E8118
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 gameplay_isDebugOptionEnabled(uint param_1)
{
  uint uVar1;
  
  uVar1 = 1 << (param_1 & 0xff);
  if (((gGameplayRegisteredDebugOptions & uVar1) != 0) &&
     ((gGameplayEnabledDebugOptions & uVar1) != 0)) {
    return 1;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: gameplay_registerDebugOption
 * EN v1.0 Address: 0x800E8134
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x800E815C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void gameplay_registerDebugOption(uint param_1)
{
  gGameplayRegisteredDebugOptions = gGameplayRegisteredDebugOptions | 1 << (param_1 & 0xff);
  return;
}

/*
 * --INFO--
 *
 * Function: gameplay_hasDebugOption
 * EN v1.0 Address: 0x800E8150
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x800E8180
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint gameplay_hasDebugOption(uint param_1)
{
  return gGameplayRegisteredDebugOptions & 1 << (param_1 & 0xff);
}

/*
 * --INFO--
 *
 * Function: gameplay_resetPreviewColor
 * EN v1.0 Address: 0x800E8168
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x800E81A0
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void gameplay_resetPreviewColor(void)
{
  gGameplayPreviewColorRed = 0x7f;
  gGameplayPreviewColorGreen = 0x7f;
  gGameplayPreviewColorBlue = 0x7f;
  return;
}

/*
 * --INFO--
 *
 * Function: gameplay_getPreviewSettings
 * EN v1.0 Address: 0x800E817C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800E81BC
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u8 * gameplay_getPreviewSettings(void)
{
  return &gGameplayPreviewSettings;
}

/*
 * --INFO--
 *
 * Function: gameplay_applyPreviewSettings
 * EN v1.0 Address: 0x800E8184
 * EN v1.0 Size: 340b
 * EN v1.1 Address: 0x800E81C8
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void gameplay_applyPreviewSettings(undefined8 param_1,undefined8 param_2,undefined8 param_3,
                                   undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                   undefined8 param_7,undefined8 param_8)
{
  FUN_8005d018(DAT_803a3e2a);
  FUN_80017500(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)DAT_803a3e26);
  FUN_80006c20(DAT_803a3e2c);
  FUN_80006768(DAT_803a3e2d,'\0');
  (**(code **)(*DAT_803dd6e8 + 0x50))(DAT_803a3e27);
  (**(code **)(*DAT_803dd6d0 + 0x6c))(DAT_803a3e28);
  FUN_8000676c((uint)gGameplayPreviewColorGreen,10,0,1,0);
  FUN_8000676c((uint)gGameplayPreviewColorRed,10,1,0,0);
  FUN_8000676c((uint)gGameplayPreviewColorBlue,10,0,0,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e82d8
 * EN v1.0 Address: 0x800E82D8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800E82C8
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined * FUN_800e82d8(void)
{
  return (undefined *)&DAT_803a4460;
}

/*
 * --INFO--
 *
 * Function: FUN_800e82e0
 * EN v1.0 Address: 0x800E82E0
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x800E82D8
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800e82e0(int param_1)
{
  undefined1 *puVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 0;
  puVar1 = &DAT_803a3f08;
  iVar3 = 0x3f;
  while (*(int *)(*(int *)(param_1 + 0x4c) + 0x14) != *(int *)(puVar1 + 0x168)) {
    puVar1 = puVar1 + 0x10;
    iVar2 = iVar2 + 1;
    iVar3 = iVar3 + -1;
    if (iVar3 == 0) {
      return 0;
    }
  }
  if (((*(float *)(param_1 + 0xc) == (float)(&DAT_803a4074)[iVar2 * 4]) &&
      (*(float *)(param_1 + 0x10) == (float)(&DAT_803a4078)[iVar2 * 4])) &&
     (*(float *)(param_1 + 0x14) == (float)(&DAT_803a407c)[iVar2 * 4])) {
    return 0;
  }
  *(undefined4 *)(param_1 + 0xc) = (&DAT_803a4074)[iVar2 * 4];
  *(undefined4 *)(param_1 + 0x10) = (&DAT_803a4078)[iVar2 * 4];
  *(undefined4 *)(param_1 + 0x14) = (&DAT_803a407c)[iVar2 * 4];
  return 1;
}

/*
 * --INFO--
 *
 * Function: FUN_800e83c8
 * EN v1.0 Address: 0x800E83C8
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800E8384
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800e83c8(int param_1)
{
  undefined1 *puVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 0;
  puVar1 = &DAT_803a3f08;
  iVar3 = 0x3f;
  do {
    if (*(int *)(param_1 + 0x14) == *(int *)(puVar1 + 0x168)) {
      *(undefined4 *)(param_1 + 8) = (&DAT_803a4074)[iVar2 * 4];
      *(undefined4 *)(param_1 + 0xc) = (&DAT_803a4078)[iVar2 * 4];
      *(undefined4 *)(param_1 + 0x10) = (&DAT_803a407c)[iVar2 * 4];
      return 1;
    }
    puVar1 = puVar1 + 0x10;
    iVar2 = iVar2 + 1;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800e842c
 * EN v1.0 Address: 0x800E842C
 * EN v1.0 Size: 516b
 * EN v1.1 Address: 0x800E83EC
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e842c(int param_1)
{
  uint uVar1;
  int iVar2;
  undefined1 *puVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  
  if ((*(ushort *)(param_1 + 6) & 0x2000) != 0) {
    return;
  }
  if (DAT_803de100 != '\0') {
    return;
  }
  iVar4 = 0;
  puVar3 = &DAT_803a3f08;
  iVar6 = 7;
  do {
    iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
    iVar5 = iVar4;
    if ((((((iVar2 == *(int *)(puVar3 + 0x168)) ||
           (iVar5 = iVar4 + 1, iVar2 == *(int *)(puVar3 + 0x178))) ||
          (iVar5 = iVar4 + 2, iVar2 == *(int *)(puVar3 + 0x188))) ||
         ((iVar5 = iVar4 + 3, iVar2 == *(int *)(puVar3 + 0x198) ||
          (iVar5 = iVar4 + 4, iVar2 == *(int *)(puVar3 + 0x1a8))))) ||
        ((iVar5 = iVar4 + 5, iVar2 == *(int *)(puVar3 + 0x1b8) ||
         ((iVar5 = iVar4 + 6, iVar2 == *(int *)(puVar3 + 0x1c8) ||
          (iVar5 = iVar4 + 7, iVar2 == *(int *)(puVar3 + 0x1d8))))))) ||
       (iVar5 = iVar4 + 8, iVar2 == *(int *)(puVar3 + 0x1e8))) break;
    puVar3 = puVar3 + 0x90;
    iVar4 = iVar4 + 9;
    iVar6 = iVar6 + -1;
    iVar5 = iVar4;
  } while (iVar6 != 0);
  if (iVar5 == 0x3f) {
    return;
  }
  puVar3 = &DAT_803a3f08 + iVar5 * 0x10;
  uVar1 = 0x3e - iVar5;
  if (iVar5 < 0x3e) {
    uVar7 = uVar1 >> 2;
    if (uVar7 != 0) {
      do {
        *(undefined4 *)(puVar3 + 0x168) = *(undefined4 *)(puVar3 + 0x178);
        *(undefined4 *)(puVar3 + 0x16c) = *(undefined4 *)(puVar3 + 0x17c);
        *(undefined4 *)(puVar3 + 0x170) = *(undefined4 *)(puVar3 + 0x180);
        *(undefined4 *)(puVar3 + 0x174) = *(undefined4 *)(puVar3 + 0x184);
        *(undefined4 *)(puVar3 + 0x178) = *(undefined4 *)(puVar3 + 0x188);
        *(undefined4 *)(puVar3 + 0x17c) = *(undefined4 *)(puVar3 + 0x18c);
        *(undefined4 *)(puVar3 + 0x180) = *(undefined4 *)(puVar3 + 400);
        *(undefined4 *)(puVar3 + 0x184) = *(undefined4 *)(puVar3 + 0x194);
        *(undefined4 *)(puVar3 + 0x188) = *(undefined4 *)(puVar3 + 0x198);
        *(undefined4 *)(puVar3 + 0x18c) = *(undefined4 *)(puVar3 + 0x19c);
        *(undefined4 *)(puVar3 + 400) = *(undefined4 *)(puVar3 + 0x1a0);
        *(undefined4 *)(puVar3 + 0x194) = *(undefined4 *)(puVar3 + 0x1a4);
        *(undefined4 *)(puVar3 + 0x198) = *(undefined4 *)(puVar3 + 0x1a8);
        *(undefined4 *)(puVar3 + 0x19c) = *(undefined4 *)(puVar3 + 0x1ac);
        *(undefined4 *)(puVar3 + 0x1a0) = *(undefined4 *)(puVar3 + 0x1b0);
        *(undefined4 *)(puVar3 + 0x1a4) = *(undefined4 *)(puVar3 + 0x1b4);
        puVar3 = puVar3 + 0x40;
        uVar7 = uVar7 - 1;
      } while (uVar7 != 0);
      uVar1 = uVar1 & 3;
      if (uVar1 == 0) {
        DAT_803c4060 = 0;
        return;
      }
    }
    do {
      *(undefined4 *)(puVar3 + 0x168) = *(undefined4 *)(puVar3 + 0x178);
      *(undefined4 *)(puVar3 + 0x16c) = *(undefined4 *)(puVar3 + 0x17c);
      *(undefined4 *)(puVar3 + 0x170) = *(undefined4 *)(puVar3 + 0x180);
      *(undefined4 *)(puVar3 + 0x174) = *(undefined4 *)(puVar3 + 0x184);
      puVar3 = puVar3 + 0x10;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
  }
  DAT_803c4060 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e8630
 * EN v1.0 Address: 0x800E8630
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x800E85F4
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e8630(int param_1)
{
  int iVar1;
  undefined1 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  if ((*(ushort *)(param_1 + 6) & 0x2000) != 0) {
    return;
  }
  if (DAT_803de100 != '\0') {
    return;
  }
  iVar3 = 0;
  puVar2 = &DAT_803a3f08;
  iVar5 = 9;
  while ((iVar4 = iVar3, *(int *)(puVar2 + 0x168) != 0 &&
         (iVar1 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14), iVar1 != *(int *)(puVar2 + 0x168)))) {
    iVar4 = iVar3 + 1;
    if ((*(int *)(puVar2 + 0x178) == 0) || (iVar1 == *(int *)(puVar2 + 0x178))) break;
    iVar4 = iVar3 + 2;
    if ((*(int *)(puVar2 + 0x188) == 0) || (iVar1 == *(int *)(puVar2 + 0x188))) break;
    iVar4 = iVar3 + 3;
    if ((*(int *)(puVar2 + 0x198) == 0) || (iVar1 == *(int *)(puVar2 + 0x198))) break;
    iVar4 = iVar3 + 4;
    if ((*(int *)(puVar2 + 0x1a8) == 0) || (iVar1 == *(int *)(puVar2 + 0x1a8))) break;
    iVar4 = iVar3 + 5;
    if ((*(int *)(puVar2 + 0x1b8) == 0) || (iVar1 == *(int *)(puVar2 + 0x1b8))) break;
    iVar4 = iVar3 + 6;
    if ((*(int *)(puVar2 + 0x1c8) == 0) || (iVar1 == *(int *)(puVar2 + 0x1c8))) break;
    puVar2 = puVar2 + 0x70;
    iVar3 = iVar3 + 7;
    iVar5 = iVar5 + -1;
    iVar4 = iVar3;
    if (iVar5 == 0) break;
  }
  if (iVar4 == 0x3f) {
    return;
  }
  (&DAT_803a4070)[iVar4 * 4] = *(undefined4 *)(*(int *)(param_1 + 0x4c) + 0x14);
  (&DAT_803a4074)[iVar4 * 4] = *(undefined4 *)(param_1 + 0xc);
  (&DAT_803a4078)[iVar4 * 4] = *(undefined4 *)(param_1 + 0x10);
  (&DAT_803a407c)[iVar4 * 4] = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(*(int *)(param_1 + 0x4c) + 8) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(*(int *)(param_1 + 0x4c) + 0xc) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(*(int *)(param_1 + 0x4c) + 0x10) = *(undefined4 *)(param_1 + 0x14);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e8794
 * EN v1.0 Address: 0x800E8794
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x800E875C
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e8794(undefined2 param_1)
{
  DAT_803a45ac = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e87a0
 * EN v1.0 Address: 0x800E87A0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800E876C
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800e87a0(void)
{
  return (int)DAT_803a45ac;
}

/*
 * --INFO--
 *
 * Function: FUN_800e87a8
 * EN v1.0 Address: 0x800E87A8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800E877C
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 * FUN_800e87a8(void)
{
  return &DAT_803a45b0;
}

/*
 * --INFO--
 *
 * Function: titleLoadSaveFiles
 * EN v1.0 Address: 0x800E8508
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x800E878C
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int titleLoadSaveFiles(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                       undefined8 param_5,undefined8 param_6,undefined8 param_7,
                       undefined8 param_8)
{
  int iVar1;
  
  iVar1 = FUN_80072600(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                      &gGameplayPreviewSettings
                      );
  if ((iVar1 == 0) || (gGameplayPreviewSettings == '\0')) {
    FUN_800033a8(-0x7fc5c1dc,0,0xe4);
    DAT_803a3e2a = 0;
    DAT_803a3e26 = 1;
    DAT_803a3e2c = 1;
    gGameplayPreviewSettings = '\x01';
    gGameplayPreviewColorRed = 0x7f;
    gGameplayPreviewColorGreen = 0x7f;
    gGameplayPreviewColorBlue = 0x7f;
  }
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: gameplay_applyPreviewSettingsForSlot
 * EN v1.0 Address: 0x800E8864
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x800E8824
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void gameplay_applyPreviewSettingsForSlot(undefined8 param_1,double param_2,undefined8 param_3,
                                          undefined8 param_4,undefined8 param_5,
                                          undefined8 param_6,undefined8 param_7,
                                          undefined8 param_8,byte param_9)
{
  DAT_803a3f29 = 0;
  DAT_803dc4f0 = param_9;
  if (DAT_803a3f2a == '\0') {
    param_1 = FUN_80003494((uint)DAT_803de110,0x803a3f08,0x564);
    if (DAT_803de114 != 0) {
      param_1 = FUN_80003494(DAT_803de114,0x803a3f08,0x564);
    }
  }
  if (DAT_803dc4f0 == 0xff) {
    DAT_803dc4f0 = 0;
  }
  if (*DAT_803de110 < '\x01') {
    *DAT_803de110 = '\x01';
  }
  if (DAT_803de110[0xc] < '\x01') {
    DAT_803de110[0xc] = '\x01';
  }
  FUN_80072564(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)DAT_803dc4f0,
               DAT_803de110,&gGameplayPreviewSettings);
  return;
}

/*
 * --INFO--
 *
 * Function: gameplay_capturePreviewSettings
 * EN v1.0 Address: 0x800E89B0
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x800E88F0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void gameplay_capturePreviewSettings(void)
{
  FUN_80244e58(0,0);
  DAT_803dc4f0 = (undefined)((int)(*((byte *)DAT_803de110 + 0x21) & 0x60) >> 5);
  *((byte *)DAT_803de110 + 0x21) = *((byte *)DAT_803de110 + 0x21) & 0x1f;
  (**(code **)(*DAT_803dd72c + 0x20))();
  return;
}

/*
 * --INFO--
 *
 * Function: gameplay_applyCurrentPreviewSettings
 * EN v1.0 Address: 0x800E8A0C
 * EN v1.0 Size: 316b
 * EN v1.1 Address: 0x800E8954
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void gameplay_applyCurrentPreviewSettings(undefined8 param_1,double param_2,undefined8 param_3,
                                          undefined8 param_4,undefined8 param_5,
                                          undefined8 param_6,undefined8 param_7,
                                          undefined8 param_8)
{
  if (DAT_803a3f2a == '\0') {
    param_1 = FUN_80003494((uint)DAT_803de110,0x803a3f08,0x564);
    if (DAT_803de114 != 0) {
      param_1 = FUN_80003494(DAT_803de114,0x803a3f08,0x564);
    }
  }
  if (DAT_803dc4f0 == 0xff) {
    DAT_803dc4f0 = 0;
  }
  if (*DAT_803de110 < '\x01') {
    *DAT_803de110 = '\x01';
  }
  if (DAT_803de110[0xc] < '\x01') {
    DAT_803de110[0xc] = '\x01';
  }
  FUN_80072564(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)DAT_803dc4f0,
               DAT_803de110,&gGameplayPreviewSettings);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e8b48
 * EN v1.0 Address: 0x800E8B48
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x800E8A10
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e8b48(void)
{
  DAT_803de100 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e8b54
 * EN v1.0 Address: 0x800E8B54
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x800E8A1C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e8b54(void)
{
  if (DAT_803de100 != '\x02') {
    return;
  }
  DAT_803de100 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e8b6c
 * EN v1.0 Address: 0x800E8B6C
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x800E8A34
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800e8b6c(void)
{
  uint uVar1;
  
  uVar1 = countLeadingZeros(2 - (uint)DAT_803de100);
  return uVar1 >> 5;
}

/*
 * --INFO--
 *
 * Function: FUN_800e8b98
 * EN v1.0 Address: 0x800E8B98
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x800E8A48
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_800e8b98(void)
{
  return DAT_803de100;
}

/*
 * --INFO--
 *
 * Function: FUN_800e8ba4
 * EN v1.0 Address: 0x800E8BA4
 * EN v1.0 Size: 428b
 * EN v1.1 Address: 0x800E8A50
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800e8ba4(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                byte param_9)
{
  int iVar1;
  
  DAT_803dc4f0 = param_9;
  FUN_800033a8(-0x7fc5c0f8,0,0xf70);
  if ((*(byte *)(DAT_803de110 + 0x21) & 0x80) == 0) {
    FUN_800033a8(DAT_803de110,0,0x6ec);
  }
  iVar1 = FUN_8007269c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (uint)DAT_803dc4f0,DAT_803de110);
  if (iVar1 == 0) {
    FUN_800e8f58(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  else if (*(char *)(DAT_803de110 + 0x21) == '\0') {
    FUN_800e8f58(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  else {
    FUN_80003494(0x803a3f08,DAT_803de110,0x6ec);
  }
  return iVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_800e8d50
 * EN v1.0 Address: 0x800E8D50
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x800E8B10
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined * FUN_800e8d50(uint param_1,uint param_2)
{
  return (undefined *)&DAT_803a3e40 + (param_1 & 0xff) * 0x28 + (param_2 & 0xff) * 8;
}

/*
 * --INFO--
 *
 * Function: FUN_800e8d6c
 * EN v1.0 Address: 0x800E8D6C
 * EN v1.0 Size: 484b
 * EN v1.1 Address: 0x800E8B38
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800e8d6c(uint param_1,byte param_2,uint param_3,undefined *param_4)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined1 *puVar4;
  undefined *puVar5;
  undefined1 *puVar6;
  int iVar7;
  uint uVar8;
  
  iVar2 = 0;
  iVar1 = (param_1 & 0xff) * 0x28;
  puVar6 = &gGameplayPreviewSettings + iVar1;
  iVar7 = 5;
  puVar4 = puVar6;
  do {
    if (*(uint *)(puVar4 + 0x1c) >> 1 < param_3) {
      iVar7 = 4;
      puVar5 = &DAT_803a3e44 + iVar1;
      uVar3 = 4 - iVar2;
      if (iVar2 < 4) {
        uVar8 = uVar3 >> 1;
        if (uVar8 == 0) goto LAB_800e8c5c;
        do {
          *(uint *)(puVar5 + 0x1c) =
               *(uint *)(puVar6 + (iVar7 + -1) * 8 + 0x1c) & 0xfffffffe |
               *(uint *)(puVar5 + 0x1c) & 1;
          puVar5[0x1f] = puVar6[(iVar7 + -1) * 8 + 0x1f] & 1 | puVar5[0x1f] & 0xfe;
          puVar5[0x20] = puVar5[0x18];
          puVar5[0x21] = puVar5[0x19];
          puVar5[0x22] = puVar5[0x1a];
          puVar5[0x23] = puVar5[0x1b];
          *(uint *)(puVar5 + 0x14) =
               *(uint *)(puVar6 + (iVar7 + -2) * 8 + 0x1c) & 0xfffffffe |
               *(uint *)(puVar5 + 0x14) & 1;
          puVar5[0x17] = puVar6[(iVar7 + -2) * 8 + 0x1f] & 1 | puVar5[0x17] & 0xfe;
          puVar5[0x18] = puVar5[0x10];
          puVar5[0x19] = puVar5[0x11];
          puVar5[0x1a] = puVar5[0x12];
          puVar5[0x1b] = puVar5[0x13];
          puVar5 = puVar5 + -0x10;
          iVar7 = iVar7 + -2;
          uVar8 = uVar8 - 1;
        } while (uVar8 != 0);
        for (uVar3 = uVar3 & 1; uVar3 != 0; uVar3 = uVar3 - 1) {
LAB_800e8c5c:
          *(uint *)(puVar5 + 0x1c) =
               *(uint *)(puVar6 + (iVar7 + -1) * 8 + 0x1c) & 0xfffffffe |
               *(uint *)(puVar5 + 0x1c) & 1;
          puVar5[0x1f] = puVar6[(iVar7 + -1) * 8 + 0x1f] & 1 | puVar5[0x1f] & 0xfe;
          puVar5[0x20] = puVar5[0x18];
          puVar5[0x21] = puVar5[0x19];
          puVar5[0x22] = puVar5[0x1a];
          puVar5[0x23] = puVar5[0x1b];
          puVar5 = puVar5 + -8;
          iVar7 = iVar7 + -1;
        }
      }
      iVar7 = iVar2 * 8;
      *(uint *)(puVar6 + iVar7 + 0x1c) = param_3 << 1 | *(uint *)(puVar6 + iVar7 + 0x1c) & 1;
      puVar6[iVar7 + 0x1f] = param_2 & 1 | puVar6[iVar7 + 0x1f] & 0xfe;
      iVar7 = iVar7 + iVar1;
      (&gGameplayPreviewSettings)[iVar7 + 0x20] = *param_4;
      (&gGameplayPreviewSettings)[iVar7 + 0x21] = param_4[1];
      (&gGameplayPreviewSettings)[iVar7 + 0x22] = param_4[2];
      (&gGameplayPreviewSettings)[iVar7 + 0x23] = param_4[3];
      return iVar2;
    }
    puVar4 = puVar4 + 8;
    iVar2 = iVar2 + 1;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  return -1;
}

/*
 * --INFO--
 *
 * Function: FUN_800e8f50
 * EN v1.0 Address: 0x800E8F50
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800E8D30
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined1 * FUN_800e8f50(void)
{
  return (undefined1 *)&DAT_803a3f24;
}

/*
 * --INFO--
 *
 * Function: FUN_800e8f58
 * EN v1.0 Address: 0x800E8F58
 * EN v1.0 Size: 832b
 * EN v1.1 Address: 0x800E8D40
 * EN v1.1 Size: 736b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e8f58(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  char *pcVar4;
  int iVar5;
  short *psVar6;
  char *pcVar7;
  char cVar8;
  undefined8 uVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286840();
  uVar3 = DAT_802c28f8;
  uVar2 = DAT_802c28f4;
  uVar1 = DAT_802c28f0;
  pcVar7 = (char *)((ulonglong)uVar10 >> 0x20);
  FUN_800033a8(-0x7fc5c0f8,0,0xf70);
  if ((*(byte *)(DAT_803de110 + 0x21) & 0x80) == 0) {
    FUN_800033a8(DAT_803de110,0,0x6ec);
  }
  DAT_803a3f28 = 0;
  DAT_803a3f08 = 0xc;
  DAT_803a3f09 = 0xc;
  DAT_803a3f0e = 0x19;
  DAT_803a3f0c = 0;
  DAT_803a3f12 = 1;
  DAT_803a459a = 0xff;
  DAT_803a3f14 = 0xc;
  DAT_803a3f15 = 0xc;
  DAT_803a3f1a = 0x19;
  DAT_803a3f18 = 0;
  DAT_803a3f1e = 1;
  DAT_803a45aa = 0xff;
  DAT_803a3f21 = 0x14;
  DAT_803a45ac = 0xffff;
  DAT_803a45b0 = lbl_803E1348;
  DAT_803a45b4 = 0xffff;
  DAT_803a45b6 = 0xffff;
  DAT_803a45ba = 0xffff;
  DAT_803a45bc = 0xffff;
  DAT_803a45be = 0xffff;
  DAT_803a45c0 = 0xffff;
  DAT_803a45c2 = 0xffff;
  DAT_803a45f1 = 0xff;
  DAT_803a45f2 = 0xff;
  DAT_803a45f3 = 0xff;
  DAT_803a45f0 = 9;
  DAT_803a3f2b = 0;
  DAT_803a3f29 = 1;
  iVar5 = 0;
  psVar6 = &DAT_80312370;
  do {
    if (*psVar6 != 0) {
      (**(code **)(*DAT_803dd72c + 0x44))(iVar5,1);
    }
    psVar6 = psVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 0x78);
  FUN_800e95e8(7,0,1);
  FUN_800e95e8(7,2,1);
  FUN_800e95e8(7,3,1);
  FUN_800e95e8(7,5,1);
  FUN_800e95e8(7,10,1);
  FUN_800e95e8(0x1d,0,1);
  FUN_800e95e8(0x1d,0x1f,1);
  FUN_800e95e8(0x13,0,1);
  FUN_800e95e8(0x13,0x16,1);
  FUN_80017698(0x967,1);
  (&DAT_803a458c)[(uint)DAT_803a3f28 * 4] = uVar1;
  (&DAT_803a4590)[(uint)DAT_803a3f28 * 4] = uVar2;
  (&DAT_803a4594)[(uint)DAT_803a3f28 * 4] = uVar3;
  DAT_803a4465 = 1;
  if (pcVar7 == (char *)0x0) {
    DAT_803a3f24 = 0x46;
    DAT_803a3f25 = 0x4f;
    DAT_803a3f26 = 0x58;
    DAT_803a3f27 = 0;
    pcVar7 = (char *)0x0;
  }
  else {
    pcVar4 = &DAT_803a3f24;
    do {
      cVar8 = *pcVar7;
      pcVar7 = pcVar7 + 1;
      *pcVar4 = cVar8;
      pcVar4 = pcVar4 + 1;
    } while (cVar8 != '\0');
  }
  uVar9 = FUN_80003494(DAT_803de110,0x803a3f08,0x6ec);
  cVar8 = (char)uVar10;
  if ((cVar8 != -1) && (DAT_803dc4f0 = cVar8, pcVar7 != (char *)0x0)) {
    FUN_80072564(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)uVar10 & 0xff,
                 DAT_803de110,&gGameplayPreviewSettings);
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e9298
 * EN v1.0 Address: 0x800E9298
 * EN v1.0 Size: 848b
 * EN v1.1 Address: 0x800E9020
 * EN v1.1 Size: 604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e9298(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar5;
  byte *pbVar6;
  uint uVar7;
  double extraout_f1;
  double dVar8;
  undefined auStack_708 [28];
  undefined auStack_6ec [5];
  char local_6e7;
  byte local_1b0 [5];
  byte local_1ab;
  byte local_1aa;
  float local_1a8;
  
  uVar1 = FUN_8028683c();
  uVar7 = 0;
  dVar8 = extraout_f1;
  do {
    iVar2 = FUN_8007269c(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar7 & 0xff,
                         auStack_708);
    if (iVar2 == 0) break;
    *(char *)(uVar1 + 0x20) = local_6e7;
    if (local_6e7 == '\0') {
      FUN_800033a8(uVar1,0,0x24);
    }
    else {
      uVar4 = 4;
      FUN_80003494(uVar1,(uint)auStack_6ec,4);
      *(char *)(uVar1 + 4) = (char)(((uint)local_1ab * 100) / 0xbb);
      if (local_1ab < 0xb4) {
        if (local_1ab < 0xb1) {
          if (local_1ab < 0xa2) {
            if (local_1ab < 0x8b) {
              if (local_1ab < 0x82) {
                if (local_1ab < 0x72) {
                  if (local_1ab < 99) {
                    if (local_1ab < 0x49) {
                      if (local_1ab < 0x3e) {
                        if (local_1ab < 9) {
                          *(undefined *)(uVar1 + 5) = 0;
                          *(undefined *)(uVar1 + 6) = 0;
                        }
                        else {
                          *(undefined *)(uVar1 + 5) = 1;
                          *(undefined *)(uVar1 + 6) = 0;
                        }
                      }
                      else {
                        *(undefined *)(uVar1 + 5) = 1;
                        *(undefined *)(uVar1 + 6) = 1;
                      }
                    }
                    else {
                      *(undefined *)(uVar1 + 5) = 2;
                      *(undefined *)(uVar1 + 6) = 1;
                    }
                  }
                  else {
                    *(undefined *)(uVar1 + 5) = 2;
                    *(undefined *)(uVar1 + 6) = 2;
                  }
                }
                else {
                  *(undefined *)(uVar1 + 5) = 3;
                  *(undefined *)(uVar1 + 6) = 2;
                }
              }
              else {
                *(undefined *)(uVar1 + 5) = 3;
                *(undefined *)(uVar1 + 6) = 3;
              }
            }
            else {
              *(undefined *)(uVar1 + 5) = 4;
              *(undefined *)(uVar1 + 6) = 3;
            }
          }
          else {
            *(undefined *)(uVar1 + 5) = 4;
            *(undefined *)(uVar1 + 6) = 4;
          }
        }
        else {
          *(undefined *)(uVar1 + 5) = 5;
          *(undefined *)(uVar1 + 6) = 4;
        }
      }
      else {
        *(undefined *)(uVar1 + 5) = 6;
        *(undefined *)(uVar1 + 6) = 4;
      }
      dVar8 = (double)(local_1a8 / lbl_803E134C);
      iVar2 = FUN_80286718(dVar8);
      *(int *)(uVar1 + 8) = iVar2;
      *(undefined4 *)(uVar1 + 0xc) = 0;
      *(undefined4 *)(uVar1 + 0x10) = 0;
      *(undefined4 *)(uVar1 + 0x14) = 0;
      *(undefined4 *)(uVar1 + 0x18) = 0;
      *(undefined4 *)(uVar1 + 0x1c) = 0;
      pbVar6 = local_1b0;
      uVar5 = uVar1;
      for (iVar2 = 0; iVar2 < (int)(uint)local_1aa; iVar2 = iVar2 + 1) {
        uVar3 = FUN_80017460(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             *pbVar6 + 0xf4,0,uVar4,in_r6,in_r7,in_r8,in_r9,in_r10);
        *(undefined4 *)(uVar5 + 0xc) = uVar3;
        uVar5 = uVar5 + 4;
        pbVar6 = pbVar6 + 1;
      }
      *(undefined *)(uVar1 + 0x21) = 0;
      *(char *)(uVar1 + 0x20) = local_6e7;
    }
    uVar1 = uVar1 + 0x24;
    uVar7 = uVar7 + 1;
  } while ((int)uVar7 < 3);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e95e8
 * EN v1.0 Address: 0x800E95E8
 * EN v1.0 Size: 1040b
 * EN v1.1 Address: 0x800E927C
 * EN v1.1 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e95e8(undefined4 param_1,undefined4 param_2,int param_3)
{
  bool bVar1;
  char cVar2;
  uint uVar3;
  char cVar4;
  short *psVar5;
  char *pcVar6;
  uint *puVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  char *pcVar11;
  int iVar12;
  int iVar13;
  longlong lVar14;
  
  lVar14 = FUN_80286830();
  uVar10 = (uint)((ulonglong)lVar14 >> 0x20);
  uVar8 = (uint)lVar14;
  pcVar11 = &DAT_803a3be0;
  if (0x4fffffffff < lVar14) {
    uVar10 = (uint)(byte)(&DAT_803a3dac)[uVar10];
  }
  if ((int)uVar10 < 0x78) {
    if ((ushort)(&DAT_80312460)[uVar10] != 0) {
      if (param_3 == -1) {
        param_3 = 1;
      }
      bVar1 = param_3 == -2;
      if (bVar1) {
        param_3 = 0;
      }
      uVar3 = FUN_80017690((uint)(ushort)(&DAT_80312460)[uVar10]);
      if (param_3 == 0) {
        uVar9 = uVar3 & ~(1 << uVar8);
      }
      else {
        uVar9 = uVar3 | 1 << uVar8;
      }
      FUN_80017698((uint)(ushort)(&DAT_80312460)[uVar10],uVar9);
      DAT_803de104 = uVar10;
      uRam803de108 = uVar9;
      if (param_3 == 0) {
        psVar5 = &DAT_80312460;
        puVar7 = &DAT_803a3c1c;
        uVar3 = ~(1 << uVar8);
        iVar12 = 0x14;
        do {
          if (*psVar5 == (&DAT_80312460)[uVar10]) {
            *puVar7 = *puVar7 & uVar3;
          }
          if (psVar5[1] == (&DAT_80312460)[uVar10]) {
            puVar7[1] = puVar7[1] & uVar3;
          }
          if (psVar5[2] == (&DAT_80312460)[uVar10]) {
            puVar7[2] = puVar7[2] & uVar3;
          }
          if (psVar5[3] == (&DAT_80312460)[uVar10]) {
            puVar7[3] = puVar7[3] & uVar3;
          }
          if (psVar5[4] == (&DAT_80312460)[uVar10]) {
            puVar7[4] = puVar7[4] & uVar3;
          }
          if (psVar5[5] == (&DAT_80312460)[uVar10]) {
            puVar7[5] = puVar7[5] & uVar3;
          }
          psVar5 = psVar5 + 6;
          puVar7 = puVar7 + 6;
          iVar12 = iVar12 + -1;
        } while (iVar12 != 0);
        if (!bVar1) {
          cVar4 = '\0';
          iVar12 = 4;
          pcVar6 = pcVar11;
          do {
            if ((((((uVar10 == (int)*pcVar6) && (cVar2 = cVar4, uVar8 == (byte)pcVar6[1])) ||
                  ((cVar2 = cVar4 + '\x01', uVar10 == (int)pcVar6[3] && (uVar8 == (byte)pcVar6[4])))
                  ) || ((cVar2 = cVar4 + '\x02', uVar10 == (int)pcVar6[6] &&
                        (uVar8 == (byte)pcVar6[7])))) ||
                ((cVar2 = cVar4 + '\x03', uVar10 == (int)pcVar6[9] && (uVar8 == (byte)pcVar6[10]))))
               || ((uVar10 == (int)pcVar6[0xc] &&
                   (cVar2 = cVar4 + '\x04', uVar8 == (byte)pcVar6[0xd])))) goto LAB_800e9628;
            pcVar6 = pcVar6 + 0xf;
            cVar4 = cVar4 + '\x05';
            iVar12 = iVar12 + -1;
          } while (iVar12 != 0);
          cVar2 = -1;
LAB_800e9628:
          if (cVar2 == -1) {
            iVar12 = 0;
            iVar13 = 0x14;
            do {
              if (*pcVar11 == -1) {
                iVar12 = iVar12 * 3;
                (&DAT_803a3be0)[iVar12] = (char)uVar10;
                (&DAT_803a3be1)[iVar12] = (char)lVar14;
                (&DAT_803a3be2)[iVar12] = 3;
                break;
              }
              pcVar11 = pcVar11 + 3;
              iVar12 = iVar12 + 1;
              iVar13 = iVar13 + -1;
            } while (iVar13 != 0);
          }
        }
      }
      else {
        uVar8 = 1 << uVar8;
        if ((uVar3 & uVar8) == 0) {
          psVar5 = &DAT_80312460;
          puVar7 = &DAT_803a3c1c;
          iVar12 = 0x14;
          do {
            if (*psVar5 == (&DAT_80312460)[uVar10]) {
              *puVar7 = *puVar7 | uVar8;
            }
            if (psVar5[1] == (&DAT_80312460)[uVar10]) {
              puVar7[1] = puVar7[1] | uVar8;
            }
            if (psVar5[2] == (&DAT_80312460)[uVar10]) {
              puVar7[2] = puVar7[2] | uVar8;
            }
            if (psVar5[3] == (&DAT_80312460)[uVar10]) {
              puVar7[3] = puVar7[3] | uVar8;
            }
            if (psVar5[4] == (&DAT_80312460)[uVar10]) {
              puVar7[4] = puVar7[4] | uVar8;
            }
            if (psVar5[5] == (&DAT_80312460)[uVar10]) {
              puVar7[5] = puVar7[5] | uVar8;
            }
            psVar5 = psVar5 + 6;
            puVar7 = puVar7 + 6;
            iVar12 = iVar12 + -1;
          } while (iVar12 != 0);
        }
      }
    }
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e99f8
 * EN v1.0 Address: 0x800E99F8
 * EN v1.0 Size: 284b
 * EN v1.1 Address: 0x800E969C
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e99f8(void)
{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = &DAT_803a3be0;
  iVar2 = 4;
  do {
    if ((*pcVar1 != -1) && (pcVar1[2] = pcVar1[2] + -1, pcVar1[2] < '\x01')) {
      *pcVar1 = -1;
    }
    if ((pcVar1[3] != -1) && (pcVar1[5] = pcVar1[5] + -1, pcVar1[5] < '\x01')) {
      pcVar1[3] = -1;
    }
    if ((pcVar1[6] != -1) && (pcVar1[8] = pcVar1[8] + -1, pcVar1[8] < '\x01')) {
      pcVar1[6] = -1;
    }
    if ((pcVar1[9] != -1) && (pcVar1[0xb] = pcVar1[0xb] + -1, pcVar1[0xb] < '\x01')) {
      pcVar1[9] = -1;
    }
    if ((pcVar1[0xc] != -1) && (pcVar1[0xe] = pcVar1[0xe] + -1, pcVar1[0xe] < '\x01')) {
      pcVar1[0xc] = -1;
    }
    pcVar1 = pcVar1 + 0xf;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e9b14
 * EN v1.0 Address: 0x800E9B14
 * EN v1.0 Size: 236b
 * EN v1.1 Address: 0x800E97C4
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800e9b14(int param_1,uint param_2)
{
  char *pcVar1;
  char cVar2;
  int iVar3;
  
  cVar2 = '\0';
  pcVar1 = &DAT_803a3be0;
  iVar3 = 4;
  while( true ) {
    if ((param_1 == *pcVar1) && (param_2 == (byte)pcVar1[1])) {
      return (int)cVar2;
    }
    if ((param_1 == pcVar1[3]) && (param_2 == (byte)pcVar1[4])) {
      return (int)(char)(cVar2 + '\x01');
    }
    if ((param_1 == pcVar1[6]) && (param_2 == (byte)pcVar1[7])) {
      return (int)(char)(cVar2 + '\x02');
    }
    if ((param_1 == pcVar1[9]) && (param_2 == (byte)pcVar1[10])) break;
    if ((param_1 == pcVar1[0xc]) && (param_2 == (byte)pcVar1[0xd])) {
      return (int)(char)(cVar2 + '\x04');
    }
    pcVar1 = pcVar1 + 0xf;
    cVar2 = cVar2 + '\x05';
    iVar3 = iVar3 + -1;
    if (iVar3 == 0) {
      return -1;
    }
  }
  return (int)(char)(cVar2 + '\x03');
}

/*
 * --INFO--
 *
 * Function: FUN_800e9c00
 * EN v1.0 Address: 0x800E9C00
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x800E98C0
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e9c00(uint param_1,int param_2)
{
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a3dac)[param_1];
  }
  (&DAT_803a3c1c)[param_1] = (&DAT_803a3c1c)[param_1] & ~(1 << param_2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e9c3c
 * EN v1.0 Address: 0x800E9C3C
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x800E995C
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e9c3c(uint param_1)
{
  uint uVar1;
  
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a3dac)[param_1];
  }
  if ((ushort)(&DAT_80312460)[param_1] != 0) {
    uVar1 = FUN_80017690((uint)(ushort)(&DAT_80312460)[param_1]);
    (&DAT_803a3c1c)[param_1] = uVar1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e9ca4
 * EN v1.0 Address: 0x800E9CA4
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x800E99DC
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800e9ca4(uint param_1,uint param_2)
{
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a3dac)[param_1];
  }
  if (param_1 != DAT_803de104) {
    DAT_803de104 = param_1;
    uRam803de108 = FUN_80017690((uint)(ushort)(&DAT_80312460)[param_1]);
  }
  return (int)uRam803de108 >> (param_2 & 0x3f) & 1;
}

/*
 * --INFO--
 *
 * Function: FUN_800e9d1c
 * EN v1.0 Address: 0x800E9D1C
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x800E9A58
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_800e9d1c(uint param_1)
{
  uint uVar1;
  
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a3dac)[param_1];
  }
  if (param_1 != (int)DAT_803de10c) {
    DAT_803de10c = (char)param_1;
    if ((((int)param_1 < 0) || (0x77 < (int)param_1)) || ((ushort)(&DAT_80312370)[param_1] == 0)) {
      uRam803de10d = 0;
    }
    else {
      uVar1 = FUN_80017690((uint)(ushort)(&DAT_80312370)[param_1]);
      uRam803de10d = (undefined)uVar1;
    }
  }
  return uRam803de10d;
}

/*
 * --INFO--
 *
 * Function: FUN_800e9da0
 * EN v1.0 Address: 0x800E9DA0
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x800E9AF4
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e9da0(uint param_1,uint param_2)
{
  uint uVar1;
  
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a3dac)[param_1];
  }
  FUN_80017698((uint)(ushort)(&DAT_80312370)[param_1],param_2);
  DAT_803de10c = (undefined)param_1;
  uRam803de10d = (undefined)param_2;
  if (0x4f < (int)param_1) {
    param_1 = (uint)(byte)(&DAT_803a3dac)[param_1];
  }
  if ((ushort)(&DAT_80312460)[param_1] != 0) {
    uVar1 = FUN_80017690((uint)(ushort)(&DAT_80312460)[param_1]);
    (&DAT_803a3c1c)[param_1] = uVar1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e9e54
 * EN v1.0 Address: 0x800E9E54
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x800E9BCC
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e9e54(void)
{
  (&DAT_803a3f08)[(uint)DAT_803a3f28 * 0xc] =
       *(undefined *)(DAT_803de110 + (uint)DAT_803a3f28 * 0xc);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e9e74
 * EN v1.0 Address: 0x800E9E74
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x800E9BEC
 * EN v1.1 Size: 632b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_800e9e74(void)
{
  return (double)DAT_803a4468;
}

/*
 * --INFO--
 *
 * Function: FUN_800e9e9c
 * EN v1.0 Address: 0x800E9E9C
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x800E9E64
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e9e9c(void)
{
  uint uVar1;
  int iVar2;
  undefined4 extraout_r4;
  undefined4 uVar3;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  DAT_803de10c = 0xff;
  DAT_803de104 = 0xffffffff;
  FUN_80042b9c(0,0,1);
  uVar3 = 0x884;
  FUN_800033a8(-0x7fc5ba0c,0,0x884);
  FUN_800176cc();
  FUN_80006770(7);
  FUN_80006b8c();
  FUN_8011e80c();
  uVar1 = (uint)DAT_803a3f28;
  FUN_800176dc((double)(float)(&DAT_803a458c)[uVar1 * 4],(double)(float)(&DAT_803a4590)[uVar1 * 4],
               (double)(float)(&DAT_803a4594)[uVar1 * 4],in_f4,in_f5,in_f6,in_f7,in_f8,
               (int)(char)(&DAT_803a4599)[uVar1 * 0x10],extraout_r4,uVar3,in_r6,in_r7,in_r8,in_r9,
               in_r10);
  iVar2 = FUN_80006b7c();
  if (iVar2 != 4) {
    FUN_80006b84(1);
  }
  FUN_800d783c(0x1e,1);
  DAT_803de100 = 2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ea000
 * EN v1.0 Address: 0x800EA000
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x800E9F30
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ea000(void)
{
  if (DAT_803de114 != 0) {
    FUN_80017814(DAT_803de114);
    DAT_803de114 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ea034
 * EN v1.0 Address: 0x800EA034
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x800E9F64
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ea034(void)
{
  if (DAT_803de114 == 0) {
    FUN_80003494(0x803a3f08,DAT_803de110,0x6ec);
  }
  else {
    FUN_80003494(0x803a3f08,DAT_803de114,0x6ec);
  }
  FUN_800e9e9c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ea1cc
 * EN v1.0 Address: 0x800EA1CC
 * EN v1.0 Size: 540b
 * EN v1.1 Address: 0x800E9FB8
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ea1cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined param_11,int param_12)
{
  bool bVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined extraout_var;
  undefined8 uVar4;
  
  puVar2 = (undefined4 *)FUN_80286840();
  bVar1 = false;
  if (DAT_803de114 == 0) {
    DAT_803de114 = FUN_80017830(0x6ec,-0xff01);
    if (DAT_803de114 == 0) goto LAB_800ea104;
  }
  if (param_12 != 0) {
    uVar4 = FUN_80017698(0x970,1);
    iVar3 = FUN_80017a98();
    iVar3 = FUN_80294d58(iVar3);
    if (1 < iVar3) {
      iVar3 = FUN_80017a98();
      FUN_80294d60(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,-1);
      bVar1 = true;
    }
  }
  FUN_80003494(DAT_803de114,0x803a3f08,0x6ec);
  *(undefined4 *)(DAT_803de114 + (uint)*(byte *)(DAT_803de114 + 0x20) * 0x10 + 0x684) = *puVar2;
  *(undefined4 *)(DAT_803de114 + (uint)*(byte *)(DAT_803de114 + 0x20) * 0x10 + 0x688) = puVar2[1];
  *(undefined4 *)(DAT_803de114 + (uint)*(byte *)(DAT_803de114 + 0x20) * 0x10 + 0x68c) = puVar2[2];
  *(undefined *)(DAT_803de114 + (uint)*(byte *)(DAT_803de114 + 0x20) * 0x10 + 0x690) = extraout_var;
  *(undefined *)(DAT_803de114 + (uint)DAT_803a3f28 * 0x10 + 0x691) = param_11;
  uVar4 = FUN_80017698(0x970,0);
  if ((param_12 != 0) && (bVar1)) {
    iVar3 = FUN_80017a98();
    FUN_80294d60(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,1);
  }
LAB_800ea104:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ea3e8
 * EN v1.0 Address: 0x800EA3E8
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x800EA11C
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ea3e8(void)
{
  if (*DAT_803de110 < '\x01') {
    *DAT_803de110 = '\x01';
  }
  if (DAT_803de110[0xc] < '\x01') {
    DAT_803de110[0xc] = '\x01';
  }
  FUN_80003494(0x803a3f08,(uint)DAT_803de110,0x6ec);
  FUN_800e9e9c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ea590
 * EN v1.0 Address: 0x800EA590
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x800EA188
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ea590(undefined4 *param_1,undefined2 param_2,uint param_3,undefined param_4)
{
  if ((param_3 & 4) != 0) {
    DAT_803a3f2a = '\0';
  }
  if (DAT_803a3f2a == '\0') {
    if ((param_3 & 1) == 0) {
      (&DAT_803a458c)[(uint)DAT_803a3f28 * 4] = *param_1;
      (&DAT_803a4590)[(uint)DAT_803a3f28 * 4] = param_1[1];
      (&DAT_803a4594)[(uint)DAT_803a3f28 * 4] = param_1[2];
      (&DAT_803a4598)[(uint)DAT_803a3f28 * 0x10] = (char)((ushort)param_2 >> 8);
      (&DAT_803a4599)[(uint)DAT_803a3f28 * 0x10] = param_4;
      FUN_80003494(DAT_803de110,0x803a3f08,0x6ec);
      if (DAT_803de114 != 0) {
        FUN_80017814(DAT_803de114);
        DAT_803de114 = 0;
      }
    }
    else {
      FUN_80003494(DAT_803de110,0x803a3f08,0x5d8);
      if (DAT_803de114 != 0) {
        FUN_80003494(DAT_803de114,0x803a3f08,0x5d8);
      }
    }
    if ((param_3 & 2) != 0) {
      DAT_803a3f2a = '\x01';
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ea698
 * EN v1.0 Address: 0x800EA698
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x800EA2D0
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ea698(void)
{
  if (DAT_803de114 != 0) {
    FUN_80017814(DAT_803de114);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ea6c4
 * EN v1.0 Address: 0x800EA6C4
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x800EA2FC
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ea6c4(void)
{
  FUN_800033a8(-0x7fc5c0f8,0,0xf70);
  if ((*(byte *)(DAT_803de110 + 0x21) & 0x80) == 0) {
    FUN_800033a8(DAT_803de110,0,0x6ec);
  }
  DAT_803de114 = 0;
  DAT_803de10c = 0xff;
  DAT_803de104 = 0xffffffff;
  FUN_800033a8(-0x7fc5c1dc,0,0xe4);
  DAT_803a3e2a = 0;
  DAT_803a3e26 = 1;
  DAT_803a3e2c = 1;
  gGameplayPreviewSettings = 1;
  gGameplayPreviewColorRed = 0x7f;
  gGameplayPreviewColorGreen = 0x7f;
  gGameplayPreviewColorBlue = 0x7f;
  DAT_803a3be0 = 0xff;
  DAT_803a3be3 = 0xff;
  DAT_803a3be6 = 0xff;
  DAT_803a3be9 = 0xff;
  DAT_803a3bec = 0xff;
  DAT_803a3bef = 0xff;
  DAT_803a3bf2 = 0xff;
  DAT_803a3bf5 = 0xff;
  DAT_803a3bf8 = 0xff;
  DAT_803a3bfb = 0xff;
  DAT_803a3bfe = 0xff;
  DAT_803a3c01 = 0xff;
  DAT_803a3c04 = 0xff;
  DAT_803a3c07 = 0xff;
  DAT_803a3c0a = 0xff;
  DAT_803a3c0d = 0xff;
  DAT_803a3c10 = 0xff;
  DAT_803a3c13 = 0xff;
  DAT_803a3c16 = 0xff;
  DAT_803a3c19 = 0xff;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ea7bc
 * EN v1.0 Address: 0x800EA7BC
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x800EA3F8
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ea7bc(int param_1)
{
  undefined *puVar1;
  uint uVar2;
  short sVar3;
  
  puVar1 = FUN_800e82d8();
  for (sVar3 = 0; sVar3 < 0xd; sVar3 = sVar3 + 1) {
    uVar2 = FUN_80017690((int)sVar3 + 0xf10);
    *(char *)(param_1 + sVar3) = (char)uVar2;
  }
  *(undefined *)(param_1 + *(short *)(&DAT_80312630 + (uint)(byte)puVar1[5] * 2)) = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ea83c
 * EN v1.0 Address: 0x800EA83C
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x800EA484
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
ushort FUN_800ea83c(void)
{
  undefined *puVar1;
  
  puVar1 = FUN_800e82d8();
  return *(ushort *)(&DAT_80312630 + (uint)(byte)puVar1[5] * 2) & 0xff;
}

/*
 * --INFO--
 *
 * Function: FUN_800ea858
 * EN v1.0 Address: 0x800EA858
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x800EA4BC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ea858(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  undefined *puVar1;
  
  puVar1 = FUN_800e82d8();
  FUN_80017470(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               (byte)puVar1[5] + 0xf4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ea8c8
 * EN v1.0 Address: 0x800EA8C8
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x800EA4E8
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800ea8c8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  undefined4 uVar1;
  undefined *puVar2;
  
  uVar1 = FUN_80017498();
  puVar2 = FUN_800e82d8();
  FUN_80017488(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               (uint)(byte)(&DAT_803a4e78)[*(short *)(&DAT_80312630 + (uint)(byte)puVar2[5] * 2)]);
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_800ea9ac
 * EN v1.0 Address: 0x800EA9AC
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x800EA540
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_800ea9ac(void)
{
  undefined *puVar1;
  
  puVar1 = FUN_800e82d8();
  return puVar1[5];
}

/*
 * --INFO--
 *
 * Function: FUN_800ea9b8
 * EN v1.0 Address: 0x800EA9B8
 * EN v1.0 Size: 408b
 * EN v1.1 Address: 0x800EA564
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ea9b8(void)
{
  uint uVar1;
  undefined *puVar2;
  short sVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint unaff_r27;
  uint uVar7;
  uint uVar8;
  short *psVar9;
  
  uVar1 = FUN_80286834();
  puVar2 = FUN_800e82d8();
  uVar7 = 0xffffffff;
  if (puVar2[6] == '\0') {
    psVar9 = &DAT_80312632;
    for (uVar8 = 1; (short)uVar8 < 0xce; uVar8 = uVar8 + 1) {
      if ((*psVar9 == 0xffff) || (*psVar9 == -1)) {
        uVar5 = 1 << (uVar8 & 0x1f);
        uVar6 = (uint)(short)((short)((uVar8 & 0xff) >> 5) + 0x12f);
        uVar4 = FUN_80017690(uVar6);
        if ((uVar4 & uVar5) == 0) {
          FUN_80017698(uVar6,uVar4 | uVar5);
        }
      }
      psVar9 = psVar9 + 1;
    }
  }
  uVar6 = 1 << (uVar1 & 0x1f);
  uVar4 = (uint)(short)((short)((uVar1 & 0xff) >> 5) + 0x12f);
  uVar8 = FUN_80017690(uVar4);
  if ((uVar8 & uVar6) == 0) {
    FUN_80017698(uVar4,uVar8 | uVar6);
    if (puVar2[6] != '\x05') {
      puVar2[6] = puVar2[6] + '\x01';
    }
    for (sVar3 = 4; sVar3 != 0; sVar3 = sVar3 + -1) {
      puVar2[sVar3] = puVar2[sVar3 + -1];
    }
    *puVar2 = (char)uVar1;
    if ((uint)(byte)puVar2[5] == (uVar1 & 0xff)) {
      do {
        puVar2[5] = puVar2[5] + '\x01';
        uVar1 = (uint)(short)(((byte)puVar2[5] >> 5) + 0x12f);
        if (uVar1 != (int)(short)uVar7) {
          unaff_r27 = FUN_80017690(uVar1);
          uVar7 = uVar1;
        }
      } while ((unaff_r27 & 1 << ((byte)puVar2[5] & 0x1f)) != 0);
    }
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800eab50
 * EN v1.0 Address: 0x800EAB50
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x800EA74C
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800eab50(void)
{
  bool bVar1;
  undefined *puVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  char *pcVar6;
  
  iVar3 = 0xd;
  puVar2 = (undefined *)0x803a4e85;
  while( true ) {
    puVar2 = puVar2 + -1;
    bVar1 = iVar3 == 0;
    iVar3 = iVar3 + -1;
    if (bVar1) break;
    *puVar2 = 0xff;
  }
  iVar3 = 0x49;
  puVar5 = (undefined4 *)0x802c7b40;
  while( true ) {
    puVar5 = puVar5 + -1;
    bVar1 = iVar3 == 0;
    iVar3 = iVar3 + -1;
    if (bVar1) break;
    pcVar6 = (char *)*puVar5;
    if ((((((*pcVar6 == 'T') && (pcVar6[1] == 'a')) && (pcVar6[2] == 's')) &&
         ((pcVar6[3] == 'k' && (pcVar6[4] == 'T')))) &&
        ((pcVar6[5] == 'e' && ((pcVar6[6] == 'x' && (pcVar6[7] == 't')))))) &&
       ((pcVar6[8] == 's' &&
        (iVar4 = ((byte)pcVar6[9] - 0x30) * 100 + ((byte)pcVar6[10] - 0x30) * 10 +
                 (uint)(byte)pcVar6[0xb], iVar4 + -0x30 < 0xd)))) {
      (&DAT_803a4e48)[iVar4] = (char)iVar3;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800eac54
 * EN v1.0 Address: 0x800EAC54
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x800EA850
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800eac54(void)
{
  if (DAT_803de118 != 0) {
    FUN_80017814(DAT_803de118);
    DAT_803de118 = 0;
    DAT_803de11c = 0;
    DAT_803de124 = 0xffffffff;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800eac94
 * EN v1.0 Address: 0x800EAC94
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x800EA890
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800eac94(void)
{
  if (DAT_803de118 != 0) {
    FUN_80017814(DAT_803de118);
    DAT_803de118 = 0;
    DAT_803de124 = 0xffffffff;
    DAT_803de11c = 0;
    DAT_803de120 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800eacd8
 * EN v1.0 Address: 0x800EACD8
 * EN v1.0 Size: 480b
 * EN v1.1 Address: 0x800EA8D4
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800eacd8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  int *local_18 [3];
  
  local_18[0] = (int *)0x0;
  if (DAT_803de124 != param_9) {
    uVar4 = FUN_80017644(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_18,
                         0x19,param_11,param_12,param_13,param_14,param_15,param_16);
    iVar2 = 0;
    for (piVar1 = local_18[0]; *piVar1 != -1; piVar1 = piVar1 + 1) {
      iVar2 = iVar2 + 1;
    }
    if ((param_9 < 0) || (iVar2 + -1 <= param_9)) {
      param_9 = 0;
    }
    iVar3 = local_18[0][param_9];
    iVar2 = local_18[0][param_9 + 1] - iVar3;
    if (iVar2 != DAT_803de11c) {
      if (DAT_803de118 != 0) {
        uVar4 = FUN_80017814(DAT_803de118);
      }
      DAT_803de118 = FUN_80017830(iVar2,2);
    }
    DAT_803de11c = iVar2;
    FUN_80017640(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803de118,0x18,
                 iVar3,iVar2,param_13,param_14,param_15,param_16);
    FUN_80017814((uint)local_18[0]);
    DAT_803de124 = param_9;
  }
  DAT_803de120 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800eaeb8
 * EN v1.0 Address: 0x800EAEB8
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x800EA9F8
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800eaeb8(int param_1)
{
  int iVar1;
  
  if (*(short *)(param_1 + 0x46) != 0x112) {
    iVar1 = *(int *)(param_1 + 0xb8);
    *(undefined *)(iVar1 + 5) = 0;
    *(undefined *)(iVar1 + 6) = 0;
    if ((*(byte *)(iVar1 + 7) & 8) == 0) {
      *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + lbl_803E1358;
      FUN_800e8630(param_1);
      *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - lbl_803E1358;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800eaf2c
 * EN v1.0 Address: 0x800EAF2C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800EAA70
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800eaf2c(int param_1,int param_2)
{
  int iVar1;
  int local_18 [3];
  
  iVar1 = FUN_80017a98();
  *(undefined *)(param_2 + 5) = 0;
  FUN_80294d00(iVar1,local_18);
  if (local_18[0] == param_1) {
    FUN_80294ce0(iVar1,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800eaf90
 * EN v1.0 Address: 0x800EAF90
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x800EABB0
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800eaf90(int param_1)
{
  ObjGroup_RemoveObject(param_1,0x10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800eafb4
 * EN v1.0 Address: 0x800EAFB4
 * EN v1.0 Size: 1116b
 * EN v1.1 Address: 0x800EAC4C
 * EN v1.1 Size: 960b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800eafb4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                uint param_9)
{
  char cVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  undefined4 *puVar8;
  undefined4 in_r7;
  int iVar9;
  undefined4 in_r8;
  int iVar10;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined2 *puVar11;
  undefined uVar12;
  double dVar13;
  undefined4 *local_18 [3];
  
  puVar11 = *(undefined2 **)(param_9 + 0xb8);
  *(undefined *)(puVar11 + 4) = 0;
  *(byte *)((int)puVar11 + 7) = *(byte *)((int)puVar11 + 7) & 0xfe;
  iVar5 = FUN_80017a98();
  if (*(char *)((int)puVar11 + 5) == '\0') {
    uVar12 = 0;
    if ((((*(byte *)(*(int *)(param_9 + 0x78) + (uint)*(byte *)(param_9 + 0xe4) * 5 + 4) & 0xf) == 6
         ) && (uVar6 = FUN_80006ba0(0), (uVar6 & 0x100) == 0)) &&
       (((*(byte *)(param_9 + 0xaf) & 1) != 0 && (*(int *)(param_9 + 0xf8) == 0)))) {
      *puVar11 = 0;
      FUN_80006ba8(0,0x100);
      uVar12 = 1;
    }
    *(undefined *)((int)puVar11 + 5) = uVar12;
    if (*(char *)((int)puVar11 + 5) != '\0') {
      *(byte *)((int)puVar11 + 7) = *(byte *)((int)puVar11 + 7) | 1;
      *(undefined *)(puVar11 + 3) = 1;
    }
    if (*(int *)(param_9 + 0xf8) == 0) {
      ObjHits_SyncObjectPositionIfDirty(param_9);
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
      if ((*(byte *)((int)puVar11 + 7) & 2) == 0) {
        *(float *)(param_9 + 0x28) = -(lbl_803E135C * lbl_803DC074 - *(float *)(param_9 + 0x28))
        ;
        *(float *)(param_9 + 0x10) =
             *(float *)(param_9 + 0x28) * lbl_803DC074 + *(float *)(param_9 + 0x10);
      }
      iVar7 = FUN_800632f4((double)*(float *)(param_9 + 0xc),(double)*(float *)(param_9 + 0x10),
                           (double)*(float *)(param_9 + 0x14),param_9,local_18,0,1);
      iVar9 = 0;
      iVar10 = 0;
      puVar8 = local_18[0];
      iVar5 = iVar7;
      if (0 < iVar7) {
        do {
          if (*(char *)((float *)*puVar8 + 5) != '\x0e') {
            fVar2 = *(float *)*puVar8;
            if ((*(float *)(param_9 + 0x10) < fVar2) &&
               (fVar2 - lbl_803E1360 < *(float *)(param_9 + 0x10))) {
              iVar9 = ((undefined4 *)local_18[0][iVar10])[4];
              *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)local_18[0][iVar10];
              *(float *)(param_9 + 0x28) = lbl_803E1364;
              break;
            }
          }
          puVar8 = puVar8 + 1;
          iVar10 = iVar10 + 1;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
      fVar4 = lbl_803E1368;
      fVar2 = lbl_803E1364;
      iVar5 = 0;
      if (0 < iVar7) {
        do {
          fVar3 = *(float *)(param_9 + 0x10) - **(float **)((int)local_18[0] + iVar5);
          if (fVar3 < fVar2) {
            fVar3 = -fVar3;
          }
          if ((fVar3 < fVar4) &&
             (cVar1 = *(char *)(*(float **)((int)local_18[0] + iVar5) + 5),
             (int)(uint)*(byte *)(puVar11 + 4) < (int)cVar1)) {
            *(char *)(puVar11 + 4) = cVar1;
          }
          iVar5 = iVar5 + 4;
          iVar7 = iVar7 + -1;
        } while (iVar7 != 0);
      }
      if (iVar9 != 0) {
        iVar5 = *(int *)(iVar9 + 0x58);
        cVar1 = *(char *)(iVar5 + 0x10f);
        *(char *)(iVar5 + 0x10f) = cVar1 + '\x01';
        *(uint *)(iVar5 + cVar1 * 4 + 0x100) = param_9;
      }
    }
  }
  else {
    dVar13 = (double)ObjHits_MarkObjectPositionDirty(param_9);
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    uVar6 = FUN_80006c00(0);
    if ((uVar6 & 0x100) != 0) {
      if (((*(byte *)((int)puVar11 + 7) & 4) == 0) && (uVar6 = FUN_80294bec(iVar5), uVar6 != 0)) {
        dVar13 = (double)FUN_80006ba8(0,0x100);
        *(undefined *)(puVar11 + 3) = 0;
      }
      else {
        dVar13 = (double)FUN_80006824(0,0x10a);
      }
    }
    if (*(int *)(param_9 + 0xf8) == 1) {
      *(undefined *)((int)puVar11 + 5) = 2;
    }
    if (((*(char *)((int)puVar11 + 5) == '\x02') && (*(int *)(param_9 + 0xf8) == 0)) &&
       (*(short *)(param_9 + 0x46) != 0x112)) {
      iVar7 = *(int *)(param_9 + 0xb8);
      *(undefined *)(iVar7 + 5) = 0;
      *(undefined *)(iVar7 + 6) = 0;
      if ((*(byte *)(iVar7 + 7) & 8) == 0) {
        *(float *)(param_9 + 0x10) = *(float *)(param_9 + 0x10) + lbl_803E1358;
        FUN_800e8630(param_9);
        dVar13 = (double)*(float *)(param_9 + 0x10);
        *(float *)(param_9 + 0x10) = (float)(dVar13 - (double)lbl_803E1358);
      }
    }
    if (*(char *)(puVar11 + 3) != '\0') {
      ObjMsg_SendToObject(dVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar5,0x100008,
                   param_9,CONCAT22(puVar11[1],*puVar11),in_r7,in_r8,in_r9,in_r10);
    }
  }
  return (int)*(char *)((int)puVar11 + 5);
}

/*
 * --INFO--
 *
 * Function: FUN_800eb410
 * EN v1.0 Address: 0x800EB410
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x800EB00C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800eb410(int param_1,int param_2)
{
  ObjGroup_AddObject(param_1,0x10);
  *(undefined2 *)(param_2 + 2) = 0;
  *(undefined *)(param_2 + 5) = 0;
  *(undefined *)(param_2 + 4) = 0;
  *(undefined *)(param_2 + 6) = 0;
  *(undefined4 *)(param_1 + 0xf8) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800eb464
 * EN v1.0 Address: 0x800EB464
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800EB068
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800eb464(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined2 extraout_r4;
  undefined4 *local_378;
  int local_374;
  float local_358;
  float local_354;
  float local_350;
  float local_34c;
  float local_348;
  float local_344;
  float local_340;
  undefined4 local_33c;
  undefined4 local_338;
  undefined2 local_334;
  undefined2 local_332;
  undefined2 local_330;
  undefined2 local_32e;
  undefined2 local_32c;
  undefined2 local_32a;
  undefined2 local_328;
  undefined2 local_326;
  uint local_324;
  undefined local_320;
  undefined local_31f;
  undefined local_31e;
  undefined local_31d;
  char local_31b;
  undefined4 local_318;
  float local_314;
  float local_310;
  float local_30c;
  undefined *local_308;
  undefined2 local_304;
  undefined local_302;
  undefined4 local_300;
  float local_2fc;
  float local_2f8;
  float local_2f4;
  undefined *local_2f0;
  undefined2 local_2ec;
  undefined local_2ea;
  undefined4 local_2e8;
  float local_2e4;
  float local_2e0;
  float local_2dc;
  undefined *local_2d8;
  undefined2 local_2d4;
  undefined local_2d2;
  undefined4 local_2d0;
  float local_2cc;
  float local_2c8;
  float local_2c4;
  undefined4 local_2c0;
  undefined2 local_2bc;
  undefined local_2ba;
  undefined4 local_2b8;
  float local_2b4;
  float local_2b0;
  float local_2ac;
  undefined4 local_2a8;
  undefined2 local_2a4;
  undefined local_2a2;
  undefined4 local_2a0;
  float local_29c;
  float local_298;
  float local_294;
  undefined *local_290;
  undefined2 local_28c;
  undefined local_28a;
  undefined4 local_288;
  float local_284;
  float local_280;
  float local_27c;
  undefined *local_278;
  undefined2 local_274;
  undefined local_272;
  undefined4 local_270;
  float local_26c;
  float local_268;
  float local_264;
  undefined *local_260;
  undefined2 local_25c;
  undefined local_25a;
  undefined4 local_258;
  float local_254;
  float local_250;
  float local_24c;
  undefined *local_248;
  undefined2 local_244;
  undefined local_242;
  undefined auStack_240 [576];
  
  local_374 = FUN_80286840();
  local_378 = &local_318;
  local_302 = 1;
  local_304 = 0x11;
  local_308 = &DAT_80312984;
  local_318 = 0x4000;
  local_314 = lbl_803E1370;
  local_310 = lbl_803E1374;
  local_30c = lbl_803E1370;
  local_2ea = 1;
  local_2ec = 0x10;
  local_2f0 = &DAT_803129a8;
  local_300 = 2;
  local_2fc = lbl_803E1378;
  local_2f8 = lbl_803E1378;
  local_2f4 = lbl_803E1378;
  local_2d2 = 1;
  local_2d4 = 0x11;
  local_2d8 = &DAT_80312984;
  local_2e8 = 0x100;
  local_2e4 = lbl_803E1370;
  local_2e0 = lbl_803E1370;
  local_2dc = lbl_803E137C;
  local_2ba = 1;
  local_2bc = 2;
  local_2c0 = 0;
  local_2d0 = 0x4000000;
  local_2cc = lbl_803E1380;
  local_2c8 = lbl_803E1370;
  local_2c4 = lbl_803E1370;
  local_2a2 = 2;
  local_2a4 = 2;
  local_2a8 = 0;
  local_2b8 = 0x4000000;
  local_2b4 = lbl_803E1380;
  local_2b0 = lbl_803E1370;
  local_2ac = lbl_803E1370;
  local_28a = 2;
  local_28c = 0x11;
  local_290 = &DAT_80312984;
  local_2a0 = 0x4000;
  local_29c = lbl_803E1370;
  local_298 = lbl_803E1374;
  local_294 = lbl_803E1370;
  local_272 = 2;
  local_274 = 0x11;
  local_278 = &DAT_80312984;
  local_288 = 4;
  local_284 = lbl_803E1370;
  local_280 = lbl_803E1370;
  local_27c = lbl_803E1370;
  local_25a = 2;
  local_25c = 0x11;
  local_260 = &DAT_80312984;
  local_270 = 0x100;
  local_26c = lbl_803E1370;
  local_268 = lbl_803E1370;
  local_264 = lbl_803E1384;
  local_242 = 2;
  local_244 = 0x10;
  local_248 = &DAT_803129a8;
  local_258 = 2;
  local_254 = lbl_803E1388;
  local_250 = lbl_803E1388;
  local_24c = lbl_803E1388;
  local_320 = 0;
  local_34c = lbl_803E1370;
  local_348 = lbl_803E138C;
  local_344 = lbl_803E1370;
  local_358 = lbl_803E1370;
  local_354 = lbl_803E1370;
  local_350 = lbl_803E1370;
  local_340 = lbl_803E1380;
  local_338 = 1;
  local_33c = 0;
  local_31f = 0x11;
  local_31e = 0;
  local_31d = 0x10;
  iVar1 = (int)(auStack_240 + -(int)local_378) / 0x18 +
          ((int)(auStack_240 + -(int)local_378) >> 0x1f);
  local_31b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_332 = DAT_803129c8;
  local_330 = DAT_803129ca;
  local_32e = DAT_803129cc;
  local_32c = DAT_803129ce;
  local_32a = DAT_803129d0;
  local_328 = DAT_803129d2;
  local_326 = DAT_803129d4;
  local_324 = param_4 | 0x4000000;
  if ((param_4 & 1) != 0) {
    if (local_374 == 0) {
      local_34c = lbl_803E1370 + *(float *)(param_3 + 0xc);
      local_348 = lbl_803E138C + *(float *)(param_3 + 0x10);
      local_344 = lbl_803E1370 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = lbl_803E1370 + *(float *)(local_374 + 0x18);
      local_348 = lbl_803E138C + *(float *)(local_374 + 0x1c);
      local_344 = lbl_803E1370 + *(float *)(local_374 + 0x20);
    }
  }
  local_334 = extraout_r4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0x11,&DAT_803128a8,8,&DAT_80312954,0xc0d,0);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800eb4d0
 * EN v1.0 Address: 0x800EB4D0
 * EN v1.0 Size: 552b
 * EN v1.1 Address: 0x800EB334
 * EN v1.1 Size: 1408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800eb4d0(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,undefined4 param_5,
                 int *param_6)
{
  int iVar1;
  double dVar2;
  short sVar3;
  short sVar4;
  short sVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  undefined4 uVar9;
  undefined *puVar10;
  undefined4 uVar11;
  undefined *puVar12;
  int iVar13;
  int iVar14;
  double in_f25;
  double dVar15;
  double in_f26;
  double dVar16;
  double in_f27;
  double dVar17;
  double in_f28;
  double dVar18;
  double in_f29;
  double dVar19;
  double in_f30;
  double dVar20;
  double in_f31;
  double dVar21;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar22;
  ushort local_468;
  undefined2 local_466;
  undefined2 local_464;
  float local_460;
  float local_45c;
  float local_458;
  float local_454;
  undefined4 *local_450;
  int local_44c;
  float local_430;
  float local_42c;
  float local_428;
  float local_424;
  float local_420;
  float local_41c;
  float local_418;
  undefined4 local_414;
  undefined4 local_410;
  undefined2 local_40c;
  undefined2 local_40a;
  undefined2 local_408;
  undefined2 local_406;
  undefined2 local_404;
  undefined2 local_402;
  undefined2 local_400;
  undefined2 local_3fe;
  uint local_3fc;
  undefined local_3f8;
  undefined local_3f7;
  undefined local_3f6;
  undefined local_3f5;
  undefined local_3f3;
  undefined4 local_3f0;
  float local_3ec;
  float local_3e8;
  float local_3e4;
  undefined *local_3e0;
  undefined2 local_3dc;
  undefined local_3da;
  undefined4 local_3d8;
  float local_3d4;
  float local_3d0;
  float local_3cc;
  undefined4 local_3c8;
  undefined2 local_3c4;
  undefined local_3c2;
  undefined4 local_3c0;
  float local_3bc;
  float local_3b8;
  float local_3b4;
  undefined *local_3b0;
  undefined2 local_3ac;
  undefined local_3aa;
  undefined4 local_3a8;
  float local_3a4;
  float local_3a0;
  float local_39c;
  undefined4 local_398;
  undefined2 local_394;
  undefined local_392;
  undefined4 local_f0;
  uint uStack_ec;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
  undefined4 local_d8;
  uint uStack_d4;
  undefined4 local_d0;
  uint uStack_cc;
  longlong local_c8;
  longlong local_c0;
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
  uVar22 = FUN_80286810();
  iVar6 = (int)((ulonglong)uVar22 >> 0x20);
  iVar8 = (int)uVar22;
  sVar3 = 0xff;
  sVar4 = 0xff;
  sVar5 = 0xff;
  iVar13 = 1;
  if (param_6 != (int *)0x0) {
    iVar13 = *param_6;
    sVar3 = (short)param_6[1];
    sVar4 = (short)param_6[2];
    sVar5 = (short)param_6[3];
  }
  dVar17 = (double)lbl_803E1390;
  dVar18 = (double)lbl_803E1394;
  dVar19 = (double)lbl_803E1398;
  dVar20 = (double)lbl_803E139C;
  dVar21 = (double)lbl_803E13A0;
  dVar16 = DOUBLE_803e13a8;
  for (iVar14 = 0; iVar14 < iVar13; iVar14 = iVar14 + 1) {
    if (iVar8 == 0) {
      uVar7 = FUN_80017760(0xffffffe5,0x1b);
      sVar3 = sVar3 + (short)uVar7;
      if (sVar3 < 0x100) {
        if (sVar3 < 0) {
          sVar3 = 0;
        }
      }
      else {
        sVar3 = 0xff;
      }
      uVar7 = FUN_80017760(0xffffffe5,0x1b);
      sVar4 = sVar4 + (short)uVar7;
      if (sVar4 < 0x100) {
        if (sVar4 < 0) {
          sVar4 = 0;
        }
      }
      else {
        sVar4 = 0xff;
      }
      uVar7 = FUN_80017760(0xffffffe5,0x1b);
      sVar5 = sVar5 + (short)uVar7;
      if (sVar5 < 0x100) {
        if (sVar5 < 0) {
          sVar5 = 0;
        }
      }
      else {
        sVar5 = 0xff;
      }
    }
    local_3da = 0;
    if (iVar8 == 0) {
      local_3dc = 3;
      local_3e0 = &DAT_803dc500;
    }
    else {
      local_3dc = 4;
      local_3e0 = &DAT_803dc508;
    }
    local_3f0 = 8;
    uStack_ec = (int)sVar3 ^ 0x80000000;
    local_f0 = 0x43300000;
    local_3ec = (float)((double)CONCAT44(0x43300000,uStack_ec) - dVar16);
    uStack_e4 = (int)sVar4 ^ 0x80000000;
    local_e8 = 0x43300000;
    local_3e8 = (float)((double)CONCAT44(0x43300000,uStack_e4) - dVar16);
    uStack_dc = (int)sVar5 ^ 0x80000000;
    local_e0 = 0x43300000;
    local_3e4 = (float)((double)CONCAT44(0x43300000,uStack_dc) - dVar16);
    uStack_d4 = FUN_80017760(0,0xfffe);
    uStack_d4 = uStack_d4 ^ 0x80000000;
    local_d8 = 0x43300000;
    dVar15 = (double)(float)((double)CONCAT44(0x43300000,uStack_d4) - dVar16);
    uStack_cc = FUN_80017760(0xfffff448,0xffffd120);
    uStack_cc = uStack_cc ^ 0x80000000;
    local_d0 = 0x43300000;
    dVar2 = (double)CONCAT44(0x43300000,uStack_cc) - dVar16;
    local_3d0 = (float)dVar2;
    local_3c2 = 0;
    local_3c4 = 0;
    local_3c8 = 0;
    local_3d8 = 0x80;
    local_3d4 = (float)dVar17;
    local_3cc = (float)dVar15;
    local_3aa = 0;
    if (iVar8 == 0) {
      local_3ac = 3;
      local_3b0 = &DAT_803dc500;
    }
    else {
      local_3ac = 4;
      local_3b0 = &DAT_803dc508;
    }
    local_3c0 = 2;
    local_3bc = (float)dVar18;
    local_3b8 = (float)dVar19;
    local_3b4 = (float)dVar20;
    local_392 = 1;
    local_394 = 0;
    local_398 = 0;
    local_3a8 = 0x400000;
    local_3a4 = (float)dVar17;
    local_3a0 = (float)dVar17;
    local_39c = (float)dVar21;
    local_45c = (float)dVar17;
    local_458 = (float)dVar17;
    local_454 = (float)dVar17;
    local_460 = (float)dVar18;
    local_464 = 0;
    iVar1 = (int)dVar2;
    local_c8 = (longlong)iVar1;
    local_466 = (undefined2)iVar1;
    local_c0 = (longlong)(int)dVar15;
    local_468 = (ushort)(int)dVar15;
    FUN_80017748(&local_468,&local_3a4);
    local_3f8 = 0;
    local_424 = (float)dVar17;
    local_420 = (float)dVar17;
    local_41c = (float)dVar17;
    local_430 = (float)dVar17;
    local_42c = (float)dVar17;
    local_428 = (float)dVar17;
    local_418 = (float)dVar18;
    local_410 = 1;
    local_414 = 0;
    if (iVar8 == 0) {
      local_3f7 = 3;
    }
    else {
      local_3f7 = 4;
    }
    local_3f6 = 0;
    local_3f5 = 0x10;
    local_3f3 = 4;
    local_40a = DAT_80312a4c;
    local_408 = DAT_80312a4e;
    local_406 = DAT_80312a50;
    local_404 = DAT_80312a52;
    local_402 = DAT_80312a54;
    local_400 = DAT_80312a56;
    local_3fe = DAT_80312a58;
    if ((param_4 & 1) != 0) {
      if ((iVar6 == 0) || (param_3 == 0)) {
        if (iVar6 == 0) {
          if (param_3 != 0) {
            local_424 = local_424 + *(float *)(param_3 + 0xc);
            local_420 = local_420 + *(float *)(param_3 + 0x10);
            local_41c = local_41c + *(float *)(param_3 + 0x14);
          }
        }
        else {
          local_424 = local_424 + *(float *)(iVar6 + 0x18);
          local_420 = local_420 + *(float *)(iVar6 + 0x1c);
          local_41c = local_41c + *(float *)(iVar6 + 0x20);
        }
      }
      else {
        local_424 = local_424 + *(float *)(iVar6 + 0x18) + *(float *)(param_3 + 0xc);
        local_420 = local_420 + *(float *)(iVar6 + 0x1c) + *(float *)(param_3 + 0x10);
        local_41c = local_41c + *(float *)(iVar6 + 0x20) + *(float *)(param_3 + 0x14);
      }
    }
    if (iVar8 == 0) {
      puVar12 = &DAT_803dc4f8;
      uVar11 = 1;
      puVar10 = (undefined *)0x803129f8;
    }
    else {
      puVar12 = &DAT_80312a40;
      uVar11 = 2;
      puVar10 = &DAT_80312a18;
    }
    if (iVar8 == 0) {
      uVar9 = 3;
    }
    else {
      uVar9 = 4;
    }
    local_450 = &local_3f0;
    local_44c = iVar6;
    local_40c = (short)uVar22;
    local_3fc = param_4 | 0x2000490;
    (**(code **)(*DAT_803dd6fc + 8))(&local_450,0,uVar9,puVar10,uVar11,puVar12,0,0);
  }
  FUN_8028685c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800eb6f8
 * EN v1.0 Address: 0x800EB6F8
 * EN v1.0 Size: 3396b
 * EN v1.1 Address: 0x800EB8B4
 * EN v1.1 Size: 4516b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800eb6f8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,uint param_12,
                 undefined4 param_13,undefined4 *param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int *piVar7;
  int iVar8;
  undefined4 *puVar9;
  undefined8 extraout_f1;
  double in_f28;
  double dVar10;
  double in_f29;
  double dVar11;
  double in_f30;
  double dVar12;
  double in_f31;
  double dVar13;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar14;
  undefined4 local_418;
  ushort local_414;
  undefined2 local_412;
  undefined2 local_410;
  float local_40c;
  float local_408;
  float local_404;
  float local_400;
  undefined4 *local_3fc;
  int local_3f8;
  float local_3dc;
  float local_3d8;
  float local_3d4;
  float local_3d0;
  float local_3cc;
  float local_3c8;
  float local_3c4;
  undefined4 local_3c0;
  undefined4 local_3bc;
  undefined2 local_3b8;
  undefined2 local_3b6;
  undefined2 local_3b4;
  undefined2 local_3b2;
  undefined2 local_3b0;
  undefined2 local_3ae;
  undefined2 local_3ac;
  undefined2 local_3aa;
  uint local_3a8;
  undefined local_3a4;
  undefined local_3a3;
  undefined local_3a2;
  undefined local_3a1;
  char local_39f;
  undefined4 local_39c;
  float local_398;
  float local_394;
  float local_390;
  undefined *local_38c;
  undefined2 local_388;
  undefined local_386;
  undefined4 local_384;
  float local_380;
  float local_37c;
  float local_378;
  undefined *local_374;
  undefined2 local_370;
  undefined local_36e;
  undefined4 local_36c;
  float local_368;
  float local_364;
  float local_360;
  undefined *local_35c;
  undefined2 local_358;
  undefined local_356 [2];
  undefined4 local_354 [5];
  undefined local_33e [678];
  undefined4 local_98;
  uint uStack_94;
  undefined4 local_90;
  uint uStack_8c;
  undefined4 local_88;
  uint uStack_84;
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
  uVar14 = FUN_80286820();
  iVar2 = (int)((ulonglong)uVar14 >> 0x20);
  uVar6 = (uint)uVar14;
  piVar7 = *(int **)(*(int *)(iVar2 + 0x7c) + *(char *)(iVar2 + 0xad) * 4);
  local_418 = DAT_803e13b0;
  if (param_14 != (undefined4 *)0x0) {
    local_418 = *param_14;
  }
  if (iVar2 == 0) {
    FUN_80135810(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 s______This_modgfx_needs_an_owner_o_80312af0,piVar7,param_11,param_12,param_13,
                 param_14,param_15,param_16);
  }
  else {
    local_408 = lbl_803E13B4;
    local_404 = lbl_803E13B4;
    local_400 = lbl_803E13B4;
    local_40c = lbl_803E13B8;
    local_410 = 0;
    iVar8 = *piVar7;
    if (*(char *)(iVar8 + 0xf2) != '\0') {
      local_3a4 = (undefined)uVar14;
      local_3b8 = (undefined2)uVar14;
      local_3d0 = lbl_803E13B4;
      local_3cc = lbl_803E13B4;
      local_3c8 = lbl_803E13B4;
      local_3dc = lbl_803E13B4;
      local_3d8 = lbl_803E13B4;
      local_3d4 = lbl_803E13B4;
      local_3c4 = lbl_803E13B8;
      local_3bc = 1;
      local_3c0 = 0;
      local_3a3 = 4;
      local_3a2 = 0;
      local_3a1 = 0;
      local_3b6 = DAT_80312ac0;
      local_3b4 = DAT_80312ac2;
      local_3b2 = DAT_80312ac4;
      local_3b0 = DAT_80312ac6;
      local_3ae = DAT_80312ac8;
      local_3ac = DAT_80312aca;
      local_3aa = DAT_80312acc;
      local_3f8 = iVar2;
      uVar3 = FUN_80017760((int)*(u16*)&local_418,(int)*((u16*)&local_418 + 1));
      if (uVar6 == 0xc) {
        uVar3 = FUN_80017760(2,6);
      }
      else if (uVar6 == 0xd) {
        uVar3 = FUN_80017760(2,6);
      }
      else if (uVar6 == 0x11) {
        uVar3 = 5;
      }
      dVar10 = (double)lbl_803E13B4;
      dVar11 = (double)lbl_803E13CC;
      dVar13 = (double)lbl_803E13D0;
      dVar12 = DOUBLE_803e13d8;
      for (; uVar3 != 0; uVar3 = uVar3 - 1) {
        uVar4 = FUN_80053078(**(uint **)(iVar8 + 0x20));
        local_386 = 0;
        local_388 = 1;
        local_38c = &DAT_803dc510;
        local_39c = 8;
        local_398 = (float)dVar10;
        local_394 = (float)dVar10;
        local_390 = (float)dVar10;
        if ((uVar6 == 0xc) || (uVar6 == 5)) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803dc514;
          local_384 = 2;
          uStack_94 = FUN_80017760(1,6);
          uStack_94 = uStack_94 ^ 0x80000000;
          local_98 = 0x43300000;
          local_380 = lbl_803E13BC *
                      (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e13d8);
          uStack_8c = FUN_80017760(1,6);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = lbl_803E13BC *
                      (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e13d8);
          uStack_84 = FUN_80017760(1,6);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_378 = lbl_803E13BC *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          puVar9 = &local_36c;
        }
        else if (uVar6 == 0xd) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803dc514;
          local_384 = 2;
          uStack_84 = FUN_80017760(1,6);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_380 = lbl_803E13BC *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uStack_8c = FUN_80017760(1,6);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = lbl_803E13BC *
                      (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e13d8);
          uStack_94 = FUN_80017760(1,6);
          uStack_94 = uStack_94 ^ 0x80000000;
          local_98 = 0x43300000;
          local_378 = lbl_803E13BC *
                      (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e13d8);
          puVar9 = &local_36c;
        }
        else if (uVar6 == 0x14) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803dc514;
          local_384 = 2;
          uStack_84 = FUN_80017760(3,6);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_380 = lbl_803E13C0 *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uStack_8c = FUN_80017760(3,6);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = lbl_803E13C0 *
                      (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e13d8);
          uStack_94 = FUN_80017760(3,6);
          uStack_94 = uStack_94 ^ 0x80000000;
          local_98 = 0x43300000;
          local_378 = lbl_803E13C0 *
                      (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e13d8);
          puVar9 = &local_36c;
        }
        else if (uVar6 == 0x11) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803dc514;
          local_384 = 2;
          uStack_84 = FUN_80017760(3,6);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_380 = lbl_803E13C0 *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uStack_8c = FUN_80017760(3,6);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = lbl_803E13C0 *
                      (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e13d8);
          uStack_94 = FUN_80017760(3,6);
          uStack_94 = uStack_94 ^ 0x80000000;
          local_98 = 0x43300000;
          local_378 = lbl_803E13C0 *
                      (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e13d8);
          puVar9 = &local_36c;
        }
        else if (uVar6 == 0x10) {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803dc514;
          local_384 = 8;
          local_380 = lbl_803E13C4;
          local_37c = (float)dVar10;
          local_378 = lbl_803E13C4;
          local_356[0] = 0;
          local_358 = 4;
          local_35c = &DAT_803dc514;
          local_36c = 2;
          uStack_84 = FUN_80017760(3,6);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_368 = lbl_803E13C8 *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uStack_8c = FUN_80017760(3,6);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          local_364 = lbl_803E13C8 *
                      (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e13d8);
          uStack_94 = FUN_80017760(3,6);
          uStack_94 = uStack_94 ^ 0x80000000;
          local_98 = 0x43300000;
          local_360 = lbl_803E13C8 *
                      (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e13d8);
          puVar9 = (undefined4 *)(local_356 + 2);
        }
        else {
          local_36e = 0;
          local_370 = 4;
          local_374 = &DAT_803dc514;
          local_384 = 2;
          uStack_84 = FUN_80017760(1,6);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          local_380 = lbl_803E13BC *
                      (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uStack_8c = FUN_80017760(1,6);
          uStack_8c = uStack_8c ^ 0x80000000;
          local_90 = 0x43300000;
          local_37c = lbl_803E13BC *
                      (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e13d8);
          uStack_94 = FUN_80017760(1,6);
          uStack_94 = uStack_94 ^ 0x80000000;
          local_98 = 0x43300000;
          local_378 = lbl_803E13BC *
                      (float)((double)CONCAT44(0x43300000,uStack_94) - DOUBLE_803e13d8);
          puVar9 = &local_36c;
        }
        *(undefined *)((int)puVar9 + 0x16) = 1;
        *(undefined2 *)(puVar9 + 5) = 0;
        puVar9[4] = 0;
        *puVar9 = 0x80000000;
        puVar9[1] = (float)dVar10;
        puVar9[2] = (float)dVar11;
        puVar9[3] = (float)dVar10;
        *(undefined *)((int)puVar9 + 0x2e) = 1;
        *(undefined2 *)(puVar9 + 0xb) = 0;
        puVar9[10] = 0;
        puVar9[6] = 0x100;
        puVar9[7] = (float)dVar10;
        uStack_84 = FUN_80017760(0xfffffff6,10);
        uStack_84 = uStack_84 ^ 0x80000000;
        local_88 = 0x43300000;
        puVar9[8] = (float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uStack_84) - dVar12
                                                    ));
        uStack_8c = FUN_80017760(0xfffffff6,10);
        uStack_8c = uStack_8c ^ 0x80000000;
        local_90 = 0x43300000;
        puVar9[9] = (float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uStack_8c) - dVar12
                                                    ));
        if (uVar6 == 0x10) {
          *(undefined *)((int)puVar9 + 0x46) = 1;
          *(undefined2 *)(puVar9 + 0x11) = 0;
          puVar9[0x10] = 0;
          puVar9[0xc] = 0x400000;
          puVar9[0xd] = lbl_803E13B4;
          puVar9[0xe] = lbl_803E13B4;
          uStack_84 = FUN_80017760(0,300);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          puVar9[0xf] = lbl_803E13D0 +
                        (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uVar5 = FUN_80017760(0xffff8001,0xfffff060);
          local_412 = (undefined2)uVar5;
          uVar5 = FUN_80017760(0,0xffff);
          local_414 = (ushort)uVar5;
          FUN_80017748(&local_414,(float *)(puVar9 + 0xd));
        }
        else if (uVar6 == 0x11) {
          *(undefined *)((int)puVar9 + 0x46) = 1;
          *(undefined2 *)(puVar9 + 0x11) = 0;
          puVar9[0x10] = 0;
          puVar9[0xc] = 0x400000;
          puVar9[0xd] = lbl_803E13B4;
          puVar9[0xe] = lbl_803E13B4;
          uStack_84 = FUN_80017760(0,300);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          puVar9[0xf] = lbl_803E13D0 +
                        (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uVar5 = FUN_80017760(0xffff8001,0xfffff060);
          local_412 = (undefined2)uVar5;
          uVar5 = FUN_80017760(0,0xffff);
          local_414 = (ushort)uVar5;
          FUN_80017748(&local_414,(float *)(puVar9 + 0xd));
        }
        else {
          *(undefined *)((int)puVar9 + 0x46) = 1;
          *(undefined2 *)(puVar9 + 0x11) = 0;
          puVar9[0x10] = 0;
          puVar9[0xc] = 0x400000;
          puVar9[0xd] = lbl_803E13B4;
          puVar9[0xe] = lbl_803E13B4;
          uStack_84 = FUN_80017760(0,100);
          uStack_84 = uStack_84 ^ 0x80000000;
          local_88 = 0x43300000;
          puVar9[0xf] = lbl_803E13D4 +
                        (float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e13d8);
          uVar5 = FUN_80017760(0xffff8001,0xfffff060);
          local_412 = (undefined2)uVar5;
          uVar5 = FUN_80017760(0,0xffff);
          local_414 = (ushort)uVar5;
          FUN_80017748(&local_414,(float *)(puVar9 + 0xd));
        }
        *(undefined *)((int)puVar9 + 0x5e) = 1;
        *(undefined2 *)(puVar9 + 0x17) = 4;
        puVar9[0x16] = (undefined4)&DAT_803dc514;
        puVar9[0x12] = 4;
        puVar9[0x13] = (float)dVar10;
        puVar9[0x14] = (float)dVar10;
        puVar9[0x15] = (float)dVar10;
        iVar1 = (int)puVar9 + (0x60 - (int)&local_39c);
        iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
        local_39f = (char)iVar1 - (char)(iVar1 >> 0x1f);
        local_3fc = &local_39c;
        local_3a8 = param_12 | 0x4000000;
        (**(code **)(*DAT_803dd6fc + 8))(&local_3fc,0,4,&DAT_80312a80,4,&DAT_80312aa8,0,uVar4);
      }
      uVar3 = FUN_80017760(2,6);
      if (uVar6 == 7) {
        uVar6 = FUN_80017760(4,6);
      }
      if (uVar6 == 0xb) {
        uVar6 = FUN_80017760(8,10);
      }
      if (uVar6 == 0xc) {
        uVar3 = FUN_80017760(1,3);
      }
      switch(uVar6) {
      case 0:
      case 0x14:
        local_410 = 0x2a;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        break;
      case 1:
        local_410 = 0x2b;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        break;
      case 2:
        local_410 = 0x184;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        break;
      case 3:
        local_410 = 0x1a1;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        break;
      case 4:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        local_410 = 0x159;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 5:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        local_410 = 0x91;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 6:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        local_410 = 0x74;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      default:
        local_410 = 0x2a;
        iVar8 = 5;
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
        break;
      case 8:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        iVar8 = 0x14;
        local_410 = 0xdf;
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,7,&local_414,1,0xffffffff,0);
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
        local_410 = 0x159;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 9:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        iVar8 = 0x14;
        local_410 = 0xde;
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,7,&local_414,1,0xffffffff,0);
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
        local_410 = 0x91;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 10:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        }
        iVar8 = 0x14;
        local_410 = 0x160;
        do {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,7,&local_414,1,0xffffffff,0);
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
        local_410 = 0x74;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,3,&local_414,1,0xffffffff,0);
        break;
      case 0xc:
        local_410 = 0x2a;
        break;
      case 0xd:
        local_410 = 0x4c;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        break;
      case 0xe:
        local_410 = 0x60;
        for (; uVar3 != 0; uVar3 = uVar3 - 1) {
          (**(code **)(*DAT_803dd708 + 8))(iVar2,0x135,&local_414,1,0xffffffff,0);
        }
        break;
      case 0xf:
        (**(code **)(*DAT_803dd708 + 8))(iVar2,0x51b,0,2,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(iVar2,0x51b,0,2,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(iVar2,0x51b,0,2,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(iVar2,0x51b,0,2,0xffffffff,0);
        break;
      case 0x10:
      case 0x11:
        local_410 = 0x4c;
        (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(iVar2,5,&local_414,1,0xffffffff,0);
      }
    }
  }
  FUN_8028686c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ec43c
 * EN v1.0 Address: 0x800EC43C
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800ECA58
 * EN v1.1 Size: 804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ec43c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined2 extraout_r4;
  undefined4 *local_378;
  int local_374;
  float local_358;
  float local_354;
  float local_350;
  float local_34c;
  float local_348;
  float local_344;
  float local_340;
  undefined4 local_33c;
  undefined4 local_338;
  undefined2 local_334;
  undefined2 local_332;
  undefined2 local_330;
  undefined2 local_32e;
  undefined2 local_32c;
  undefined2 local_32a;
  undefined2 local_328;
  undefined2 local_326;
  uint local_324;
  undefined local_320;
  undefined local_31f;
  undefined local_31e;
  undefined local_31d;
  char local_31b;
  undefined4 local_318;
  float local_314;
  float local_310;
  float local_30c;
  undefined *local_308;
  undefined2 local_304;
  undefined local_302;
  undefined4 local_300;
  float local_2fc;
  float local_2f8;
  float local_2f4;
  undefined *local_2f0;
  undefined2 local_2ec;
  undefined local_2ea;
  undefined4 local_2e8;
  float local_2e4;
  float local_2e0;
  float local_2dc;
  undefined *local_2d8;
  undefined2 local_2d4;
  undefined local_2d2;
  undefined4 local_2d0;
  float local_2cc;
  float local_2c8;
  float local_2c4;
  undefined *local_2c0;
  undefined2 local_2bc;
  undefined local_2ba;
  undefined4 local_2b8;
  float local_2b4;
  float local_2b0;
  float local_2ac;
  undefined *local_2a8;
  undefined2 local_2a4;
  undefined local_2a2;
  undefined4 local_2a0;
  float local_29c;
  float local_298;
  float local_294;
  undefined *local_290;
  undefined2 local_28c;
  undefined local_28a;
  undefined4 local_288;
  float local_284;
  float local_280;
  float local_27c;
  undefined *local_278;
  undefined2 local_274;
  undefined local_272;
  undefined4 local_270;
  float local_26c;
  float local_268;
  float local_264;
  undefined *local_260;
  undefined2 local_25c;
  undefined local_25a;
  undefined4 local_258;
  float local_254;
  float local_250;
  float local_24c;
  undefined *local_248;
  undefined2 local_244;
  undefined local_242;
  undefined4 local_240;
  float local_23c;
  float local_238;
  float local_234;
  undefined *local_230;
  undefined2 local_22c;
  undefined local_22a;
  undefined4 local_228;
  float local_224;
  float local_220;
  float local_21c;
  undefined *local_218;
  undefined2 local_214;
  undefined local_212;
  undefined auStack_210 [528];
  
  local_374 = FUN_80286840();
  local_378 = &local_318;
  local_302 = 0;
  local_304 = 0x15;
  local_308 = &DAT_80312d20;
  local_318 = 4;
  local_314 = lbl_803E13E0;
  local_310 = lbl_803E13E0;
  local_30c = lbl_803E13E0;
  local_2ea = 0;
  local_2ec = 0x15;
  local_2f0 = &DAT_80312d20;
  local_300 = 2;
  local_2fc = lbl_803E13E4;
  local_2f8 = lbl_803E13E8;
  local_2f4 = lbl_803E13E4;
  local_2d2 = 0;
  local_2d4 = 0x15;
  local_2d8 = &DAT_80312d20;
  local_2e8 = 0x400000;
  local_2e4 = lbl_803E13E0;
  local_2e0 = lbl_803E13EC;
  local_2dc = lbl_803E13E0;
  local_2ba = 1;
  local_2bc = 7;
  local_2c0 = &DAT_80312ce4;
  local_2d0 = 4;
  local_2cc = lbl_803E13F0;
  local_2c8 = lbl_803E13E0;
  local_2c4 = lbl_803E13E0;
  local_2a2 = 1;
  local_2a4 = 0x15;
  local_2a8 = &DAT_80312d20;
  local_2b8 = 0x4000;
  local_2b4 = lbl_803E13F4;
  local_2b0 = lbl_803E13F8;
  local_2ac = lbl_803E13E0;
  local_28a = 1;
  local_28c = 0x15;
  local_290 = &DAT_80312d20;
  local_2a0 = 0x400000;
  local_29c = lbl_803E13E0;
  local_298 = lbl_803E13FC;
  local_294 = lbl_803E13E0;
  local_272 = 2;
  local_274 = 0x15;
  local_278 = &DAT_80312d20;
  local_288 = 0x4000;
  local_284 = lbl_803E13F8;
  local_280 = lbl_803E13F4;
  local_27c = lbl_803E13E0;
  local_25a = 2;
  local_25c = 0x15;
  local_260 = &DAT_80312d20;
  local_270 = 0x400000;
  local_26c = lbl_803E13E0;
  local_268 = lbl_803E1400;
  local_264 = lbl_803E13E0;
  local_242 = 2;
  local_244 = 0x15;
  local_248 = &DAT_80312d20;
  local_258 = 2;
  local_254 = lbl_803E1404;
  local_250 = lbl_803E13E8;
  local_24c = lbl_803E1404;
  local_22a = 3;
  local_22c = 7;
  local_230 = &DAT_80312ce4;
  local_240 = 4;
  local_23c = lbl_803E13E0;
  local_238 = lbl_803E13E0;
  local_234 = lbl_803E13E0;
  local_212 = 3;
  local_214 = 0x15;
  local_218 = &DAT_80312d20;
  local_228 = 0x4000;
  local_224 = lbl_803E13F8;
  local_220 = lbl_803E13F4;
  local_21c = lbl_803E13E0;
  local_320 = 0;
  local_34c = lbl_803E13E0;
  local_348 = lbl_803E1408;
  local_344 = lbl_803E13E0;
  local_358 = lbl_803E13E0;
  local_354 = lbl_803E13E0;
  local_350 = lbl_803E13E0;
  local_340 = lbl_803E140C;
  local_338 = 2;
  local_33c = 7;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 0x1e;
  iVar1 = (int)(auStack_210 + -(int)local_378) / 0x18 +
          ((int)(auStack_210 + -(int)local_378) >> 0x1f);
  local_31b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_332 = DAT_80312d4c;
  local_330 = DAT_80312d4e;
  local_32e = DAT_80312d50;
  local_32c = DAT_80312d52;
  local_32a = DAT_80312d54;
  local_328 = DAT_80312d56;
  local_326 = DAT_80312d58;
  local_324 = param_4 | 0xc000040;
  if ((param_4 & 1) != 0) {
    if (local_374 == 0) {
      local_34c = lbl_803E13E0 + *(float *)(param_3 + 0xc);
      local_348 = lbl_803E1408 + *(float *)(param_3 + 0x10);
      local_344 = lbl_803E13E0 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = lbl_803E13E0 + *(float *)(local_374 + 0x18);
      local_348 = lbl_803E1408 + *(float *)(local_374 + 0x1c);
      local_344 = lbl_803E13E0 + *(float *)(local_374 + 0x20);
    }
  }
  local_334 = extraout_r4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0x15,&DAT_80312b70,0x18,&DAT_80312c44,0x20b,0);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ec4a8
 * EN v1.0 Address: 0x800EC4A8
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800ECD7C
 * EN v1.1 Size: 804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ec4a8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined2 extraout_r4;
  undefined4 *local_378;
  int local_374;
  float local_358;
  float local_354;
  float local_350;
  float local_34c;
  float local_348;
  float local_344;
  float local_340;
  undefined4 local_33c;
  undefined4 local_338;
  undefined2 local_334;
  undefined2 local_332;
  undefined2 local_330;
  undefined2 local_32e;
  undefined2 local_32c;
  undefined2 local_32a;
  undefined2 local_328;
  undefined2 local_326;
  uint local_324;
  undefined local_320;
  undefined local_31f;
  undefined local_31e;
  undefined local_31d;
  char local_31b;
  undefined4 local_318;
  float local_314;
  float local_310;
  float local_30c;
  undefined *local_308;
  undefined2 local_304;
  undefined local_302;
  undefined4 local_300;
  float local_2fc;
  float local_2f8;
  float local_2f4;
  undefined *local_2f0;
  undefined2 local_2ec;
  undefined local_2ea;
  undefined4 local_2e8;
  float local_2e4;
  float local_2e0;
  float local_2dc;
  undefined *local_2d8;
  undefined2 local_2d4;
  undefined local_2d2;
  undefined4 local_2d0;
  float local_2cc;
  float local_2c8;
  float local_2c4;
  undefined *local_2c0;
  undefined2 local_2bc;
  undefined local_2ba;
  undefined4 local_2b8;
  float local_2b4;
  float local_2b0;
  float local_2ac;
  undefined *local_2a8;
  undefined2 local_2a4;
  undefined local_2a2;
  undefined4 local_2a0;
  float local_29c;
  float local_298;
  float local_294;
  undefined *local_290;
  undefined2 local_28c;
  undefined local_28a;
  undefined4 local_288;
  float local_284;
  float local_280;
  float local_27c;
  undefined *local_278;
  undefined2 local_274;
  undefined local_272;
  undefined4 local_270;
  float local_26c;
  float local_268;
  float local_264;
  undefined *local_260;
  undefined2 local_25c;
  undefined local_25a;
  undefined4 local_258;
  float local_254;
  float local_250;
  float local_24c;
  undefined *local_248;
  undefined2 local_244;
  undefined local_242;
  undefined4 local_240;
  float local_23c;
  float local_238;
  float local_234;
  undefined *local_230;
  undefined2 local_22c;
  undefined local_22a;
  undefined4 local_228;
  float local_224;
  float local_220;
  float local_21c;
  undefined *local_218;
  undefined2 local_214;
  undefined local_212;
  undefined auStack_210 [528];
  
  local_374 = FUN_80286840();
  local_378 = &local_318;
  local_302 = 0;
  local_304 = 0x15;
  local_308 = &DAT_80312f30;
  local_318 = 4;
  local_314 = lbl_803E1410;
  local_310 = lbl_803E1410;
  local_30c = lbl_803E1410;
  local_2ea = 0;
  local_2ec = 0x15;
  local_2f0 = &DAT_80312f30;
  local_300 = 2;
  local_2fc = lbl_803E1414;
  local_2f8 = lbl_803E1418;
  local_2f4 = lbl_803E1414;
  local_2d2 = 0;
  local_2d4 = 0x15;
  local_2d8 = &DAT_80312f30;
  local_2e8 = 0x400000;
  local_2e4 = lbl_803E1410;
  local_2e0 = lbl_803E141C;
  local_2dc = lbl_803E1410;
  local_2ba = 1;
  local_2bc = 7;
  local_2c0 = &DAT_80312ef4;
  local_2d0 = 4;
  local_2cc = lbl_803E1420;
  local_2c8 = lbl_803E1410;
  local_2c4 = lbl_803E1410;
  local_2a2 = 1;
  local_2a4 = 0x15;
  local_2a8 = &DAT_80312f30;
  local_2b8 = 0x4000;
  local_2b4 = lbl_803E1424;
  local_2b0 = lbl_803E1428;
  local_2ac = lbl_803E1410;
  local_28a = 1;
  local_28c = 0x15;
  local_290 = &DAT_80312f30;
  local_2a0 = 0x400000;
  local_29c = lbl_803E1410;
  local_298 = lbl_803E142C;
  local_294 = lbl_803E1410;
  local_272 = 2;
  local_274 = 0x15;
  local_278 = &DAT_80312f30;
  local_288 = 0x4000;
  local_284 = lbl_803E1428;
  local_280 = lbl_803E1424;
  local_27c = lbl_803E1410;
  local_25a = 2;
  local_25c = 0x15;
  local_260 = &DAT_80312f30;
  local_270 = 0x400000;
  local_26c = lbl_803E1410;
  local_268 = lbl_803E1430;
  local_264 = lbl_803E1410;
  local_242 = 2;
  local_244 = 0x15;
  local_248 = &DAT_80312f30;
  local_258 = 2;
  local_254 = lbl_803E1434;
  local_250 = lbl_803E1418;
  local_24c = lbl_803E1434;
  local_22a = 3;
  local_22c = 7;
  local_230 = &DAT_80312ef4;
  local_240 = 4;
  local_23c = lbl_803E1410;
  local_238 = lbl_803E1410;
  local_234 = lbl_803E1410;
  local_212 = 3;
  local_214 = 0x15;
  local_218 = &DAT_80312f30;
  local_228 = 0x4000;
  local_224 = lbl_803E1428;
  local_220 = lbl_803E1424;
  local_21c = lbl_803E1410;
  local_320 = 0;
  local_34c = lbl_803E1410;
  local_348 = lbl_803E1438;
  local_344 = lbl_803E1410;
  local_358 = lbl_803E1410;
  local_354 = lbl_803E1410;
  local_350 = lbl_803E1410;
  local_340 = lbl_803E143C;
  local_338 = 2;
  local_33c = 7;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 0x1e;
  iVar1 = (int)(auStack_210 + -(int)local_378) / 0x18 +
          ((int)(auStack_210 + -(int)local_378) >> 0x1f);
  local_31b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_332 = DAT_80312f5c;
  local_330 = DAT_80312f5e;
  local_32e = DAT_80312f60;
  local_32c = DAT_80312f62;
  local_32a = DAT_80312f64;
  local_328 = DAT_80312f66;
  local_326 = DAT_80312f68;
  local_324 = param_4 | 0xc000040;
  if ((param_4 & 1) != 0) {
    if (local_374 == 0) {
      local_34c = lbl_803E1410 + *(float *)(param_3 + 0xc);
      local_348 = lbl_803E1438 + *(float *)(param_3 + 0x10);
      local_344 = lbl_803E1410 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = lbl_803E1410 + *(float *)(local_374 + 0x18);
      local_348 = lbl_803E1438 + *(float *)(local_374 + 0x1c);
      local_344 = lbl_803E1410 + *(float *)(local_374 + 0x20);
    }
  }
  local_334 = extraout_r4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0x15,&DAT_80312d80,0x18,&DAT_80312e54,0x20b,0);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ec514
 * EN v1.0 Address: 0x800EC514
 * EN v1.0 Size: 1260b
 * EN v1.1 Address: 0x800ED0A0
 * EN v1.1 Size: 1168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ec514(undefined4 param_1,undefined param_2,undefined4 param_3,uint param_4)
{
  double dVar1;
  
  (**(code **)(*DAT_803dd6fc + 0x34))(param_1,param_2,0x12,3,9);
  (**(code **)(*DAT_803dd6fc + 0x4c))(&DAT_8031325c);
  (**(code **)(*DAT_803dd6fc + 0x54))(param_4 | 0x4004484);
  (**(code **)(*DAT_803dd6fc + 0x38))();
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1440,(double)lbl_803E1444,(double)lbl_803E1440,2,9,&DAT_80313158)
  ;
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1448,(double)lbl_803E1444,(double)lbl_803E144C,2,9,&DAT_8031316c)
  ;
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1448,(double)lbl_803E1444,(double)lbl_803E1448,2,9,&DAT_80313180)
  ;
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1448,(double)lbl_803E1444,(double)lbl_803E1448,2,9,&DAT_80313194)
  ;
  dVar1 = (double)lbl_803E1450;
  (**(code **)(*DAT_803dd6fc + 0x3c))(dVar1,dVar1,dVar1,4,0x24,&DAT_803131f0);
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1454,(double)lbl_803E1458,(double)lbl_803E145C,8,0x24,
             &DAT_803131f0);
  (**(code **)(*DAT_803dd6fc + 0x40))();
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1460,(double)lbl_803E1464,(double)lbl_803E1460,2,0,0);
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1450,(double)lbl_803E1468,(double)lbl_803E1450,0x4000,0,0);
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E146C,(double)lbl_803E146C,(double)lbl_803E1470,0x1800000,0x5e0,0)
  ;
  (**(code **)(*DAT_803dd6fc + 0x40))();
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1474,(double)lbl_803E1450,(double)lbl_803E1450,4,0x12,
             &DAT_80313238);
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1450,(double)lbl_803E1468,(double)lbl_803E1450,0x4000,0x24,
             &DAT_803131f0);
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1450,(double)lbl_803E1450,(double)lbl_803E1478,0x100,0,0);
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E146C,(double)lbl_803E146C,(double)lbl_803E1470,0x1800000,0x5e0,0)
  ;
  (**(code **)(*DAT_803dd6fc + 0x40))();
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1450,(double)lbl_803E1468,(double)lbl_803E1450,0x4000,0x24,
             &DAT_803131f0);
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1450,(double)lbl_803E1450,(double)lbl_803E1478,0x100,0,0);
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E146C,(double)lbl_803E146C,(double)lbl_803E1470,0x1800000,0x5e0,0)
  ;
  (**(code **)(*DAT_803dd6fc + 0x40))();
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1450,(double)lbl_803E1468,(double)lbl_803E1450,0x4000,0x24,
             &DAT_803131f0);
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E1450,(double)lbl_803E1450,(double)lbl_803E1478,0x100,0,0);
  dVar1 = (double)lbl_803E1450;
  (**(code **)(*DAT_803dd6fc + 0x3c))(dVar1,dVar1,dVar1,4,0x24,&DAT_803131f0);
  (**(code **)(*DAT_803dd6fc + 0x50))(param_3,&DAT_80312f90,0x24,&DAT_803130f8,0x10,0x120,0);
  (**(code **)(*DAT_803dd6fc + 0x58))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800eca00
 * EN v1.0 Address: 0x800ECA00
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800ED530
 * EN v1.1 Size: 848b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800eca00(int param_1,undefined2 param_2,int param_3,uint param_4)
{
  undefined4 *local_378;
  int local_374;
  float local_358;
  float local_354;
  float local_350;
  float local_34c;
  float local_348;
  float local_344;
  float local_340;
  undefined4 local_33c;
  undefined4 local_338;
  undefined2 local_334;
  undefined2 local_332;
  undefined2 local_330;
  undefined2 local_32e;
  undefined2 local_32c;
  undefined2 local_32a;
  undefined2 local_328;
  undefined2 local_326;
  uint local_324;
  undefined local_320;
  undefined local_31f;
  undefined local_31e;
  undefined local_31d;
  undefined local_31b;
  undefined4 local_318;
  float local_314;
  float local_310;
  float local_30c;
  undefined4 local_308;
  undefined2 local_304;
  undefined local_302;
  undefined4 local_300;
  float local_2fc;
  float local_2f8;
  float local_2f4;
  undefined4 local_2f0;
  undefined2 local_2ec;
  undefined local_2ea;
  undefined4 local_2e8;
  float local_2e4;
  float local_2e0;
  float local_2dc;
  undefined *local_2d8;
  undefined2 local_2d4;
  undefined local_2d2;
  undefined4 local_2d0;
  float local_2cc;
  float local_2c8;
  float local_2c4;
  undefined *local_2c0;
  undefined2 local_2bc;
  undefined local_2ba;
  undefined4 local_2b8;
  float local_2b4;
  float local_2b0;
  float local_2ac;
  undefined *local_2a8;
  undefined2 local_2a4;
  undefined local_2a2;
  undefined4 local_2a0;
  float local_29c;
  float local_298;
  float local_294;
  undefined *local_290;
  undefined2 local_28c;
  undefined local_28a;
  undefined4 local_288;
  float local_284;
  float local_280;
  float local_27c;
  undefined *local_278;
  undefined2 local_274;
  undefined local_272;
  undefined4 local_270;
  float local_26c;
  float local_268;
  float local_264;
  undefined4 local_260;
  undefined2 local_25c;
  undefined local_25a;
  undefined4 local_258;
  float local_254;
  float local_250;
  float local_24c;
  undefined4 local_248;
  undefined2 local_244;
  undefined local_242;
  undefined4 local_240;
  float local_23c;
  float local_238;
  float local_234;
  undefined4 local_230;
  undefined2 local_22c;
  undefined local_22a;
  undefined4 local_228;
  float local_224;
  float local_220;
  float local_21c;
  undefined *local_218;
  undefined2 local_214;
  undefined local_212;
  undefined4 local_210;
  float local_20c;
  float local_208;
  float local_204;
  undefined *local_200;
  undefined2 local_1fc;
  undefined local_1fa;
  undefined4 local_1f8;
  float local_1f4;
  float local_1f0;
  float local_1ec;
  undefined4 local_1e8;
  undefined2 local_1e4;
  undefined local_1e2;
  
  local_302 = 0;
  local_304 = 0x32;
  local_308 = 0;
  local_318 = 0x800000;
  local_314 = lbl_803E1480;
  local_310 = lbl_803E1484;
  local_30c = lbl_803E1484;
  local_2ea = 0;
  local_2ec = 0x7a;
  local_2f0 = 0;
  local_300 = 0x10000;
  local_2fc = lbl_803E1484;
  local_2f8 = lbl_803E1484;
  local_2f4 = lbl_803E1484;
  local_2d2 = 0;
  local_2d4 = 7;
  local_2d8 = &DAT_803133a0;
  local_2e8 = 4;
  local_2e4 = lbl_803E1484;
  local_2e0 = lbl_803E1484;
  local_2dc = lbl_803E1484;
  local_2ba = 0;
  local_2bc = 7;
  local_2c0 = &DAT_80313390;
  local_2d0 = 2;
  local_2cc = lbl_803E1488;
  local_2c8 = lbl_803E1480;
  local_2c4 = lbl_803E1488;
  local_2a2 = 0;
  local_2a4 = 7;
  local_2a8 = &DAT_803133a0;
  local_2b8 = 2;
  local_2b4 = lbl_803E148C;
  local_2b0 = lbl_803E1490;
  local_2ac = lbl_803E148C;
  local_28a = 0;
  local_28c = 7;
  local_290 = &DAT_80313390;
  local_2a0 = 8;
  local_29c = lbl_803E1484;
  local_298 = lbl_803E1494;
  local_294 = lbl_803E1498;
  local_272 = 0;
  local_274 = 7;
  local_278 = &DAT_803133a0;
  local_288 = 8;
  local_284 = lbl_803E149C;
  local_280 = lbl_803E149C;
  local_27c = lbl_803E1498;
  local_25a = 0;
  local_25c = 1;
  local_260 = 0;
  local_270 = 0x8000;
  local_26c = lbl_803E1484;
  local_268 = lbl_803E149C;
  local_264 = lbl_803E1484;
  local_242 = 0;
  local_244 = 1;
  local_248 = 0;
  local_258 = 0x80000;
  local_254 = lbl_803E1484;
  local_250 = lbl_803E14A0;
  local_24c = lbl_803E1484;
  local_22a = 1;
  local_22c = 1;
  local_230 = 0;
  local_240 = 0x80000;
  local_23c = lbl_803E1484;
  local_238 = lbl_803E1484;
  local_234 = lbl_803E1484;
  local_212 = 2;
  local_214 = 0xe;
  local_218 = &DAT_80313374;
  local_228 = 0x4000;
  local_224 = lbl_803E1484;
  local_220 = lbl_803E14A4;
  local_21c = lbl_803E1484;
  local_1fa = 2;
  local_1fc = 7;
  local_200 = &DAT_80313390;
  local_210 = 4;
  local_20c = lbl_803E1484;
  local_208 = lbl_803E1484;
  local_204 = lbl_803E1484;
  local_1e2 = 2;
  local_1e4 = 1;
  local_1e8 = 0;
  local_1f8 = 0x80000;
  local_1f4 = lbl_803E1484;
  local_1f0 = lbl_803E14A8;
  local_1ec = lbl_803E1484;
  local_320 = 0;
  local_34c = lbl_803E1484;
  local_348 = lbl_803E1484;
  local_344 = lbl_803E1484;
  local_358 = lbl_803E1484;
  local_354 = lbl_803E1484;
  local_350 = lbl_803E1484;
  local_340 = lbl_803E1480;
  local_338 = 1;
  local_33c = 0;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 0x10;
  local_31b = 0;
  local_332 = DAT_803133b0;
  local_330 = DAT_803133b2;
  local_32e = DAT_803133b4;
  local_32c = DAT_803133b6;
  local_32a = DAT_803133b8;
  local_328 = DAT_803133ba;
  local_326 = DAT_803133bc;
  local_378 = &local_318;
  local_324 = param_4 | 0x4000002;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = lbl_803E1484 + *(float *)(param_3 + 0xc);
      local_348 = lbl_803E1484 + *(float *)(param_3 + 0x10);
      local_344 = lbl_803E1484 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = lbl_803E1484 + *(float *)(param_1 + 0x18);
      local_348 = lbl_803E1484 + *(float *)(param_1 + 0x1c);
      local_344 = lbl_803E1484 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_334 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0xe,&DAT_803132a0,0xc,&DAT_8031332c,0x48,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800eca64
 * EN v1.0 Address: 0x800ECA64
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x800ED880
 * EN v1.1 Size: 1092b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800eca64(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  int iVar2;
  undefined2 extraout_r4;
  undefined4 *local_398;
  int local_394;
  float local_378;
  float local_374;
  float local_370;
  float local_36c;
  float local_368;
  float local_364;
  float local_360;
  undefined4 local_35c;
  undefined4 local_358;
  undefined2 local_354;
  undefined2 local_352;
  undefined2 local_350;
  undefined2 local_34e;
  undefined2 local_34c;
  undefined2 local_34a;
  undefined2 local_348;
  undefined2 local_346;
  uint local_344;
  undefined local_340;
  undefined local_33f;
  undefined local_33e;
  undefined local_33d;
  char local_33b;
  undefined4 local_338;
  float local_334;
  float local_330;
  float local_32c;
  undefined *local_328;
  undefined2 local_324;
  undefined local_322;
  undefined4 local_320;
  float local_31c;
  float local_318;
  float local_314;
  undefined *local_310;
  undefined2 local_30c;
  undefined local_30a;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined4 local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined4 local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined *local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined *local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined *local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined4 local_278;
  float local_274;
  float local_270;
  float local_26c;
  undefined *local_268;
  undefined2 local_264;
  undefined local_262;
  undefined4 local_260;
  float local_25c;
  float local_258;
  float local_254;
  undefined4 local_250;
  undefined2 local_24c;
  undefined local_24a;
  undefined4 local_248;
  float local_244;
  float local_240;
  float local_23c;
  undefined4 local_238;
  undefined2 local_234;
  undefined local_232;
  undefined4 local_230;
  float local_22c;
  float local_228;
  float local_224;
  undefined *local_220;
  undefined2 local_21c;
  undefined local_21a;
  undefined4 local_218;
  float local_214;
  float local_210;
  float local_20c;
  undefined *local_208;
  undefined2 local_204;
  undefined local_202;
  undefined auStack_200 [456];
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  iVar2 = FUN_8028683c();
  local_322 = 0;
  local_324 = 0xe;
  local_328 = &DAT_803134d4;
  local_338 = 4;
  local_334 = lbl_803E14B0;
  local_330 = lbl_803E14B0;
  local_32c = lbl_803E14B0;
  local_30a = 0;
  local_30c = 0xe;
  local_310 = &DAT_803134d4;
  local_320 = 2;
  local_31c = lbl_803E14B4;
  local_318 = lbl_803E14B4;
  local_314 = lbl_803E14B4;
  local_2f2 = 0;
  local_2f4 = 0xe;
  local_2f8 = &DAT_803134d4;
  local_308 = 8;
  uStack_34 = FUN_80017760(0,0x69);
  uStack_34 = uStack_34 ^ 0x80000000;
  local_38 = 0x43300000;
  local_304 = lbl_803E14B8 + (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e14d0);
  uStack_2c = FUN_80017760(0,0x69);
  uStack_2c = uStack_2c ^ 0x80000000;
  local_30 = 0x43300000;
  local_300 = lbl_803E14B8 + (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e14d0);
  uStack_24 = FUN_80017760(0,0x69);
  uStack_24 = uStack_24 ^ 0x80000000;
  local_28 = 0x43300000;
  local_2fc = lbl_803E14B8 + (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e14d0);
  local_2da = 0;
  local_2dc = 0x7a;
  local_2e0 = 0;
  local_2f0 = 0x10000;
  local_2ec = lbl_803E14B0;
  local_2e8 = lbl_803E14B0;
  local_2e4 = lbl_803E14B0;
  uStack_1c = FUN_80017760(0,0xfffe);
  uStack_1c = uStack_1c ^ 0x80000000;
  local_20 = 0x43300000;
  local_2cc = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e14d0);
  local_2c2 = 0;
  local_2c4 = 0;
  local_2c8 = 0;
  local_2d8 = 0x80;
  local_2d4 = lbl_803E14B0;
  local_2d0 = lbl_803E14B0;
  local_2aa = 1;
  local_2ac = 10;
  local_2b0 = &DAT_803134f0;
  local_2c0 = 4;
  local_2bc = lbl_803E14BC;
  local_2b8 = lbl_803E14B0;
  local_2b4 = lbl_803E14B0;
  local_292 = 1;
  local_294 = 0xe;
  local_298 = &DAT_803134d4;
  local_2a8 = 2;
  local_2a4 = lbl_803E14C0;
  local_2a0 = lbl_803E14C0;
  local_29c = lbl_803E14C0;
  local_27a = 2;
  local_27c = 0xe;
  local_280 = &DAT_803134d4;
  local_290 = 0x4000;
  local_28c = lbl_803E14C4;
  local_288 = lbl_803E14B0;
  local_284 = lbl_803E14B0;
  local_262 = 2;
  local_264 = 0xe;
  local_268 = &DAT_803134d4;
  local_278 = 0x4000;
  local_274 = lbl_803E14C4;
  local_270 = lbl_803E14B0;
  local_26c = lbl_803E14B0;
  local_24a = 2;
  local_24c = 0x53;
  local_250 = 0;
  local_260 = 0x800000;
  local_25c = lbl_803E14C8;
  local_258 = lbl_803E14B0;
  local_254 = lbl_803E14B0;
  local_232 = 2;
  local_234 = 0x54;
  local_238 = 0;
  local_248 = 0x1800000;
  local_244 = lbl_803E14C8;
  local_240 = lbl_803E14B0;
  local_23c = lbl_803E14CC;
  local_21a = 2;
  local_21c = 10;
  local_220 = &DAT_803134f0;
  local_230 = 4;
  local_22c = lbl_803E14B0;
  local_228 = lbl_803E14B0;
  local_224 = lbl_803E14B0;
  local_202 = 2;
  local_204 = 0xe;
  local_208 = &DAT_803134d4;
  local_218 = 2;
  local_214 = lbl_803E14C0;
  local_210 = lbl_803E14C0;
  local_20c = lbl_803E14C0;
  local_340 = 0;
  local_36c = lbl_803E14B0;
  local_368 = lbl_803E14C0;
  local_364 = lbl_803E14B0;
  local_378 = lbl_803E14B0;
  local_374 = lbl_803E14B0;
  local_370 = lbl_803E14B0;
  local_360 = lbl_803E14C8;
  local_358 = 1;
  local_35c = 0;
  local_33f = 0xe;
  local_33e = 0;
  local_33d = 0x10;
  iVar1 = (int)(auStack_200 + -(int)&local_338) / 0x18 +
          ((int)(auStack_200 + -(int)&local_338) >> 0x1f);
  local_33b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_352 = DAT_80313504;
  local_350 = DAT_80313506;
  local_34e = DAT_80313508;
  local_34c = DAT_8031350a;
  local_34a = DAT_8031350c;
  local_348 = DAT_8031350e;
  local_346 = DAT_80313510;
  local_344 = param_4 | 0x1000000;
  if ((param_4 & 1) != 0) {
    if (iVar2 == 0) {
      local_36c = lbl_803E14B0 + *(float *)(param_3 + 0xc);
      local_368 = lbl_803E14C0 + *(float *)(param_3 + 0x10);
      local_364 = lbl_803E14B0 + *(float *)(param_3 + 0x14);
    }
    else {
      local_36c = lbl_803E14B0 + *(float *)(iVar2 + 0x18);
      local_368 = lbl_803E14C0 + *(float *)(iVar2 + 0x1c);
      local_364 = lbl_803E14B0 + *(float *)(iVar2 + 0x20);
    }
  }
  local_398 = &local_338;
  local_394 = iVar2;
  local_354 = extraout_r4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_398,0,0xe,&DAT_803133e0,0xc,&DAT_8031346c,0x46,0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ecb04
 * EN v1.0 Address: 0x800ECB04
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x800EDCC4
 * EN v1.1 Size: 1100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ecb04(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  short *psVar2;
  undefined2 extraout_r4;
  undefined4 *local_388;
  short *local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  char local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined4 local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined4 local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined4 local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined4 local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined *local_270;
  undefined2 local_26c;
  undefined local_26a;
  undefined4 local_268;
  float local_264;
  float local_260;
  float local_25c;
  undefined *local_258;
  undefined2 local_254;
  undefined local_252;
  undefined4 local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined4 local_240;
  undefined2 local_23c;
  undefined local_23a;
  undefined4 local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined4 local_228;
  undefined2 local_224;
  undefined local_222;
  undefined4 local_220;
  float local_21c;
  float local_218;
  float local_214;
  undefined *local_210;
  undefined2 local_20c;
  undefined local_20a;
  undefined4 local_208;
  float local_204;
  float local_200;
  float local_1fc;
  undefined *local_1f8;
  undefined2 local_1f4;
  undefined local_1f2;
  undefined4 local_1f0;
  float local_1ec;
  float local_1e8;
  float local_1e4;
  undefined *local_1e0;
  undefined2 local_1dc;
  undefined local_1da;
  undefined4 local_1d8;
  float local_1d4;
  float local_1d0;
  float local_1cc;
  undefined4 local_1c8;
  undefined2 local_1c4;
  undefined local_1c2;
  undefined auStack_1c0 [408];
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  psVar2 = (short *)FUN_8028683c();
  local_312 = 0;
  local_314 = 8;
  local_318 = &DAT_803135d8;
  local_328 = 4;
  local_324 = lbl_803E14D8;
  local_320 = lbl_803E14D8;
  local_31c = lbl_803E14D8;
  local_2fa = 0;
  local_2fc = 1;
  local_300 = 0;
  local_310 = 0x2008000;
  local_30c = lbl_803E14DC;
  local_308 = lbl_803E14E0;
  local_304 = lbl_803E14DC;
  local_2e2 = 0;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2f8 = 0x2080000;
  local_2f4 = lbl_803E14D8;
  local_2f0 = lbl_803E14E4;
  local_2ec = lbl_803E14E8;
  local_2ca = 0;
  local_2cc = 9;
  local_2d0 = &DAT_803135c4;
  local_2e0 = 0x80;
  local_2dc = lbl_803E14D8;
  local_2d8 = lbl_803E14D8;
  uStack_24 = (int)*psVar2 ^ 0x80000000;
  local_28 = 0x43300000;
  local_2d4 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1510);
  local_2b2 = 0;
  local_2b4 = 0x7a;
  local_2b8 = 0;
  local_2c8 = 0x10000;
  local_2c4 = lbl_803E14D8;
  local_2c0 = lbl_803E14D8;
  local_2bc = lbl_803E14D8;
  local_29a = 0;
  local_29c = 9;
  local_2a0 = &DAT_803135c4;
  local_2b0 = 2;
  uStack_1c = FUN_80017760(0,0xc);
  uStack_1c = uStack_1c ^ 0x80000000;
  local_20 = 0x43300000;
  local_2ac = lbl_803E14F0 +
              lbl_803E14EC * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e1510);
  local_282 = 1;
  local_284 = 0;
  local_288 = 0;
  local_298 = 0x10000000;
  local_294 = lbl_803E14F4;
  local_290 = lbl_803E14F8;
  local_28c = lbl_803E14D8;
  local_26a = 1;
  local_26c = 8;
  local_270 = &DAT_803135d8;
  local_280 = 0x4000;
  local_27c = lbl_803E14D8;
  local_278 = lbl_803E14FC;
  local_274 = lbl_803E14D8;
  local_252 = 1;
  local_254 = 9;
  local_258 = &DAT_803135c4;
  local_268 = 0x100;
  local_264 = lbl_803E1500;
  local_260 = lbl_803E14D8;
  local_25c = lbl_803E14D8;
  local_23a = 1;
  local_23c = 0;
  local_240 = 0;
  local_250 = 0x400000;
  local_24c = lbl_803E14D8;
  local_248 = lbl_803E14D8;
  local_244 = lbl_803E1504;
  local_222 = 1;
  local_224 = 0;
  local_228 = 0;
  local_238 = 0x2080000;
  local_234 = lbl_803E14D8;
  local_230 = lbl_803E14E4;
  local_22c = lbl_803E1504;
  local_20a = 2;
  local_20c = 8;
  local_210 = &DAT_803135d8;
  local_220 = 0x4000;
  local_21c = lbl_803E14D8;
  local_218 = lbl_803E14FC;
  local_214 = lbl_803E14D8;
  local_1f2 = 2;
  local_1f4 = 9;
  local_1f8 = &DAT_803135c4;
  local_208 = 0x100;
  local_204 = lbl_803E1500;
  local_200 = lbl_803E14D8;
  local_1fc = lbl_803E14D8;
  local_1da = 2;
  local_1dc = 1;
  local_1e0 = &DAT_803dc520;
  local_1f0 = 4;
  local_1ec = lbl_803E14D8;
  local_1e8 = lbl_803E14D8;
  local_1e4 = lbl_803E14D8;
  local_1c2 = 2;
  local_1c4 = 0;
  local_1c8 = 0;
  local_1d8 = 0x2008000;
  local_1d4 = lbl_803E14D8;
  local_1d0 = lbl_803E14D8;
  local_1cc = lbl_803E14D8;
  local_330 = 0;
  local_35c = lbl_803E14D8;
  local_358 = lbl_803E14E4;
  local_354 = lbl_803E1508;
  local_368 = lbl_803E14D8;
  local_364 = lbl_803E14D8;
  local_360 = lbl_803E14D8;
  local_350 = lbl_803E150C;
  local_348 = 1;
  local_34c = 0;
  local_32f = 9;
  local_32e = 0;
  local_32d = 0;
  iVar1 = (int)(auStack_1c0 + -(int)&local_328) / 0x18 +
          ((int)(auStack_1c0 + -(int)&local_328) >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_803135e8;
  local_340 = DAT_803135ea;
  local_33e = DAT_803135ec;
  local_33c = DAT_803135ee;
  local_33a = DAT_803135f0;
  local_338 = DAT_803135f2;
  local_336 = DAT_803135f4;
  local_334 = param_4 | 0x4000010;
  if ((param_4 & 1) != 0) {
    if (psVar2 == (short *)0x0) {
      local_35c = lbl_803E14D8 + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E14E4 + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E1508 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E14D8 + *(float *)(psVar2 + 0xc);
      local_358 = lbl_803E14E4 + *(float *)(psVar2 + 0xe);
      local_354 = lbl_803E1508 + *(float *)(psVar2 + 0x10);
    }
  }
  local_388 = &local_328;
  local_384 = psVar2;
  local_344 = extraout_r4;
  local_2a8 = local_2ac;
  local_2a4 = local_2ac;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,9,&DAT_80313538,8,&DAT_80313594,0x90,0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ecb7c
 * EN v1.0 Address: 0x800ECB7C
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x800EE110
 * EN v1.1 Size: 1000b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ecb7c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  uint uVar1;
  undefined8 uVar2;
  undefined4 *local_388;
  int local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  undefined local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined *local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined4 local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined *local_270;
  undefined2 local_26c;
  undefined local_26a;
  undefined4 local_268;
  float local_264;
  float local_260;
  float local_25c;
  undefined4 local_258;
  undefined2 local_254;
  undefined local_252;
  undefined4 local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined *local_240;
  undefined2 local_23c;
  undefined local_23a;
  undefined4 local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined4 local_228;
  undefined2 local_224;
  undefined local_222;
  undefined4 local_220;
  float local_21c;
  float local_218;
  float local_214;
  undefined *local_210;
  undefined2 local_20c;
  undefined local_20a;
  undefined4 local_208;
  float local_204;
  float local_200;
  float local_1fc;
  undefined *local_1f8;
  undefined2 local_1f4;
  undefined local_1f2;
  undefined4 local_1f0;
  float local_1ec;
  float local_1e8;
  float local_1e4;
  undefined *local_1e0;
  undefined2 local_1dc;
  undefined local_1da;
  undefined4 local_28;
  uint uStack_24;
  
  uVar2 = FUN_80286838();
  local_384 = (int)((ulonglong)uVar2 >> 0x20);
  uVar1 = (uint)*(byte *)(*(int *)(local_384 + 0x4c) + 0x1a);
  if ((int)uVar2 == 1) {
    DAT_803137f6 = 0;
    local_294 = lbl_803E151C;
  }
  else {
    local_294 = lbl_803E1518;
    if ((int)uVar2 == 2) {
      uVar1 = 6;
      local_294 = lbl_803E1520;
    }
  }
  local_312 = 0;
  local_314 = 0x15;
  local_318 = &DAT_803137c8;
  local_328 = 4;
  local_324 = lbl_803E1520;
  local_320 = lbl_803E1520;
  local_31c = lbl_803E1520;
  local_2fa = 0;
  local_2fc = 0xe;
  local_300 = &DAT_803137ac;
  local_310 = 2;
  local_30c = lbl_803E1524;
  local_308 = lbl_803E1528;
  local_304 = lbl_803E1524;
  local_2e2 = 0;
  local_2e4 = 7;
  local_2e8 = &DAT_8031378c;
  local_2f8 = 2;
  local_2f4 = lbl_803E1524;
  local_2f0 = lbl_803E1528;
  local_2ec = lbl_803E1524;
  local_2ca = 1;
  local_2cc = 7;
  local_2d0 = &DAT_8031378c;
  local_2e0 = 4;
  local_2dc = lbl_803E152C;
  local_2d8 = lbl_803E1520;
  local_2d4 = lbl_803E1520;
  local_2b2 = 1;
  local_2b4 = 7;
  local_2b8 = &DAT_8031379c;
  local_2c8 = 4;
  local_2c4 = lbl_803E152C;
  local_2c0 = lbl_803E1520;
  local_2bc = lbl_803E1520;
  local_29a = 1;
  local_29c = 0x15;
  local_2a0 = &DAT_803137c8;
  local_2b0 = 0x100;
  local_2ac = lbl_803E1520;
  local_2a8 = lbl_803E1520;
  local_2a4 = lbl_803E1530;
  local_282 = 2;
  local_284 = 0x3a;
  local_288 = 0;
  local_298 = 0x1800000;
  local_290 = lbl_803E1520;
  local_28c = lbl_803E1534;
  local_26a = 2;
  local_26c = 0x15;
  local_270 = &DAT_803137c8;
  local_280 = 0x100;
  local_27c = lbl_803E1520;
  local_278 = lbl_803E1520;
  local_274 = lbl_803E1530;
  local_252 = 3;
  local_254 = 0x3a;
  local_258 = 0;
  local_268 = 0x1800000;
  local_260 = lbl_803E1520;
  local_25c = lbl_803E1534;
  local_23a = 3;
  local_23c = 0x15;
  local_240 = &DAT_803137c8;
  local_250 = 0x100;
  local_24c = lbl_803E1520;
  local_248 = lbl_803E1520;
  local_244 = lbl_803E1530;
  local_222 = 4;
  local_224 = 2;
  local_228 = 0;
  local_238 = 0x2000;
  local_234 = lbl_803E1520;
  local_230 = lbl_803E1520;
  local_22c = lbl_803E1520;
  local_20a = 5;
  local_20c = 7;
  local_210 = &DAT_8031378c;
  local_220 = 4;
  local_21c = lbl_803E1520;
  local_218 = lbl_803E1520;
  local_214 = lbl_803E1520;
  local_1f2 = 5;
  local_1f4 = 7;
  local_1f8 = &DAT_8031379c;
  local_208 = 4;
  local_204 = lbl_803E1520;
  local_200 = lbl_803E1520;
  local_1fc = lbl_803E1520;
  local_1da = 5;
  local_1dc = 0x15;
  local_1e0 = &DAT_803137c8;
  local_1f0 = 0x100;
  local_1ec = lbl_803E1520;
  local_1e8 = lbl_803E1520;
  local_1e4 = lbl_803E1530;
  local_330 = 0;
  local_344 = (undefined2)uVar2;
  local_35c = lbl_803E1520;
  local_358 = lbl_803E1520;
  local_354 = lbl_803E1520;
  local_368 = lbl_803E1520;
  local_364 = lbl_803E1520;
  local_360 = lbl_803E1520;
  if (uVar1 == 0) {
    local_350 = lbl_803E1518;
  }
  else {
    local_28 = 0x43300000;
    local_350 = lbl_803E1538 * (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803e1540);
    uStack_24 = uVar1;
  }
  local_348 = 2;
  local_34c = 7;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x1e;
  local_32b = 0xe;
  local_342 = DAT_803137f4;
  local_340 = DAT_803137f6;
  local_33e = DAT_803137f8;
  local_33c = DAT_803137fa;
  local_33a = DAT_803137fc;
  local_338 = DAT_803137fe;
  local_336 = DAT_80313800;
  local_388 = &local_328;
  local_334 = param_4 | 0xc0400c0;
  if ((param_4 & 1) != 0) {
    if (local_384 == 0) {
      local_35c = lbl_803E1520 + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E1520 + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E1520 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E1520 + *(float *)(local_384 + 0x18);
      local_358 = lbl_803E1520 + *(float *)(local_384 + 0x1c);
      local_354 = lbl_803E1520 + *(float *)(local_384 + 0x20);
    }
  }
  local_264 = local_294;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_80313618,0x18,&DAT_803136ec,0x5e0,0);
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ecbf8
 * EN v1.0 Address: 0x800ECBF8
 * EN v1.0 Size: 412b
 * EN v1.1 Address: 0x800EE4F8
 * EN v1.1 Size: 1696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ecbf8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  short *psVar6;
  undefined8 uVar7;
  undefined4 *local_388;
  int local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  undefined local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined *local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined *local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined *local_270;
  undefined2 local_26c;
  undefined local_26a;
  undefined4 local_268;
  float local_264;
  float local_260;
  float local_25c;
  undefined *local_258;
  undefined2 local_254;
  undefined local_252;
  undefined4 local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined *local_240;
  undefined2 local_23c;
  undefined local_23a;
  undefined4 local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined *local_228;
  undefined2 local_224;
  undefined local_222;
  undefined4 local_220;
  float local_21c;
  float local_218;
  float local_214;
  undefined *local_210;
  undefined2 local_20c;
  undefined local_20a;
  undefined4 local_208;
  float local_204;
  float local_200;
  float local_1fc;
  undefined *local_1f8;
  undefined2 local_1f4;
  undefined local_1f2;
  undefined4 local_1f0;
  float local_1ec;
  float local_1e8;
  float local_1e4;
  undefined4 local_1e0;
  undefined2 local_1dc;
  undefined local_1da;
  undefined4 local_1d8;
  float local_1d4;
  float local_1d0;
  float local_1cc;
  undefined *local_1c8;
  undefined2 local_1c4;
  undefined local_1c2;
  undefined4 local_1c0;
  float local_1bc;
  float local_1b8;
  float local_1b4;
  undefined *local_1b0;
  undefined2 local_1ac;
  undefined local_1aa;
  undefined4 local_1a8;
  float local_1a4;
  float local_1a0;
  float local_19c;
  undefined *local_198;
  undefined2 local_194;
  undefined local_192;
  undefined4 local_190;
  float local_18c;
  float local_188;
  float local_184;
  undefined *local_180;
  undefined2 local_17c;
  undefined local_17a;
  undefined4 local_28;
  uint uStack_24;
  
  uVar7 = FUN_80286834();
  iVar1 = (int)((ulonglong)uVar7 >> 0x20);
  iVar3 = (int)uVar7;
  psVar6 = &DAT_80313828;
  if (iVar3 == 1) {
    DAT_8031393a = 0;
  }
  uVar4 = (uint)*(byte *)(*(int *)(iVar1 + 0x4c) + 0x1a);
  if (iVar3 == 2) {
    iVar5 = 0;
    do {
      if (*psVar6 < 1) {
        if (*psVar6 < 0) {
          uVar2 = FUN_80017760(0,800);
          *psVar6 = *psVar6 - (short)uVar2;
        }
      }
      else {
        uVar2 = FUN_80017760(0,800);
        *psVar6 = *psVar6 + (short)uVar2;
      }
      if (psVar6[1] < 1) {
        if (psVar6[1] < 0) {
          uVar2 = FUN_80017760(0,300);
          *psVar6 = *psVar6 - (short)uVar2;
        }
      }
      else {
        uVar2 = FUN_80017760(0,300);
        *psVar6 = *psVar6 + (short)uVar2;
      }
      if (psVar6[2] < 1) {
        if (psVar6[2] < 0) {
          uVar2 = FUN_80017760(0,800);
          *psVar6 = *psVar6 - (short)uVar2;
        }
      }
      else {
        uVar2 = FUN_80017760(0,800);
        *psVar6 = *psVar6 + (short)uVar2;
      }
      psVar6 = psVar6 + 5;
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0xe);
  }
  if (iVar3 == 2) {
    local_31c = lbl_803E1548;
  }
  else {
    local_31c = lbl_803E1550;
  }
  local_2fa = 0;
  local_2fc = 7;
  local_300 = &DAT_80313928;
  local_30c = lbl_803E154C;
  local_310 = 8;
  local_312 = 0;
  local_314 = 7;
  local_318 = &DAT_80313918;
  local_328 = 8;
  local_2e2 = 0;
  local_2e4 = 0xe;
  local_2e8 = &DAT_803138fc;
  local_2f8 = 4;
  local_2f4 = lbl_803E1554;
  local_2f0 = lbl_803E1554;
  local_2ec = lbl_803E1554;
  if ((iVar3 == 3) && (param_3 != 0)) {
    local_2c0 = *(float *)(param_3 + 8);
    local_2d4 = lbl_803E1558 * local_2c0;
    local_2d8 = lbl_803E155C * local_2c0;
    local_2bc = lbl_803E1560 * local_2c0;
  }
  else {
    local_2d8 = lbl_803E155C;
    local_2d4 = lbl_803E1558;
    local_2c0 = lbl_803E1564;
    local_2bc = lbl_803E1560;
  }
  local_2b2 = 0;
  local_2b4 = 7;
  local_2b8 = &DAT_80313918;
  local_2c8 = 2;
  local_2ca = 0;
  local_2cc = 7;
  local_2d0 = &DAT_80313928;
  local_2e0 = 2;
  local_29a = 1;
  local_29c = 7;
  local_2a0 = &DAT_80313918;
  local_2b0 = 4;
  local_2ac = lbl_803E1568;
  local_2a8 = lbl_803E1554;
  local_2a4 = lbl_803E1554;
  local_282 = 1;
  local_284 = 7;
  local_288 = &DAT_80313928;
  local_298 = 4;
  local_294 = lbl_803E156C;
  local_290 = lbl_803E1554;
  local_28c = lbl_803E1554;
  local_26a = 1;
  local_26c = 0xe;
  local_270 = &DAT_803138fc;
  local_280 = 0x100;
  local_27c = lbl_803E1554;
  local_278 = lbl_803E1554;
  local_274 = lbl_803E1570;
  local_252 = 1;
  local_254 = 0xe;
  local_258 = &DAT_803138fc;
  local_268 = 0x4000;
  local_264 = lbl_803E1574;
  local_260 = lbl_803E1554;
  local_25c = lbl_803E1554;
  local_23a = 2;
  local_23c = 0xe;
  local_240 = &DAT_803138fc;
  local_250 = 0x100;
  local_24c = lbl_803E1554;
  local_248 = lbl_803E1554;
  local_244 = lbl_803E1570;
  local_222 = 2;
  local_224 = 0xe;
  local_228 = &DAT_803138fc;
  local_238 = 0x4000;
  local_234 = lbl_803E1574;
  local_230 = lbl_803E1554;
  local_22c = lbl_803E1554;
  local_20a = 3;
  local_20c = 0xe;
  local_210 = &DAT_803138fc;
  local_220 = 0x100;
  local_21c = lbl_803E1554;
  local_218 = lbl_803E1554;
  local_214 = lbl_803E1570;
  local_1f2 = 3;
  local_1f4 = 0xe;
  local_1f8 = &DAT_803138fc;
  local_208 = 0x4000;
  local_204 = lbl_803E1574;
  local_200 = lbl_803E1554;
  local_1fc = lbl_803E1554;
  local_1da = 4;
  local_1dc = 1;
  local_1e0 = 0;
  local_1f0 = 0x2000;
  local_1ec = lbl_803E1554;
  local_1e8 = lbl_803E1554;
  local_1e4 = lbl_803E1554;
  local_1c2 = 5;
  local_1c4 = 7;
  local_1c8 = &DAT_80313918;
  local_1d8 = 4;
  local_1d4 = lbl_803E1554;
  local_1d0 = lbl_803E1554;
  local_1cc = lbl_803E1554;
  local_1aa = 5;
  local_1ac = 7;
  local_1b0 = &DAT_80313928;
  local_1c0 = 4;
  local_1bc = lbl_803E1554;
  local_1b8 = lbl_803E1554;
  local_1b4 = lbl_803E1554;
  local_192 = 5;
  local_194 = 0xe;
  local_198 = &DAT_803138fc;
  local_1a8 = 0x100;
  local_1a4 = lbl_803E1554;
  local_1a0 = lbl_803E1554;
  local_19c = lbl_803E1570;
  local_17a = 5;
  local_17c = 0xe;
  local_180 = &DAT_803138fc;
  local_190 = 0x4000;
  local_18c = lbl_803E1574;
  local_188 = lbl_803E1554;
  local_184 = lbl_803E1554;
  local_330 = 0;
  local_344 = (undefined2)uVar7;
  local_35c = lbl_803E1554;
  local_358 = lbl_803E1578;
  local_354 = lbl_803E1554;
  local_368 = lbl_803E1554;
  local_364 = lbl_803E1554;
  local_360 = lbl_803E1554;
  if (uVar4 == 0) {
    local_350 = lbl_803E1564;
  }
  else {
    local_28 = 0x43300000;
    local_350 = lbl_803E157C * (float)((double)CONCAT44(0x43300000,uVar4) - DOUBLE_803e1580);
    uStack_24 = uVar4;
  }
  local_348 = 1;
  local_34c = 0;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x1e;
  local_32b = 0x12;
  local_342 = DAT_80313938;
  local_340 = DAT_8031393a;
  local_33e = DAT_8031393c;
  local_33c = DAT_8031393e;
  local_33a = DAT_80313940;
  local_338 = DAT_80313942;
  local_336 = DAT_80313944;
  local_388 = &local_328;
  local_334 = param_4 | 0x40000c0;
  if ((param_4 & 1) != 0) {
    if (iVar1 == 0) {
      local_35c = lbl_803E1554 + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E1578 + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E1554 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E1554 + *(float *)(iVar1 + 0x18);
      local_358 = lbl_803E1578 + *(float *)(iVar1 + 0x1c);
      local_354 = lbl_803E1554 + *(float *)(iVar1 + 0x20);
    }
  }
  local_384 = iVar1;
  local_324 = local_31c;
  local_320 = local_31c;
  local_308 = local_30c;
  local_304 = local_30c;
  local_2dc = local_2d4;
  local_2c4 = local_2bc;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0xe,&DAT_80313828,0xc,&DAT_803138b4,0x40,0);
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ecd94
 * EN v1.0 Address: 0x800ECD94
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x800EEB98
 * EN v1.1 Size: 824b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ecd94(int param_1,int param_2,int param_3,uint param_4)
{
  uint uVar1;
  undefined4 *local_378;
  int local_374;
  float local_358;
  float local_354;
  float local_350;
  float local_34c;
  float local_348;
  float local_344;
  float local_340;
  undefined4 local_33c;
  undefined4 local_338;
  undefined2 local_334;
  undefined2 local_332;
  undefined2 local_330;
  undefined2 local_32e;
  undefined2 local_32c;
  undefined2 local_32a;
  undefined2 local_328;
  undefined2 local_326;
  uint local_324;
  undefined local_320;
  undefined local_31f;
  undefined local_31e;
  undefined local_31d;
  undefined local_31b;
  undefined4 local_318;
  float local_314;
  float local_310;
  float local_30c;
  undefined *local_308;
  undefined2 local_304;
  undefined local_302;
  undefined4 local_300;
  float local_2fc;
  float local_2f8;
  float local_2f4;
  undefined *local_2f0;
  undefined2 local_2ec;
  undefined local_2ea;
  undefined4 local_2e8;
  float local_2e4;
  float local_2e0;
  float local_2dc;
  undefined *local_2d8;
  undefined2 local_2d4;
  undefined local_2d2;
  undefined4 local_2d0;
  float local_2cc;
  float local_2c8;
  float local_2c4;
  undefined *local_2c0;
  undefined2 local_2bc;
  undefined local_2ba;
  undefined4 local_2b8;
  float local_2b4;
  float local_2b0;
  float local_2ac;
  undefined *local_2a8;
  undefined2 local_2a4;
  undefined local_2a2;
  undefined4 local_2a0;
  float local_29c;
  float local_298;
  float local_294;
  undefined *local_290;
  undefined2 local_28c;
  undefined local_28a;
  undefined4 local_288;
  float local_284;
  float local_280;
  float local_27c;
  undefined4 local_278;
  undefined2 local_274;
  undefined local_272;
  undefined4 local_270;
  float local_26c;
  float local_268;
  float local_264;
  undefined *local_260;
  undefined2 local_25c;
  undefined local_25a;
  undefined4 local_258;
  float local_254;
  float local_250;
  float local_24c;
  undefined *local_248;
  undefined2 local_244;
  undefined local_242;
  undefined4 local_18;
  uint uStack_14;
  
  if (param_2 == 1) {
    DAT_80313a7a = 0;
  }
  uVar1 = (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x1a);
  local_302 = 0;
  local_304 = 7;
  local_308 = &DAT_80313a58;
  local_318 = 2;
  local_314 = lbl_803E1588;
  local_310 = lbl_803E158C;
  local_30c = lbl_803E1588;
  local_2ea = 0;
  local_2ec = 7;
  local_2f0 = &DAT_80313a68;
  local_300 = 2;
  local_2fc = lbl_803E1590;
  local_2f8 = lbl_803E1594;
  local_2f4 = lbl_803E1590;
  local_2d2 = 0;
  local_2d4 = 0xe;
  local_2d8 = &DAT_80313a3c;
  local_2e8 = 4;
  local_2e4 = lbl_803E1598;
  local_2e0 = lbl_803E1598;
  local_2dc = lbl_803E1598;
  local_2ba = 1;
  local_2bc = 7;
  local_2c0 = &DAT_80313a68;
  local_2d0 = 4;
  local_2cc = lbl_803E159C;
  local_2c8 = lbl_803E1598;
  local_2c4 = lbl_803E1598;
  local_2a2 = 1;
  local_2a4 = 0xe;
  local_2a8 = &DAT_80313a3c;
  local_2b8 = 0x100;
  local_2b4 = lbl_803E1598;
  local_2b0 = lbl_803E1598;
  local_2ac = lbl_803E15A0;
  local_28a = 2;
  local_28c = 0xe;
  local_290 = &DAT_80313a3c;
  local_2a0 = 0x100;
  local_29c = lbl_803E1598;
  local_298 = lbl_803E1598;
  local_294 = lbl_803E15A0;
  local_272 = 3;
  local_274 = 1;
  local_278 = 0;
  local_288 = 0x2000;
  local_284 = lbl_803E1598;
  local_280 = lbl_803E1598;
  local_27c = lbl_803E1598;
  local_25a = 4;
  local_25c = 7;
  local_260 = &DAT_80313a68;
  local_270 = 4;
  local_26c = lbl_803E1598;
  local_268 = lbl_803E1598;
  local_264 = lbl_803E1598;
  local_242 = 4;
  local_244 = 0xe;
  local_248 = &DAT_80313a3c;
  local_258 = 0x100;
  local_254 = lbl_803E1598;
  local_250 = lbl_803E1598;
  local_24c = lbl_803E15A0;
  local_320 = 0;
  local_334 = (undefined2)param_2;
  local_34c = lbl_803E1598;
  local_348 = lbl_803E1598;
  local_344 = lbl_803E1598;
  local_358 = lbl_803E1598;
  local_354 = lbl_803E1598;
  local_350 = lbl_803E1598;
  if (uVar1 == 0) {
    local_340 = lbl_803E158C;
  }
  else {
    local_18 = 0x43300000;
    local_340 = lbl_803E15A4 * (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803e15a8);
    uStack_14 = uVar1;
  }
  local_338 = 1;
  local_33c = 0;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 0x1e;
  local_31b = 9;
  local_332 = DAT_80313a78;
  local_330 = DAT_80313a7a;
  local_32e = DAT_80313a7c;
  local_32c = DAT_80313a7e;
  local_32a = DAT_80313a80;
  local_328 = DAT_80313a82;
  local_326 = DAT_80313a84;
  local_378 = &local_318;
  local_324 = param_4 | 0x4040080;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = lbl_803E1598 + *(float *)(param_3 + 0xc);
      local_348 = lbl_803E1598 + *(float *)(param_3 + 0x10);
      local_344 = lbl_803E1598 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = lbl_803E1598 + *(float *)(param_1 + 0x18);
      local_348 = lbl_803E1598 + *(float *)(param_1 + 0x1c);
      local_344 = lbl_803E1598 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0xe,&DAT_80313968,0xc,&DAT_803139f4,0x5e0,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ece08
 * EN v1.0 Address: 0x800ECE08
 * EN v1.0 Size: 124b
 * EN v1.1 Address: 0x800EEED0
 * EN v1.1 Size: 952b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ece08(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  uint uVar1;
  undefined8 uVar2;
  undefined4 *local_388;
  int local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  undefined local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined *local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined *local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined *local_270;
  undefined2 local_26c;
  undefined local_26a;
  undefined4 local_268;
  float local_264;
  float local_260;
  float local_25c;
  undefined *local_258;
  undefined2 local_254;
  undefined local_252;
  undefined4 local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined4 local_240;
  undefined2 local_23c;
  undefined local_23a;
  undefined4 local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined *local_228;
  undefined2 local_224;
  undefined local_222;
  undefined4 local_220;
  float local_21c;
  float local_218;
  float local_214;
  undefined *local_210;
  undefined2 local_20c;
  undefined local_20a;
  undefined4 local_208;
  float local_204;
  float local_200;
  float local_1fc;
  undefined *local_1f8;
  undefined2 local_1f4;
  undefined local_1f2;
  undefined4 local_28;
  uint uStack_24;
  
  uVar2 = FUN_80286840();
  local_384 = (int)((ulonglong)uVar2 >> 0x20);
  if ((int)uVar2 == 1) {
    DAT_80313bba = 0;
  }
  uVar1 = (uint)*(byte *)(*(int *)(local_384 + 0x4c) + 0x1a);
  local_312 = 0;
  local_314 = 7;
  local_318 = &DAT_80313b98;
  local_328 = 8;
  local_324 = lbl_803E15B0;
  local_320 = lbl_803E15B0;
  local_31c = lbl_803E15B0;
  local_2fa = 0;
  local_2fc = 7;
  local_300 = &DAT_80313ba8;
  local_310 = 8;
  local_30c = lbl_803E15B4;
  local_308 = lbl_803E15B4;
  local_304 = lbl_803E15B4;
  local_2e2 = 0;
  local_2e4 = 0xe;
  local_2e8 = &DAT_80313b7c;
  local_2f8 = 4;
  local_2f4 = lbl_803E15B8;
  local_2f0 = lbl_803E15B8;
  local_2ec = lbl_803E15B8;
  local_2ca = 0;
  local_2cc = 7;
  local_2d0 = &DAT_80313ba8;
  local_2e0 = 2;
  local_2dc = lbl_803E15BC;
  local_2d8 = lbl_803E15C0;
  local_2d4 = lbl_803E15BC;
  local_2b2 = 0;
  local_2b4 = 7;
  local_2b8 = &DAT_80313b98;
  local_2c8 = 2;
  local_2c4 = lbl_803E15C4;
  local_2c0 = lbl_803E15C8;
  local_2bc = lbl_803E15C4;
  local_29a = 1;
  local_29c = 0x12;
  local_2a0 = &DAT_80313b7c;
  local_2b0 = 0x100;
  local_2ac = lbl_803E15B8;
  local_2a8 = lbl_803E15B8;
  local_2a4 = lbl_803E15CC;
  local_282 = 1;
  local_284 = 7;
  local_288 = &DAT_80313b98;
  local_298 = 4;
  local_294 = lbl_803E15D0;
  local_290 = lbl_803E15B8;
  local_28c = lbl_803E15B8;
  local_26a = 1;
  local_26c = 7;
  local_270 = &DAT_80313ba8;
  local_280 = 4;
  local_27c = lbl_803E15D4;
  local_278 = lbl_803E15B8;
  local_274 = lbl_803E15B8;
  local_252 = 2;
  local_254 = 0x12;
  local_258 = &DAT_80313b7c;
  local_268 = 0x4000;
  local_264 = lbl_803E15D8;
  local_260 = lbl_803E15B8;
  local_25c = lbl_803E15B8;
  local_23a = 3;
  local_23c = 1;
  local_240 = 0;
  local_250 = 0x2000;
  local_24c = lbl_803E15B8;
  local_248 = lbl_803E15B8;
  local_244 = lbl_803E15B8;
  local_222 = 4;
  local_224 = 7;
  local_228 = &DAT_80313b98;
  local_238 = 4;
  local_234 = lbl_803E15B8;
  local_230 = lbl_803E15B8;
  local_22c = lbl_803E15B8;
  local_20a = 4;
  local_20c = 7;
  local_210 = &DAT_80313ba8;
  local_220 = 4;
  local_21c = lbl_803E15B8;
  local_218 = lbl_803E15B8;
  local_214 = lbl_803E15B8;
  local_1f2 = 4;
  local_1f4 = 0x12;
  local_1f8 = &DAT_80313b7c;
  local_208 = 0x4000;
  local_204 = lbl_803E15D8;
  local_200 = lbl_803E15B8;
  local_1fc = lbl_803E15B8;
  local_330 = 0;
  local_344 = (undefined2)uVar2;
  local_35c = lbl_803E15B8;
  local_358 = lbl_803E15B8;
  local_354 = lbl_803E15B8;
  local_368 = lbl_803E15B8;
  local_364 = lbl_803E15B8;
  local_360 = lbl_803E15B8;
  if (uVar1 == 0) {
    local_350 = lbl_803E15C8;
  }
  else {
    local_28 = 0x43300000;
    local_350 = lbl_803E15DC * (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803e15e0);
    uStack_24 = uVar1;
  }
  local_348 = 1;
  local_34c = 0;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x1e;
  local_32b = 0xd;
  local_342 = DAT_80313bb8;
  local_340 = DAT_80313bba;
  local_33e = DAT_80313bbc;
  local_33c = DAT_80313bbe;
  local_33a = DAT_80313bc0;
  local_338 = DAT_80313bc2;
  local_336 = DAT_80313bc4;
  local_388 = &local_328;
  local_334 = param_4 | 0x40000c0;
  if ((param_4 & 1) != 0) {
    if (local_384 == 0) {
      local_35c = lbl_803E15B8 + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E15B8 + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E15B8 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E15B8 + *(float *)(local_384 + 0x18);
      local_358 = lbl_803E15B8 + *(float *)(local_384 + 0x1c);
      local_354 = lbl_803E15B8 + *(float *)(local_384 + 0x20);
    }
  }
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0xe,&DAT_80313aa8,0xc,&DAT_80313b34,0x40,0);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ece84
 * EN v1.0 Address: 0x800ECE84
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800EF288
 * EN v1.1 Size: 948b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ece84(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  uint uVar1;
  ulonglong uVar2;
  undefined4 *local_388;
  int local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  undefined local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined *local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined4 local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined *local_270;
  undefined2 local_26c;
  undefined local_26a;
  undefined4 local_268;
  float local_264;
  float local_260;
  float local_25c;
  undefined4 local_258;
  undefined2 local_254;
  undefined local_252;
  undefined4 local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined *local_240;
  undefined2 local_23c;
  undefined local_23a;
  undefined4 local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined4 local_228;
  undefined2 local_224;
  undefined local_222;
  undefined4 local_220;
  float local_21c;
  float local_218;
  float local_214;
  undefined *local_210;
  undefined2 local_20c;
  undefined local_20a;
  undefined4 local_208;
  float local_204;
  float local_200;
  float local_1fc;
  undefined *local_1f8;
  undefined2 local_1f4;
  undefined local_1f2;
  undefined4 local_1f0;
  float local_1ec;
  float local_1e8;
  float local_1e4;
  undefined *local_1e0;
  undefined2 local_1dc;
  undefined local_1da;
  undefined4 local_28;
  uint uStack_24;
  
  uVar2 = FUN_80286838();
  local_384 = (int)(uVar2 >> 0x20);
  uVar1 = (uint)uVar2 & 0xff;
  local_312 = 0;
  local_314 = 0x15;
  local_318 = &DAT_80313d98;
  local_328 = 4;
  local_324 = lbl_803E15E8;
  local_320 = lbl_803E15E8;
  local_31c = lbl_803E15E8;
  local_2fa = 0;
  local_2fc = 0xe;
  local_300 = &DAT_80313d7c;
  local_310 = 2;
  local_30c = lbl_803E15EC;
  local_308 = lbl_803E15F0;
  local_304 = lbl_803E15EC;
  local_2e2 = 0;
  local_2e4 = 7;
  local_2e8 = &DAT_80313d5c;
  local_2f8 = 2;
  local_2f4 = lbl_803E15EC;
  local_2f0 = lbl_803E15F0;
  local_2ec = lbl_803E15EC;
  local_2ca = 1;
  local_2cc = 7;
  local_2d0 = &DAT_80313d5c;
  local_2e0 = 4;
  local_2dc = lbl_803E15F4;
  local_2d8 = lbl_803E15E8;
  local_2d4 = lbl_803E15E8;
  local_2b2 = 1;
  local_2b4 = 7;
  local_2b8 = &DAT_80313d6c;
  local_2c8 = 4;
  local_2c4 = lbl_803E15F4;
  local_2c0 = lbl_803E15E8;
  local_2bc = lbl_803E15E8;
  local_29a = 1;
  local_29c = 0x15;
  local_2a0 = &DAT_80313d98;
  local_2b0 = 0x100;
  local_2ac = lbl_803E15E8;
  local_2a8 = lbl_803E15E8;
  local_2a4 = lbl_803E15F8;
  local_282 = 2;
  local_284 = 0x3a;
  local_288 = 0;
  local_298 = 0x1800000;
  local_294 = lbl_803E15E8;
  local_290 = lbl_803E15E8;
  local_28c = lbl_803E15FC;
  local_26a = 2;
  local_26c = 0x15;
  local_270 = &DAT_80313d98;
  local_280 = 0x100;
  local_27c = lbl_803E15E8;
  local_278 = lbl_803E15E8;
  local_274 = lbl_803E15F8;
  local_252 = 3;
  local_254 = 0x3a;
  local_258 = 0;
  local_268 = 0x1800000;
  local_264 = lbl_803E15E8;
  local_260 = lbl_803E15E8;
  local_25c = lbl_803E15FC;
  local_23a = 3;
  local_23c = 0x15;
  local_240 = &DAT_80313d98;
  local_250 = 0x100;
  local_24c = lbl_803E15E8;
  local_248 = lbl_803E15E8;
  local_244 = lbl_803E15F8;
  local_222 = 4;
  local_224 = 2;
  local_228 = 0;
  local_238 = 0x2000;
  local_234 = lbl_803E15E8;
  local_230 = lbl_803E15E8;
  local_22c = lbl_803E15E8;
  local_20a = 5;
  local_20c = 7;
  local_210 = &DAT_80313d5c;
  local_220 = 4;
  local_21c = lbl_803E15E8;
  local_218 = lbl_803E15E8;
  local_214 = lbl_803E15E8;
  local_1f2 = 5;
  local_1f4 = 7;
  local_1f8 = &DAT_80313d6c;
  local_208 = 4;
  local_204 = lbl_803E15E8;
  local_200 = lbl_803E15E8;
  local_1fc = lbl_803E15E8;
  local_1da = 5;
  local_1dc = 0x15;
  local_1e0 = &DAT_80313d98;
  local_1f0 = 0x100;
  local_1ec = lbl_803E15E8;
  local_1e8 = lbl_803E15E8;
  local_1e4 = lbl_803E15F8;
  local_330 = 0;
  local_344 = (undefined2)uVar2;
  local_35c = lbl_803E15E8;
  local_358 = lbl_803E15E8;
  local_354 = lbl_803E15E8;
  local_368 = lbl_803E15E8;
  local_364 = lbl_803E15E8;
  local_360 = lbl_803E15E8;
  if ((uVar2 & 0xff) == 0) {
    local_350 = lbl_803E1604;
  }
  else {
    local_28 = 0x43300000;
    local_350 = lbl_803E1600 * (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803e1608);
    uStack_24 = uVar1;
  }
  local_348 = 2;
  local_34c = 7;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x1e;
  local_32b = 0xe;
  local_342 = DAT_80313dc4;
  local_340 = DAT_80313dc6;
  local_33e = DAT_80313dc8;
  local_33c = DAT_80313dca;
  local_33a = DAT_80313dcc;
  local_338 = DAT_80313dce;
  local_336 = DAT_80313dd0;
  local_388 = &local_328;
  local_334 = param_4 | 0xc0400c0;
  if ((param_4 & 1) != 0) {
    if (local_384 == 0) {
      local_35c = lbl_803E15E8 + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E15E8 + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E15E8 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E15E8 + *(float *)(local_384 + 0x18);
      local_358 = lbl_803E15E8 + *(float *)(local_384 + 0x1c);
      local_354 = lbl_803E15E8 + *(float *)(local_384 + 0x20);
    }
  }
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_80313be8,0x18,&DAT_80313cbc,0x5e0,0);
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ecef0
 * EN v1.0 Address: 0x800ECEF0
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800EF63C
 * EN v1.1 Size: 1044b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ecef0(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  undefined2 extraout_r4;
  undefined4 *local_388;
  int local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  undefined local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined4 local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined4 local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined4 local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined *local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined *local_270;
  undefined2 local_26c;
  undefined local_26a;
  undefined4 local_268;
  float local_264;
  float local_260;
  float local_25c;
  undefined4 local_258;
  undefined2 local_254;
  undefined local_252;
  undefined4 local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined4 local_240;
  undefined2 local_23c;
  undefined local_23a;
  undefined4 local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined4 local_228;
  undefined2 local_224;
  undefined local_222;
  undefined4 local_220;
  float local_21c;
  float local_218;
  float local_214;
  undefined *local_210;
  undefined2 local_20c;
  undefined local_20a;
  undefined4 local_208;
  float local_204;
  float local_200;
  float local_1fc;
  undefined4 local_1f8;
  undefined2 local_1f4;
  undefined local_1f2;
  undefined4 local_1f0;
  float local_1ec;
  float local_1e8;
  float local_1e4;
  undefined4 local_1e0;
  undefined2 local_1dc;
  undefined local_1da;
  undefined4 local_1d8;
  float local_1d4;
  float local_1d0;
  float local_1cc;
  undefined *local_1c8;
  undefined2 local_1c4;
  undefined local_1c2;
  undefined4 local_1c0;
  float local_1bc;
  float local_1b8;
  float local_1b4;
  undefined *local_1b0;
  undefined2 local_1ac;
  undefined local_1aa;
  undefined4 local_1a8;
  float local_1a4;
  float local_1a0;
  float local_19c;
  undefined4 local_198;
  undefined2 local_194;
  undefined local_192;
  undefined4 local_190;
  float local_18c;
  float local_188;
  float local_184;
  undefined *local_180;
  undefined2 local_17c;
  undefined local_17a;
  undefined4 local_178;
  float local_174;
  float local_170;
  float local_16c;
  undefined4 local_168;
  undefined2 local_164;
  undefined local_162;
  
  local_384 = FUN_80286838();
  local_312 = 0;
  local_314 = 0x15;
  local_318 = &DAT_80313fa8;
  local_328 = 4;
  local_324 = lbl_803E1610;
  local_320 = lbl_803E1610;
  local_31c = lbl_803E1610;
  local_2fa = 0;
  local_2fc = 0x15;
  local_300 = &DAT_80313fa8;
  local_310 = 2;
  local_30c = lbl_803E1614;
  local_308 = lbl_803E1618;
  local_304 = lbl_803E1614;
  local_2e2 = 0;
  local_2e4 = 0x50;
  local_2e8 = 0;
  local_2f8 = 0x20000000;
  local_2f4 = lbl_803E161C;
  local_2f0 = lbl_803E1620;
  local_2ec = lbl_803E1624;
  local_2ca = 0;
  local_2cc = 0;
  local_2d0 = 0;
  local_2e0 = 0x80000;
  local_2dc = lbl_803E1610;
  local_2d8 = lbl_803E1628;
  local_2d4 = lbl_803E1610;
  local_2b2 = 0;
  local_2b4 = 0;
  local_2b8 = 0;
  local_2c8 = 0x400000;
  local_2c4 = lbl_803E1610;
  local_2c0 = lbl_803E162C;
  local_2bc = lbl_803E1610;
  local_29a = 1;
  local_29c = 0x15;
  local_2a0 = &DAT_80313fa8;
  local_2b0 = 2;
  local_2ac = lbl_803E1630;
  local_2a8 = lbl_803E1634;
  local_2a4 = lbl_803E1630;
  local_282 = 1;
  local_284 = 7;
  local_288 = &DAT_80313f6c;
  local_298 = 4;
  local_294 = lbl_803E1638;
  local_290 = lbl_803E1610;
  local_28c = lbl_803E1610;
  local_26a = 1;
  local_26c = 0x15;
  local_270 = &DAT_80313fa8;
  local_280 = 0x4000;
  local_27c = lbl_803E1610;
  local_278 = lbl_803E1618;
  local_274 = lbl_803E1610;
  local_252 = 1;
  local_254 = 0;
  local_258 = 0;
  local_268 = 0x100;
  local_264 = lbl_803E1610;
  local_260 = lbl_803E1610;
  local_25c = lbl_803E163C;
  local_23a = 1;
  local_23c = 0;
  local_240 = 0;
  local_250 = 0x80000;
  local_24c = lbl_803E1610;
  local_248 = lbl_803E162C;
  local_244 = lbl_803E1610;
  local_222 = 1;
  local_224 = 0;
  local_228 = 0;
  local_238 = 0x400000;
  local_234 = lbl_803E1610;
  local_230 = lbl_803E1610;
  local_22c = lbl_803E1610;
  local_20a = 2;
  local_20c = 0x15;
  local_210 = &DAT_80313fa8;
  local_220 = 0x4000;
  local_21c = lbl_803E1610;
  local_218 = lbl_803E1618;
  local_214 = lbl_803E1610;
  local_1f2 = 2;
  local_1f4 = 0;
  local_1f8 = 0;
  local_208 = 0x100;
  local_204 = lbl_803E1610;
  local_200 = lbl_803E1610;
  local_1fc = lbl_803E163C;
  local_1da = 3;
  local_1dc = 0;
  local_1e0 = 0;
  local_1f0 = 0x80000;
  local_1ec = lbl_803E1610;
  local_1e8 = lbl_803E1640;
  local_1e4 = lbl_803E1610;
  local_1c2 = 3;
  local_1c4 = 7;
  local_1c8 = &DAT_80313f6c;
  local_1d8 = 4;
  local_1d4 = lbl_803E1610;
  local_1d0 = lbl_803E1610;
  local_1cc = lbl_803E1610;
  local_1aa = 3;
  local_1ac = 0x15;
  local_1b0 = &DAT_80313fa8;
  local_1c0 = 0x4000;
  local_1bc = lbl_803E1610;
  local_1b8 = lbl_803E1618;
  local_1b4 = lbl_803E1610;
  local_192 = 3;
  local_194 = 0;
  local_198 = 0;
  local_1a8 = 0x100;
  local_1a4 = lbl_803E1610;
  local_1a0 = lbl_803E1610;
  local_19c = lbl_803E163C;
  local_17a = 3;
  local_17c = 0x15;
  local_180 = &DAT_80313fa8;
  local_190 = 2;
  local_18c = lbl_803E1614;
  local_188 = lbl_803E1634;
  local_184 = lbl_803E1614;
  local_162 = 4;
  local_164 = 0;
  local_168 = 0;
  local_178 = 0x20000000;
  local_174 = lbl_803E161C;
  local_170 = lbl_803E1620;
  local_16c = lbl_803E1624;
  local_330 = 0;
  local_35c = lbl_803E1610;
  local_358 = lbl_803E1610;
  local_354 = lbl_803E1610;
  local_368 = lbl_803E1610;
  local_364 = lbl_803E1610;
  local_360 = lbl_803E1610;
  local_350 = lbl_803E1634;
  local_348 = 2;
  local_34c = 7;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x1e;
  local_32b = 0x14;
  local_342 = DAT_80313fd4;
  local_340 = DAT_80313fd6;
  local_33e = DAT_80313fd8;
  local_33c = DAT_80313fda;
  local_33a = DAT_80313fdc;
  local_338 = DAT_80313fde;
  local_336 = DAT_80313fe0;
  local_388 = &local_328;
  local_334 = param_4 | 0xc010080;
  if ((param_4 & 1) != 0) {
    if (local_384 == 0) {
      local_35c = lbl_803E1610 + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E1610 + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E1610 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E1610 + *(float *)(local_384 + 0x18);
      local_358 = lbl_803E1610 + *(float *)(local_384 + 0x1c);
      local_354 = lbl_803E1610 + *(float *)(local_384 + 0x20);
    }
  }
  local_344 = extraout_r4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_80313df8,0x18,&DAT_80313ecc,0x155,0);
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ecf5c
 * EN v1.0 Address: 0x800ECF5C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800EFA50
 * EN v1.1 Size: 636b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ecf5c(int param_1,undefined2 param_2,int param_3,uint param_4)
{
  undefined4 *local_378;
  int local_374;
  float local_358;
  float local_354;
  float local_350;
  float local_34c;
  float local_348;
  float local_344;
  float local_340;
  undefined4 local_33c;
  undefined4 local_338;
  undefined2 local_334;
  undefined2 local_332;
  undefined2 local_330;
  undefined2 local_32e;
  undefined2 local_32c;
  undefined2 local_32a;
  undefined2 local_328;
  undefined2 local_326;
  uint local_324;
  undefined local_320;
  undefined local_31f;
  undefined local_31e;
  undefined local_31d;
  undefined local_31b;
  undefined4 local_318;
  float local_314;
  float local_310;
  float local_30c;
  undefined *local_308;
  undefined2 local_304;
  undefined local_302;
  undefined4 local_300;
  float local_2fc;
  float local_2f8;
  float local_2f4;
  undefined *local_2f0;
  undefined2 local_2ec;
  undefined local_2ea;
  undefined4 local_2e8;
  float local_2e4;
  float local_2e0;
  float local_2dc;
  undefined *local_2d8;
  undefined2 local_2d4;
  undefined local_2d2;
  undefined4 local_2d0;
  float local_2cc;
  float local_2c8;
  float local_2c4;
  undefined *local_2c0;
  undefined2 local_2bc;
  undefined local_2ba;
  undefined4 local_2b8;
  float local_2b4;
  float local_2b0;
  float local_2ac;
  undefined *local_2a8;
  undefined2 local_2a4;
  undefined local_2a2;
  undefined4 local_2a0;
  float local_29c;
  float local_298;
  float local_294;
  undefined *local_290;
  undefined2 local_28c;
  undefined local_28a;
  undefined4 local_288;
  float local_284;
  float local_280;
  float local_27c;
  undefined *local_278;
  undefined2 local_274;
  undefined local_272;
  
  local_302 = 0;
  local_304 = 0x15;
  local_308 = &DAT_803141b8;
  local_318 = 4;
  local_314 = lbl_803E1648;
  local_310 = lbl_803E1648;
  local_30c = lbl_803E1648;
  local_2ea = 0;
  local_2ec = 0x15;
  local_2f0 = &DAT_803141b8;
  local_300 = 2;
  local_2fc = lbl_803E164C;
  local_2f8 = lbl_803E1650;
  local_2f4 = lbl_803E164C;
  local_2d2 = 1;
  local_2d4 = 7;
  local_2d8 = &DAT_8031417c;
  local_2e8 = 4;
  local_2e4 = lbl_803E1654;
  local_2e0 = lbl_803E1648;
  local_2dc = lbl_803E1648;
  local_2ba = 1;
  local_2bc = 0x15;
  local_2c0 = &DAT_803141b8;
  local_2d0 = 0x4000;
  local_2cc = lbl_803E1648;
  local_2c8 = lbl_803E1658;
  local_2c4 = lbl_803E1648;
  local_2a2 = 2;
  local_2a4 = 0x15;
  local_2a8 = &DAT_803141b8;
  local_2b8 = 0x4000;
  local_2b4 = lbl_803E1648;
  local_2b0 = lbl_803E1658;
  local_2ac = lbl_803E1648;
  local_28a = 3;
  local_28c = 7;
  local_290 = &DAT_8031417c;
  local_2a0 = 4;
  local_29c = lbl_803E1648;
  local_298 = lbl_803E1648;
  local_294 = lbl_803E1648;
  local_272 = 3;
  local_274 = 0x15;
  local_278 = &DAT_803141b8;
  local_288 = 0x4000;
  local_284 = lbl_803E1648;
  local_280 = lbl_803E1658;
  local_27c = lbl_803E1648;
  local_320 = 0;
  local_34c = lbl_803E1648;
  local_348 = lbl_803E1648;
  local_344 = lbl_803E1648;
  local_358 = lbl_803E1648;
  local_354 = lbl_803E1648;
  local_350 = lbl_803E1648;
  local_340 = lbl_803E165C;
  local_338 = 2;
  local_33c = 7;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 0x1e;
  local_31b = 7;
  local_332 = DAT_803141e4;
  local_330 = DAT_803141e6;
  local_32e = DAT_803141e8;
  local_32c = DAT_803141ea;
  local_32a = DAT_803141ec;
  local_328 = DAT_803141ee;
  local_326 = DAT_803141f0;
  local_378 = &local_318;
  local_324 = param_4 | 0xc010040;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = lbl_803E1648 + *(float *)(param_3 + 0xc);
      local_348 = lbl_803E1648 + *(float *)(param_3 + 0x10);
      local_344 = lbl_803E1648 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = lbl_803E1648 + *(float *)(param_1 + 0x18);
      local_348 = lbl_803E1648 + *(float *)(param_1 + 0x1c);
      local_344 = lbl_803E1648 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_334 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0x15,&DAT_80314008,0x18,&DAT_803140dc,0xe3,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ecfc0
 * EN v1.0 Address: 0x800ECFC0
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800EFCCC
 * EN v1.1 Size: 788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ecfc0(int param_1,undefined2 param_2,int param_3,uint param_4)
{
  undefined4 *local_378;
  int local_374;
  float local_358;
  float local_354;
  float local_350;
  float local_34c;
  float local_348;
  float local_344;
  float local_340;
  undefined4 local_33c;
  undefined4 local_338;
  undefined2 local_334;
  undefined2 local_332;
  undefined2 local_330;
  undefined2 local_32e;
  undefined2 local_32c;
  undefined2 local_32a;
  undefined2 local_328;
  undefined2 local_326;
  uint local_324;
  undefined local_320;
  undefined local_31f;
  undefined local_31e;
  undefined local_31d;
  undefined local_31b;
  undefined4 local_318;
  float local_314;
  float local_310;
  float local_30c;
  undefined *local_308;
  undefined2 local_304;
  undefined local_302;
  undefined4 local_300;
  float local_2fc;
  float local_2f8;
  float local_2f4;
  undefined *local_2f0;
  undefined2 local_2ec;
  undefined local_2ea;
  undefined4 local_2e8;
  float local_2e4;
  float local_2e0;
  float local_2dc;
  undefined *local_2d8;
  undefined2 local_2d4;
  undefined local_2d2;
  undefined4 local_2d0;
  float local_2cc;
  float local_2c8;
  float local_2c4;
  undefined *local_2c0;
  undefined2 local_2bc;
  undefined local_2ba;
  undefined4 local_2b8;
  float local_2b4;
  float local_2b0;
  float local_2ac;
  undefined *local_2a8;
  undefined2 local_2a4;
  undefined local_2a2;
  undefined4 local_2a0;
  float local_29c;
  float local_298;
  float local_294;
  undefined4 local_290;
  undefined2 local_28c;
  undefined local_28a;
  undefined4 local_288;
  float local_284;
  float local_280;
  float local_27c;
  undefined *local_278;
  undefined2 local_274;
  undefined local_272;
  undefined4 local_270;
  float local_26c;
  float local_268;
  float local_264;
  undefined4 local_260;
  undefined2 local_25c;
  undefined local_25a;
  undefined4 local_258;
  float local_254;
  float local_250;
  float local_24c;
  undefined *local_248;
  undefined2 local_244;
  undefined local_242;
  undefined4 local_240;
  float local_23c;
  float local_238;
  float local_234;
  undefined *local_230;
  undefined2 local_22c;
  undefined local_22a;
  undefined4 local_228;
  float local_224;
  float local_220;
  float local_21c;
  undefined4 local_218;
  undefined2 local_214;
  undefined local_212;
  
  local_302 = 0;
  local_304 = 0x15;
  local_308 = &DAT_803143c8;
  local_318 = 4;
  local_314 = lbl_803E1660;
  local_310 = lbl_803E1660;
  local_30c = lbl_803E1660;
  local_2ea = 0;
  local_2ec = 0x15;
  local_2f0 = &DAT_803143c8;
  local_300 = 2;
  local_2fc = lbl_803E1664;
  local_2f8 = lbl_803E1668;
  local_2f4 = lbl_803E1664;
  local_2d2 = 1;
  local_2d4 = 7;
  local_2d8 = &DAT_8031437c;
  local_2e8 = 2;
  local_2e4 = lbl_803E1668;
  local_2e0 = lbl_803E166C;
  local_2dc = lbl_803E1668;
  local_2ba = 1;
  local_2bc = 7;
  local_2c0 = &DAT_8031438c;
  local_2d0 = 4;
  local_2cc = lbl_803E1670;
  local_2c8 = lbl_803E1660;
  local_2c4 = lbl_803E1660;
  local_2a2 = 1;
  local_2a4 = 0x15;
  local_2a8 = &DAT_803143c8;
  local_2b8 = 0x4000;
  local_2b4 = lbl_803E1660;
  local_2b0 = lbl_803E1674;
  local_2ac = lbl_803E1660;
  local_28a = 1;
  local_28c = 0;
  local_290 = 0;
  local_2a0 = 0x100;
  local_29c = lbl_803E1660;
  local_298 = lbl_803E1660;
  local_294 = lbl_803E1678;
  local_272 = 2;
  local_274 = 0x15;
  local_278 = &DAT_803143c8;
  local_288 = 0x4000;
  local_284 = lbl_803E1660;
  local_280 = lbl_803E1674;
  local_27c = lbl_803E1660;
  local_25a = 2;
  local_25c = 0;
  local_260 = 0;
  local_270 = 0x100;
  local_26c = lbl_803E1660;
  local_268 = lbl_803E1660;
  local_264 = lbl_803E1678;
  local_242 = 3;
  local_244 = 7;
  local_248 = &DAT_8031438c;
  local_258 = 4;
  local_254 = lbl_803E1660;
  local_250 = lbl_803E1660;
  local_24c = lbl_803E1660;
  local_22a = 3;
  local_22c = 0x15;
  local_230 = &DAT_803143c8;
  local_240 = 0x4000;
  local_23c = lbl_803E1660;
  local_238 = lbl_803E1674;
  local_234 = lbl_803E1660;
  local_212 = 3;
  local_214 = 0;
  local_218 = 0;
  local_228 = 0x100;
  local_224 = lbl_803E1660;
  local_220 = lbl_803E1660;
  local_21c = lbl_803E1678;
  local_320 = 0;
  local_34c = lbl_803E1660;
  local_348 = lbl_803E1660;
  local_344 = lbl_803E1660;
  local_358 = lbl_803E1660;
  local_354 = lbl_803E1660;
  local_350 = lbl_803E1660;
  local_340 = lbl_803E166C;
  local_338 = 2;
  local_33c = 7;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 0x1e;
  local_31b = 0xb;
  local_332 = DAT_803143f4;
  local_330 = DAT_803143f6;
  local_32e = DAT_803143f8;
  local_32c = DAT_803143fa;
  local_32a = DAT_803143fc;
  local_328 = DAT_803143fe;
  local_326 = DAT_80314400;
  local_378 = &local_318;
  local_324 = param_4 | 0xc0100c0;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = lbl_803E1660 + *(float *)(param_3 + 0xc);
      local_348 = lbl_803E1660 + *(float *)(param_3 + 0x10);
      local_344 = lbl_803E1660 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = lbl_803E1660 + *(float *)(param_1 + 0x18);
      local_348 = lbl_803E1660 + *(float *)(param_1 + 0x1c);
      local_344 = lbl_803E1660 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_334 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0x15,&DAT_80314218,0x18,&DAT_803142ec,0x41,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed024
 * EN v1.0 Address: 0x800ED024
 * EN v1.0 Size: 516b
 * EN v1.1 Address: 0x800EFFE0
 * EN v1.1 Size: 1256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed024(short *param_1,int param_2,int param_3,uint param_4,undefined4 param_5,
                 uint *param_6)
{
  int iVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  undefined4 *local_388;
  short *local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  char local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined4 local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined4 local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined4 local_2a0;
  undefined2 local_29c;
  undefined local_29a [2];
  undefined4 local_298 [5];
  undefined local_282 [602];
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  uStack_1c = 0x30;
  uStack_24 = 0x31;
  uStack_14 = 1;
  local_2b4 = 0x50;
  if (param_6 != (uint *)0x0) {
    uStack_14 = *param_6;
    uStack_1c = param_6[1];
    uStack_24 = param_6[2];
    local_2b4 = (undefined2)param_6[3];
  }
  local_312 = 0;
  local_314 = 8;
  local_318 = &DAT_803144b0;
  local_328 = 4;
  local_324 = lbl_803E1680;
  local_320 = lbl_803E1680;
  local_31c = lbl_803E1680;
  local_2fa = 0;
  local_2fc = 8;
  local_300 = &DAT_803144b0;
  local_310 = 2;
  if (param_1 == (short *)0x0) {
    local_308 = lbl_803E1688;
    local_304 = lbl_803E1684;
  }
  else {
    local_304 = lbl_803E1684 * *(float *)(param_1 + 4);
    local_308 = lbl_803E1688 * *(float *)(param_1 + 4);
  }
  local_2e2 = 0;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2f8 = 0x80;
  local_2f4 = lbl_803E1680;
  local_2f0 = lbl_803E1680;
  if (param_1 == (short *)0x0) {
    local_2ec = lbl_803E1680;
  }
  else {
    local_2ec = (float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) - DOUBLE_803e16a0);
  }
  local_2ca = 1;
  local_2cc = 8;
  local_2d0 = &DAT_803144b0;
  local_2e0 = 4;
  local_2dc = lbl_803E168C;
  local_2d8 = lbl_803E1680;
  local_2d4 = lbl_803E1680;
  local_2b2 = 1;
  local_2b8 = 0;
  local_2c8 = 0x20000000;
  local_2c4 = (float)((double)CONCAT44(0x43300000,uStack_14 ^ 0x80000000) - DOUBLE_803e16a0);
  local_2c0 = (float)((double)CONCAT44(0x43300000,uStack_1c ^ 0x80000000) - DOUBLE_803e16a0);
  local_2bc = (float)((double)CONCAT44(0x43300000,uStack_24 ^ 0x80000000) - DOUBLE_803e16a0);
  puVar2 = &local_2b0;
  if (param_2 == 0) {
    local_29a[0] = 2;
    local_29c = 0x3b;
    local_2a0 = 0;
    local_2b0 = 0x1800000;
    local_2ac = lbl_803E1690;
    local_2a8 = lbl_803E1680;
    local_2a4 = lbl_803E1694;
    puVar2 = (undefined4 *)(local_29a + 2);
  }
  *(undefined *)((int)puVar2 + 0x16) = 2;
  *(undefined2 *)(puVar2 + 5) = 0;
  puVar2[4] = 0;
  *puVar2 = 0x100;
  puVar2[1] = lbl_803E1680;
  puVar2[2] = lbl_803E1680;
  puVar2[3] = lbl_803E1698;
  *(undefined *)((int)puVar2 + 0x2e) = 3;
  *(undefined2 *)(puVar2 + 0xb) = 1;
  puVar2[10] = 0;
  puVar2[6] = 0x2000;
  puVar2[7] = lbl_803E1680;
  puVar2[8] = lbl_803E1680;
  puVar2[9] = lbl_803E1680;
  *(undefined *)((int)puVar2 + 0x46) = 4;
  *(undefined2 *)(puVar2 + 0x11) = 8;
  puVar2[0x10] = (undefined4)&DAT_803144b0;
  puVar2[0xc] = 4;
  puVar2[0xd] = lbl_803E1680;
  puVar2[0xe] = lbl_803E1680;
  puVar2[0xf] = lbl_803E1680;
  *(undefined *)((int)puVar2 + 0x5e) = 4;
  *(undefined2 *)(puVar2 + 0x17) = 0;
  puVar2[0x16] = 0;
  puVar2[0x12] = 0x20000000;
  uStack_14 = uStack_14 ^ 0x80000000;
  local_18 = 0x43300000;
  puVar2[0x13] = (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e16a0);
  uStack_1c = uStack_1c ^ 0x80000000;
  local_20 = 0x43300000;
  puVar2[0x14] = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e16a0);
  uStack_24 = uStack_24 ^ 0x80000000;
  local_28 = 0x43300000;
  puVar2[0x15] = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e16a0);
  local_330 = (undefined)param_2;
  local_344 = (undefined2)param_2;
  local_35c = lbl_803E1680;
  if (param_3 == 0) {
    local_358 = lbl_803E1680;
  }
  else {
    local_358 = *(float *)(param_3 + 0x10);
  }
  local_354 = lbl_803E1680;
  local_368 = lbl_803E1680;
  local_364 = lbl_803E1680;
  local_360 = lbl_803E1680;
  local_350 = lbl_803E1690;
  local_348 = 1;
  local_34c = 0;
  local_32f = 8;
  local_32e = 0;
  local_32d = 0x1e;
  iVar1 = (int)puVar2 + (0x60 - (int)&local_328);
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_803144c0;
  local_340 = DAT_803144c2;
  local_33e = DAT_803144c4;
  local_33c = DAT_803144c6;
  local_33a = DAT_803144c8;
  local_338 = DAT_803144ca;
  local_336 = DAT_803144cc;
  local_388 = &local_328;
  if (param_2 == 2) {
    local_334 = (param_4 | 0x4000080) ^ 0x40000;
  }
  else {
    local_334 = param_4 | 0x4040080;
  }
  if ((local_334 & 1) != 0) {
    if (param_1 == (short *)0x0) {
      local_35c = lbl_803E1680 + *(float *)(param_3 + 0xc);
      local_358 = local_358 + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E1680 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E1680 + *(float *)(param_1 + 0xc);
      local_358 = local_358 + *(float *)(param_1 + 0xe);
      local_354 = lbl_803E1680 + *(float *)(param_1 + 0x10);
    }
  }
  if (param_2 == 2) {
    uVar3 = 0xc11;
  }
  else {
    uVar3 = 0x5e0;
  }
  local_384 = param_1;
  local_30c = local_304;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,8,&DAT_80314448,4,&DAT_80314498,uVar3,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed228
 * EN v1.0 Address: 0x800ED228
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800F04C8
 * EN v1.1 Size: 864b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed228(int param_1,int param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined4 *local_388;
  int local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  char local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined *local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined4 local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined *local_270;
  undefined2 local_26c;
  undefined local_26a;
  undefined4 local_268;
  float local_264;
  float local_260;
  float local_25c;
  undefined *local_258;
  undefined2 local_254;
  undefined local_252;
  undefined4 local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined4 local_240;
  undefined2 local_23c;
  undefined local_23a;
  undefined auStack_238 [528];
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  local_388 = &local_328;
  local_312 = 0;
  local_314 = 0x12;
  local_318 = &DAT_80314618;
  local_328 = 4;
  local_324 = lbl_803E16A8;
  local_320 = lbl_803E16A8;
  local_31c = lbl_803E16A8;
  local_2fa = 0;
  local_2fc = 0x12;
  local_300 = &DAT_80314618;
  local_310 = 2;
  local_30c = lbl_803E16AC;
  local_308 = lbl_803E16B0;
  local_304 = lbl_803E16AC;
  local_2e2 = 0;
  local_2e4 = 9;
  local_2e8 = &DAT_80314604;
  local_2f8 = 8;
  iVar1 = param_2 * 3;
  uStack_24 = (uint)(byte)(&DAT_80314660)[iVar1];
  local_28 = 0x43300000;
  local_2f4 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e16d0);
  uStack_1c = (uint)(byte)(&DAT_80314661)[iVar1];
  local_20 = 0x43300000;
  local_2f0 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e16d0);
  uStack_14 = (uint)(byte)(&DAT_80314662)[iVar1];
  local_18 = 0x43300000;
  local_2ec = (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e16d0);
  local_2ca = 1;
  local_2cc = 0x12;
  local_2d0 = &DAT_80314618;
  local_2e0 = 4;
  local_2dc = lbl_803E16B4;
  local_2d8 = lbl_803E16A8;
  local_2d4 = lbl_803E16A8;
  local_2b2 = 1;
  local_2b4 = 0x12;
  local_2b8 = &DAT_80314618;
  local_2c8 = 2;
  local_2c4 = lbl_803E16B8;
  local_2c0 = lbl_803E16BC;
  local_2bc = lbl_803E16B8;
  local_29a = 3;
  local_29c = 0x12;
  local_2a0 = &DAT_80314618;
  local_2b0 = 0x100;
  local_2ac = lbl_803E16A8;
  local_2a8 = lbl_803E16A8;
  local_2a4 = lbl_803E16C0;
  local_282 = 4;
  local_284 = 2;
  local_288 = 0;
  local_298 = 0x2000;
  local_294 = lbl_803E16A8;
  local_290 = lbl_803E16A8;
  local_28c = lbl_803E16A8;
  local_26a = 5;
  local_26c = 0x12;
  local_270 = &DAT_80314618;
  local_280 = 4;
  local_27c = lbl_803E16A8;
  local_278 = lbl_803E16A8;
  local_274 = lbl_803E16A8;
  local_252 = 5;
  local_254 = 0x12;
  local_258 = &DAT_80314618;
  local_268 = 2;
  local_264 = lbl_803E16C4;
  local_260 = lbl_803E16C8;
  local_25c = lbl_803E16C4;
  local_23a = 5;
  local_23c = 0x7a;
  local_240 = 0;
  local_250 = 0x10000;
  local_24c = lbl_803E16A8;
  local_248 = lbl_803E16A8;
  local_244 = lbl_803E16A8;
  local_330 = 0;
  local_344 = (undefined2)param_2;
  local_35c = lbl_803E16A8;
  local_358 = lbl_803E16A8;
  local_354 = lbl_803E16A8;
  local_368 = lbl_803E16A8;
  local_364 = lbl_803E16A8;
  local_360 = lbl_803E16A8;
  local_350 = lbl_803E16CC;
  local_348 = 1;
  local_34c = 0;
  local_32f = 0x12;
  local_32e = 0;
  local_32d = 0x10;
  iVar1 = (int)(auStack_238 + -(int)local_388) / 0x18 +
          ((int)(auStack_238 + -(int)local_388) >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_80314650;
  local_340 = DAT_80314652;
  local_33e = DAT_80314654;
  local_33c = DAT_80314656;
  local_33a = DAT_80314658;
  local_338 = DAT_8031465a;
  local_336 = DAT_8031465c;
  local_334 = param_4 | 0x5000004;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_35c = lbl_803E16A8 + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E16A8 + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E16A8 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E16A8 + *(float *)(param_1 + 0x18);
      local_358 = lbl_803E16A8 + *(float *)(param_1 + 0x1c);
      local_354 = lbl_803E16A8 + *(float *)(param_1 + 0x20);
    }
  }
  local_384 = param_1;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x12,&DAT_803144f0,0x10,&DAT_803145a4,0x3e,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed28c
 * EN v1.0 Address: 0x800ED28C
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800F0828
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed28c(int param_1,undefined2 param_2,int param_3,uint param_4)
{
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  uint local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  undefined local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined *local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined4 local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined *local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined *local_280;
  undefined2 local_27c;
  undefined local_27a;
  
  local_2f2 = 0;
  local_2f4 = 5;
  local_2f8 = &DAT_803146e4;
  local_308 = 4;
  local_304 = lbl_803E16D8;
  local_300 = lbl_803E16DC;
  local_2fc = lbl_803E16DC;
  local_2da = 0;
  local_2dc = 5;
  local_2e0 = &DAT_803146e4;
  local_2f0 = 2;
  local_2ec = lbl_803E16E0;
  local_2e8 = lbl_803E16E0;
  local_2e4 = lbl_803E16E0;
  local_2c2 = 0;
  local_2c4 = 5;
  local_2c8 = &DAT_803146e4;
  local_2d8 = 8;
  local_2d4 = lbl_803E16E4;
  local_2d0 = lbl_803E16E4;
  local_2cc = lbl_803E16E4;
  local_2aa = 0;
  local_2ac = 0x7a;
  local_2b0 = 0;
  local_2c0 = 0x10000;
  local_2bc = lbl_803E16DC;
  local_2b8 = lbl_803E16DC;
  local_2b4 = lbl_803E16DC;
  local_292 = 1;
  local_294 = 5;
  local_298 = &DAT_803146e4;
  local_2a8 = 4;
  local_2a4 = lbl_803E16DC;
  local_2a0 = lbl_803E16DC;
  local_29c = lbl_803E16DC;
  local_27a = 1;
  local_27c = 5;
  local_280 = &DAT_803146e4;
  local_290 = 2;
  local_28c = lbl_803E16E8;
  local_288 = lbl_803E16EC;
  local_284 = lbl_803E16E8;
  local_310 = 0;
  local_33c = lbl_803E16DC;
  local_338 = lbl_803E16F0;
  local_334 = lbl_803E16DC;
  local_348 = lbl_803E16DC;
  local_344 = lbl_803E16DC;
  local_340 = lbl_803E16DC;
  local_330 = lbl_803E16EC;
  local_328 = 1;
  local_32c = 0;
  local_30f = 5;
  local_30e = 0;
  local_30d = 0x10;
  local_30b = 6;
  local_322 = DAT_803146f0;
  local_320 = DAT_803146f2;
  local_31e = DAT_803146f4;
  local_31c = DAT_803146f6;
  local_31a = DAT_803146f8;
  local_318 = DAT_803146fa;
  local_316 = DAT_803146fc;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000010;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = lbl_803E16DC + *(float *)(param_3 + 0xc);
      local_338 = lbl_803E16F0 + *(float *)(param_3 + 0x10);
      local_334 = lbl_803E16DC + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = lbl_803E16DC + *(float *)(param_1 + 0x18);
      local_338 = lbl_803E16F0 + *(float *)(param_1 + 0x1c);
      local_334 = lbl_803E16DC + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  local_324 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,5,&DAT_80314690,4,&DAT_803146c4,0x5e,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed2f0
 * EN v1.0 Address: 0x800ED2F0
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800F0A88
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed2f0(int param_1,undefined2 param_2,int param_3,uint param_4)
{
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  uint local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  undefined local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined *local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined *local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined *local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined *local_280;
  undefined2 local_27c;
  undefined local_27a;
  
  local_2f2 = 0;
  local_2f4 = 0xe;
  local_2f8 = &DAT_80314814;
  local_308 = 0x80;
  local_304 = lbl_803E16F8;
  local_300 = lbl_803E16FC;
  local_2fc = lbl_803E16F8;
  local_2da = 0;
  local_2dc = 7;
  local_2e0 = &DAT_80314840;
  local_2f0 = 4;
  local_2ec = lbl_803E16F8;
  local_2e8 = lbl_803E16F8;
  local_2e4 = lbl_803E16F8;
  local_2c2 = 0;
  local_2c4 = 7;
  local_2c8 = &DAT_80314830;
  local_2d8 = 2;
  local_2d4 = lbl_803E1700;
  local_2d0 = lbl_803E1704;
  local_2cc = lbl_803E1700;
  local_2aa = 0;
  local_2ac = 7;
  local_2b0 = &DAT_80314840;
  local_2c0 = 2;
  local_2bc = lbl_803E1708;
  local_2b8 = lbl_803E1704;
  local_2b4 = lbl_803E1708;
  local_292 = 1;
  local_294 = 0xe;
  local_298 = &DAT_80314814;
  local_2a8 = 0x4000;
  local_2a4 = lbl_803E16F8;
  local_2a0 = lbl_803E170C;
  local_29c = lbl_803E16F8;
  local_27a = 1;
  local_27c = 7;
  local_280 = &DAT_80314830;
  local_290 = 4;
  local_28c = lbl_803E16F8;
  local_288 = lbl_803E16F8;
  local_284 = lbl_803E16F8;
  local_310 = 0;
  local_33c = lbl_803E16F8;
  local_338 = lbl_803E16F8;
  local_334 = lbl_803E16F8;
  local_348 = lbl_803E16F8;
  local_344 = lbl_803E16F8;
  local_340 = lbl_803E16F8;
  local_330 = lbl_803E1710;
  local_328 = 1;
  local_32c = 0;
  local_30f = 0xe;
  local_30e = 0;
  local_30d = 0x10;
  local_30b = 6;
  local_322 = DAT_80314850;
  local_320 = DAT_80314852;
  local_31e = DAT_80314854;
  local_31c = DAT_80314856;
  local_31a = DAT_80314858;
  local_318 = DAT_8031485a;
  local_316 = DAT_8031485c;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000004;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = lbl_803E16F8 + *(float *)(param_3 + 0xc);
      local_338 = lbl_803E16F8 + *(float *)(param_3 + 0x10);
      local_334 = lbl_803E16F8 + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = lbl_803E16F8 + *(float *)(param_1 + 0x18);
      local_338 = lbl_803E16F8 + *(float *)(param_1 + 0x1c);
      local_334 = lbl_803E16F8 + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  local_324 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0xe,&DAT_80314740,0xc,&DAT_803147cc,0x34,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed354
 * EN v1.0 Address: 0x800ED354
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800F0CE8
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed354(int param_1,undefined2 param_2,int param_3,uint param_4)
{
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  uint local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  undefined local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined *local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined4 local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined *local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined *local_280;
  undefined2 local_27c;
  undefined local_27a;
  
  local_2f2 = 0;
  local_2f4 = 5;
  local_2f8 = &DAT_803148d4;
  local_308 = 4;
  local_304 = lbl_803E1718;
  local_300 = lbl_803E171C;
  local_2fc = lbl_803E171C;
  local_2da = 0;
  local_2dc = 5;
  local_2e0 = &DAT_803148d4;
  local_2f0 = 2;
  local_2ec = lbl_803E1720;
  local_2e8 = lbl_803E1720;
  local_2e4 = lbl_803E1720;
  local_2c2 = 0;
  local_2c4 = 5;
  local_2c8 = &DAT_803148d4;
  local_2d8 = 8;
  local_2d4 = lbl_803E171C;
  local_2d0 = lbl_803E1724;
  local_2cc = lbl_803E171C;
  local_2aa = 0;
  local_2ac = 0x7a;
  local_2b0 = 0;
  local_2c0 = 0x10000;
  local_2bc = lbl_803E171C;
  local_2b8 = lbl_803E171C;
  local_2b4 = lbl_803E171C;
  local_292 = 1;
  local_294 = 5;
  local_298 = &DAT_803148d4;
  local_2a8 = 4;
  local_2a4 = lbl_803E171C;
  local_2a0 = lbl_803E171C;
  local_29c = lbl_803E171C;
  local_27a = 1;
  local_27c = 5;
  local_280 = &DAT_803148d4;
  local_290 = 2;
  local_28c = lbl_803E1728;
  local_288 = lbl_803E172C;
  local_284 = lbl_803E1728;
  local_310 = 0;
  local_33c = lbl_803E171C;
  local_338 = lbl_803E1730;
  local_334 = lbl_803E171C;
  local_348 = lbl_803E171C;
  local_344 = lbl_803E171C;
  local_340 = lbl_803E171C;
  local_330 = lbl_803E172C;
  local_328 = 1;
  local_32c = 0;
  local_30f = 5;
  local_30e = 0;
  local_30d = 0x10;
  local_30b = 6;
  local_322 = DAT_803148e0;
  local_320 = DAT_803148e2;
  local_31e = DAT_803148e4;
  local_31c = DAT_803148e6;
  local_31a = DAT_803148e8;
  local_318 = DAT_803148ea;
  local_316 = DAT_803148ec;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000010;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = lbl_803E171C + *(float *)(param_3 + 0xc);
      local_338 = lbl_803E1730 + *(float *)(param_3 + 0x10);
      local_334 = lbl_803E171C + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = lbl_803E171C + *(float *)(param_1 + 0x18);
      local_338 = lbl_803E1730 + *(float *)(param_1 + 0x1c);
      local_334 = lbl_803E171C + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  local_324 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,5,&DAT_80314880,4,&DAT_803148b4,0x5e,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed3b8
 * EN v1.0 Address: 0x800ED3B8
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800F0F38
 * EN v1.1 Size: 1352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed3b8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  undefined2 extraout_r4;
  undefined4 *local_398;
  int local_394;
  float local_378;
  float local_374;
  float local_370;
  float local_36c;
  float local_368;
  float local_364;
  float local_360;
  undefined4 local_35c;
  undefined4 local_358;
  undefined2 local_354;
  undefined2 local_352;
  undefined2 local_350;
  undefined2 local_34e;
  undefined2 local_34c;
  undefined2 local_34a;
  undefined2 local_348;
  undefined2 local_346;
  uint local_344;
  undefined local_340;
  undefined local_33f;
  undefined local_33e;
  undefined local_33d;
  undefined local_33b;
  undefined4 local_338;
  float local_334;
  float local_330;
  float local_32c;
  undefined *local_328;
  undefined2 local_324;
  undefined local_322;
  undefined4 local_320;
  float local_31c;
  float local_318;
  float local_314;
  undefined *local_310;
  undefined2 local_30c;
  undefined local_30a;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined *local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined *local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined4 local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined4 local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined4 local_278;
  float local_274;
  float local_270;
  float local_26c;
  undefined4 local_268;
  undefined2 local_264;
  undefined local_262;
  undefined4 local_260;
  float local_25c;
  float local_258;
  float local_254;
  undefined4 local_250;
  undefined2 local_24c;
  undefined local_24a;
  undefined4 local_248;
  float local_244;
  float local_240;
  float local_23c;
  undefined4 local_238;
  undefined2 local_234;
  undefined local_232;
  undefined4 local_230;
  float local_22c;
  float local_228;
  float local_224;
  undefined4 local_220;
  undefined2 local_21c;
  undefined local_21a;
  undefined4 local_218;
  float local_214;
  float local_210;
  float local_20c;
  undefined *local_208;
  undefined2 local_204;
  undefined local_202;
  undefined4 local_200;
  float local_1fc;
  float local_1f8;
  float local_1f4;
  undefined *local_1f0;
  undefined2 local_1ec;
  undefined local_1ea;
  undefined4 local_1e8;
  float local_1e4;
  float local_1e0;
  float local_1dc;
  undefined *local_1d8;
  undefined2 local_1d4;
  undefined local_1d2;
  undefined4 local_1d0;
  float local_1cc;
  float local_1c8;
  float local_1c4;
  undefined4 local_1c0;
  undefined2 local_1bc;
  undefined local_1ba;
  undefined4 local_1b8;
  float local_1b4;
  float local_1b0;
  float local_1ac;
  undefined4 local_1a8;
  undefined2 local_1a4;
  undefined local_1a2;
  undefined4 local_1a0;
  float local_19c;
  float local_198;
  float local_194;
  undefined *local_190;
  undefined2 local_18c;
  undefined local_18a;
  undefined4 local_188;
  float local_184;
  float local_180;
  float local_17c;
  undefined *local_178;
  undefined2 local_174;
  undefined local_172;
  undefined4 local_170;
  float local_16c;
  float local_168;
  float local_164;
  undefined *local_160;
  undefined2 local_15c;
  undefined local_15a;
  undefined4 local_158;
  float local_154;
  float local_150;
  float local_14c;
  undefined4 local_148;
  undefined2 local_144;
  undefined local_142;
  undefined4 local_140;
  float local_13c;
  float local_138;
  float local_134;
  undefined4 local_130;
  undefined2 local_12c;
  undefined local_12a;
  undefined4 local_128;
  float local_124;
  float local_120;
  float local_11c;
  undefined *local_118;
  undefined2 local_114;
  undefined local_112;
  undefined4 local_110;
  float local_10c;
  float local_108;
  float local_104;
  undefined *local_100;
  undefined2 local_fc;
  undefined local_fa;
  undefined4 local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  undefined *local_e8;
  undefined2 local_e4;
  undefined local_e2;
  undefined4 local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  undefined4 local_d0;
  undefined2 local_cc;
  undefined local_ca;
  undefined4 local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  undefined *local_b8;
  undefined2 local_b4;
  undefined local_b2;
  undefined4 local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  undefined *local_a0;
  undefined2 local_9c;
  undefined local_9a;
  undefined4 local_98;
  float local_94;
  float local_90;
  float local_8c;
  undefined4 local_88;
  undefined2 local_84;
  undefined local_82;
  undefined4 local_80;
  float local_7c;
  float local_78;
  float local_74;
  undefined4 local_70;
  undefined2 local_6c;
  undefined local_6a;
  
  local_394 = FUN_80286824();
  local_322 = 0;
  local_324 = 0x18;
  local_328 = &DAT_80314a60;
  local_338 = 2;
  local_334 = lbl_803E1738;
  local_330 = lbl_803E173C;
  local_32c = lbl_803E1738;
  local_30a = 0;
  local_30c = 0x18;
  local_310 = &DAT_80314a60;
  local_320 = 4;
  local_31c = lbl_803E1740;
  local_318 = lbl_803E1740;
  local_314 = lbl_803E1740;
  local_2f2 = 0;
  local_2f4 = 0x18;
  local_2f8 = &DAT_80314a60;
  local_308 = 8;
  local_304 = lbl_803E1744;
  local_300 = lbl_803E1744;
  local_2fc = lbl_803E1740;
  local_2da = 0;
  local_2dc = 0x18;
  local_2e0 = &DAT_80314a60;
  local_2f0 = 8;
  local_2ec = lbl_803E1744;
  local_2e8 = lbl_803E1744;
  local_2e4 = lbl_803E1740;
  local_2c2 = 0;
  local_2c4 = 8;
  local_2c8 = &DAT_80314a90;
  local_2d8 = 8;
  local_2d4 = lbl_803E1744;
  local_2d0 = lbl_803E1748;
  local_2cc = lbl_803E1740;
  local_2aa = 0;
  local_2ac = 0xc;
  local_2b0 = &DAT_80314aa0;
  local_2c0 = 8;
  local_2bc = lbl_803E174C;
  local_2b8 = lbl_803E1740;
  local_2b4 = lbl_803E1740;
  local_292 = 0;
  local_294 = 0x7a;
  local_298 = 0;
  local_2a8 = 0x10000;
  local_2a4 = lbl_803E1740;
  local_2a0 = lbl_803E1740;
  local_29c = lbl_803E1740;
  local_27a = 0;
  local_27c = 0x14;
  local_280 = 0;
  local_290 = 0x800000;
  local_28c = lbl_803E1750;
  local_288 = lbl_803E1740;
  local_284 = lbl_803E1740;
  local_262 = 0;
  local_264 = 0x11;
  local_268 = 0;
  local_278 = 0x800000;
  local_274 = lbl_803E1754;
  local_270 = lbl_803E1740;
  local_26c = lbl_803E1740;
  local_24a = 0;
  local_24c = 1;
  local_250 = 0;
  local_260 = 0x2008000;
  local_25c = lbl_803E1744;
  local_258 = lbl_803E1748;
  local_254 = lbl_803E1740;
  local_232 = 0;
  local_234 = 0;
  local_238 = 0;
  local_248 = 0x80000;
  local_244 = lbl_803E1740;
  local_240 = lbl_803E1758;
  local_23c = lbl_803E1740;
  local_21a = 0;
  local_21c = 0;
  local_220 = 0;
  local_230 = 0x100;
  local_22c = lbl_803E1740;
  local_228 = lbl_803E1740;
  local_224 = lbl_803E175C;
  local_202 = 1;
  local_204 = 4;
  local_208 = &DAT_803dc528;
  local_218 = 4;
  local_214 = lbl_803E1760;
  local_210 = lbl_803E1740;
  local_20c = lbl_803E1740;
  local_1ea = 1;
  local_1ec = 8;
  local_1f0 = &DAT_80314a90;
  local_200 = 4;
  local_1fc = lbl_803E1764;
  local_1f8 = lbl_803E1740;
  local_1f4 = lbl_803E1740;
  local_1d2 = 1;
  local_1d4 = 0x18;
  local_1d8 = &DAT_80314a60;
  local_1e8 = 0x4000;
  local_1e4 = lbl_803E1740;
  local_1e0 = lbl_803E1768;
  local_1dc = lbl_803E1740;
  local_1ba = 1;
  local_1bc = 0x7a;
  local_1c0 = 0;
  local_1d0 = 0x10000;
  local_1cc = lbl_803E1750;
  local_1c8 = lbl_803E1740;
  local_1c4 = lbl_803E1740;
  local_1a2 = 1;
  local_1a4 = 0;
  local_1a8 = 0;
  local_1b8 = 0x100;
  local_1b4 = lbl_803E1740;
  local_1b0 = lbl_803E1740;
  local_1ac = lbl_803E175C;
  local_18a = 2;
  local_18c = 4;
  local_190 = &DAT_803dc528;
  local_1a0 = 4;
  local_19c = lbl_803E1740;
  local_198 = lbl_803E1740;
  local_194 = lbl_803E1740;
  local_172 = 2;
  local_174 = 8;
  local_178 = &DAT_80314a90;
  local_188 = 4;
  local_184 = lbl_803E1748;
  local_180 = lbl_803E1740;
  local_17c = lbl_803E1740;
  local_15a = 2;
  local_15c = 0x18;
  local_160 = &DAT_80314a60;
  local_170 = 0x4000;
  local_16c = lbl_803E1740;
  local_168 = lbl_803E1768;
  local_164 = lbl_803E1740;
  local_142 = 2;
  local_144 = 0;
  local_148 = 0;
  local_158 = 0x80000;
  local_154 = lbl_803E1740;
  local_150 = lbl_803E176C;
  local_14c = lbl_803E1740;
  local_12a = 2;
  local_12c = 0;
  local_130 = 0;
  local_140 = 0x100;
  local_13c = lbl_803E1740;
  local_138 = lbl_803E1740;
  local_134 = lbl_803E175C;
  local_112 = 3;
  local_114 = 8;
  local_118 = &DAT_80314a90;
  local_128 = 4;
  local_124 = lbl_803E1740;
  local_120 = lbl_803E1740;
  local_11c = lbl_803E1740;
  local_fa = 3;
  local_fc = 0xc;
  local_100 = &DAT_80314aa0;
  local_110 = 4;
  local_10c = lbl_803E1770;
  local_108 = lbl_803E1740;
  local_104 = lbl_803E1740;
  local_e2 = 3;
  local_e4 = 0x18;
  local_e8 = &DAT_80314a60;
  local_f8 = 0x4000;
  local_f4 = lbl_803E1740;
  local_f0 = lbl_803E1768;
  local_ec = lbl_803E1740;
  local_ca = 3;
  local_cc = 0;
  local_d0 = 0;
  local_e0 = 0x100;
  local_dc = lbl_803E1740;
  local_d8 = lbl_803E1740;
  local_d4 = lbl_803E175C;
  local_b2 = 4;
  local_b4 = 0xc;
  local_b8 = &DAT_80314aa0;
  local_c8 = 4;
  local_c4 = lbl_803E1740;
  local_c0 = lbl_803E1740;
  local_bc = lbl_803E1740;
  local_9a = 4;
  local_9c = 0x18;
  local_a0 = &DAT_80314a60;
  local_b0 = 0x4000;
  local_ac = lbl_803E1740;
  local_a8 = lbl_803E1768;
  local_a4 = lbl_803E1740;
  local_82 = 4;
  local_84 = 0;
  local_88 = 0;
  local_98 = 0x2008000;
  local_94 = lbl_803E1744;
  local_90 = lbl_803E1748;
  local_8c = lbl_803E1740;
  local_6a = 4;
  local_6c = 0;
  local_70 = 0;
  local_80 = 0x100;
  local_7c = lbl_803E1740;
  local_78 = lbl_803E1740;
  local_74 = lbl_803E175C;
  local_340 = 0;
  local_36c = lbl_803E1740;
  local_368 = lbl_803E1740;
  local_364 = lbl_803E1740;
  local_378 = lbl_803E1740;
  local_374 = lbl_803E1740;
  local_370 = lbl_803E1740;
  local_360 = lbl_803E1750;
  local_358 = 1;
  local_35c = 0;
  local_33f = 0x18;
  local_33e = 0;
  local_33d = 0x10;
  local_33b = 0x14;
  local_352 = DAT_80314ab8;
  local_350 = DAT_80314aba;
  local_34e = DAT_80314abc;
  local_34c = DAT_80314abe;
  local_34a = DAT_80314ac0;
  local_348 = DAT_80314ac2;
  local_346 = DAT_80314ac4;
  local_398 = &local_338;
  local_344 = param_4 | 0x4000084;
  if ((param_4 & 1) != 0) {
    if (local_394 == 0) {
      local_36c = lbl_803E1740 + *(float *)(param_3 + 0xc);
      local_368 = lbl_803E1740 + *(float *)(param_3 + 0x10);
      local_364 = lbl_803E1740 + *(float *)(param_3 + 0x14);
    }
    else {
      local_36c = lbl_803E1740 + *(float *)(local_394 + 0x18);
      local_368 = lbl_803E1740 + *(float *)(local_394 + 0x1c);
      local_364 = lbl_803E1740 + *(float *)(local_394 + 0x20);
    }
  }
  local_354 = extraout_r4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_398,0,0x18,&DAT_80314910,0x10,&DAT_80314a00,0x48,0);
  FUN_80286870();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed424
 * EN v1.0 Address: 0x800ED424
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800F1480
 * EN v1.1 Size: 1280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed424(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  undefined2 extraout_r4;
  undefined4 *local_398;
  int local_394;
  float local_378;
  float local_374;
  float local_370;
  float local_36c;
  float local_368;
  float local_364;
  float local_360;
  undefined4 local_35c;
  undefined4 local_358;
  undefined2 local_354;
  undefined2 local_352;
  undefined2 local_350;
  undefined2 local_34e;
  undefined2 local_34c;
  undefined2 local_34a;
  undefined2 local_348;
  undefined2 local_346;
  uint local_344;
  undefined local_340;
  undefined local_33f;
  undefined local_33e;
  undefined local_33d;
  undefined local_33b;
  undefined4 local_338;
  float local_334;
  float local_330;
  float local_32c;
  undefined *local_328;
  undefined2 local_324;
  undefined local_322;
  undefined4 local_320;
  float local_31c;
  float local_318;
  float local_314;
  undefined *local_310;
  undefined2 local_30c;
  undefined local_30a;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined *local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined4 local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined4 local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined *local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined4 local_278;
  float local_274;
  float local_270;
  float local_26c;
  undefined *local_268;
  undefined2 local_264;
  undefined local_262;
  undefined4 local_260;
  float local_25c;
  float local_258;
  float local_254;
  undefined4 local_250;
  undefined2 local_24c;
  undefined local_24a;
  undefined4 local_248;
  float local_244;
  float local_240;
  float local_23c;
  undefined4 local_238;
  undefined2 local_234;
  undefined local_232;
  undefined4 local_230;
  float local_22c;
  float local_228;
  float local_224;
  undefined4 local_220;
  undefined2 local_21c;
  undefined local_21a;
  undefined4 local_218;
  float local_214;
  float local_210;
  float local_20c;
  undefined *local_208;
  undefined2 local_204;
  undefined local_202;
  undefined4 local_200;
  float local_1fc;
  float local_1f8;
  float local_1f4;
  undefined *local_1f0;
  undefined2 local_1ec;
  undefined local_1ea;
  undefined4 local_1e8;
  float local_1e4;
  float local_1e0;
  float local_1dc;
  undefined *local_1d8;
  undefined2 local_1d4;
  undefined local_1d2;
  undefined4 local_1d0;
  float local_1cc;
  float local_1c8;
  float local_1c4;
  undefined *local_1c0;
  undefined2 local_1bc;
  undefined local_1ba;
  undefined4 local_1b8;
  float local_1b4;
  float local_1b0;
  float local_1ac;
  undefined4 local_1a8;
  undefined2 local_1a4;
  undefined local_1a2;
  undefined4 local_1a0;
  float local_19c;
  float local_198;
  float local_194;
  undefined *local_190;
  undefined2 local_18c;
  undefined local_18a;
  undefined4 local_188;
  float local_184;
  float local_180;
  float local_17c;
  undefined *local_178;
  undefined2 local_174;
  undefined local_172;
  undefined4 local_170;
  float local_16c;
  float local_168;
  float local_164;
  undefined *local_160;
  undefined2 local_15c;
  undefined local_15a;
  undefined4 local_158;
  float local_154;
  float local_150;
  float local_14c;
  undefined *local_148;
  undefined2 local_144;
  undefined local_142;
  undefined4 local_140;
  float local_13c;
  float local_138;
  float local_134;
  undefined4 local_130;
  undefined2 local_12c;
  undefined local_12a;
  undefined4 local_128;
  float local_124;
  float local_120;
  float local_11c;
  undefined4 local_118;
  undefined2 local_114;
  undefined local_112;
  undefined4 local_110;
  float local_10c;
  float local_108;
  float local_104;
  undefined4 local_100;
  undefined2 local_fc;
  undefined local_fa;
  undefined4 local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  undefined *local_e8;
  undefined2 local_e4;
  undefined local_e2;
  undefined4 local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  undefined *local_d0;
  undefined2 local_cc;
  undefined local_ca;
  undefined4 local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  undefined4 local_b8;
  undefined2 local_b4;
  undefined local_b2;
  
  local_394 = FUN_80286824();
  local_322 = 0;
  local_324 = 0x12;
  local_328 = &DAT_80314c38;
  local_338 = 4;
  local_334 = lbl_803E1778;
  local_330 = lbl_803E1778;
  local_32c = lbl_803E1778;
  local_30a = 0;
  local_30c = 9;
  local_310 = &DAT_80314bfc;
  local_320 = 8;
  local_31c = lbl_803E177C;
  local_318 = lbl_803E177C;
  local_314 = lbl_803E1778;
  local_2f2 = 0;
  local_2f4 = 9;
  local_2f8 = &DAT_80314c10;
  local_308 = 2;
  local_304 = lbl_803E1780;
  local_300 = lbl_803E1784;
  local_2fc = lbl_803E1780;
  local_2da = 0;
  local_2dc = 0x12;
  local_2e0 = &DAT_80314c38;
  local_2f0 = 2;
  local_2ec = lbl_803E1788;
  local_2e8 = lbl_803E1780;
  local_2e4 = lbl_803E1788;
  local_2c2 = 0;
  local_2c4 = 9;
  local_2c8 = &DAT_80314c10;
  local_2d8 = 8;
  local_2d4 = lbl_803E178C;
  local_2d0 = lbl_803E1778;
  local_2cc = lbl_803E1778;
  local_2aa = 0;
  local_2ac = 1;
  local_2b0 = 0;
  local_2c0 = 0x8000;
  local_2bc = lbl_803E177C;
  local_2b8 = lbl_803E1790;
  local_2b4 = lbl_803E1778;
  local_292 = 0;
  local_294 = 0;
  local_298 = 0;
  local_2a8 = 0x80000;
  local_2a4 = lbl_803E1778;
  local_2a0 = lbl_803E1794;
  local_29c = lbl_803E1778;
  local_27a = 1;
  local_27c = 0x12;
  local_280 = &DAT_80314c38;
  local_290 = 4;
  local_28c = lbl_803E177C;
  local_288 = lbl_803E1778;
  local_284 = lbl_803E1778;
  local_262 = 1;
  local_264 = 9;
  local_268 = &DAT_80314c10;
  local_278 = 2;
  local_274 = lbl_803E1780;
  local_270 = lbl_803E1798;
  local_26c = lbl_803E1780;
  local_24a = 1;
  local_24c = 0x7a;
  local_250 = 0;
  local_260 = 0x10000;
  local_25c = lbl_803E1778;
  local_258 = lbl_803E1778;
  local_254 = lbl_803E1778;
  local_232 = 1;
  local_234 = 0;
  local_238 = 0;
  local_248 = 0x80000;
  local_244 = lbl_803E1778;
  local_240 = lbl_803E1794;
  local_23c = lbl_803E1778;
  local_21a = 2;
  local_21c = 0x9d;
  local_220 = 0;
  local_230 = 0x20000;
  local_22c = lbl_803E1778;
  local_228 = lbl_803E1778;
  local_224 = lbl_803E1778;
  local_202 = 3;
  local_204 = 9;
  local_208 = &DAT_80314bfc;
  local_218 = 8;
  local_214 = lbl_803E177C;
  local_210 = lbl_803E179C;
  local_20c = lbl_803E1778;
  local_1ea = 3;
  local_1ec = 0x12;
  local_1f0 = &DAT_80314c38;
  local_200 = 0x100;
  local_1fc = lbl_803E1778;
  local_1f8 = lbl_803E1778;
  local_1f4 = lbl_803E17A0;
  local_1d2 = 3;
  local_1d4 = 5;
  local_1d8 = &DAT_80314c70;
  local_1e8 = 2;
  local_1e4 = lbl_803E17A4;
  local_1e0 = lbl_803E1780;
  local_1dc = lbl_803E17A4;
  local_1ba = 3;
  local_1bc = 4;
  local_1c0 = &DAT_803dc530;
  local_1d0 = 2;
  local_1cc = lbl_803E17A8;
  local_1c8 = lbl_803E1780;
  local_1c4 = lbl_803E17A8;
  local_1a2 = 3;
  local_1a4 = 0;
  local_1a8 = 0;
  local_1b8 = 0x80000;
  local_1b4 = lbl_803E1778;
  local_1b0 = lbl_803E17AC;
  local_1ac = lbl_803E1778;
  local_18a = 4;
  local_18c = 9;
  local_190 = &DAT_80314bfc;
  local_1a0 = 8;
  local_19c = lbl_803E177C;
  local_198 = lbl_803E177C;
  local_194 = lbl_803E1778;
  local_172 = 4;
  local_174 = 0x12;
  local_178 = &DAT_80314c38;
  local_188 = 0x100;
  local_184 = lbl_803E1778;
  local_180 = lbl_803E1778;
  local_17c = lbl_803E17A0;
  local_15a = 4;
  local_15c = 5;
  local_160 = &DAT_80314c70;
  local_170 = 2;
  local_16c = lbl_803E17A8;
  local_168 = lbl_803E1780;
  local_164 = lbl_803E17A8;
  local_142 = 4;
  local_144 = 4;
  local_148 = &DAT_803dc530;
  local_158 = 2;
  local_154 = lbl_803E17A4;
  local_150 = lbl_803E1780;
  local_14c = lbl_803E17A4;
  local_12a = 5;
  local_12c = 2;
  local_130 = 0;
  local_140 = 0x1000;
  local_13c = lbl_803E1780;
  local_138 = lbl_803E1778;
  local_134 = lbl_803E1778;
  local_112 = 6;
  local_114 = 0x9d;
  local_118 = 0;
  local_128 = 0x20000;
  local_124 = lbl_803E1778;
  local_120 = lbl_803E1778;
  local_11c = lbl_803E1778;
  local_fa = 6;
  local_fc = 0x9b;
  local_100 = 0;
  local_110 = 0x10000;
  local_10c = lbl_803E1778;
  local_108 = lbl_803E1778;
  local_104 = lbl_803E1778;
  local_e2 = 6;
  local_e4 = 0x12;
  local_e8 = &DAT_80314c38;
  local_f8 = 4;
  local_f4 = lbl_803E1778;
  local_f0 = lbl_803E1778;
  local_ec = lbl_803E1778;
  local_ca = 6;
  local_cc = 0x12;
  local_d0 = &DAT_80314c38;
  local_e0 = 2;
  local_dc = lbl_803E17B0;
  local_d8 = lbl_803E1780;
  local_d4 = lbl_803E17B0;
  local_b2 = 6;
  local_b4 = 0;
  local_b8 = 0;
  local_c8 = 0x80000;
  local_c4 = lbl_803E1778;
  local_c0 = lbl_803E17AC;
  local_bc = lbl_803E1778;
  local_340 = 0;
  local_36c = lbl_803E1778;
  local_368 = lbl_803E1778;
  local_364 = lbl_803E1778;
  local_378 = lbl_803E1778;
  local_374 = lbl_803E1778;
  local_370 = lbl_803E1778;
  local_360 = lbl_803E1780;
  local_358 = 1;
  local_35c = 0;
  local_33f = 0x12;
  local_33e = 0;
  local_33d = 0xc;
  local_33b = 0x1b;
  local_352 = DAT_80314c7c;
  local_350 = DAT_80314c7e;
  local_34e = DAT_80314c80;
  local_34c = DAT_80314c82;
  local_34a = DAT_80314c84;
  local_348 = DAT_80314c86;
  local_346 = DAT_80314c88;
  local_398 = &local_338;
  local_344 = param_4 | 0x1000082;
  if ((param_4 & 1) != 0) {
    if (local_394 == 0) {
      local_36c = lbl_803E1778 + *(float *)(param_3 + 0xc);
      local_368 = lbl_803E1778 + *(float *)(param_3 + 0x10);
      local_364 = lbl_803E1778 + *(float *)(param_3 + 0x14);
    }
    else {
      local_36c = lbl_803E1778 + *(float *)(local_394 + 0x18);
      local_368 = lbl_803E1778 + *(float *)(local_394 + 0x1c);
      local_364 = lbl_803E1778 + *(float *)(local_394 + 0x20);
    }
  }
  local_354 = extraout_r4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_398,0,0x12,&DAT_80314ae8,0x10,&DAT_80314b9c,0x45,0);
  FUN_80286870();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed490
 * EN v1.0 Address: 0x800ED490
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x800F1980
 * EN v1.1 Size: 884b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed490(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined2 extraout_r4;
  undefined4 *local_388;
  int local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  char local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined4 local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined4 local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined *local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined4 local_270;
  undefined2 local_26c;
  undefined local_26a;
  undefined4 local_268;
  float local_264;
  float local_260;
  float local_25c;
  undefined *local_258;
  undefined2 local_254;
  undefined local_252;
  undefined4 local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined4 local_240;
  undefined2 local_23c;
  undefined local_23a;
  undefined4 local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined *local_228;
  undefined2 local_224;
  undefined local_222;
  undefined4 local_220;
  float local_21c;
  float local_218;
  float local_214;
  undefined *local_210;
  undefined2 local_20c;
  undefined local_20a;
  undefined4 local_208;
  float local_204;
  float local_200;
  float local_1fc;
  undefined *local_1f8;
  undefined2 local_1f4;
  undefined local_1f2;
  undefined4 local_1f0;
  float local_1ec;
  float local_1e8;
  float local_1e4;
  undefined4 local_1e0;
  undefined2 local_1dc;
  undefined local_1da;
  undefined auStack_1d8 [472];
  
  local_384 = FUN_80286838();
  local_388 = &local_328;
  local_312 = 0;
  local_314 = 0x15;
  local_318 = &DAT_80314e60;
  local_328 = 4;
  local_324 = lbl_803E17B8;
  local_320 = lbl_803E17B8;
  local_31c = lbl_803E17B8;
  local_2fa = 0;
  local_2fc = 0x15;
  local_300 = &DAT_80314e60;
  local_310 = 2;
  local_30c = lbl_803E17BC;
  local_308 = lbl_803E17C0;
  local_304 = lbl_803E17BC;
  local_2e2 = 0;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2f8 = 0x400000;
  local_2f4 = lbl_803E17B8;
  local_2f0 = lbl_803E17C4;
  local_2ec = lbl_803E17B8;
  local_2ca = 0;
  local_2cc = 0x124;
  local_2d0 = 0;
  local_2e0 = 0x20000;
  local_2dc = lbl_803E17B8;
  local_2d8 = lbl_803E17B8;
  local_2d4 = lbl_803E17B8;
  local_2b2 = 1;
  local_2b4 = 0x15;
  local_2b8 = &DAT_80314e60;
  local_2c8 = 2;
  local_2c4 = lbl_803E17C8;
  local_2c0 = lbl_803E17CC;
  local_2bc = lbl_803E17C8;
  local_29a = 1;
  local_29c = 0xe;
  local_2a0 = &DAT_80314e8c;
  local_2b0 = 4;
  local_2ac = lbl_803E17D0;
  local_2a8 = lbl_803E17B8;
  local_2a4 = lbl_803E17B8;
  local_282 = 1;
  local_284 = 0x15;
  local_288 = &DAT_80314e60;
  local_298 = 0x4000;
  local_294 = lbl_803E17C0;
  local_290 = lbl_803E17C0;
  local_28c = lbl_803E17B8;
  local_26a = 1;
  local_26c = 0;
  local_270 = 0;
  local_280 = 0x400000;
  local_27c = lbl_803E17B8;
  local_278 = lbl_803E17D4;
  local_274 = lbl_803E17B8;
  local_252 = 2;
  local_254 = 0x15;
  local_258 = &DAT_80314e60;
  local_268 = 0x4000;
  local_264 = lbl_803E17C0;
  local_260 = lbl_803E17C0;
  local_25c = lbl_803E17B8;
  local_23a = 3;
  local_23c = 0x124;
  local_240 = 0;
  local_250 = 0x20000;
  local_24c = lbl_803E17B8;
  local_248 = lbl_803E17B8;
  local_244 = lbl_803E17B8;
  local_222 = 3;
  local_224 = 0xe;
  local_228 = &DAT_80314e8c;
  local_238 = 4;
  local_234 = lbl_803E17B8;
  local_230 = lbl_803E17B8;
  local_22c = lbl_803E17B8;
  local_20a = 3;
  local_20c = 0x15;
  local_210 = &DAT_80314e60;
  local_220 = 0x4000;
  local_21c = lbl_803E17C0;
  local_218 = lbl_803E17C0;
  local_214 = lbl_803E17B8;
  local_1f2 = 3;
  local_1f4 = 0x15;
  local_1f8 = &DAT_80314e60;
  local_208 = 2;
  local_204 = lbl_803E17BC;
  local_200 = lbl_803E17D8;
  local_1fc = lbl_803E17BC;
  local_1da = 3;
  local_1dc = 0;
  local_1e0 = 0;
  local_1f0 = 0x400000;
  local_1ec = lbl_803E17B8;
  local_1e8 = lbl_803E17C4;
  local_1e4 = lbl_803E17B8;
  local_330 = 0;
  local_35c = lbl_803E17B8;
  local_358 = lbl_803E17B8;
  local_354 = lbl_803E17B8;
  local_368 = lbl_803E17B8;
  local_364 = lbl_803E17B8;
  local_360 = lbl_803E17B8;
  local_350 = lbl_803E17D8;
  local_348 = 2;
  local_34c = 7;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x1e;
  iVar1 = (int)(auStack_1d8 + -(int)local_388) / 0x18 +
          ((int)(auStack_1d8 + -(int)local_388) >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_80314ea8;
  local_340 = DAT_80314eaa;
  local_33e = DAT_80314eac;
  local_33c = DAT_80314eae;
  local_33a = DAT_80314eb0;
  local_338 = DAT_80314eb2;
  local_336 = DAT_80314eb4;
  local_334 = param_4 | 0xc0100c0;
  if ((param_4 & 1) != 0) {
    if (local_384 == 0) {
      local_35c = lbl_803E17B8 + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E17B8 + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E17B8 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E17B8 + *(float *)(local_384 + 0x18);
      local_358 = lbl_803E17B8 + *(float *)(local_384 + 0x1c);
      local_354 = lbl_803E17B8 + *(float *)(local_384 + 0x20);
    }
  }
  local_344 = extraout_r4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_80314cb0,0x18,&DAT_80314d84,0x154,0);
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed4fc
 * EN v1.0 Address: 0x800ED4FC
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800F1CF4
 * EN v1.1 Size: 780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed4fc(int param_1,undefined2 param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined4 *local_378;
  int local_374;
  float local_358;
  float local_354;
  float local_350;
  float local_34c;
  float local_348;
  float local_344;
  float local_340;
  undefined4 local_33c;
  undefined4 local_338;
  undefined2 local_334;
  undefined2 local_332;
  undefined2 local_330;
  undefined2 local_32e;
  undefined2 local_32c;
  undefined2 local_32a;
  undefined2 local_328;
  undefined2 local_326;
  uint local_324;
  undefined local_320;
  undefined local_31f;
  undefined local_31e;
  undefined local_31d;
  char local_31b;
  undefined4 local_318;
  float local_314;
  float local_310;
  float local_30c;
  undefined *local_308;
  undefined2 local_304;
  undefined local_302;
  undefined4 local_300;
  float local_2fc;
  float local_2f8;
  float local_2f4;
  undefined *local_2f0;
  undefined2 local_2ec;
  undefined local_2ea;
  undefined4 local_2e8;
  float local_2e4;
  float local_2e0;
  float local_2dc;
  undefined4 local_2d8;
  undefined2 local_2d4;
  undefined local_2d2;
  undefined4 local_2d0;
  float local_2cc;
  float local_2c8;
  float local_2c4;
  undefined *local_2c0;
  undefined2 local_2bc;
  undefined local_2ba;
  undefined4 local_2b8;
  float local_2b4;
  float local_2b0;
  float local_2ac;
  undefined *local_2a8;
  undefined2 local_2a4;
  undefined local_2a2;
  undefined4 local_2a0;
  float local_29c;
  float local_298;
  float local_294;
  undefined *local_290;
  undefined2 local_28c;
  undefined local_28a;
  undefined4 local_288;
  float local_284;
  float local_280;
  float local_27c;
  undefined4 local_278;
  undefined2 local_274;
  undefined local_272;
  undefined4 local_270;
  float local_26c;
  float local_268;
  float local_264;
  undefined *local_260;
  undefined2 local_25c;
  undefined local_25a;
  undefined4 local_258;
  float local_254;
  float local_250;
  float local_24c;
  undefined *local_248;
  undefined2 local_244;
  undefined local_242;
  undefined4 local_240;
  float local_23c;
  float local_238;
  float local_234;
  undefined *local_230;
  undefined2 local_22c;
  undefined local_22a;
  undefined auStack_228 [536];
  
  local_378 = &local_318;
  local_302 = 0;
  local_304 = 0x15;
  local_308 = &DAT_80315088;
  local_318 = 4;
  local_314 = lbl_803E17E0;
  local_310 = lbl_803E17E0;
  local_30c = lbl_803E17E0;
  local_2ea = 0;
  local_2ec = 0x15;
  local_2f0 = &DAT_80315088;
  local_300 = 2;
  local_2fc = lbl_803E17E4;
  local_2f8 = lbl_803E17E8;
  local_2f4 = lbl_803E17E4;
  local_2d2 = 0;
  local_2d4 = 0;
  local_2d8 = 0;
  local_2e8 = 0x400000;
  local_2e4 = lbl_803E17E0;
  local_2e0 = lbl_803E17E0;
  local_2dc = lbl_803E17E0;
  local_2ba = 1;
  local_2bc = 0x15;
  local_2c0 = &DAT_80315088;
  local_2d0 = 2;
  local_2cc = lbl_803E17EC;
  local_2c8 = lbl_803E17F0;
  local_2c4 = lbl_803E17EC;
  local_2a2 = 1;
  local_2a4 = 0xe;
  local_2a8 = &DAT_803150b4;
  local_2b8 = 4;
  local_2b4 = lbl_803E17F4;
  local_2b0 = lbl_803E17E0;
  local_2ac = lbl_803E17E0;
  local_28a = 1;
  local_28c = 0x15;
  local_290 = &DAT_80315088;
  local_2a0 = 0x4000;
  local_29c = lbl_803E17E8;
  local_298 = lbl_803E17E8;
  local_294 = lbl_803E17E0;
  local_272 = 1;
  local_274 = 0;
  local_278 = 0;
  local_288 = 0x100;
  local_284 = lbl_803E17E0;
  local_280 = lbl_803E17E0;
  local_27c = lbl_803E17F8;
  local_25a = 2;
  local_25c = 0x15;
  local_260 = &DAT_80315088;
  local_270 = 0x4000;
  local_26c = lbl_803E17E8;
  local_268 = lbl_803E17E8;
  local_264 = lbl_803E17E0;
  local_242 = 3;
  local_244 = 0x15;
  local_248 = &DAT_80315088;
  local_258 = 0x4000;
  local_254 = lbl_803E17E8;
  local_250 = lbl_803E17E8;
  local_24c = lbl_803E17E0;
  local_22a = 3;
  local_22c = 0xe;
  local_230 = &DAT_803150b4;
  local_240 = 4;
  local_23c = lbl_803E17E0;
  local_238 = lbl_803E17E0;
  local_234 = lbl_803E17E0;
  local_320 = 0;
  local_34c = lbl_803E17E0;
  local_348 = lbl_803E17E0;
  local_344 = lbl_803E17E0;
  local_358 = lbl_803E17E0;
  local_354 = lbl_803E17E0;
  local_350 = lbl_803E17E0;
  local_340 = lbl_803E17FC;
  local_338 = 2;
  local_33c = 7;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 0x1e;
  iVar1 = (int)(auStack_228 + -(int)local_378) / 0x18 +
          ((int)(auStack_228 + -(int)local_378) >> 0x1f);
  local_31b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_332 = DAT_803150d0;
  local_330 = DAT_803150d2;
  local_32e = DAT_803150d4;
  local_32c = DAT_803150d6;
  local_32a = DAT_803150d8;
  local_328 = DAT_803150da;
  local_326 = DAT_803150dc;
  local_324 = param_4 | 0xc0100c0;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = lbl_803E17E0 + *(float *)(param_3 + 0xc);
      local_348 = lbl_803E17E0 + *(float *)(param_3 + 0x10);
      local_344 = lbl_803E17E0 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = lbl_803E17E0 + *(float *)(param_1 + 0x18);
      local_348 = lbl_803E17E0 + *(float *)(param_1 + 0x1c);
      local_344 = lbl_803E17E0 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_334 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0x15,&DAT_80314ed8,0x18,&DAT_80314fac,0x154,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed560
 * EN v1.0 Address: 0x800ED560
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x800F2000
 * EN v1.1 Size: 1192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed560(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  int iVar2;
  undefined2 extraout_r4;
  undefined4 *local_388;
  int local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  char local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined4 local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined4 local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined *local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined4 local_270;
  undefined2 local_26c;
  undefined local_26a;
  undefined4 local_268;
  float local_264;
  float local_260;
  float local_25c;
  undefined *local_258;
  undefined2 local_254;
  undefined local_252;
  undefined4 local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined *local_240;
  undefined2 local_23c;
  undefined local_23a;
  undefined4 local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined *local_228;
  undefined2 local_224;
  undefined local_222;
  undefined4 local_220;
  float local_21c;
  float local_218;
  float local_214;
  undefined4 local_210;
  undefined2 local_20c;
  undefined local_20a;
  undefined4 local_208;
  float local_204;
  float local_200;
  float local_1fc;
  undefined *local_1f8;
  undefined2 local_1f4;
  undefined local_1f2;
  undefined4 local_1f0;
  float local_1ec;
  float local_1e8;
  float local_1e4;
  undefined *local_1e0;
  undefined2 local_1dc;
  undefined local_1da;
  undefined4 local_1d8;
  float local_1d4;
  float local_1d0;
  float local_1cc;
  undefined *local_1c8;
  undefined2 local_1c4;
  undefined local_1c2;
  undefined4 local_1c0;
  float local_1bc;
  float local_1b8;
  float local_1b4;
  undefined4 local_1b0;
  undefined2 local_1ac;
  undefined local_1aa;
  undefined4 local_1a8;
  float local_1a4;
  float local_1a0;
  float local_19c;
  undefined4 local_198;
  undefined2 local_194;
  undefined local_192;
  undefined auStack_190 [360];
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  iVar2 = FUN_8028683c();
  local_312 = 0;
  local_314 = 0x15;
  local_318 = &DAT_803152b0;
  local_328 = 4;
  local_324 = lbl_803E1800;
  local_320 = lbl_803E1800;
  local_31c = lbl_803E1800;
  local_2fa = 0;
  local_2fc = 0x15;
  local_300 = &DAT_803152b0;
  local_310 = 2;
  local_30c = lbl_803E1804;
  local_308 = lbl_803E1808;
  local_304 = lbl_803E1804;
  local_2e2 = 0;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2f8 = 0x400000;
  local_2f4 = lbl_803E1800;
  local_2f0 = lbl_803E180C;
  local_2ec = lbl_803E1800;
  local_2ca = 0;
  local_2cc = 0x124;
  local_2d0 = 0;
  local_2e0 = 0x20000;
  local_2dc = lbl_803E1800;
  local_2d8 = lbl_803E1800;
  local_2d4 = lbl_803E1800;
  local_2b2 = 1;
  local_2b4 = 0x15;
  local_2b8 = &DAT_803152b0;
  local_2c8 = 2;
  local_2c4 = lbl_803E1810;
  local_2c0 = lbl_803E1814;
  local_2bc = lbl_803E1810;
  local_29a = 1;
  local_29c = 0xe;
  local_2a0 = &DAT_803152dc;
  local_2b0 = 4;
  local_2ac = lbl_803E1818;
  local_2a8 = lbl_803E1800;
  local_2a4 = lbl_803E1800;
  local_282 = 1;
  local_284 = 0x15;
  local_288 = &DAT_803152b0;
  local_298 = 0x4000;
  local_294 = lbl_803E181C;
  local_290 = lbl_803E1820;
  local_28c = lbl_803E1800;
  local_26a = 1;
  local_26c = 0;
  local_270 = 0;
  local_280 = 0x400000;
  local_27c = lbl_803E1800;
  local_278 = lbl_803E1824;
  local_274 = lbl_803E1800;
  local_252 = 1;
  local_254 = 0x15;
  local_258 = &DAT_803152b0;
  local_268 = 8;
  uStack_24 = FUN_80017760(100,0xff);
  uStack_24 = uStack_24 ^ 0x80000000;
  local_28 = 0x43300000;
  local_264 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1830);
  local_260 = lbl_803E1818;
  local_25c = lbl_803E1818;
  local_23a = 2;
  local_23c = 0x15;
  local_240 = &DAT_803152b0;
  local_250 = 0x4000;
  local_24c = lbl_803E181C;
  local_248 = lbl_803E1820;
  local_244 = lbl_803E1800;
  local_222 = 2;
  local_224 = 0x15;
  local_228 = &DAT_803152b0;
  local_238 = 8;
  uStack_1c = FUN_80017760(100,0xff);
  uStack_1c = uStack_1c ^ 0x80000000;
  local_20 = 0x43300000;
  local_234 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e1830);
  local_230 = lbl_803E1818;
  local_22c = lbl_803E1818;
  local_20a = 3;
  local_20c = 0x124;
  local_210 = 0;
  local_220 = 0x20000;
  local_21c = lbl_803E1800;
  local_218 = lbl_803E1800;
  local_214 = lbl_803E1800;
  local_1f2 = 3;
  local_1f4 = 0xe;
  local_1f8 = &DAT_803152dc;
  local_208 = 4;
  local_204 = lbl_803E1800;
  local_200 = lbl_803E1800;
  local_1fc = lbl_803E1800;
  local_1da = 3;
  local_1dc = 0x15;
  local_1e0 = &DAT_803152b0;
  local_1f0 = 0x4000;
  local_1ec = lbl_803E181C;
  local_1e8 = lbl_803E1820;
  local_1e4 = lbl_803E1800;
  local_1c2 = 3;
  local_1c4 = 0x15;
  local_1c8 = &DAT_803152b0;
  local_1d8 = 2;
  local_1d4 = lbl_803E1804;
  local_1d0 = lbl_803E1828;
  local_1cc = lbl_803E1804;
  local_1aa = 3;
  local_1ac = 0;
  local_1b0 = 0;
  local_1c0 = 0x400000;
  local_1bc = lbl_803E1800;
  local_1b8 = lbl_803E180C;
  local_1b4 = lbl_803E1800;
  local_192 = 3;
  local_194 = 0;
  local_198 = 0;
  local_1a8 = 0x80000;
  local_1a4 = lbl_803E1800;
  local_1a0 = lbl_803E182C;
  local_19c = lbl_803E1800;
  local_330 = 0;
  local_35c = lbl_803E1800;
  local_358 = lbl_803E1800;
  local_354 = lbl_803E1800;
  local_368 = lbl_803E1800;
  local_364 = lbl_803E1800;
  local_360 = lbl_803E1800;
  local_350 = lbl_803E1828;
  local_348 = 2;
  local_34c = 7;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x1e;
  iVar1 = (int)(auStack_190 + -(int)&local_328) / 0x18 +
          ((int)(auStack_190 + -(int)&local_328) >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_803152f8;
  local_340 = DAT_803152fa;
  local_33e = DAT_803152fc;
  local_33c = DAT_803152fe;
  local_33a = DAT_80315300;
  local_338 = DAT_80315302;
  local_336 = DAT_80315304;
  local_334 = param_4 | 0xc0104c0;
  if ((param_4 & 1) != 0) {
    if (iVar2 == 0) {
      local_35c = lbl_803E1800 + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E1800 + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E1800 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E1800 + *(float *)(iVar2 + 0xc);
      local_358 = lbl_803E1800 + *(float *)(iVar2 + 0x10);
      local_354 = lbl_803E1800 + *(float *)(iVar2 + 0x14);
    }
  }
  local_388 = &local_328;
  local_384 = iVar2;
  local_344 = extraout_r4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_80315100,0x18,&DAT_803151d4,0xd9,0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed5e4
 * EN v1.0 Address: 0x800ED5E4
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x800F24A8
 * EN v1.1 Size: 1160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed5e4(int param_1,int param_2,int param_3,uint param_4)
{
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  uint local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  undefined local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined4 local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined *local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined *local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined *local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined4 local_278;
  float local_274;
  float local_270;
  float local_26c;
  undefined *local_268;
  undefined2 local_264;
  undefined local_262;
  undefined4 local_260;
  float local_25c;
  float local_258;
  float local_254;
  undefined *local_250;
  undefined2 local_24c;
  undefined local_24a;
  undefined4 local_248;
  float local_244;
  float local_240;
  float local_23c;
  undefined *local_238;
  undefined2 local_234;
  undefined local_232;
  undefined4 local_230;
  float local_22c;
  float local_228;
  float local_224;
  undefined *local_220;
  undefined2 local_21c;
  undefined local_21a;
  
  local_2f2 = 0;
  local_2f4 = 0x15;
  local_2f8 = &DAT_803154d8;
  local_308 = 4;
  local_304 = lbl_803E1838;
  local_300 = lbl_803E1838;
  local_2fc = lbl_803E1838;
  if (param_2 == 0) {
    local_2e8 = lbl_803E1840;
    local_2d0 = lbl_803E1848;
  }
  else {
    local_2e8 = lbl_803E1844;
    local_2d0 = lbl_803E184C;
  }
  local_2c2 = 0;
  local_2c4 = 0;
  local_2c8 = 0;
  local_2d8 = 0x400000;
  local_2da = 0;
  local_2dc = 0x15;
  local_2e0 = &DAT_803154d8;
  local_2ec = lbl_803E183C;
  local_2f0 = 2;
  local_2aa = 1;
  local_2ac = 0x15;
  local_2b0 = &DAT_803154d8;
  local_2c0 = 2;
  local_2bc = lbl_803E1850;
  local_2b8 = lbl_803E1854;
  local_2b4 = lbl_803E1850;
  local_292 = 1;
  local_294 = 0xe;
  local_298 = &DAT_80315520;
  local_2a8 = 4;
  local_2a4 = lbl_803E1858;
  local_2d4 = lbl_803E1838;
  local_2a0 = lbl_803E1838;
  local_29c = lbl_803E1838;
  if (param_2 == 0) {
    local_288 = lbl_803E185C;
  }
  else {
    local_288 = lbl_803E1860;
  }
  local_27a = 1;
  local_27c = 0x15;
  local_280 = &DAT_803154d8;
  local_28c = lbl_803E1838;
  local_290 = 0x4000;
  local_262 = 2;
  local_264 = 7;
  local_268 = &DAT_8031548c;
  local_278 = 2;
  local_274 = lbl_803E1864;
  local_270 = lbl_803E1840;
  local_26c = lbl_803E1864;
  local_24a = 2;
  local_24c = 7;
  local_250 = &DAT_8031549c;
  local_260 = 2;
  local_25c = lbl_803E1854;
  local_258 = lbl_803E1840;
  local_254 = lbl_803E1854;
  if (param_2 == 0) {
    local_240 = lbl_803E185C;
  }
  else {
    local_240 = lbl_803E1860;
  }
  local_232 = 2;
  local_234 = 0x15;
  local_238 = &DAT_803154d8;
  local_248 = 0x4000;
  local_21a = 2;
  local_21c = 0xe;
  local_220 = &DAT_80315520;
  local_230 = 4;
  local_244 = lbl_803E1838;
  local_22c = lbl_803E1838;
  local_228 = lbl_803E1838;
  local_224 = lbl_803E1838;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = lbl_803E1838;
  local_338 = lbl_803E1838;
  local_334 = lbl_803E1838;
  local_348 = lbl_803E1838;
  local_344 = lbl_803E1838;
  local_340 = lbl_803E1838;
  local_330 = lbl_803E1840;
  local_328 = 2;
  local_32c = 7;
  local_30f = 0xe;
  local_30e = 0;
  local_30d = 0x1e;
  local_30b = 10;
  local_322 = DAT_8031553c;
  local_320 = DAT_8031553e;
  local_31e = DAT_80315540;
  local_31c = DAT_80315542;
  local_31a = DAT_80315544;
  local_318 = DAT_80315546;
  local_316 = DAT_80315548;
  local_368 = &local_308;
  local_314 = param_4 | 0xc0104c0;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = lbl_803E1838 + *(float *)(param_3 + 0xc);
      local_338 = lbl_803E1838 + *(float *)(param_3 + 0x10);
      local_334 = lbl_803E1838 + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = lbl_803E1838 + *(float *)(param_1 + 0xc);
      local_338 = lbl_803E1838 + *(float *)(param_1 + 0x10);
      local_334 = lbl_803E1838 + *(float *)(param_1 + 0x14);
    }
  }
  local_364 = param_1;
  local_2e4 = local_2ec;
  local_2cc = local_2d4;
  local_284 = local_28c;
  local_23c = local_244;
  if (param_2 == 0) {
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0x15,&DAT_80315328,0x18,&DAT_803153fc,0x2e,0);
  }
  else {
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0x15,&DAT_80315328,0x18,&DAT_803153fc,0xd9,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed68c
 * EN v1.0 Address: 0x800ED68C
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x800F2930
 * EN v1.1 Size: 1016b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed68c(int param_1,int param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  uint local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  char local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined4 local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined4 local_2e0;
  undefined2 local_2dc;
  undefined local_2da [2];
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined4 local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined4 local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8 [170];
  
  local_2f4 = 100;
  local_300 = lbl_803E1868;
  local_2fc = lbl_803E186C;
  if (param_2 == 0) {
    local_2f4 = 0x8c;
  }
  else if (param_2 == 1) {
    local_2f4 = 0x8c;
    local_300 = lbl_803E1870;
    local_2fc = lbl_803E1874;
  }
  else if (param_2 == 2) {
    local_2f4 = 0x8c;
    local_300 = lbl_803E1878;
    local_2fc = lbl_803E187C;
  }
  else if (param_2 == 3) {
    local_2f4 = 0x8c;
    local_300 = lbl_803E1880;
    local_2fc = lbl_803E1884;
  }
  else if (param_2 == 4) {
    local_2f4 = 0x154;
    local_300 = lbl_803E1888;
    local_2fc = lbl_803E188C;
  }
  else if (param_2 == 5) {
    local_2f4 = 0x280;
    DAT_80315574 = 800;
    local_300 = lbl_803E1890;
    local_2fc = lbl_803E1894;
  }
  else if (param_2 == 6) {
    local_2f4 = 100;
    DAT_80315574 = 0x14;
    local_300 = lbl_803E1898;
    local_2fc = lbl_803E189C;
  }
  else if (param_2 == 7) {
    local_2f4 = 200;
    DAT_80315572 = 0x14;
    DAT_80315574 = 0x14;
    DAT_80315576 = 0x14;
    local_300 = lbl_803E18A0;
    local_2fc = lbl_803E18A4;
  }
  else if (param_2 == 8) {
    local_2f4 = 0x41;
    DAT_80315572 = 0x14;
    DAT_80315574 = 0x14;
    DAT_80315576 = 0x14;
    local_300 = lbl_803E18A8;
    local_2fc = lbl_803E18AC;
  }
  local_2f2 = 0;
  local_2f8 = 0;
  local_308 = 0x20000000;
  local_304 = lbl_803E18B0;
  puVar2 = &local_2f0;
  if (param_2 == 0) {
    local_2da[0] = 0;
    local_2dc = 0;
    local_2e0 = 0;
    local_2f0 = 0x80000;
    local_2ec = lbl_803E18B4;
    local_2e8 = lbl_803E18B8;
    local_2e4 = lbl_803E18B4;
    local_2c2 = 1;
    local_2c4 = 0;
    local_2c8 = 0;
    local_2d8 = 0x80000;
    local_2d4 = lbl_803E18B4;
    local_2d0 = lbl_803E18B4;
    local_2cc = lbl_803E18B4;
    local_2aa = 3;
    local_2ac = 0;
    local_2b0 = 0;
    local_2c0 = 0x80000;
    local_2bc = lbl_803E18B4;
    local_2b8 = lbl_803E18B8;
    local_2b4 = lbl_803E18B4;
    puVar2 = local_2a8;
  }
  else if (param_2 == 6) {
    local_2da[0] = 3;
    local_2dc = 1;
    local_2e0 = 0;
    local_2f0 = 0x2000;
    local_2ec = lbl_803E18B4;
    local_2e8 = lbl_803E18B4;
    local_2e4 = lbl_803E18B4;
    puVar2 = &local_2d8;
  }
  else if (param_2 == 8) {
    local_2da[0] = 3;
    local_2dc = 1;
    local_2e0 = 0;
    local_2f0 = 0x2000;
    local_2ec = lbl_803E18B4;
    local_2e8 = lbl_803E18B4;
    local_2e4 = lbl_803E18B4;
    puVar2 = &local_2d8;
  }
  *(undefined *)((int)puVar2 + 0x16) = 4;
  *(undefined2 *)(puVar2 + 5) = 0;
  puVar2[4] = 0;
  *puVar2 = 0x20000000;
  puVar2[1] = lbl_803E18B0;
  puVar2[2] = local_300;
  puVar2[3] = local_2fc;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = lbl_803E18B4;
  local_338 = lbl_803E18B4;
  local_334 = lbl_803E18B4;
  local_348 = lbl_803E18B4;
  local_344 = lbl_803E18B4;
  local_340 = lbl_803E18B4;
  local_330 = lbl_803E18BC;
  local_328 = 0;
  local_32c = 0;
  local_30f = 0;
  local_30e = 0;
  local_30d = 0;
  iVar1 = (int)puVar2 + (0x18 - (int)&local_308);
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_30b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_322 = DAT_80315570;
  local_320 = DAT_80315572;
  local_31e = DAT_80315574;
  local_31c = DAT_80315576;
  local_31a = DAT_80315578;
  local_318 = DAT_8031557a;
  local_316 = DAT_8031557c;
  local_368 = &local_308;
  local_314 = param_4 | 0x10800;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = lbl_803E18B4 + *(float *)(param_3 + 0xc);
      local_338 = lbl_803E18B4 + *(float *)(param_3 + 0x10);
      local_334 = lbl_803E18B4 + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = lbl_803E18B4 + *(float *)(param_1 + 0x18);
      local_338 = lbl_803E18B4 + *(float *)(param_1 + 0x1c);
      local_334 = lbl_803E18B4 + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0,0,0,0,0,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed880
 * EN v1.0 Address: 0x800ED880
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800F2D28
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed880(int param_1,undefined2 param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  uint local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  char local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined4 local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined4 local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined4 local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined4 local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined4 local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined4 local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined auStack_278 [632];
  
  local_368 = &local_308;
  local_2f2 = 0;
  local_2f4 = 0x8c;
  local_2f8 = 0;
  local_308 = 0x20000000;
  local_304 = lbl_803E18C0;
  local_300 = lbl_803E18C4;
  local_2fc = lbl_803E18C8;
  local_2da = 0;
  local_2dc = 0;
  local_2e0 = 0;
  local_2f0 = 0x80000;
  local_2ec = lbl_803E18CC;
  local_2e8 = lbl_803E18D0;
  local_2e4 = lbl_803E18CC;
  local_2c2 = 1;
  local_2c4 = 0;
  local_2c8 = 0;
  local_2d8 = 0x80000;
  local_2d4 = lbl_803E18CC;
  local_2d0 = lbl_803E18CC;
  local_2cc = lbl_803E18CC;
  local_2aa = 3;
  local_2ac = 1;
  local_2b0 = 0;
  local_2c0 = 0x2000;
  local_2bc = lbl_803E18CC;
  local_2b8 = lbl_803E18CC;
  local_2b4 = lbl_803E18CC;
  local_292 = 4;
  local_294 = 0;
  local_298 = 0;
  local_2a8 = 0x80000;
  local_2a4 = lbl_803E18CC;
  local_2a0 = lbl_803E18D0;
  local_29c = lbl_803E18CC;
  local_27a = 5;
  local_27c = 0;
  local_280 = 0;
  local_290 = 0x20000000;
  local_28c = lbl_803E18C0;
  local_288 = lbl_803E18C4;
  local_284 = lbl_803E18C8;
  local_310 = 0;
  local_33c = lbl_803E18CC;
  local_338 = lbl_803E18CC;
  local_334 = lbl_803E18CC;
  local_348 = lbl_803E18CC;
  local_344 = lbl_803E18CC;
  local_340 = lbl_803E18CC;
  local_330 = lbl_803E18D4;
  local_328 = 0;
  local_32c = 0;
  local_30f = 0;
  local_30e = 0;
  local_30d = 0;
  iVar1 = (int)(auStack_278 + -(int)local_368) / 0x18 +
          ((int)(auStack_278 + -(int)local_368) >> 0x1f);
  local_30b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_322 = DAT_803155a0;
  local_320 = DAT_803155a2;
  local_31e = DAT_803155a4;
  local_31c = DAT_803155a6;
  local_31a = DAT_803155a8;
  local_318 = DAT_803155aa;
  local_316 = DAT_803155ac;
  local_314 = param_4 | 0x10c00;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = lbl_803E18CC + *(float *)(param_3 + 0xc);
      local_338 = lbl_803E18CC + *(float *)(param_3 + 0x10);
      local_334 = lbl_803E18CC + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = lbl_803E18CC + *(float *)(param_1 + 0x18);
      local_338 = lbl_803E18CC + *(float *)(param_1 + 0x1c);
      local_334 = lbl_803E18CC + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  local_324 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0,0,0,0,0,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed8e4
 * EN v1.0 Address: 0x800ED8E4
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800F2F88
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed8e4(int param_1,undefined2 param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined4 *local_368;
  int local_364;
  float local_348;
  float local_344;
  float local_340;
  float local_33c;
  float local_338;
  float local_334;
  float local_330;
  undefined4 local_32c;
  undefined4 local_328;
  undefined2 local_324;
  undefined2 local_322;
  undefined2 local_320;
  undefined2 local_31e;
  undefined2 local_31c;
  undefined2 local_31a;
  undefined2 local_318;
  undefined2 local_316;
  uint local_314;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  char local_30b;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined4 local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined4 local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined4 local_2c8;
  undefined2 local_2c4;
  undefined local_2c2;
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined4 local_2b0;
  undefined2 local_2ac;
  undefined local_2aa;
  undefined4 local_2a8;
  float local_2a4;
  float local_2a0;
  float local_29c;
  undefined4 local_298;
  undefined2 local_294;
  undefined local_292;
  undefined4 local_290;
  float local_28c;
  float local_288;
  float local_284;
  undefined4 local_280;
  undefined2 local_27c;
  undefined local_27a;
  undefined auStack_278 [632];
  
  local_368 = &local_308;
  local_2f2 = 0;
  local_2f4 = 0x8c;
  local_2f8 = 0;
  local_308 = 0x20000000;
  local_304 = lbl_803E18D8;
  local_300 = lbl_803E18DC;
  local_2fc = lbl_803E18E0;
  local_2da = 0;
  local_2dc = 0;
  local_2e0 = 0;
  local_2f0 = 0x80000;
  local_2ec = lbl_803E18E4;
  local_2e8 = lbl_803E18E8;
  local_2e4 = lbl_803E18E4;
  local_2c2 = 1;
  local_2c4 = 0;
  local_2c8 = 0;
  local_2d8 = 0x80000;
  local_2d4 = lbl_803E18E4;
  local_2d0 = lbl_803E18E4;
  local_2cc = lbl_803E18E4;
  local_2aa = 3;
  local_2ac = 1;
  local_2b0 = 0;
  local_2c0 = 0x2000;
  local_2bc = lbl_803E18E4;
  local_2b8 = lbl_803E18E4;
  local_2b4 = lbl_803E18E4;
  local_292 = 4;
  local_294 = 0;
  local_298 = 0;
  local_2a8 = 0x80000;
  local_2a4 = lbl_803E18E4;
  local_2a0 = lbl_803E18E8;
  local_29c = lbl_803E18E4;
  local_27a = 5;
  local_27c = 0;
  local_280 = 0;
  local_290 = 0x20000000;
  local_28c = lbl_803E18D8;
  local_288 = lbl_803E18DC;
  local_284 = lbl_803E18E0;
  local_310 = 0;
  local_33c = lbl_803E18E4;
  local_338 = lbl_803E18E4;
  local_334 = lbl_803E18E4;
  local_348 = lbl_803E18E4;
  local_344 = lbl_803E18E4;
  local_340 = lbl_803E18E4;
  local_330 = lbl_803E18EC;
  local_328 = 0;
  local_32c = 0;
  local_30f = 0;
  local_30e = 0;
  local_30d = 0;
  iVar1 = (int)(auStack_278 + -(int)local_368) / 0x18 +
          ((int)(auStack_278 + -(int)local_368) >> 0x1f);
  local_30b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_322 = DAT_803155d0;
  local_320 = DAT_803155d2;
  local_31e = DAT_803155d4;
  local_31c = DAT_803155d6;
  local_31a = DAT_803155d8;
  local_318 = DAT_803155da;
  local_316 = DAT_803155dc;
  local_314 = param_4 | 0x10c00;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = lbl_803E18E4 + *(float *)(param_3 + 0xc);
      local_338 = lbl_803E18E4 + *(float *)(param_3 + 0x10);
      local_334 = lbl_803E18E4 + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = lbl_803E18E4 + *(float *)(param_1 + 0x18);
      local_338 = lbl_803E18E4 + *(float *)(param_1 + 0x1c);
      local_334 = lbl_803E18E4 + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  local_324 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0,0,0,0,0,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed948
 * EN v1.0 Address: 0x800ED948
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800F31E8
 * EN v1.1 Size: 1204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed948(int param_1,undefined2 param_2,short *param_3,uint param_4)
{
  undefined4 *local_388;
  int local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  undefined local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined4 local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined *local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0;
  float local_2ac;
  float local_2a8;
  float local_2a4;
  undefined *local_2a0;
  undefined2 local_29c;
  undefined local_29a;
  undefined4 local_298;
  float local_294;
  float local_290;
  float local_28c;
  undefined4 local_288;
  undefined2 local_284;
  undefined local_282;
  undefined4 local_280;
  float local_27c;
  float local_278;
  float local_274;
  undefined *local_270;
  undefined2 local_26c;
  undefined local_26a;
  undefined4 local_268;
  float local_264;
  float local_260;
  float local_25c;
  undefined *local_258;
  undefined2 local_254;
  undefined local_252;
  undefined4 local_250;
  float local_24c;
  float local_248;
  float local_244;
  undefined *local_240;
  undefined2 local_23c;
  undefined local_23a;
  undefined4 local_238;
  float local_234;
  float local_230;
  float local_22c;
  undefined *local_228;
  undefined2 local_224;
  undefined local_222;
  undefined4 local_220;
  float local_21c;
  float local_218;
  float local_214;
  undefined *local_210;
  undefined2 local_20c;
  undefined local_20a;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  local_312 = 0;
  local_314 = 200;
  local_318 = 0;
  local_328 = 0x800000;
  local_324 = lbl_803E18F0;
  local_320 = lbl_803E18F4;
  local_31c = lbl_803E18F4;
  local_2fa = 0;
  local_2fc = 0xe;
  local_300 = &DAT_803156d4;
  local_310 = 0x80;
  local_30c = lbl_803E18F4;
  local_308 = lbl_803E18F4;
  if (param_3 == (short *)0x0) {
    local_304 = lbl_803E18F4;
  }
  else {
    uStack_24 = (int)*param_3 ^ 0x80000000;
    local_28 = 0x43300000;
    local_304 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1928);
  }
  local_2e2 = 0;
  local_2e4 = 7;
  local_2e8 = &DAT_80315700;
  local_2f8 = 4;
  local_2f4 = lbl_803E18F4;
  local_2f0 = lbl_803E18F4;
  local_2ec = lbl_803E18F4;
  local_2ca = 0;
  local_2cc = 7;
  local_2d0 = &DAT_803156f0;
  local_2e0 = 2;
  local_2dc = lbl_803E18F8;
  local_2d8 = lbl_803E18FC;
  local_2d4 = lbl_803E18F8;
  local_2b2 = 0;
  local_2b4 = 7;
  local_2b8 = &DAT_80315700;
  local_2c8 = 2;
  local_2c0 = lbl_803E1900;
  local_2c4 = lbl_803E18F0;
  local_29a = 1;
  local_29c = 7;
  local_2a0 = &DAT_80315700;
  local_2b0 = 2;
  if (param_3 == (short *)0x0) {
    local_2ac = lbl_803E1908;
    local_2a8 = lbl_803E190C;
    local_2a4 = lbl_803E1908;
  }
  else {
    uStack_24 = (int)param_3[2] ^ 0x80000000;
    local_28 = 0x43300000;
    local_2ac = lbl_803E1904 *
                lbl_803E1908 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1928);
    local_20 = 0x43300000;
    local_2a8 = lbl_803E1904 *
                lbl_803E190C * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1928);
    local_18 = 0x43300000;
    local_2a4 = lbl_803E1904 *
                lbl_803E1908 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1928);
    uStack_1c = uStack_24;
    uStack_14 = uStack_24;
  }
  local_282 = 1;
  local_284 = 0x7a;
  local_288 = 0;
  local_298 = 0x10000;
  local_294 = lbl_803E18F4;
  local_290 = lbl_803E18F4;
  local_28c = lbl_803E18F4;
  local_26a = 1;
  local_26c = 0xe;
  local_270 = &DAT_803156d4;
  local_280 = 0x4000;
  local_27c = lbl_803E18F4;
  local_278 = lbl_803E1910;
  local_274 = lbl_803E18F4;
  local_252 = 1;
  local_254 = 7;
  local_258 = &DAT_803156f0;
  local_268 = 4;
  local_264 = lbl_803E1914;
  local_260 = lbl_803E18F4;
  local_25c = lbl_803E18F4;
  local_23a = 2;
  local_23c = 0xe;
  local_240 = &DAT_803156d4;
  local_250 = 2;
  local_24c = lbl_803E1918;
  local_248 = lbl_803E191C;
  local_244 = lbl_803E1918;
  local_222 = 2;
  local_224 = 0xe;
  local_228 = &DAT_803156d4;
  local_238 = 0x4000;
  local_234 = lbl_803E18F4;
  local_230 = lbl_803E1920;
  local_22c = lbl_803E18F4;
  local_20a = 2;
  local_20c = 7;
  local_210 = &DAT_803156f0;
  local_220 = 4;
  local_21c = lbl_803E18F4;
  local_218 = lbl_803E18F4;
  local_214 = lbl_803E18F4;
  local_330 = 0;
  if (param_3 == (short *)0x0) {
    local_35c = lbl_803E18F4;
    local_358 = lbl_803E18F4;
    local_354 = lbl_803E18F4;
  }
  else {
    local_35c = *(float *)(param_3 + 6);
    local_358 = *(float *)(param_3 + 8);
    local_354 = *(float *)(param_3 + 10);
  }
  local_368 = lbl_803E18F4;
  local_364 = lbl_803E18F4;
  local_360 = lbl_803E18F4;
  local_350 = lbl_803E18F0;
  local_348 = 1;
  local_34c = 0;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 0x10;
  local_32b = 0xb;
  local_342 = DAT_80315710;
  local_340 = DAT_80315712;
  local_33e = DAT_80315714;
  local_33c = DAT_80315716;
  local_33a = DAT_80315718;
  local_338 = DAT_8031571a;
  local_336 = DAT_8031571c;
  local_388 = &local_328;
  local_334 = param_4 | 0x4000400;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_35c = local_35c + *(float *)(param_3 + 6);
      local_358 = local_358 + *(float *)(param_3 + 8);
      local_354 = local_354 + *(float *)(param_3 + 10);
    }
    else {
      local_35c = local_35c + *(float *)(param_1 + 0x18);
      local_358 = local_358 + *(float *)(param_1 + 0x1c);
      local_354 = local_354 + *(float *)(param_1 + 0x20);
    }
  }
  local_384 = param_1;
  local_344 = param_2;
  local_2bc = local_2c4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0xe,&DAT_80315600,0xc,&DAT_8031568c,0x34,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ed9ac
 * EN v1.0 Address: 0x800ED9AC
 * EN v1.0 Size: 1620b
 * EN v1.1 Address: 0x800F369C
 * EN v1.1 Size: 2256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ed9ac(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined8 uVar5;
  undefined4 *local_388;
  int local_384;
  float local_368;
  float local_364;
  float local_360;
  float local_35c;
  float local_358;
  float local_354;
  float local_350;
  undefined4 local_34c;
  undefined4 local_348;
  undefined2 local_344;
  undefined2 local_342;
  undefined2 local_340;
  undefined2 local_33e;
  undefined2 local_33c;
  undefined2 local_33a;
  undefined2 local_338;
  undefined2 local_336;
  uint local_334;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  char local_32b;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312 [2];
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined *local_300;
  undefined2 local_2fc;
  undefined local_2fa [2];
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined *local_2e8;
  undefined2 local_2e4;
  undefined local_2e2 [2];
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8 [168];
  undefined4 local_28;
  uint uStack_24;
  
  uVar5 = FUN_80286834();
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  iVar3 = (int)uVar5;
  if (iVar3 == 0) {
    local_312[0] = 0;
    local_314 = 9;
    local_318 = &DAT_803157cc;
    local_328 = 0x80;
    local_324 = lbl_803E1930;
    local_320 = lbl_803E1930;
    local_31c = lbl_803E1934;
    local_2fa[0] = 0;
    local_2fc = 8;
    local_300 = &DAT_803157cc;
    local_310 = 2;
    local_30c = lbl_803E1938;
    local_308 = lbl_803E1938;
    local_304 = lbl_803E193C;
    puVar4 = &local_2f8;
  }
  else if (iVar3 == 1) {
    DAT_803157f2 = 0x50;
    DAT_803157f4 = 0x118;
    local_312[0] = 0;
    local_314 = 0x69;
    local_318 = (undefined *)0x0;
    local_328 = 0x1800000;
    local_324 = lbl_803E1940;
    local_320 = lbl_803E1930;
    local_31c = lbl_803E1930;
    local_2fa[0] = 0;
    local_2fc = 8;
    local_300 = &DAT_803157cc;
    local_310 = 2;
    uStack_24 = FUN_80017760(0,0xc);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    local_304 = lbl_803E1944 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1980);
    local_30c = lbl_803E1948 + local_304;
    local_304 = lbl_803E194C + local_304;
    local_2e2[0] = 0;
    local_2e4 = 9;
    local_2e8 = &DAT_803157cc;
    local_2f8 = 0x80;
    local_2f4 = lbl_803E1930;
    local_2f0 = lbl_803E1930;
    local_2ec = lbl_803E1950;
    local_2ca = 0;
    local_2cc = 8;
    local_2d0 = &DAT_803157e0;
    local_2e0 = 4;
    local_2dc = lbl_803E1954;
    local_2d8 = lbl_803E1930;
    local_2d4 = lbl_803E1930;
    puVar4 = local_2c8;
    local_308 = local_30c;
  }
  else {
    puVar4 = &local_328;
    if (iVar3 == 2) {
      DAT_803157f2 = 0x50;
      DAT_803157f4 = 0x50;
      local_312[0] = 0;
      local_314 = 0x1fc;
      local_318 = (undefined *)0x0;
      local_328 = 0x1800000;
      local_324 = lbl_803E1940;
      local_320 = lbl_803E1930;
      local_31c = lbl_803E1930;
      local_2fa[0] = 0;
      local_2fc = 8;
      local_300 = &DAT_803157cc;
      local_310 = 2;
      uStack_24 = FUN_80017760(0,0xc);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_304 = lbl_803E1944 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1980)
      ;
      local_30c = lbl_803E1958 + local_304;
      local_304 = lbl_803E195C + local_304;
      local_2e2[0] = 0;
      local_2e4 = 0x8c;
      local_2e8 = (undefined *)0x0;
      local_2f8 = 0x20000000;
      local_2f4 = lbl_803E1960;
      local_2f0 = lbl_803E1964;
      local_2ec = lbl_803E1968;
      local_2ca = 0;
      local_2cc = 9;
      local_2d0 = &DAT_803157cc;
      local_2e0 = 0x80;
      local_2dc = lbl_803E1930;
      local_2d8 = lbl_803E1930;
      local_2d4 = lbl_803E1950;
      puVar4 = local_2c8;
      local_308 = local_30c;
    }
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_803157cc;
    *puVar4 = 0x4000;
    puVar4[1] = lbl_803E1930;
    puVar4[2] = lbl_803E1930;
    puVar4[3] = lbl_803E1930;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 8;
    puVar4[10] = (undefined4)&DAT_803157cc;
    puVar4[6] = 2;
    puVar4[7] = lbl_803E196C;
    puVar4[8] = lbl_803E196C;
    puVar4[9] = lbl_803E196C;
    puVar4 = puVar4 + 0xc;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_803157cc;
    *puVar4 = 0x4000;
    puVar4[1] = lbl_803E1930;
    puVar4[2] = lbl_803E1970;
    puVar4[3] = lbl_803E1930;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 0x8f;
    puVar4[10] = 0;
    puVar4[6] = 0x1800000;
    puVar4[7] = lbl_803E195C;
    puVar4[8] = lbl_803E1930;
    puVar4[9] = lbl_803E1930;
    *(undefined *)((int)puVar4 + 0x46) = 0;
    *(undefined2 *)(puVar4 + 0x11) = 4;
    puVar4[0x10] = (undefined4)&DAT_803dc538;
    puVar4[0xc] = 2;
    puVar4[0xd] = lbl_803E1940;
    puVar4[0xe] = lbl_803E1940;
    puVar4[0xf] = lbl_803E1974;
    puVar4 = puVar4 + 0x12;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_803157cc;
    *puVar4 = 0x4000;
    puVar4[1] = lbl_803E1930;
    puVar4[2] = lbl_803E1930;
    puVar4[3] = lbl_803E1930;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 0x1fd;
    puVar4[10] = 0;
    puVar4[6] = 0x1800000;
    puVar4[7] = lbl_803E1974;
    puVar4[8] = lbl_803E1930;
    puVar4[9] = lbl_803E1930;
    puVar4 = puVar4 + 0xc;
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_803157cc;
    *puVar4 = 0x100;
    puVar4[1] = lbl_803E1978;
    puVar4[2] = lbl_803E1930;
    puVar4[3] = lbl_803E1930;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_803157cc;
    *puVar4 = 0x100;
    puVar4[1] = lbl_803E197C;
    puVar4[2] = lbl_803E1930;
    puVar4[3] = lbl_803E1930;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_803157cc;
    *puVar4 = 0x100;
    puVar4[1] = lbl_803E197C;
    puVar4[2] = lbl_803E1930;
    puVar4[3] = lbl_803E1930;
    puVar4 = puVar4 + 6;
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_803157cc;
    *puVar4 = 0x100;
    puVar4[1] = lbl_803E1978;
    puVar4[2] = lbl_803E1930;
    puVar4[3] = lbl_803E1930;
    *(undefined *)((int)puVar4 + 0x2e) = 2;
    *(undefined2 *)(puVar4 + 0xb) = 9;
    puVar4[10] = (undefined4)&DAT_803157cc;
    puVar4[6] = 4;
    puVar4[7] = lbl_803E1930;
    puVar4[8] = lbl_803E1930;
    puVar4[9] = lbl_803E1930;
    puVar4 = puVar4 + 0xc;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_803157cc;
    *puVar4 = 0x100;
    puVar4[1] = lbl_803E197C;
    puVar4[2] = lbl_803E1930;
    puVar4[3] = lbl_803E1930;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_803157cc;
    *puVar4 = 0x100;
    puVar4[1] = lbl_803E197C;
    puVar4[2] = lbl_803E1930;
    puVar4[3] = lbl_803E1930;
    *(undefined *)((int)puVar4 + 0x2e) = 2;
    *(undefined2 *)(puVar4 + 0xb) = 9;
    puVar4[10] = (undefined4)&DAT_803157cc;
    puVar4[6] = 4;
    puVar4[7] = lbl_803E1930;
    puVar4[8] = lbl_803E1930;
    puVar4[9] = lbl_803E1930;
    puVar4 = puVar4 + 0xc;
  }
  if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 3;
    *(undefined2 *)(puVar4 + 5) = 0;
    puVar4[4] = 0;
    *puVar4 = 0x20000000;
    puVar4[1] = lbl_803E1960;
    puVar4[2] = lbl_803E1964;
    puVar4[3] = lbl_803E1968;
    puVar4 = puVar4 + 6;
  }
  local_344 = (undefined2)uVar5;
  local_35c = lbl_803E1930;
  local_368 = lbl_803E1930;
  local_364 = lbl_803E1930;
  local_360 = lbl_803E1930;
  local_350 = lbl_803E1940;
  local_348 = 1;
  local_34c = 0;
  local_32f = 9;
  local_32e = 0;
  local_32d = 0;
  iVar1 = (int)puVar4 - (int)&local_328;
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_803157f0;
  local_340 = DAT_803157f2;
  local_33e = DAT_803157f4;
  local_33c = DAT_803157f6;
  local_33a = DAT_803157f8;
  local_338 = DAT_803157fa;
  local_336 = DAT_803157fc;
  local_388 = &local_328;
  local_334 = param_4 | 0x4000000;
  local_358 = local_35c;
  local_354 = local_35c;
  if ((param_4 & 1) != 0) {
    if (iVar2 == 0) {
      local_35c = lbl_803E1930 + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E1930 + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E1930 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E1930 + *(float *)(iVar2 + 0x18);
      local_358 = lbl_803E1930 + *(float *)(iVar2 + 0x1c);
      local_354 = lbl_803E1930 + *(float *)(iVar2 + 0x20);
    }
  }
  local_384 = iVar2;
  if (iVar3 == 0) {
    local_330 = 0;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,9,&DAT_80315740,8,&DAT_8031579c,0x156,0);
  }
  else if (iVar3 == 1) {
    local_330 = 0;
    local_334 = param_4 | 0x4000004;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,9,&DAT_80315740,8,&DAT_8031579c,0x89,0);
  }
  else if (iVar3 == 2) {
    local_330 = 0;
    local_334 = param_4 | 0x4000004;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,9,&DAT_80315740,8,&DAT_8031579c,0x23b,0);
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ee000
 * EN v1.0 Address: 0x800EE000
 * EN v1.0 Size: 268b
 * EN v1.1 Address: 0x800F3F6C
 * EN v1.1 Size: 1188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ee000(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined8 uVar5;
  undefined4 *local_3b8;
  int local_3b4;
  float local_398;
  float local_394;
  float local_390;
  float local_38c;
  float local_388;
  float local_384;
  float local_380;
  undefined4 local_37c;
  undefined4 local_378;
  undefined2 local_374;
  undefined2 local_372;
  undefined2 local_370;
  undefined2 local_36e;
  undefined2 local_36c;
  undefined2 local_36a;
  undefined2 local_368;
  undefined2 local_366;
  uint local_364;
  undefined local_360;
  undefined local_35f;
  undefined local_35e;
  undefined local_35d;
  char local_35b;
  undefined4 local_358;
  float local_354;
  float local_350;
  float local_34c;
  undefined *local_348;
  undefined2 local_344;
  undefined local_342;
  undefined4 local_340;
  float local_33c;
  float local_338;
  float local_334;
  undefined *local_330;
  undefined2 local_32c;
  undefined local_32a;
  undefined4 local_328;
  float local_324;
  float local_320;
  float local_31c;
  undefined *local_318;
  undefined2 local_314;
  undefined local_312;
  undefined4 local_310;
  float local_30c;
  float local_308;
  float local_304;
  undefined4 local_300;
  undefined2 local_2fc;
  undefined local_2fa;
  undefined4 local_2f8;
  float local_2f4;
  float local_2f0;
  float local_2ec;
  undefined4 local_2e8;
  undefined2 local_2e4;
  undefined local_2e2;
  undefined4 local_2e0;
  float local_2dc;
  float local_2d8;
  float local_2d4;
  undefined *local_2d0;
  undefined2 local_2cc;
  undefined local_2ca;
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined4 local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 auStack_2b0 [150];
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
  
  uVar5 = FUN_80286838();
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  iVar3 = (int)uVar5;
  local_342 = 0;
  local_344 = 8;
  local_348 = &DAT_803158c0;
  local_358 = 4;
  local_354 = lbl_803E1988;
  local_350 = lbl_803E1988;
  local_34c = lbl_803E1988;
  local_32a = 0;
  local_32c = 8;
  local_330 = &DAT_803158ac;
  local_340 = 2;
  uStack_54 = FUN_80017760(10,0xf);
  uStack_54 = uStack_54 ^ 0x80000000;
  local_58 = 0x43300000;
  local_33c = lbl_803E198C * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e19b0);
  uStack_4c = FUN_80017760(10,0xf);
  uStack_4c = uStack_4c ^ 0x80000000;
  local_50 = 0x43300000;
  local_338 = lbl_803E198C * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e19b0);
  uStack_44 = FUN_80017760(10,0xf);
  uStack_44 = uStack_44 ^ 0x80000000;
  local_48 = 0x43300000;
  local_334 = lbl_803E1990 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e19b0);
  local_312 = 0;
  local_314 = 9;
  local_318 = &DAT_803158ac;
  local_328 = 0x80;
  local_324 = lbl_803E1988;
  local_320 = lbl_803E1988;
  local_31c = lbl_803E1994;
  local_2fa = 1;
  local_2fc = 0x9c;
  local_300 = 0;
  local_310 = 0x800000;
  local_30c = lbl_803E1998;
  local_308 = lbl_803E199C;
  local_304 = lbl_803E1988;
  local_2e2 = 1;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2f8 = 0x400000;
  uStack_3c = FUN_80017760(0xfffff830,200);
  uStack_3c = uStack_3c ^ 0x80000000;
  local_40 = 0x43300000;
  local_2f4 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e19b0);
  uStack_34 = FUN_80017760(0xffffff38,200);
  uStack_34 = uStack_34 ^ 0x80000000;
  local_38 = 0x43300000;
  local_2f0 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e19b0);
  uStack_2c = FUN_80017760(0xffffff38,200);
  uStack_2c = uStack_2c ^ 0x80000000;
  local_30 = 0x43300000;
  local_2ec = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e19b0);
  local_2ca = 1;
  local_2cc = 9;
  local_2d0 = &DAT_803158ac;
  local_2e0 = 4;
  local_2dc = lbl_803E1988;
  local_2d8 = lbl_803E1988;
  local_2d4 = lbl_803E1988;
  puVar4 = &local_2c8;
  if (iVar3 == 0) {
    local_2b2 = 3;
    local_2b4 = 0;
    local_2b8 = 0;
    local_2c8 = 0x20000000;
    local_2c4 = lbl_803E19A0;
    local_2c0 = lbl_803E19A4;
    local_2bc = lbl_803E19A8;
    puVar4 = auStack_2b0;
  }
  local_374 = (undefined2)uVar5;
  if (iVar3 == 0) {
    local_388 = lbl_803E1988;
  }
  else {
    local_388 = lbl_803E19AC;
  }
  local_38c = lbl_803E1988;
  local_398 = lbl_803E1988;
  local_394 = lbl_803E1988;
  local_390 = lbl_803E1988;
  local_380 = lbl_803E199C;
  local_378 = 1;
  local_37c = 0;
  local_35f = 9;
  local_35e = 0;
  local_35d = 0;
  iVar1 = ((int)puVar4 - (int)&local_358) / 0x18 + ((int)puVar4 - (int)&local_358 >> 0x1f);
  local_35b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_372 = DAT_803158d0;
  local_370 = DAT_803158d2;
  local_36e = DAT_803158d4;
  local_36c = DAT_803158d6;
  local_36a = DAT_803158d8;
  local_368 = DAT_803158da;
  local_366 = DAT_803158dc;
  local_3b8 = &local_358;
  local_364 = param_4 | 0x4000000;
  local_384 = local_38c;
  if ((param_4 & 1) != 0) {
    if (iVar2 == 0) {
      local_38c = lbl_803E1988 + *(float *)(param_3 + 0xc);
      local_388 = local_388 + *(float *)(param_3 + 0x10);
      local_384 = lbl_803E1988 + *(float *)(param_3 + 0x14);
    }
    else {
      local_38c = lbl_803E1988 + *(float *)(iVar2 + 0x18);
      local_388 = local_388 + *(float *)(iVar2 + 0x1c);
      local_384 = lbl_803E1988 + *(float *)(iVar2 + 0x20);
    }
  }
  local_3b4 = iVar2;
  if (iVar3 == 0) {
    local_360 = 0;
    (**(code **)(*DAT_803dd6fc + 8))(&local_3b8,0,9,&DAT_80315820,8,&DAT_8031587c,0x156,0);
  }
  else if (iVar3 == 1) {
    local_360 = 0;
    (**(code **)(*DAT_803dd6fc + 8))(&local_3b8,0,9,&DAT_80315820,8,&DAT_8031587c,0xc0d,0);
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800ee10c
 * EN v1.0 Address: 0x800EE10C
 * EN v1.0 Size: 800b
 * EN v1.1 Address: 0x800F4410
 * EN v1.1 Size: 1464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800ee10c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined8 uVar5;
  undefined4 *local_398;
  int local_394;
  float local_378;
  float local_374;
  float local_370;
  float local_36c;
  float local_368;
  float local_364;
  float local_360;
  undefined4 local_35c;
  undefined4 local_358;
  undefined2 local_354;
  undefined2 local_352;
  undefined2 local_350;
  undefined2 local_34e;
  undefined2 local_34c;
  undefined2 local_34a;
  undefined2 local_348;
  undefined2 local_346;
  uint local_344;
  undefined local_340;
  undefined local_33f;
  undefined local_33e;
  undefined local_33d;
  char local_33b;
  undefined4 local_338;
  float local_334;
  float local_330;
  float local_32c;
  undefined *local_328;
  undefined2 local_324;
  undefined local_322;
  undefined4 local_320;
  float local_31c;
  float local_318;
  float local_314;
  undefined *local_310;
  undefined2 local_30c;
  undefined local_30a;
  undefined4 local_308;
  float local_304;
  float local_300;
  float local_2fc;
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined4 local_2f0;
  float local_2ec;
  float local_2e8;
  float local_2e4;
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da;
  undefined4 local_2d8;
  float local_2d4;
  float local_2d0;
  float local_2cc;
  undefined4 local_2c8;
  undefined2 local_2c4;
  undefined local_2c2 [2];
  undefined4 local_2c0;
  float local_2bc;
  float local_2b8;
  float local_2b4;
  undefined4 local_2b0;
  undefined2 local_2ac;
  undefined local_2aa [2];
  undefined4 local_2a8 [5];
  undefined local_292 [602];
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  
  uVar5 = FUN_80286838();
  iVar1 = (int)uVar5;
  if (iVar1 == 1) {
    DAT_80315a28 = 0x1130;
  }
  else {
    DAT_80315a28 = 100;
  }
  local_322 = 0;
  local_324 = 0xe;
  local_328 = &DAT_803159f4;
  local_338 = 4;
  local_334 = lbl_803E19B8;
  local_330 = lbl_803E19B8;
  local_32c = lbl_803E19B8;
  if (iVar1 == 1) {
    local_30a = 0;
    local_30c = 0xe;
    local_310 = &DAT_803159f4;
    local_320 = 2;
    local_31c = lbl_803E19BC;
    local_318 = lbl_803E19BC;
  }
  else {
    local_30a = 0;
    local_30c = 0xe;
    local_310 = &DAT_803159f4;
    local_320 = 2;
    local_31c = lbl_803E19BC;
    uStack_34 = FUN_80017760(3,5);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    local_318 = lbl_803E19C0 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e1a00);
  }
  local_2f2 = 0;
  local_2f4 = 0xe;
  local_2f8 = &DAT_803159f4;
  local_308 = 0x80;
  local_304 = lbl_803E19B8;
  local_300 = lbl_803E19B8;
  local_2fc = lbl_803E19C4;
  local_314 = lbl_803E19BC;
  if (iVar1 == 1) {
    local_2da = 0;
    local_2dc = 0xe;
    local_2e0 = &DAT_803159f4;
    local_2f0 = 0x400000;
    local_2ec = lbl_803E19C8;
    local_2e8 = lbl_803E19CC;
    local_2e4 = lbl_803E19B8;
    local_2c2[0] = 0;
    local_2c4 = 400;
    local_2c8 = 0;
    local_2d8 = 0x20000000;
    local_2d4 = lbl_803E19D0;
    local_2d0 = lbl_803E19D4;
    local_2cc = lbl_803E19D8;
    local_2aa[0] = 0;
    local_2ac = 0;
    local_2b0 = 0;
    local_2c0 = 0x80000;
    local_2bc = lbl_803E19DC;
    local_2b8 = lbl_803E19E0;
    local_2b4 = lbl_803E19B8;
    puVar4 = (undefined4 *)(local_2aa + 2);
  }
  else {
    local_2da = 0;
    local_2dc = 0xe;
    local_2e0 = &DAT_803159f4;
    local_2f0 = 0x400000;
    uStack_34 = FUN_80017760(0,0x14);
    uStack_34 = uStack_34 ^ 0x80000000;
    local_38 = 0x43300000;
    local_2ec = lbl_803E19E4 + (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e1a00);
    local_2e8 = lbl_803E19CC;
    uStack_2c = FUN_80017760(0,0x1e);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    local_2e4 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e1a00);
    puVar4 = &local_2d8;
  }
  *(undefined *)((int)puVar4 + 0x16) = 1;
  *(undefined2 *)(puVar4 + 5) = 10;
  puVar4[4] = (undefined4)&DAT_80315a10;
  *puVar4 = 4;
  puVar4[1] = lbl_803E19E8;
  puVar4[2] = lbl_803E19B8;
  puVar4[3] = lbl_803E19B8;
  *(undefined *)((int)puVar4 + 0x2e) = 1;
  *(undefined2 *)(puVar4 + 0xb) = 0xe;
  puVar4[10] = (undefined4)&DAT_803159f4;
  puVar4[6] = 2;
  puVar4[7] = lbl_803E19BC;
  puVar4[8] = lbl_803E19BC;
  puVar4[9] = lbl_803E19BC;
  puVar3 = puVar4 + 0xc;
  if (iVar1 != 1) {
    *(undefined *)((int)puVar4 + 0x46) = 2;
    *(undefined2 *)(puVar4 + 0x11) = 0xe;
    puVar4[0x10] = (undefined4)&DAT_803159f4;
    *puVar3 = 0x400000;
    uStack_2c = FUN_80017760(1,0x28);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    puVar4[0xd] = lbl_803E19EC * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e1a00)
    ;
    puVar4[0xe] = lbl_803E19B8;
    puVar4[0xf] = lbl_803E19B8;
    puVar3 = puVar4 + 0x12;
  }
  *(undefined *)((int)puVar3 + 0x16) = 2;
  *(undefined2 *)(puVar3 + 5) = 0xe;
  puVar3[4] = (undefined4)&DAT_803159f4;
  *puVar3 = 0x4000;
  uStack_2c = FUN_80017760(0xfffffffd,3);
  uStack_2c = uStack_2c ^ 0x80000000;
  local_30 = 0x43300000;
  puVar3[1] = lbl_803E19F0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e1a00);
  puVar3[2] = lbl_803E19B8;
  puVar3[3] = lbl_803E19B8;
  *(undefined *)((int)puVar3 + 0x2e) = 3;
  *(undefined2 *)(puVar3 + 0xb) = 0xe;
  puVar3[10] = (undefined4)&DAT_803159f4;
  puVar3[6] = 0x4000;
  puVar3[7] = lbl_803E19F4;
  puVar3[8] = lbl_803E19B8;
  puVar3[9] = lbl_803E19B8;
  *(undefined *)((int)puVar3 + 0x46) = 3;
  *(undefined2 *)(puVar3 + 0x11) = 10;
  puVar3[0x10] = (undefined4)&DAT_80315a10;
  puVar3[0xc] = 4;
  puVar3[0xd] = lbl_803E19B8;
  puVar3[0xe] = lbl_803E19B8;
  puVar3[0xf] = lbl_803E19B8;
  puVar4 = puVar3 + 0x12;
  if (iVar1 == 1) {
    *(undefined *)((int)puVar3 + 0x5e) = 3;
    *(undefined2 *)(puVar3 + 0x17) = 0;
    puVar3[0x16] = 0;
    *puVar4 = 0x20000000;
    puVar3[0x13] = lbl_803E19D0;
    puVar3[0x14] = lbl_803E19D4;
    puVar3[0x15] = lbl_803E19D8;
    puVar4 = puVar3 + 0x18;
  }
  local_340 = 0;
  local_354 = (undefined2)uVar5;
  local_36c = lbl_803E19B8;
  local_368 = lbl_803E19F8;
  local_364 = lbl_803E19B8;
  local_378 = lbl_803E19B8;
  local_374 = lbl_803E19B8;
  local_370 = lbl_803E19B8;
  local_360 = lbl_803E19BC;
  local_358 = 1;
  local_35c = 0;
  local_33f = 0xe;
  local_33e = 0;
  local_394 = (int)((ulonglong)uVar5 >> 0x20);
  uVar2 = FUN_80017760(0x18,0x1c);
  local_33d = (undefined)uVar2;
  iVar1 = ((int)puVar4 - (int)&local_338) / 0x18 + ((int)puVar4 - (int)&local_338 >> 0x1f);
  local_33b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_352 = DAT_80315a24;
  local_350 = DAT_80315a26;
  local_34e = DAT_80315a28;
  local_34c = DAT_80315a2a;
  local_34a = DAT_80315a2c;
  local_348 = DAT_80315a2e;
  local_346 = DAT_80315a30;
  local_398 = &local_338;
  local_344 = param_4 | 0x1000000;
  if ((param_4 & 1) != 0) {
    if (local_394 == 0) {
      local_36c = local_36c + *(float *)(param_3 + 0xc);
      local_368 = local_368 + *(float *)(param_3 + 0x10);
      local_364 = local_364 + *(float *)(param_3 + 0x14);
    }
    else {
      local_36c = local_36c + *(float *)(local_394 + 0x18);
      local_368 = local_368 + *(float *)(local_394 + 0x1c);
      local_364 = local_364 + *(float *)(local_394 + 0x20);
    }
  }
  (**(code **)(*DAT_803dd6fc + 8))(&local_398,0,0xe,&DAT_80315900,0xc,&DAT_8031598c,0x8e,0);
  FUN_80286884();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_800EA048(void) {}
void fn_800EA754(void) {}
void fn_800EADC4(void) {}
void fn_800EADC8(void) {}
void fn_800EB090(void) {}
void fn_800EB094(void) {}
void fn_800ECAD8(void) {}
void fn_800ECADC(void) {}
void fn_800ECDFC(void) {}
void fn_800ECE00(void) {}
void fn_800ED28C(void) {}
void fn_800ED290(void) {}
void fn_800ED5DC(void) {}
void fn_800ED5E0(void) {}
void fn_800EDA20(void) {}
void fn_800EDA24(void) {}
void fn_800EDE6C(void) {}
void fn_800EDE70(void) {}
void fn_800EE254(void) {}
void fn_800EE258(void) {}
void fn_800EE8F4(void) {}
void fn_800EE8F8(void) {}
void fn_800EEC2C(void) {}
void fn_800EEC30(void) {}
void fn_800EEFE4(void) {}
void fn_800EEFE8(void) {}
void fn_800EF398(void) {}
void fn_800EF39C(void) {}
void fn_800EF7AC(void) {}
void fn_800EF7B0(void) {}
void fn_800EFA28(void) {}
void fn_800EFA2C(void) {}
void fn_800EFD2C(void) {}
void fn_800EFD30(void) {}
void fn_800EFD3C(void) {}
void fn_800EFD40(void) {}
void fn_800F0224(void) {}
void fn_800F0228(void) {}
void fn_800F0584(void) {}
void fn_800F0588(void) {}
void fn_800F07D4(void) {}
void fn_800F07D8(void) {}
void fn_800F07E4(void) {}
void fn_800F07E8(void) {}
void fn_800F0A44(void) {}
void fn_800F0A48(void) {}
void fn_800F0C94(void) {}
void fn_800F0C98(void) {}
void fn_800F11DC(void) {}
void fn_800F11E0(void) {}
void fn_800F16DC(void) {}
void fn_800F16E0(void) {}
void fn_800F1A50(void) {}
void fn_800F1A54(void) {}
void fn_800F1D5C(void) {}
void fn_800F1D60(void) {}
void fn_800F2204(void) {}
void fn_800F2208(void) {}
void fn_800F268C(void) {}
void fn_800F2690(void) {}
void fn_800F2A84(void) {}
void fn_800F2A88(void) {}
void fn_800F2CE4(void) {}
void fn_800F2CE8(void) {}
void fn_800F2F44(void) {}
void fn_800F2F48(void) {}
void fn_800F33F8(void) {}
void fn_800F33FC(void) {}
void fn_800F3CC8(void) {}
void fn_800F3CCC(void) {}
void fn_800F416C(void) {}
void fn_800F4170(void) {}
void fn_800F4724(void) {}
void fn_800F4728(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_800EFD34(void) { return 0x0; }
int fn_800F07DC(void) { return 0x0; }

/* sda21 accessors. */
extern u8 lbl_803DD488;
u8 fn_800E87C4(void) { return lbl_803DD488; }

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void fn_800EA920(int x) { ObjGroup_RemoveObject(x, 0x10); }
#pragma peephole reset
#pragma scheduling reset

/* lbl = N (byte) */
void fn_800E878C(void) { lbl_803DD488 = 0x0; }

/* 12b 3-insn patterns. */
s32 fn_800EA914(u8 *obj) { return *(s8*)(obj + 0x5); }

/* misc 8b leaves */
u8 fn_800EA900(u8 *p) { return p[8]; }

/* if (lbl) fn(lbl); */
extern u32 lbl_803DD49C;
extern void fn_80023800(u32);
#pragma scheduling off
#pragma peephole off
void fn_800EA04C(void) { if (lbl_803DD49C != 0) fn_80023800(lbl_803DD49C); }
#pragma peephole reset
#pragma scheduling reset

extern void* fn_800E8044(void);
#pragma scheduling off
#pragma peephole off
u8 fn_800EA2BC(void) { u8 *p = (u8*)fn_800E8044(); return p[5]; }
#pragma peephole reset
#pragma scheduling reset

/* conditional init/free pair. */
#pragma scheduling off
#pragma peephole off
void gplayClearRestartPoint(void) { if (lbl_803DD49C != 0) { fn_80023800(lbl_803DD49C); lbl_803DD49C = 0; } }
#pragma peephole reset
#pragma scheduling reset
