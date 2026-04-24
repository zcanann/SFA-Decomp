#include "ghidra_import.h"
#include "main/dll/foodbag.h"

extern uint FUN_80022264();
extern undefined8 FUN_8028681c();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286868();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_80315a58;
extern undefined4 DAT_80315b2c;
extern undefined DAT_80315bbc;
extern undefined DAT_80315bcc;
extern undefined DAT_80315c08;
extern undefined4 DAT_80315c50;
extern undefined4 DAT_80315c52;
extern undefined4 DAT_80315c54;
extern undefined4 DAT_80315c56;
extern undefined4 DAT_80315c58;
extern undefined4 DAT_80315c5a;
extern undefined4 DAT_80315c5c;
extern undefined4 DAT_80315c80;
extern undefined4 DAT_80315d54;
extern undefined DAT_80315de4;
extern undefined DAT_80315df4;
extern undefined DAT_80315e04;
extern undefined DAT_80315e30;
extern undefined4 DAT_80315e78;
extern undefined4 DAT_80315e7a;
extern undefined4 DAT_80315e7c;
extern undefined4 DAT_80315e7e;
extern undefined4 DAT_80315e80;
extern undefined4 DAT_80315e82;
extern undefined4 DAT_80315e84;
extern undefined4 DAT_80315ea8;
extern undefined4 DAT_80315f04;
extern undefined DAT_80315f24;
extern undefined DAT_80315f38;
extern undefined4 DAT_80315f44;
extern undefined4 DAT_80315f46;
extern undefined4 DAT_80315f48;
extern undefined4 DAT_80315f4a;
extern undefined4 DAT_80315f4c;
extern undefined4 DAT_80315f4e;
extern undefined4 DAT_80315f50;
extern undefined4 DAT_80315f78;
extern undefined4 DAT_80315fd4;
extern undefined4 DAT_80316030;
extern undefined DAT_80316060;
extern undefined4 DAT_80316074;
extern undefined4 DAT_80316084;
extern undefined4 DAT_80316086;
extern undefined4 DAT_80316088;
extern undefined4 DAT_8031608a;
extern undefined4 DAT_8031608c;
extern undefined4 DAT_8031608e;
extern undefined4 DAT_80316090;
extern undefined4 DAT_803160b8;
extern undefined4 DAT_80316114;
extern undefined DAT_80316144;
extern undefined DAT_80316158;
extern undefined4 DAT_80316168;
extern undefined4 DAT_8031616a;
extern undefined4 DAT_8031616c;
extern undefined4 DAT_8031616e;
extern undefined4 DAT_80316170;
extern undefined4 DAT_80316172;
extern undefined4 DAT_80316174;
extern undefined4 DAT_80316198;
extern undefined4 DAT_8031626c;
extern undefined DAT_80316348;
extern undefined4 DAT_80316390;
extern undefined4 DAT_80316392;
extern undefined4 DAT_80316394;
extern undefined4 DAT_80316396;
extern undefined4 DAT_80316398;
extern undefined4 DAT_8031639a;
extern undefined4 DAT_8031639c;
extern undefined4 DAT_803163c0;
extern undefined4 DAT_80316494;
extern undefined DAT_80316524;
extern undefined DAT_80316534;
extern undefined DAT_80316570;
extern undefined4 DAT_803165b8;
extern undefined4 DAT_803165ba;
extern undefined4 DAT_803165bc;
extern undefined4 DAT_803165be;
extern undefined4 DAT_803165c0;
extern undefined4 DAT_803165c2;
extern undefined4 DAT_803165c4;
extern undefined4 DAT_803165e8;
extern undefined4 DAT_80316750;
extern undefined DAT_803167b0;
extern undefined DAT_803167c4;
extern undefined DAT_803167d8;
extern undefined DAT_803167ec;
extern undefined DAT_80316848;
extern undefined DAT_80316890;
extern undefined4 DAT_803168b4;
extern undefined4 DAT_803168b6;
extern undefined4 DAT_803168b8;
extern undefined4 DAT_803168ba;
extern undefined4 DAT_803168bc;
extern undefined4 DAT_803168be;
extern undefined4 DAT_803168c0;
extern undefined4 DAT_803168c4;
extern undefined4 DAT_803168f8;
extern undefined4 DAT_80316a60;
extern undefined DAT_80316ac0;
extern undefined DAT_80316ad4;
extern undefined DAT_80316ae8;
extern undefined DAT_80316afc;
extern undefined DAT_80316b58;
extern undefined DAT_80316ba0;
extern undefined4 DAT_80316bc4;
extern undefined4 DAT_80316bc6;
extern undefined4 DAT_80316bc8;
extern undefined4 DAT_80316bca;
extern undefined4 DAT_80316bcc;
extern undefined4 DAT_80316bce;
extern undefined4 DAT_80316bd0;
extern undefined4 DAT_80316bf8;
extern undefined4 DAT_80316c20;
extern undefined4 DAT_80316c2c;
extern undefined4 DAT_80316c2e;
extern undefined4 DAT_80316c30;
extern undefined4 DAT_80316c32;
extern undefined4 DAT_80316c34;
extern undefined4 DAT_80316c36;
extern undefined4 DAT_80316c38;
extern undefined4 DAT_80316c3c;
extern undefined4 DAT_80316c70;
extern undefined4 DAT_80316c72;
extern undefined4 DAT_80316c74;
extern undefined4 DAT_80316c76;
extern undefined4 DAT_80316c78;
extern undefined4 DAT_80316c7a;
extern undefined4 DAT_80316c7c;
extern undefined4 DAT_80316ca0;
extern undefined4 DAT_80316e08;
extern undefined DAT_80316e38;
extern undefined DAT_80316e4c;
extern undefined4 DAT_80316e60;
extern undefined4 DAT_80316e62;
extern undefined4 DAT_80316e64;
extern undefined4 DAT_80316e66;
extern undefined4 DAT_80316e68;
extern undefined4 DAT_80316e6a;
extern undefined4 DAT_80316e6c;
extern undefined4 DAT_80316e90;
extern undefined4 DAT_80316f8c;
extern undefined DAT_8031704c;
extern undefined4 DAT_80317080;
extern undefined4 DAT_80317082;
extern undefined4 DAT_80317084;
extern undefined4 DAT_80317086;
extern undefined4 DAT_80317088;
extern undefined4 DAT_8031708a;
extern undefined4 DAT_8031708c;
extern undefined4 DAT_803170b0;
extern undefined4 DAT_80317218;
extern undefined DAT_80317248;
extern undefined DAT_8031725c;
extern undefined4 DAT_80317270;
extern undefined4 DAT_80317272;
extern undefined4 DAT_80317274;
extern undefined4 DAT_80317276;
extern undefined4 DAT_80317278;
extern undefined4 DAT_8031727a;
extern undefined4 DAT_8031727c;
extern undefined4 DAT_803172a0;
extern undefined4 DAT_803172f0;
extern undefined DAT_80317338;
extern undefined4 DAT_80317348;
extern undefined4 DAT_8031734a;
extern undefined4 DAT_8031734c;
extern undefined4 DAT_8031734e;
extern undefined4 DAT_80317350;
extern undefined4 DAT_80317352;
extern undefined4 DAT_80317354;
extern undefined4 DAT_80317378;
extern undefined4 DAT_8031744c;
extern undefined DAT_80317528;
extern undefined4 DAT_80317570;
extern undefined4 DAT_80317572;
extern undefined4 DAT_80317574;
extern undefined4 DAT_80317576;
extern undefined4 DAT_80317578;
extern undefined4 DAT_8031757a;
extern undefined4 DAT_8031757c;
extern undefined4 DAT_803175a0;
extern undefined4 DAT_80317674;
extern undefined DAT_80317714;
extern undefined DAT_80317724;
extern undefined DAT_80317734;
extern undefined DAT_80317750;
extern undefined4 DAT_8031777c;
extern undefined4 DAT_8031777e;
extern undefined4 DAT_80317780;
extern undefined4 DAT_80317782;
extern undefined4 DAT_80317784;
extern undefined4 DAT_80317786;
extern undefined4 DAT_80317788;
extern undefined4 DAT_803177b0;
extern undefined4 DAT_8031780c;
extern undefined DAT_8031783c;
extern undefined4 DAT_80317860;
extern undefined4 DAT_80317862;
extern undefined4 DAT_80317864;
extern undefined4 DAT_80317866;
extern undefined4 DAT_80317868;
extern undefined4 DAT_8031786a;
extern undefined4 DAT_8031786c;
extern undefined4 DAT_80317890;
extern undefined4 DAT_803178b0;
extern undefined4 DAT_803178b2;
extern undefined4 DAT_803178b4;
extern undefined4 DAT_803178b6;
extern undefined4 DAT_803178b8;
extern undefined4 DAT_803178ba;
extern undefined4 DAT_803178bc;
extern undefined4 DAT_803178e0;
extern undefined4 DAT_80317994;
extern undefined DAT_80317a08;
extern undefined4 DAT_80317a40;
extern undefined4 DAT_80317a42;
extern undefined4 DAT_80317a44;
extern undefined4 DAT_80317a46;
extern undefined4 DAT_80317a48;
extern undefined4 DAT_80317a4a;
extern undefined4 DAT_80317a4c;
extern undefined4 DAT_80317a80;
extern undefined4 DAT_80317b34;
extern undefined DAT_80317b94;
extern undefined DAT_80317ba8;
extern undefined DAT_80317bd0;
extern undefined DAT_80317c08;
extern undefined4 DAT_80317c14;
extern undefined4 DAT_80317c16;
extern undefined4 DAT_80317c18;
extern undefined4 DAT_80317c1a;
extern undefined4 DAT_80317c1c;
extern undefined4 DAT_80317c1e;
extern undefined4 DAT_80317c20;
extern undefined DAT_803dc540;
extern undefined4 DAT_803dc548;
extern undefined DAT_803dc550;
extern undefined DAT_803dc554;
extern undefined DAT_803dc55c;
extern undefined DAT_803dc560;
extern undefined DAT_803dc568;
extern undefined4 DAT_803dc570;
extern undefined DAT_803dc578;
extern undefined DAT_803dc580;
extern undefined4* DAT_803dd6fc;
extern undefined4 DAT_803de128;
extern f64 DOUBLE_803e1c28;
extern f64 DOUBLE_803e1c60;
extern f64 DOUBLE_803e1d28;
extern f64 DOUBLE_803e1d58;
extern f64 DOUBLE_803e1db0;
extern f64 DOUBLE_803e1df0;
extern f32 FLOAT_803e1a08;
extern f32 FLOAT_803e1a0c;
extern f32 FLOAT_803e1a10;
extern f32 FLOAT_803e1a14;
extern f32 FLOAT_803e1a18;
extern f32 FLOAT_803e1a1c;
extern f32 FLOAT_803e1a20;
extern f32 FLOAT_803e1a24;
extern f32 FLOAT_803e1a28;
extern f32 FLOAT_803e1a2c;
extern f32 FLOAT_803e1a30;
extern f32 FLOAT_803e1a34;
extern f32 FLOAT_803e1a38;
extern f32 FLOAT_803e1a3c;
extern f32 FLOAT_803e1a40;
extern f32 FLOAT_803e1a44;
extern f32 FLOAT_803e1a48;
extern f32 FLOAT_803e1a4c;
extern f32 FLOAT_803e1a50;
extern f32 FLOAT_803e1a58;
extern f32 FLOAT_803e1a5c;
extern f32 FLOAT_803e1a60;
extern f32 FLOAT_803e1a64;
extern f32 FLOAT_803e1a68;
extern f32 FLOAT_803e1a6c;
extern f32 FLOAT_803e1a70;
extern f32 FLOAT_803e1a74;
extern f32 FLOAT_803e1a78;
extern f32 FLOAT_803e1a80;
extern f32 FLOAT_803e1a84;
extern f32 FLOAT_803e1a88;
extern f32 FLOAT_803e1a8c;
extern f32 FLOAT_803e1a90;
extern f32 FLOAT_803e1a94;
extern f32 FLOAT_803e1a98;
extern f32 FLOAT_803e1a9c;
extern f32 FLOAT_803e1aa0;
extern f32 FLOAT_803e1aa4;
extern f32 FLOAT_803e1aa8;
extern f32 FLOAT_803e1aac;
extern f32 FLOAT_803e1ab0;
extern f32 FLOAT_803e1ab4;
extern f32 FLOAT_803e1ab8;
extern f32 FLOAT_803e1abc;
extern f32 FLOAT_803e1ac0;
extern f32 FLOAT_803e1ac4;
extern f32 FLOAT_803e1ac8;
extern f32 FLOAT_803e1acc;
extern f32 FLOAT_803e1ad0;
extern f32 FLOAT_803e1ad4;
extern f32 FLOAT_803e1ad8;
extern f32 FLOAT_803e1adc;
extern f32 FLOAT_803e1ae0;
extern f32 FLOAT_803e1ae4;
extern f32 FLOAT_803e1ae8;
extern f32 FLOAT_803e1aec;
extern f32 FLOAT_803e1af0;
extern f32 FLOAT_803e1af4;
extern f32 FLOAT_803e1af8;
extern f32 FLOAT_803e1afc;
extern f32 FLOAT_803e1b00;
extern f32 FLOAT_803e1b04;
extern f32 FLOAT_803e1b08;
extern f32 FLOAT_803e1b0c;
extern f32 FLOAT_803e1b10;
extern f32 FLOAT_803e1b14;
extern f32 FLOAT_803e1b18;
extern f32 FLOAT_803e1b1c;
extern f32 FLOAT_803e1b20;
extern f32 FLOAT_803e1b24;
extern f32 FLOAT_803e1b28;
extern f32 FLOAT_803e1b30;
extern f32 FLOAT_803e1b34;
extern f32 FLOAT_803e1b38;
extern f32 FLOAT_803e1b3c;
extern f32 FLOAT_803e1b40;
extern f32 FLOAT_803e1b44;
extern f32 FLOAT_803e1b48;
extern f32 FLOAT_803e1b4c;
extern f32 FLOAT_803e1b50;
extern f32 FLOAT_803e1b58;
extern f32 FLOAT_803e1b5c;
extern f32 FLOAT_803e1b60;
extern f32 FLOAT_803e1b64;
extern f32 FLOAT_803e1b68;
extern f32 FLOAT_803e1b6c;
extern f32 FLOAT_803e1b70;
extern f32 FLOAT_803e1b74;
extern f32 FLOAT_803e1b78;
extern f32 FLOAT_803e1b7c;
extern f32 FLOAT_803e1b80;
extern f32 FLOAT_803e1b84;
extern f32 FLOAT_803e1b88;
extern f32 FLOAT_803e1b8c;
extern f32 FLOAT_803e1b90;
extern f32 FLOAT_803e1b94;
extern f32 FLOAT_803e1b98;
extern f32 FLOAT_803e1ba0;
extern f32 FLOAT_803e1ba4;
extern f32 FLOAT_803e1ba8;
extern f32 FLOAT_803e1bac;
extern f32 FLOAT_803e1bb0;
extern f32 FLOAT_803e1bb4;
extern f32 FLOAT_803e1bb8;
extern f32 FLOAT_803e1bbc;
extern f32 FLOAT_803e1bc0;
extern f32 FLOAT_803e1bc4;
extern f32 FLOAT_803e1bc8;
extern f32 FLOAT_803e1bcc;
extern f32 FLOAT_803e1bd0;
extern f32 FLOAT_803e1bd4;
extern f32 FLOAT_803e1bd8;
extern f32 FLOAT_803e1bdc;
extern f32 FLOAT_803e1be0;
extern f32 FLOAT_803e1be4;
extern f32 FLOAT_803e1be8;
extern f32 FLOAT_803e1bec;
extern f32 FLOAT_803e1bf0;
extern f32 FLOAT_803e1bf4;
extern f32 FLOAT_803e1bf8;
extern f32 FLOAT_803e1bfc;
extern f32 FLOAT_803e1c00;
extern f32 FLOAT_803e1c04;
extern f32 FLOAT_803e1c08;
extern f32 FLOAT_803e1c0c;
extern f32 FLOAT_803e1c10;
extern f32 FLOAT_803e1c14;
extern f32 FLOAT_803e1c18;
extern f32 FLOAT_803e1c1c;
extern f32 FLOAT_803e1c20;
extern f32 FLOAT_803e1c30;
extern f32 FLOAT_803e1c34;
extern f32 FLOAT_803e1c38;
extern f32 FLOAT_803e1c3c;
extern f32 FLOAT_803e1c40;
extern f32 FLOAT_803e1c44;
extern f32 FLOAT_803e1c48;
extern f32 FLOAT_803e1c4c;
extern f32 FLOAT_803e1c50;
extern f32 FLOAT_803e1c54;
extern f32 FLOAT_803e1c58;
extern f32 FLOAT_803e1c68;
extern f32 FLOAT_803e1c6c;
extern f32 FLOAT_803e1c70;
extern f32 FLOAT_803e1c74;
extern f32 FLOAT_803e1c78;
extern f32 FLOAT_803e1c7c;
extern f32 FLOAT_803e1c80;
extern f32 FLOAT_803e1c84;
extern f32 FLOAT_803e1c88;
extern f32 FLOAT_803e1c90;
extern f32 FLOAT_803e1c94;
extern f32 FLOAT_803e1c98;
extern f32 FLOAT_803e1c9c;
extern f32 FLOAT_803e1ca0;
extern f32 FLOAT_803e1ca4;
extern f32 FLOAT_803e1ca8;
extern f32 FLOAT_803e1cac;
extern f32 FLOAT_803e1cb0;
extern f32 FLOAT_803e1cb4;
extern f32 FLOAT_803e1cb8;
extern f32 FLOAT_803e1cbc;
extern f32 FLOAT_803e1cc0;
extern f32 FLOAT_803e1cc4;
extern f32 FLOAT_803e1cc8;
extern f32 FLOAT_803e1cd0;
extern f32 FLOAT_803e1cd4;
extern f32 FLOAT_803e1cd8;
extern f32 FLOAT_803e1ce0;
extern f32 FLOAT_803e1ce4;
extern f32 FLOAT_803e1ce8;
extern f32 FLOAT_803e1cec;
extern f32 FLOAT_803e1cf0;
extern f32 FLOAT_803e1cf4;
extern f32 FLOAT_803e1cf8;
extern f32 FLOAT_803e1cfc;
extern f32 FLOAT_803e1d00;
extern f32 FLOAT_803e1d04;
extern f32 FLOAT_803e1d08;
extern f32 FLOAT_803e1d0c;
extern f32 FLOAT_803e1d10;
extern f32 FLOAT_803e1d14;
extern f32 FLOAT_803e1d18;
extern f32 FLOAT_803e1d1c;
extern f32 FLOAT_803e1d20;
extern f32 FLOAT_803e1d24;
extern f32 FLOAT_803e1d30;
extern f32 FLOAT_803e1d34;
extern f32 FLOAT_803e1d38;
extern f32 FLOAT_803e1d3c;
extern f32 FLOAT_803e1d40;
extern f32 FLOAT_803e1d44;
extern f32 FLOAT_803e1d48;
extern f32 FLOAT_803e1d4c;
extern f32 FLOAT_803e1d50;
extern f32 FLOAT_803e1d54;
extern f32 FLOAT_803e1d60;
extern f32 FLOAT_803e1d64;
extern f32 FLOAT_803e1d68;
extern f32 FLOAT_803e1d6c;
extern f32 FLOAT_803e1d70;
extern f32 FLOAT_803e1d74;
extern f32 FLOAT_803e1d78;
extern f32 FLOAT_803e1d7c;
extern f32 FLOAT_803e1d80;
extern f32 FLOAT_803e1d84;
extern f32 FLOAT_803e1d88;
extern f32 FLOAT_803e1d8c;
extern f32 FLOAT_803e1d90;
extern f32 FLOAT_803e1d94;
extern f32 FLOAT_803e1d98;
extern f32 FLOAT_803e1d9c;
extern f32 FLOAT_803e1da0;
extern f32 FLOAT_803e1da4;
extern f32 FLOAT_803e1da8;
extern f32 FLOAT_803e1db8;
extern f32 FLOAT_803e1dbc;
extern f32 FLOAT_803e1dc0;
extern f32 FLOAT_803e1dc4;
extern f32 FLOAT_803e1dc8;
extern f32 FLOAT_803e1dcc;
extern f32 FLOAT_803e1dd0;
extern f32 FLOAT_803e1dd4;
extern f32 FLOAT_803e1dd8;
extern f32 FLOAT_803e1ddc;
extern f32 FLOAT_803e1de0;
extern f32 FLOAT_803e1de4;
extern f32 FLOAT_803e1de8;
extern f32 FLOAT_803e1dec;
extern f32 FLOAT_803e1df8;
extern f32 FLOAT_803e1dfc;
extern f32 FLOAT_803e1e00;
extern f32 FLOAT_803e1e04;
extern f32 FLOAT_803e1e08;
extern f32 FLOAT_803e1e0c;
extern f32 FLOAT_803e1e10;
extern f32 FLOAT_803e1e14;
extern f32 FLOAT_803e1e18;
extern f32 FLOAT_803e1e1c;
extern f32 FLOAT_803e1e20;
extern f32 FLOAT_803e1e24;
extern f32 FLOAT_803e1e28;
extern f32 FLOAT_803e1e2c;
extern f32 FLOAT_803e1e30;
extern f32 FLOAT_803e1e34;
extern f32 FLOAT_803e1e38;
extern f32 FLOAT_803e1e3c;
extern f32 FLOAT_803e1e40;
extern f32 FLOAT_803e1e44;
extern f32 FLOAT_803e1e48;
extern f32 FLOAT_803e1e4c;
extern f32 FLOAT_803e1e50;
extern f32 FLOAT_803e1e54;

/*
 * --INFO--
 *
 * Function: FUN_800f49c8
 * EN v1.0 Address: 0x800F472C
 * EN v1.0 Size: 1340b
 * EN v1.1 Address: 0x800F49C8
 * EN v1.1 Size: 1348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f49c8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
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
  undefined4 local_1d8;
  float local_1d4;
  float local_1d0;
  float local_1cc;
  undefined4 local_1c8;
  undefined2 local_1c4;
  undefined local_1c2;
  undefined4 local_1c0;
  float local_1bc;
  float local_1b8;
  float local_1b4;
  undefined4 local_1b0;
  undefined2 local_1ac;
  undefined local_1aa;
  
  uVar2 = FUN_80286834();
  local_384 = (int)((ulonglong)uVar2 >> 0x20);
  iVar1 = (int)uVar2;
  local_312 = 0;
  local_314 = 0x15;
  local_318 = &DAT_80315c08;
  local_328 = 4;
  local_324 = FLOAT_803e1a08;
  local_320 = FLOAT_803e1a08;
  local_31c = FLOAT_803e1a08;
  if ((iVar1 == 0) || (iVar1 == 3)) {
    local_304 = FLOAT_803e1a0c;
  }
  else if ((iVar1 == 1) || (iVar1 == 2)) {
    local_304 = FLOAT_803e1a14;
  }
  else {
    local_304 = FLOAT_803e1a14;
  }
  local_2fa = 0;
  local_2fc = 0x15;
  local_300 = &DAT_80315c08;
  local_308 = FLOAT_803e1a10;
  local_310 = 2;
  local_2e2 = 0;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2f8 = 0x400000;
  local_2f4 = FLOAT_803e1a08;
  local_2f0 = FLOAT_803e1a18;
  local_2ec = FLOAT_803e1a08;
  local_2ca = 1;
  local_2cc = 0x15;
  local_2d0 = &DAT_80315c08;
  local_2e0 = 2;
  local_2dc = FLOAT_803e1a1c;
  local_2d8 = FLOAT_803e1a20;
  local_2d4 = FLOAT_803e1a1c;
  local_2b2 = 1;
  local_2b4 = 7;
  local_2b8 = &DAT_80315bbc;
  local_2c8 = 4;
  local_2c4 = FLOAT_803e1a24;
  local_2c0 = FLOAT_803e1a08;
  local_2bc = FLOAT_803e1a08;
  local_29a = 1;
  local_29c = 7;
  local_2a0 = &DAT_80315bcc;
  local_2b0 = 4;
  local_2ac = FLOAT_803e1a28;
  local_2a8 = FLOAT_803e1a08;
  local_2a4 = FLOAT_803e1a08;
  local_282 = 1;
  local_284 = 0x15;
  local_288 = &DAT_80315c08;
  local_298 = 0x4000;
  local_294 = FLOAT_803e1a2c;
  local_290 = FLOAT_803e1a30;
  local_28c = FLOAT_803e1a08;
  local_26a = 1;
  local_26c = 0;
  local_270 = 0;
  local_280 = 0x400000;
  local_27c = FLOAT_803e1a08;
  local_278 = FLOAT_803e1a34;
  local_274 = FLOAT_803e1a08;
  local_252 = 2;
  local_254 = 0x1e;
  local_258 = 0;
  local_268 = 0x20000;
  local_264 = FLOAT_803e1a1c;
  local_260 = FLOAT_803e1a08;
  local_25c = FLOAT_803e1a08;
  local_23a = 2;
  local_23c = 0x15;
  local_240 = &DAT_80315c08;
  local_250 = 0x4000;
  local_24c = FLOAT_803e1a2c;
  local_248 = FLOAT_803e1a30;
  local_244 = FLOAT_803e1a08;
  local_222 = 2;
  local_224 = 0;
  local_228 = 0;
  local_238 = 0x400000;
  local_234 = FLOAT_803e1a08;
  local_230 = FLOAT_803e1a38;
  local_22c = FLOAT_803e1a08;
  local_20a = 3;
  local_20c = 0x15;
  local_210 = &DAT_80315c08;
  local_220 = 0x4000;
  local_21c = FLOAT_803e1a2c;
  local_218 = FLOAT_803e1a30;
  local_214 = FLOAT_803e1a08;
  local_1f2 = 3;
  local_1f4 = 7;
  local_1f8 = &DAT_80315bbc;
  local_208 = 4;
  local_204 = FLOAT_803e1a08;
  local_200 = FLOAT_803e1a08;
  local_1fc = FLOAT_803e1a08;
  local_1da = 3;
  local_1dc = 7;
  local_1e0 = &DAT_80315bcc;
  local_1f0 = 4;
  local_1ec = FLOAT_803e1a08;
  local_1e8 = FLOAT_803e1a08;
  local_1e4 = FLOAT_803e1a08;
  local_1c2 = 3;
  local_1c4 = 0x1e;
  local_1c8 = 0;
  local_1d8 = 0x20000;
  local_1d4 = FLOAT_803e1a1c;
  local_1d0 = FLOAT_803e1a08;
  local_1cc = FLOAT_803e1a08;
  local_1aa = 3;
  local_1ac = 0;
  local_1b0 = 0;
  local_1c0 = 0x400000;
  local_1bc = FLOAT_803e1a08;
  local_1b8 = FLOAT_803e1a34;
  local_1b4 = FLOAT_803e1a08;
  local_330 = 0;
  local_344 = (undefined2)uVar2;
  local_35c = FLOAT_803e1a08;
  local_358 = FLOAT_803e1a08;
  local_354 = FLOAT_803e1a08;
  if (iVar1 == 3) {
    local_354 = FLOAT_803e1a4c;
  }
  else if (iVar1 < 3) {
    if (iVar1 == 1) {
      local_35c = FLOAT_803e1a40;
      local_354 = FLOAT_803e1a44;
    }
    else if (iVar1 < 1) {
      if (-1 < iVar1) {
        local_354 = FLOAT_803e1a3c;
      }
    }
    else {
      local_35c = FLOAT_803e1a48;
      local_354 = FLOAT_803e1a44;
    }
  }
  else if (iVar1 == 5) {
    local_35c = FLOAT_803e1a48;
    local_354 = FLOAT_803e1a50;
  }
  else if (iVar1 < 5) {
    local_35c = FLOAT_803e1a40;
    local_354 = FLOAT_803e1a50;
  }
  local_368 = FLOAT_803e1a08;
  local_364 = FLOAT_803e1a08;
  local_360 = FLOAT_803e1a08;
  local_350 = FLOAT_803e1a1c;
  local_348 = 2;
  local_34c = 7;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 10;
  local_32b = 0x10;
  local_342 = DAT_80315c50;
  local_340 = DAT_80315c52;
  local_33e = DAT_80315c54;
  local_33c = DAT_80315c56;
  local_33a = DAT_80315c58;
  local_338 = DAT_80315c5a;
  local_336 = DAT_80315c5c;
  local_388 = &local_328;
  local_334 = param_4 | 0xc010080;
  if ((param_4 & 1) != 0) {
    if (local_384 == 0) {
      local_35c = local_35c + *(float *)(param_3 + 0xc);
      local_358 = FLOAT_803e1a08 + *(float *)(param_3 + 0x10);
      local_354 = local_354 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = local_35c + *(float *)(local_384 + 0x18);
      local_358 = FLOAT_803e1a08 + *(float *)(local_384 + 0x1c);
      local_354 = local_354 + *(float *)(local_384 + 0x20);
    }
  }
  local_30c = local_304;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_80315a58,0x18,&DAT_80315b2c,0x2e,0);
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f4f0c
 * EN v1.0 Address: 0x800F4C70
 * EN v1.0 Size: 812b
 * EN v1.1 Address: 0x800F4F0C
 * EN v1.1 Size: 820b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f4f0c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,undefined4 param_5,
                 float *param_6)
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
  undefined auStack_228 [552];
  
  local_374 = FUN_80286840();
  local_2f4 = FLOAT_803e1a58;
  if (param_6 != (float *)0x0) {
    local_2f4 = *param_6;
  }
  local_378 = &local_318;
  local_302 = 0;
  local_304 = 0x15;
  local_308 = &DAT_80315e30;
  local_318 = 4;
  local_314 = FLOAT_803e1a5c;
  local_310 = FLOAT_803e1a5c;
  local_30c = FLOAT_803e1a5c;
  local_2ea = 0;
  local_2ec = 0x15;
  local_2f0 = &DAT_80315e30;
  local_300 = 2;
  local_2fc = FLOAT_803e1a60 * local_2f4;
  local_2f4 = FLOAT_803e1a64 * local_2f4;
  local_2d2 = 1;
  local_2d4 = 7;
  local_2d8 = &DAT_80315e04;
  local_2e8 = 2;
  local_2e4 = FLOAT_803e1a68;
  local_2e0 = FLOAT_803e1a68;
  local_2dc = FLOAT_803e1a58;
  local_2ba = 2;
  local_2bc = 7;
  local_2c0 = &DAT_80315de4;
  local_2d0 = 4;
  local_2cc = FLOAT_803e1a6c;
  local_2c8 = FLOAT_803e1a5c;
  local_2c4 = FLOAT_803e1a5c;
  local_2a2 = 2;
  local_2a4 = 7;
  local_2a8 = &DAT_80315df4;
  local_2b8 = 4;
  local_2b4 = FLOAT_803e1a6c;
  local_2b0 = FLOAT_803e1a5c;
  local_2ac = FLOAT_803e1a5c;
  local_28a = 2;
  local_28c = 7;
  local_290 = &DAT_80315df4;
  local_2a0 = 2;
  local_29c = FLOAT_803e1a70;
  local_298 = FLOAT_803e1a70;
  local_294 = FLOAT_803e1a58;
  local_272 = 2;
  local_274 = 0x15;
  local_278 = &DAT_80315e30;
  local_288 = 0x4000;
  local_284 = FLOAT_803e1a74;
  local_280 = FLOAT_803e1a78;
  local_27c = FLOAT_803e1a5c;
  local_25a = 3;
  local_25c = 0x15;
  local_260 = &DAT_80315e30;
  local_270 = 0x4000;
  local_26c = FLOAT_803e1a74;
  local_268 = FLOAT_803e1a78;
  local_264 = FLOAT_803e1a5c;
  local_242 = 3;
  local_244 = 7;
  local_248 = &DAT_80315de4;
  local_258 = 4;
  local_254 = FLOAT_803e1a5c;
  local_250 = FLOAT_803e1a5c;
  local_24c = FLOAT_803e1a5c;
  local_22a = 3;
  local_22c = 7;
  local_230 = &DAT_80315df4;
  local_240 = 4;
  local_23c = FLOAT_803e1a5c;
  local_238 = FLOAT_803e1a5c;
  local_234 = FLOAT_803e1a5c;
  local_320 = 0;
  local_34c = FLOAT_803e1a5c;
  local_348 = FLOAT_803e1a5c;
  local_344 = FLOAT_803e1a5c;
  local_358 = FLOAT_803e1a5c;
  local_354 = FLOAT_803e1a5c;
  local_350 = FLOAT_803e1a5c;
  local_340 = FLOAT_803e1a58;
  local_338 = 2;
  local_33c = 7;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 10;
  iVar1 = (int)(auStack_228 + -(int)local_378) / 0x18 +
          ((int)(auStack_228 + -(int)local_378) >> 0x1f);
  local_31b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_332 = DAT_80315e78;
  local_330 = DAT_80315e7a;
  local_32e = DAT_80315e7c;
  local_32c = DAT_80315e7e;
  local_32a = DAT_80315e80;
  local_328 = DAT_80315e82;
  local_326 = DAT_80315e84;
  local_324 = param_4 | 0xc010080;
  if ((param_4 & 1) != 0) {
    if (local_374 == 0) {
      local_34c = FLOAT_803e1a5c + *(float *)(param_3 + 0xc);
      local_348 = FLOAT_803e1a5c + *(float *)(param_3 + 0x10);
      local_344 = FLOAT_803e1a5c + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = FLOAT_803e1a5c + *(float *)(local_374 + 0x18);
      local_348 = FLOAT_803e1a5c + *(float *)(local_374 + 0x1c);
      local_344 = FLOAT_803e1a5c + *(float *)(local_374 + 0x20);
    }
  }
  local_334 = extraout_r4;
  local_2f8 = local_2fc;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0x15,&DAT_80315c80,0x18,&DAT_80315d54,0x89,0);
  DAT_803de128 = DAT_803de128 + 1;
  if (DAT_803de128 == 5) {
    DAT_803de128 = 0;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f5240
 * EN v1.0 Address: 0x800F4FA4
 * EN v1.0 Size: 820b
 * EN v1.1 Address: 0x800F5240
 * EN v1.1 Size: 828b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f5240(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,float *param_6
                 )
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
  
  local_2e4 = FLOAT_803e1a80;
  if (param_6 != (float *)0x0) {
    local_2e4 = *param_6;
  }
  if (param_3 != 0) {
    local_2e4 = *(float *)(param_3 + 8);
  }
  local_302 = 0;
  local_304 = 5;
  local_308 = &DAT_80315f38;
  local_318 = 0x4000;
  local_314 = FLOAT_803e1a84;
  local_310 = FLOAT_803e1a88;
  local_30c = FLOAT_803e1a84;
  local_2ea = 0;
  local_2ec = 9;
  local_2f0 = &DAT_80315f24;
  local_300 = 4;
  local_2fc = FLOAT_803e1a84;
  local_2f8 = FLOAT_803e1a84;
  local_2f4 = FLOAT_803e1a84;
  if (param_2 == 1) {
    local_2e4 = FLOAT_803e1a8c * local_2e4;
  }
  else {
    local_2e4 = FLOAT_803e1a94 * local_2e4;
  }
  local_2d2 = 0;
  local_2d4 = 9;
  local_2d8 = &DAT_80315f24;
  local_2dc = FLOAT_803e1a90;
  local_2e8 = 2;
  local_2ba = 1;
  local_2bc = 3;
  local_2c0 = &DAT_803dc540;
  local_2d0 = 4;
  local_2cc = FLOAT_803e1a98;
  local_2c8 = FLOAT_803e1a84;
  local_2c4 = FLOAT_803e1a84;
  local_2a2 = 1;
  local_2a4 = 5;
  local_2a8 = &DAT_80315f38;
  local_2b8 = 0x4000;
  local_2b4 = FLOAT_803e1a9c;
  local_2b0 = FLOAT_803e1a88;
  local_2ac = FLOAT_803e1a84;
  local_28a = 2;
  local_28c = 5;
  local_290 = &DAT_80315f38;
  local_2a0 = 0x4000;
  local_29c = FLOAT_803e1a9c;
  local_298 = FLOAT_803e1a88;
  local_294 = FLOAT_803e1a84;
  local_272 = 2;
  local_274 = 3;
  local_278 = &DAT_803dc540;
  local_288 = 4;
  local_284 = FLOAT_803e1a84;
  local_280 = FLOAT_803e1a84;
  local_27c = FLOAT_803e1a84;
  local_320 = 0;
  local_334 = (undefined2)param_2;
  local_34c = FLOAT_803e1a84;
  local_348 = FLOAT_803e1a84;
  local_344 = FLOAT_803e1a84;
  local_358 = FLOAT_803e1a84;
  local_354 = FLOAT_803e1a84;
  local_350 = FLOAT_803e1a84;
  local_2e0 = FLOAT_803e1a80;
  local_340 = FLOAT_803e1a80;
  local_338 = 1;
  local_33c = 9;
  local_31f = 9;
  local_31e = 0;
  local_31d = 10;
  local_31b = 7;
  local_332 = DAT_80315f44;
  local_330 = DAT_80315f46;
  local_32e = DAT_80315f48;
  local_32c = DAT_80315f4a;
  local_32a = DAT_80315f4c;
  local_328 = DAT_80315f4e;
  local_326 = DAT_80315f50;
  local_378 = &local_318;
  local_324 = param_4 | 0x4010080;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = FLOAT_803e1a84 + *(float *)(param_3 + 0xc);
      local_348 = FLOAT_803e1a84 + *(float *)(param_3 + 0x10);
      local_344 = FLOAT_803e1a84 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = FLOAT_803e1a84 + *(float *)(param_1 + 0x18);
      local_348 = FLOAT_803e1a84 + *(float *)(param_1 + 0x1c);
      local_344 = FLOAT_803e1a84 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,9,&DAT_80315ea8,5,&DAT_80315f04,0x3c,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f557c
 * EN v1.0 Address: 0x800F52E0
 * EN v1.0 Size: 1264b
 * EN v1.1 Address: 0x800F557C
 * EN v1.1 Size: 1272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f557c(int param_1,int param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
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
  undefined *local_2e0;
  undefined2 local_2dc;
  undefined local_2da [2];
  undefined4 local_2d8 [5];
  undefined local_2c2 [706];
  
  local_2f2 = 0;
  local_2f4 = 0x8c;
  local_2f8 = 0;
  local_308 = 0x20000000;
  local_304 = FLOAT_803e1aa0;
  local_300 = FLOAT_803e1aa4;
  local_2fc = FLOAT_803e1aa8;
  puVar2 = &local_2f0;
  if (param_2 != 2) {
    local_2da[0] = 0;
    local_2dc = 9;
    local_2e0 = &DAT_80316060;
    local_2f0 = 0x80;
    local_2ec = FLOAT_803e1aac;
    local_2e8 = FLOAT_803e1aac;
    local_2e4 = FLOAT_803e1ab0;
    puVar2 = (undefined4 *)(local_2da + 2);
  }
  if (param_2 == 0) {
    *(undefined *)((int)puVar2 + 0x16) = 0;
    *(undefined2 *)(puVar2 + 5) = 8;
    puVar2[4] = (undefined4)&DAT_80316074;
    *puVar2 = 2;
    puVar2[1] = FLOAT_803e1ab4;
    puVar2[2] = FLOAT_803e1ab4;
    puVar2[3] = FLOAT_803e1ab8;
  }
  else {
    *(undefined *)((int)puVar2 + 0x16) = 0;
    *(undefined2 *)(puVar2 + 5) = 8;
    puVar2[4] = (undefined4)&DAT_80316074;
    *puVar2 = 2;
    puVar2[1] = FLOAT_803e1abc;
    puVar2[2] = FLOAT_803e1abc;
    puVar2[3] = FLOAT_803e1ac0;
  }
  if (param_2 == 0) {
    *(undefined *)((int)puVar2 + 0x2e) = 1;
    *(undefined2 *)(puVar2 + 0xb) = 8;
    puVar2[10] = (undefined4)&DAT_80316060;
    puVar2[6] = 2;
    puVar2[7] = FLOAT_803e1ac4;
    puVar2[8] = FLOAT_803e1ac4;
    puVar2[9] = FLOAT_803e1ac4;
  }
  else {
    *(undefined *)((int)puVar2 + 0x2e) = 1;
    *(undefined2 *)(puVar2 + 0xb) = 8;
    puVar2[10] = (undefined4)&DAT_80316060;
    puVar2[6] = 2;
    puVar2[7] = FLOAT_803e1ac4;
    puVar2[8] = FLOAT_803e1ac4;
    puVar2[9] = FLOAT_803e1ac4;
  }
  puVar3 = puVar2 + 0xc;
  if (param_2 == 0) {
    *(undefined *)((int)puVar2 + 0x46) = 1;
    *(undefined2 *)(puVar2 + 0x11) = 9;
    puVar2[0x10] = (undefined4)&DAT_80316060;
    *puVar3 = 0x100;
    puVar2[0xd] = FLOAT_803e1ac8;
    puVar2[0xe] = FLOAT_803e1aac;
    puVar2[0xf] = FLOAT_803e1aac;
    puVar3 = puVar2 + 0x12;
    *(undefined *)((int)puVar2 + 0x5e) = 1;
    *(undefined2 *)(puVar2 + 0x17) = 1;
    puVar2[0x16] = (undefined4)&DAT_803dc548;
    *puVar3 = 0x4000;
    puVar2[0x13] = FLOAT_803e1acc;
    puVar2[0x14] = FLOAT_803e1acc;
    puVar2[0x15] = FLOAT_803e1aac;
  }
  else if (param_2 == 1) {
    *(undefined *)((int)puVar2 + 0x46) = 1;
    *(undefined2 *)(puVar2 + 0x11) = 9;
    puVar2[0x10] = (undefined4)&DAT_80316060;
    *puVar3 = 0x100;
    puVar2[0xd] = FLOAT_803e1ad0;
    puVar2[0xe] = FLOAT_803e1aac;
    puVar2[0xf] = FLOAT_803e1aac;
    puVar3 = puVar2 + 0x12;
  }
  if (param_2 == 0) {
    *(undefined *)((int)puVar3 + 0x16) = 2;
    *(undefined2 *)(puVar3 + 5) = 9;
    puVar3[4] = (undefined4)&DAT_80316060;
    *puVar3 = 0x100;
    puVar3[1] = FLOAT_803e1ac8;
    puVar3[2] = FLOAT_803e1aac;
    puVar3[3] = FLOAT_803e1aac;
    *(undefined *)((int)puVar3 + 0x2e) = 2;
    *(undefined2 *)(puVar3 + 0xb) = 1;
    puVar3[10] = (undefined4)&DAT_803dc548;
    puVar3[6] = 0x4000;
    puVar3[7] = FLOAT_803e1acc;
    puVar3[8] = FLOAT_803e1acc;
    puVar3[9] = FLOAT_803e1aac;
    puVar3 = puVar3 + 6;
  }
  else if (param_2 == 1) {
    *(undefined *)((int)puVar3 + 0x16) = 2;
    *(undefined2 *)(puVar3 + 5) = 9;
    puVar3[4] = (undefined4)&DAT_80316060;
    *puVar3 = 0x100;
    puVar3[1] = FLOAT_803e1ad0;
    puVar3[2] = FLOAT_803e1aac;
    puVar3[3] = FLOAT_803e1aac;
    puVar3 = puVar3 + 6;
  }
  *(undefined *)((int)puVar3 + 0x16) = 2;
  *(undefined2 *)(puVar3 + 5) = 9;
  puVar3[4] = (undefined4)&DAT_80316060;
  *puVar3 = 4;
  puVar3[1] = FLOAT_803e1aac;
  puVar3[2] = FLOAT_803e1aac;
  puVar3[3] = FLOAT_803e1aac;
  *(undefined *)((int)puVar3 + 0x2e) = 3;
  *(undefined2 *)(puVar3 + 0xb) = 0;
  puVar3[10] = 0;
  puVar3[6] = 0x20000000;
  puVar3[7] = FLOAT_803e1aa0;
  puVar3[8] = FLOAT_803e1aa4;
  puVar3[9] = FLOAT_803e1aa8;
  local_324 = (undefined2)param_2;
  local_33c = FLOAT_803e1aac;
  local_338 = FLOAT_803e1aac;
  local_334 = FLOAT_803e1aac;
  local_348 = FLOAT_803e1aac;
  local_344 = FLOAT_803e1aac;
  local_340 = FLOAT_803e1aac;
  local_330 = FLOAT_803e1ad4;
  local_328 = 1;
  local_32c = 0;
  local_30f = 9;
  local_30e = 0;
  local_30d = 0x20;
  iVar1 = (int)puVar3 + (0x30 - (int)&local_308);
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_30b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_322 = DAT_80316084;
  local_320 = DAT_80316086;
  local_31e = DAT_80316088;
  local_31c = DAT_8031608a;
  local_31a = DAT_8031608c;
  local_318 = DAT_8031608e;
  local_316 = DAT_80316090;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000000;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = FLOAT_803e1aac + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1aac + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1aac + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = FLOAT_803e1aac + *(float *)(param_1 + 0x18);
      local_338 = FLOAT_803e1aac + *(float *)(param_1 + 0x1c);
      local_334 = FLOAT_803e1aac + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  if (param_2 == 0) {
    local_310 = 0;
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,9,&DAT_80315f78,8,&DAT_80316030,0x156,0);
  }
  else {
    local_310 = 0;
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,9,&DAT_80315fd4,8,&DAT_80316030,0x8a,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f5a74
 * EN v1.0 Address: 0x800F57D8
 * EN v1.0 Size: 684b
 * EN v1.1 Address: 0x800F5A74
 * EN v1.1 Size: 692b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f5a74(int param_1,int param_2,int param_3,uint param_4)
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
  
  local_2f2 = 0;
  local_2f4 = 9;
  local_2f8 = &DAT_80316144;
  local_308 = 0x80;
  local_304 = FLOAT_803e1ad8;
  local_300 = FLOAT_803e1ad8;
  local_2fc = FLOAT_803e1adc;
  if (param_2 == 1) {
    local_2e8 = FLOAT_803e1ae0;
    local_2e4 = FLOAT_803e1ae4;
  }
  else {
    local_2e8 = FLOAT_803e1ae8;
    local_2e4 = FLOAT_803e1aec;
  }
  local_2da = 0;
  local_2dc = 8;
  local_2e0 = &DAT_80316158;
  local_2f0 = 2;
  local_2c2 = 1;
  local_2c4 = 8;
  local_2c8 = &DAT_80316144;
  local_2d8 = 2;
  local_2d4 = FLOAT_803e1aec;
  local_2d0 = FLOAT_803e1aec;
  local_2cc = FLOAT_803e1af0;
  local_2aa = 1;
  local_2ac = 9;
  local_2b0 = &DAT_80316144;
  local_2c0 = 0x100;
  local_2bc = FLOAT_803e1af4;
  local_2b8 = FLOAT_803e1ad8;
  local_2b4 = FLOAT_803e1ad8;
  local_292 = 1;
  local_294 = 9;
  local_298 = &DAT_80316144;
  local_2a8 = 4;
  local_2a4 = FLOAT_803e1ad8;
  local_2a0 = FLOAT_803e1ad8;
  local_29c = FLOAT_803e1ad8;
  local_324 = (undefined2)param_2;
  local_33c = FLOAT_803e1ad8;
  local_338 = FLOAT_803e1ad8;
  local_334 = FLOAT_803e1ad8;
  local_348 = FLOAT_803e1ad8;
  local_344 = FLOAT_803e1ad8;
  local_340 = FLOAT_803e1ad8;
  local_330 = FLOAT_803e1af0;
  local_328 = 1;
  local_32c = 0;
  local_30f = 9;
  local_30e = 0;
  local_30d = 0x20;
  local_30b = 5;
  local_322 = DAT_80316168;
  local_320 = DAT_8031616a;
  local_31e = DAT_8031616c;
  local_31c = DAT_8031616e;
  local_31a = DAT_80316170;
  local_318 = DAT_80316172;
  local_316 = DAT_80316174;
  local_368 = &local_308;
  local_314 = param_4 | 0x4000010;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = FLOAT_803e1ad8 + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1ad8 + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1ad8 + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = FLOAT_803e1ad8 + *(float *)(param_1 + 0x18);
      local_338 = FLOAT_803e1ad8 + *(float *)(param_1 + 0x1c);
      local_334 = FLOAT_803e1ad8 + *(float *)(param_1 + 0x20);
    }
  }
  local_310 = 0;
  local_364 = param_1;
  local_2ec = local_2e8;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,9,&DAT_803160b8,8,&DAT_80316114,0x156,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f5d28
 * EN v1.0 Address: 0x800F5A8C
 * EN v1.0 Size: 1724b
 * EN v1.1 Address: 0x800F5D28
 * EN v1.1 Size: 1732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f5d28(int param_1,int param_2,int param_3,uint param_4)
{
  float fVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
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
  undefined local_27a [2];
  undefined4 local_278 [5];
  undefined local_262 [606];
  
  fVar1 = FLOAT_803e1af8;
  if (((param_2 == 0) || (param_2 == 2)) || (param_2 == 0x1e)) {
    DAT_80316392 = 0xc;
  }
  else if ((param_2 == 1) || (param_2 == 3)) {
    fVar1 = FLOAT_803e1af8 * FLOAT_803e1afc;
    DAT_80316392 = 4;
    DAT_80316398 = 0x32;
  }
  local_2f2 = 0;
  local_2f4 = 0x15;
  local_2f8 = &DAT_80316348;
  local_308 = 4;
  local_304 = FLOAT_803e1b00;
  local_300 = FLOAT_803e1b00;
  local_2fc = FLOAT_803e1b00;
  if ((param_2 == 0) || (param_2 == 2)) {
    local_2e8 = FLOAT_803e1b04;
    local_2e4 = FLOAT_803e1b08;
  }
  else if (param_2 == 0xe) {
    local_2e8 = FLOAT_803e1b0c;
    local_2e4 = FLOAT_803e1b10;
  }
  else if (param_2 == 0x1e) {
    local_2e8 = FLOAT_803e1b14;
    local_2e4 = FLOAT_803e1b08;
  }
  else {
    local_2e8 = FLOAT_803e1b04;
    local_2e4 = FLOAT_803e1b18;
  }
  local_2da = 0;
  local_2dc = 0x15;
  local_2e0 = &DAT_80316348;
  local_2f0 = 2;
  local_2c2 = 0;
  local_2c4 = 0x77;
  local_2c8 = 0;
  local_2d8 = 0x10000;
  local_2d4 = FLOAT_803e1b00;
  local_2d0 = FLOAT_803e1b00;
  local_2cc = FLOAT_803e1b00;
  local_2aa = 0;
  local_2ac = 0x79;
  local_2b0 = 0;
  local_2c0 = 0x10000;
  local_2bc = FLOAT_803e1b00;
  local_2b8 = FLOAT_803e1b00;
  local_2b4 = FLOAT_803e1b00;
  local_292 = 1;
  local_294 = 0x15;
  local_298 = &DAT_80316348;
  local_2a8 = 4;
  local_2a4 = FLOAT_803e1b1c;
  local_2a0 = FLOAT_803e1b00;
  local_29c = FLOAT_803e1b00;
  puVar4 = &local_290;
  if ((param_2 == 0) || (param_2 == 2)) {
    local_27a[0] = 1;
    local_27c = 0x15;
    local_280 = &DAT_80316348;
    local_290 = 2;
    local_28c = FLOAT_803e1b20;
    local_288 = FLOAT_803e1b20;
    local_284 = FLOAT_803e1b24;
    puVar4 = (undefined4 *)(local_27a + 2);
  }
  else if (param_2 == 0x1e) {
    local_27a[0] = 1;
    local_27c = 0x15;
    local_280 = &DAT_80316348;
    local_290 = 2;
    local_28c = FLOAT_803e1b20;
    local_288 = FLOAT_803e1b20;
    local_284 = FLOAT_803e1b28;
    puVar4 = (undefined4 *)(local_27a + 2);
  }
  *(undefined *)((int)puVar4 + 0x16) = 1;
  *(undefined2 *)(puVar4 + 5) = 0x15;
  puVar4[4] = (undefined4)&DAT_80316348;
  *puVar4 = 0x4000;
  puVar4[1] = FLOAT_803e1b20;
  puVar4[2] = fVar1;
  puVar4[3] = FLOAT_803e1b00;
  *(undefined *)((int)puVar4 + 0x2e) = 2;
  *(undefined2 *)(puVar4 + 0xb) = 0x15;
  puVar4[10] = (undefined4)&DAT_80316348;
  puVar4[6] = 4;
  puVar4[7] = FLOAT_803e1b1c;
  puVar4[8] = FLOAT_803e1b00;
  puVar4[9] = FLOAT_803e1b00;
  *(undefined *)((int)puVar4 + 0x46) = 2;
  *(undefined2 *)(puVar4 + 0x11) = 0x15;
  puVar4[0x10] = (undefined4)&DAT_80316348;
  puVar4[0xc] = 0x4000;
  puVar4[0xd] = FLOAT_803e1b20;
  puVar4[0xe] = fVar1;
  puVar4[0xf] = FLOAT_803e1b00;
  *(undefined *)((int)puVar4 + 0x5e) = 3;
  *(undefined2 *)(puVar4 + 0x17) = 0x15;
  puVar4[0x16] = (undefined4)&DAT_80316348;
  puVar4[0x12] = 0x4000;
  puVar4[0x13] = FLOAT_803e1b20;
  puVar4[0x14] = fVar1;
  puVar4[0x15] = FLOAT_803e1b00;
  *(undefined *)((int)puVar4 + 0x76) = 4;
  *(undefined2 *)(puVar4 + 0x1d) = 0x15;
  puVar4[0x1c] = (undefined4)&DAT_80316348;
  puVar4[0x18] = 0x4000;
  puVar4[0x19] = FLOAT_803e1b20;
  puVar4[0x1a] = fVar1;
  puVar4[0x1b] = FLOAT_803e1b00;
  puVar3 = puVar4 + 0x1e;
  if ((param_2 == 0) || (param_2 == 0x1e)) {
    *(undefined *)((int)puVar4 + 0x8e) = 4;
    *(undefined2 *)(puVar4 + 0x23) = 2;
    puVar4[0x22] = 0;
    *puVar3 = 0x2000;
    puVar4[0x1f] = FLOAT_803e1b00;
    puVar4[0x20] = FLOAT_803e1b00;
    puVar4[0x21] = FLOAT_803e1b00;
    puVar3 = puVar4 + 0x24;
  }
  *(undefined *)((int)puVar3 + 0x16) = 5;
  *(undefined2 *)(puVar3 + 5) = 0x15;
  puVar3[4] = (undefined4)&DAT_80316348;
  *puVar3 = 0x4000;
  puVar3[1] = FLOAT_803e1b20;
  puVar3[2] = fVar1;
  puVar3[3] = FLOAT_803e1b00;
  *(undefined *)((int)puVar3 + 0x2e) = 5;
  *(undefined2 *)(puVar3 + 0xb) = 0x15;
  puVar3[10] = (undefined4)&DAT_80316348;
  puVar3[6] = 4;
  puVar3[7] = FLOAT_803e1b00;
  puVar3[8] = FLOAT_803e1b00;
  puVar3[9] = FLOAT_803e1b00;
  puVar4 = puVar3 + 0xc;
  if ((param_2 == 1) || (param_2 == 3)) {
    *(undefined *)((int)puVar3 + 0x46) = 5;
    *(undefined2 *)(puVar3 + 0x11) = 0x15;
    puVar3[0x10] = (undefined4)&DAT_80316348;
    *puVar4 = 2;
    puVar3[0xd] = FLOAT_803e1b20;
    puVar3[0xe] = FLOAT_803e1b20;
    puVar3[0xf] = FLOAT_803e1b08;
    puVar4 = puVar3 + 0x12;
  }
  *(undefined *)((int)puVar4 + 0x16) = 5;
  *(undefined2 *)(puVar4 + 5) = 0x78;
  puVar4[4] = 0;
  *puVar4 = 0x10000;
  puVar4[1] = FLOAT_803e1b00;
  puVar4[2] = FLOAT_803e1b00;
  puVar4[3] = FLOAT_803e1b00;
  *(undefined *)((int)puVar4 + 0x2e) = 5;
  *(undefined2 *)(puVar4 + 0xb) = 0xffff;
  puVar4[10] = 0;
  puVar4[6] = 0x10000;
  puVar4[7] = FLOAT_803e1b00;
  puVar4[8] = FLOAT_803e1b00;
  puVar4[9] = FLOAT_803e1b00;
  local_310 = 0;
  local_324 = (undefined2)param_2;
  local_33c = FLOAT_803e1b00;
  local_338 = FLOAT_803e1b00;
  local_334 = FLOAT_803e1b00;
  local_348 = FLOAT_803e1b00;
  local_344 = FLOAT_803e1b00;
  local_340 = FLOAT_803e1b00;
  local_330 = FLOAT_803e1b20;
  local_328 = 2;
  local_32c = 7;
  local_30f = 0xe;
  local_30e = 0;
  local_30d = 10;
  iVar2 = (int)puVar4 + (0x30 - (int)&local_308);
  iVar2 = iVar2 / 0x18 + (iVar2 >> 0x1f);
  local_30b = (char)iVar2 - (char)(iVar2 >> 0x1f);
  local_322 = DAT_80316390;
  local_320 = DAT_80316392;
  local_31e = DAT_80316394;
  local_31c = DAT_80316396;
  local_31a = DAT_80316398;
  local_318 = DAT_8031639a;
  local_316 = DAT_8031639c;
  local_368 = &local_308;
  local_314 = param_4 | 0xc0104c0;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = FLOAT_803e1b00 + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1b00 + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1b00 + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = FLOAT_803e1b00 + *(float *)(param_1 + 0x18);
      local_338 = FLOAT_803e1b00 + *(float *)(param_1 + 0x1c);
      local_334 = FLOAT_803e1b00 + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  local_2ec = local_2e8;
  if (param_2 == 0x1e) {
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0x15,&DAT_80316198,0x18,&DAT_8031626c,0x3e9,0);
  }
  else if ((param_2 == 2) || (param_2 == 3)) {
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0x15,&DAT_80316198,0x18,&DAT_8031626c,0x23d,0);
  }
  else if ((param_2 - 10U < 4) || (param_2 == 0xe)) {
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0x15,&DAT_80316198,0x18,&DAT_8031626c,0x2e,0);
  }
  else {
    (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0x15,&DAT_80316198,0x18,&DAT_8031626c,0xd9,0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f63ec
 * EN v1.0 Address: 0x800F6150
 * EN v1.0 Size: 988b
 * EN v1.1 Address: 0x800F63EC
 * EN v1.1 Size: 996b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f63ec(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
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
  undefined auStack_1d8 [472];
  
  uVar3 = FUN_80286838();
  local_384 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = (int)uVar3;
  if ((iVar2 == 1) || (iVar2 == 4)) {
    DAT_803165bc = 0x50;
  }
  if (iVar2 == 2) {
    DAT_803165bc = 0x6e;
  }
  local_388 = &local_328;
  local_312 = 0;
  local_314 = 0x15;
  local_318 = &DAT_80316570;
  local_328 = 4;
  local_324 = FLOAT_803e1b30;
  local_320 = FLOAT_803e1b30;
  local_31c = FLOAT_803e1b30;
  local_2fa = 0;
  local_2fc = 0x15;
  local_300 = &DAT_80316570;
  local_310 = 2;
  local_30c = FLOAT_803e1b34;
  local_308 = FLOAT_803e1b38;
  local_304 = FLOAT_803e1b34;
  local_2e2 = 1;
  local_2e4 = 0x15;
  local_2e8 = &DAT_80316570;
  local_2f8 = 2;
  local_2f4 = FLOAT_803e1b3c;
  local_2f0 = FLOAT_803e1b40;
  local_2ec = FLOAT_803e1b3c;
  local_2ca = 1;
  local_2cc = 7;
  local_2d0 = &DAT_80316524;
  local_2e0 = 4;
  local_2dc = FLOAT_803e1b44;
  local_2d8 = FLOAT_803e1b30;
  local_2d4 = FLOAT_803e1b30;
  local_2b2 = 1;
  local_2b4 = 7;
  local_2b8 = &DAT_80316534;
  local_2c8 = 4;
  local_2c4 = FLOAT_803e1b48;
  local_2c0 = FLOAT_803e1b30;
  local_2bc = FLOAT_803e1b30;
  local_29a = 1;
  local_29c = 0x15;
  local_2a0 = &DAT_80316570;
  local_2b0 = 0x4000;
  local_2ac = FLOAT_803e1b4c;
  local_2a8 = FLOAT_803e1b50;
  local_2a4 = FLOAT_803e1b30;
  local_282 = 2;
  local_284 = 0x1e;
  local_288 = 0;
  local_298 = 0x20000;
  local_294 = FLOAT_803e1b3c;
  local_290 = FLOAT_803e1b30;
  local_28c = FLOAT_803e1b30;
  local_26a = 2;
  local_26c = 0x15;
  local_270 = &DAT_80316570;
  local_280 = 2;
  local_27c = FLOAT_803e1b50;
  local_278 = FLOAT_803e1b3c;
  local_274 = FLOAT_803e1b50;
  local_252 = 2;
  local_254 = 0x15;
  local_258 = &DAT_80316570;
  local_268 = 0x4000;
  local_264 = FLOAT_803e1b4c;
  local_260 = FLOAT_803e1b50;
  local_25c = FLOAT_803e1b30;
  local_23a = 3;
  local_23c = 0x15;
  local_240 = &DAT_80316570;
  local_250 = 2;
  local_24c = FLOAT_803e1b50;
  local_248 = FLOAT_803e1b3c;
  local_244 = FLOAT_803e1b50;
  local_222 = 3;
  local_224 = 0x15;
  local_228 = &DAT_80316570;
  local_238 = 0x4000;
  local_234 = FLOAT_803e1b4c;
  local_230 = FLOAT_803e1b50;
  local_22c = FLOAT_803e1b30;
  local_20a = 3;
  local_20c = 7;
  local_210 = &DAT_80316524;
  local_220 = 4;
  local_21c = FLOAT_803e1b30;
  local_218 = FLOAT_803e1b30;
  local_214 = FLOAT_803e1b30;
  local_1f2 = 3;
  local_1f4 = 7;
  local_1f8 = &DAT_80316534;
  local_208 = 4;
  local_204 = FLOAT_803e1b30;
  local_200 = FLOAT_803e1b30;
  local_1fc = FLOAT_803e1b30;
  local_1da = 3;
  local_1dc = 0x1e;
  local_1e0 = 0;
  local_1f0 = 0x20000;
  local_1ec = FLOAT_803e1b3c;
  local_1e8 = FLOAT_803e1b30;
  local_1e4 = FLOAT_803e1b30;
  local_330 = 0;
  local_344 = (undefined2)uVar3;
  local_35c = FLOAT_803e1b30;
  local_358 = FLOAT_803e1b30;
  local_354 = FLOAT_803e1b30;
  local_368 = FLOAT_803e1b30;
  local_364 = FLOAT_803e1b30;
  local_360 = FLOAT_803e1b30;
  local_350 = FLOAT_803e1b3c;
  local_348 = 2;
  local_34c = 7;
  local_32f = 0xe;
  local_32e = 0;
  local_32d = 10;
  iVar1 = (int)(auStack_1d8 + -(int)local_388) / 0x18 +
          ((int)(auStack_1d8 + -(int)local_388) >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_803165b8;
  local_340 = DAT_803165ba;
  local_33e = DAT_803165bc;
  local_33c = DAT_803165be;
  local_33a = DAT_803165c0;
  local_338 = DAT_803165c2;
  local_336 = DAT_803165c4;
  local_334 = param_4 | 0xc010480;
  if ((param_4 & 1) != 0) {
    if (local_384 == 0) {
      local_35c = FLOAT_803e1b30 + *(float *)(param_3 + 0xc);
      local_358 = FLOAT_803e1b30 + *(float *)(param_3 + 0x10);
      local_354 = FLOAT_803e1b30 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = FLOAT_803e1b30 + *(float *)(local_384 + 0x18);
      local_358 = FLOAT_803e1b30 + *(float *)(local_384 + 0x1c);
      local_354 = FLOAT_803e1b30 + *(float *)(local_384 + 0x20);
    }
  }
  if ((iVar2 == 3) || (iVar2 == 4)) {
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_803163c0,0x18,&DAT_80316494,0xd9,0);
  }
  else {
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x15,&DAT_803163c0,0x18,&DAT_80316494,0x2e,0);
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f67d0
 * EN v1.0 Address: 0x800F6534
 * EN v1.0 Size: 1100b
 * EN v1.1 Address: 0x800F67D0
 * EN v1.1 Size: 1108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f67d0(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  undefined8 uVar2;
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
  undefined4 local_1e0;
  float local_1dc;
  float local_1d8;
  float local_1d4;
  undefined *local_1d0;
  undefined2 local_1cc;
  undefined local_1ca;
  undefined4 local_1c8;
  float local_1c4;
  float local_1c0;
  float local_1bc;
  undefined *local_1b8;
  undefined2 local_1b4;
  undefined local_1b2;
  undefined4 local_1b0;
  float local_1ac;
  float local_1a8;
  float local_1a4;
  undefined *local_1a0;
  undefined2 local_19c;
  undefined local_19a;
  undefined4 local_198;
  float local_194;
  float local_190;
  float local_18c;
  undefined *local_188;
  undefined2 local_184;
  undefined local_182;
  undefined4 local_180;
  float local_17c;
  float local_178;
  float local_174;
  undefined *local_170;
  undefined2 local_16c;
  undefined local_16a;
  undefined4 local_168;
  float local_164;
  float local_160;
  float local_15c;
  undefined *local_158;
  undefined2 local_154;
  undefined local_152;
  undefined4 local_150;
  float local_14c;
  float local_148;
  float local_144;
  undefined *local_140;
  undefined2 local_13c;
  undefined local_13a;
  undefined auStack_138 [312];
  
  uVar2 = FUN_8028683c();
  local_374 = (int)((ulonglong)uVar2 >> 0x20);
  local_378 = &local_318;
  local_302 = 0;
  local_304 = 9;
  local_308 = &DAT_803167b0;
  local_318 = 2;
  local_314 = FLOAT_803e1b58;
  local_310 = FLOAT_803e1b5c;
  local_30c = FLOAT_803e1b58;
  local_2ea = 0;
  local_2ec = 9;
  local_2f0 = &DAT_803167c4;
  local_300 = 2;
  local_2fc = FLOAT_803e1b60;
  local_2f8 = FLOAT_803e1b5c;
  local_2f4 = FLOAT_803e1b60;
  local_2d2 = 0;
  local_2d4 = 9;
  local_2d8 = &DAT_803167d8;
  local_2e8 = 2;
  local_2e4 = FLOAT_803e1b60;
  local_2e0 = FLOAT_803e1b5c;
  local_2dc = FLOAT_803e1b60;
  local_2ba = 0;
  local_2bc = 9;
  local_2c0 = &DAT_803167ec;
  local_2d0 = 2;
  local_2cc = FLOAT_803e1b60;
  local_2c8 = FLOAT_803e1b5c;
  local_2c4 = FLOAT_803e1b60;
  local_2a2 = 0;
  local_2a4 = 0x24;
  local_2a8 = &DAT_80316848;
  local_2b8 = 4;
  local_2b4 = FLOAT_803e1b64;
  local_2b0 = FLOAT_803e1b64;
  local_2ac = FLOAT_803e1b64;
  local_28a = 0;
  local_28c = 0;
  local_290 = 0;
  local_2a0 = 0x400000;
  local_29c = FLOAT_803e1b68;
  local_298 = FLOAT_803e1b6c;
  local_294 = FLOAT_803e1b70;
  local_272 = 1;
  local_274 = 0x24;
  local_278 = &DAT_80316848;
  local_288 = 2;
  local_284 = FLOAT_803e1b74;
  local_280 = FLOAT_803e1b78;
  local_27c = FLOAT_803e1b74;
  local_25a = 1;
  local_25c = 0x24;
  local_260 = &DAT_80316848;
  local_270 = 0x4000;
  local_26c = FLOAT_803e1b64;
  local_268 = FLOAT_803e1b64;
  local_264 = FLOAT_803e1b64;
  local_242 = 1;
  local_244 = 0x24;
  local_248 = &DAT_80316848;
  local_258 = 0x100;
  local_254 = FLOAT_803e1b64;
  local_250 = FLOAT_803e1b64;
  local_24c = FLOAT_803e1b7c;
  local_22a = 2;
  local_22c = 0x12;
  local_230 = &DAT_80316890;
  local_240 = 4;
  local_23c = FLOAT_803e1b80;
  local_238 = FLOAT_803e1b64;
  local_234 = FLOAT_803e1b64;
  local_212 = 2;
  local_214 = 0x24;
  local_218 = &DAT_80316848;
  local_228 = 2;
  local_224 = FLOAT_803e1b84;
  local_220 = FLOAT_803e1b84;
  local_21c = FLOAT_803e1b84;
  local_1fa = 2;
  local_1fc = 0x24;
  local_200 = &DAT_80316848;
  local_210 = 0x4000;
  local_20c = FLOAT_803e1b64;
  local_208 = FLOAT_803e1b64;
  local_204 = FLOAT_803e1b64;
  local_1e2 = 2;
  local_1e4 = 0;
  local_1e8 = 0;
  local_1f8 = 0x400000;
  local_1f4 = FLOAT_803e1b88;
  local_1f0 = FLOAT_803e1b8c;
  local_1ec = FLOAT_803e1b90;
  local_1ca = 2;
  local_1cc = 0x24;
  local_1d0 = &DAT_80316848;
  local_1e0 = 0x100;
  local_1dc = FLOAT_803e1b64;
  local_1d8 = FLOAT_803e1b64;
  local_1d4 = FLOAT_803e1b7c;
  local_1b2 = 3;
  local_1b4 = 0x24;
  local_1b8 = &DAT_80316848;
  local_1c8 = 0x100;
  local_1c4 = FLOAT_803e1b64;
  local_1c0 = FLOAT_803e1b64;
  local_1bc = FLOAT_803e1b7c;
  local_19a = 3;
  local_19c = 0x24;
  local_1a0 = &DAT_80316848;
  local_1b0 = 0x4000;
  local_1ac = FLOAT_803e1b64;
  local_1a8 = FLOAT_803e1b64;
  local_1a4 = FLOAT_803e1b64;
  local_182 = 4;
  local_184 = 0x24;
  local_188 = &DAT_80316848;
  local_198 = 0x4000;
  local_194 = FLOAT_803e1b64;
  local_190 = FLOAT_803e1b64;
  local_18c = FLOAT_803e1b64;
  local_16a = 4;
  local_16c = 0x24;
  local_170 = &DAT_80316848;
  local_180 = 0x100;
  local_17c = FLOAT_803e1b64;
  local_178 = FLOAT_803e1b64;
  local_174 = FLOAT_803e1b80;
  local_152 = 4;
  local_154 = 0x12;
  local_158 = &DAT_80316890;
  local_168 = 4;
  local_164 = FLOAT_803e1b64;
  local_160 = FLOAT_803e1b64;
  local_15c = FLOAT_803e1b64;
  local_13a = 4;
  local_13c = 0x24;
  local_140 = &DAT_80316848;
  local_150 = 2;
  local_14c = FLOAT_803e1b94;
  local_148 = FLOAT_803e1b98;
  local_144 = FLOAT_803e1b94;
  local_320 = 0;
  local_334 = (undefined2)uVar2;
  local_34c = FLOAT_803e1b64;
  local_348 = FLOAT_803e1b64;
  local_344 = FLOAT_803e1b64;
  local_358 = FLOAT_803e1b64;
  local_354 = FLOAT_803e1b64;
  local_350 = FLOAT_803e1b64;
  local_340 = FLOAT_803e1b98;
  local_338 = 3;
  local_33c = 9;
  local_31f = 0x12;
  local_31e = 0;
  local_31d = 0x10;
  iVar1 = (int)(auStack_138 + -(int)local_378) / 0x18 +
          ((int)(auStack_138 + -(int)local_378) >> 0x1f);
  local_31b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_332 = DAT_803168b4;
  local_330 = DAT_803168b6;
  local_32e = DAT_803168b8;
  local_32c = DAT_803168ba;
  local_32a = DAT_803168bc;
  local_328 = DAT_803168be;
  local_326 = DAT_803168c0;
  local_324 = param_4 | 0x4000484;
  if ((param_4 & 1) != 0) {
    if (local_374 == 0) {
      local_34c = FLOAT_803e1b64 + *(float *)(param_3 + 0xc);
      local_348 = FLOAT_803e1b64 + *(float *)(param_3 + 0x10);
      local_344 = FLOAT_803e1b64 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = FLOAT_803e1b64 + *(float *)(local_374 + 0x18);
      local_348 = FLOAT_803e1b64 + *(float *)(local_374 + 0x1c);
      local_344 = FLOAT_803e1b64 + *(float *)(local_374 + 0x20);
    }
  }
  (**(code **)(*DAT_803dd6fc + 8))
            (&local_378,0,0x24,&DAT_803165e8,0x10,&DAT_80316750,
             *(undefined4 *)(&DAT_803168c4 + (int)uVar2 * 4),0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f6c24
 * EN v1.0 Address: 0x800F6988
 * EN v1.0 Size: 1100b
 * EN v1.1 Address: 0x800F6C24
 * EN v1.1 Size: 1108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f6c24(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
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
  undefined4 local_1e0;
  float local_1dc;
  float local_1d8;
  float local_1d4;
  undefined *local_1d0;
  undefined2 local_1cc;
  undefined local_1ca;
  undefined4 local_1c8;
  float local_1c4;
  float local_1c0;
  float local_1bc;
  undefined *local_1b8;
  undefined2 local_1b4;
  undefined local_1b2;
  float local_1ac;
  float local_1a8;
  float local_1a4;
  undefined *local_1a0;
  undefined2 local_19c;
  undefined local_19a;
  float local_194;
  float local_190;
  float local_18c;
  undefined *local_188;
  undefined2 local_184;
  undefined local_182;
  undefined4 local_180;
  float local_17c;
  float local_178;
  float local_174;
  undefined *local_170;
  undefined2 local_16c;
  undefined local_16a;
  undefined4 local_168;
  float local_164;
  float local_160;
  float local_15c;
  undefined *local_158;
  undefined2 local_154;
  undefined local_152;
  undefined4 local_150;
  float local_14c;
  float local_148;
  float local_144;
  undefined *local_140;
  undefined2 local_13c;
  undefined local_13a;
  undefined auStack_138 [312];
  
  local_374 = FUN_8028683c();
  local_378 = &local_318;
  local_302 = 0;
  local_304 = 9;
  local_308 = &DAT_80316ac0;
  local_318 = 2;
  local_314 = FLOAT_803e1ba0;
  local_310 = FLOAT_803e1ba4;
  local_30c = FLOAT_803e1ba0;
  local_2ea = 0;
  local_2ec = 9;
  local_2f0 = &DAT_80316ad4;
  local_300 = 2;
  local_2fc = FLOAT_803e1ba8;
  local_2f8 = FLOAT_803e1ba4;
  local_2f4 = FLOAT_803e1ba8;
  local_2d2 = 0;
  local_2d4 = 9;
  local_2d8 = &DAT_80316ae8;
  local_2e8 = 2;
  local_2e4 = FLOAT_803e1ba8;
  local_2e0 = FLOAT_803e1ba4;
  local_2dc = FLOAT_803e1ba8;
  local_2ba = 0;
  local_2bc = 9;
  local_2c0 = &DAT_80316afc;
  local_2d0 = 2;
  local_2cc = FLOAT_803e1ba8;
  local_2c8 = FLOAT_803e1ba4;
  local_2c4 = FLOAT_803e1ba8;
  local_2a2 = 0;
  local_2a4 = 0x24;
  local_2a8 = &DAT_80316b58;
  local_2b8 = 4;
  local_2b4 = FLOAT_803e1bac;
  local_2b0 = FLOAT_803e1bac;
  local_2ac = FLOAT_803e1bac;
  local_28a = 0;
  local_28c = 0;
  local_290 = 0;
  local_2a0 = 0x400000;
  local_29c = FLOAT_803e1bb0;
  local_298 = FLOAT_803e1bb4;
  local_294 = FLOAT_803e1bb8;
  local_272 = 1;
  local_274 = 0x24;
  local_278 = &DAT_80316b58;
  local_288 = 2;
  local_284 = FLOAT_803e1bbc;
  local_280 = FLOAT_803e1bc0;
  local_27c = FLOAT_803e1bbc;
  local_25a = 1;
  local_25c = 0x24;
  local_260 = &DAT_80316b58;
  local_270 = 0x4000;
  local_26c = FLOAT_803e1bac;
  local_268 = FLOAT_803e1bac;
  local_264 = FLOAT_803e1bac;
  local_242 = 1;
  local_244 = 0x24;
  local_248 = &DAT_80316b58;
  local_258 = 0x100;
  local_254 = FLOAT_803e1bac;
  local_250 = FLOAT_803e1bac;
  local_24c = FLOAT_803e1bc4;
  local_22a = 2;
  local_22c = 0x12;
  local_230 = &DAT_80316ba0;
  local_240 = 4;
  local_23c = FLOAT_803e1bc8;
  local_238 = FLOAT_803e1bac;
  local_234 = FLOAT_803e1bac;
  local_212 = 2;
  local_214 = 0x24;
  local_218 = &DAT_80316b58;
  local_228 = 2;
  local_224 = FLOAT_803e1bcc;
  local_220 = FLOAT_803e1bd0;
  local_21c = FLOAT_803e1bcc;
  local_1fa = 2;
  local_1fc = 0x24;
  local_200 = &DAT_80316b58;
  local_210 = 0x4000;
  local_20c = FLOAT_803e1bac;
  local_208 = FLOAT_803e1bac;
  local_204 = FLOAT_803e1bac;
  local_1e2 = 2;
  local_1e4 = 0;
  local_1e8 = 0;
  local_1f8 = 0x400000;
  local_1f4 = FLOAT_803e1bd4;
  local_1f0 = FLOAT_803e1bd8;
  local_1ec = FLOAT_803e1bdc;
  local_1ca = 2;
  local_1cc = 0x24;
  local_1d0 = &DAT_80316b58;
  local_1e0 = 0x100;
  local_1dc = FLOAT_803e1bac;
  local_1d8 = FLOAT_803e1bac;
  local_1d4 = FLOAT_803e1bc4;
  local_1b2 = 3;
  local_1b4 = 0x24;
  local_1b8 = &DAT_80316b58;
  local_1c8 = 0x100;
  local_1c4 = FLOAT_803e1bac;
  local_1c0 = FLOAT_803e1bac;
  local_1bc = FLOAT_803e1bc4;
  local_19a = 3;
  local_19c = 0x24;
  local_1a0 = &DAT_80316b58;
  local_1ac = FLOAT_803e1bac;
  local_1a8 = FLOAT_803e1be0;
  local_1a4 = FLOAT_803e1bac;
  local_182 = 4;
  local_184 = 0x24;
  local_188 = &DAT_80316b58;
  local_194 = FLOAT_803e1bac;
  local_190 = FLOAT_803e1be0;
  local_18c = FLOAT_803e1bac;
  local_16a = 4;
  local_16c = 0x24;
  local_170 = &DAT_80316b58;
  local_180 = 0x100;
  local_17c = FLOAT_803e1bac;
  local_178 = FLOAT_803e1bac;
  local_174 = FLOAT_803e1be4;
  local_152 = 4;
  local_154 = 0x12;
  local_158 = &DAT_80316ba0;
  local_168 = 4;
  local_164 = FLOAT_803e1bac;
  local_160 = FLOAT_803e1bac;
  local_15c = FLOAT_803e1bac;
  local_13a = 4;
  local_13c = 0x24;
  local_140 = &DAT_80316b58;
  local_150 = 2;
  local_14c = FLOAT_803e1be8;
  local_148 = FLOAT_803e1bec;
  local_144 = FLOAT_803e1be8;
  local_320 = 0;
  local_34c = FLOAT_803e1bac;
  local_348 = FLOAT_803e1bac;
  local_344 = FLOAT_803e1bac;
  local_358 = FLOAT_803e1bac;
  local_354 = FLOAT_803e1bac;
  local_350 = FLOAT_803e1bac;
  local_340 = FLOAT_803e1bec;
  local_338 = 3;
  local_33c = 9;
  local_31f = 0x12;
  local_31e = 0;
  local_31d = 0x10;
  iVar1 = (int)(auStack_138 + -(int)local_378) / 0x18 +
          ((int)(auStack_138 + -(int)local_378) >> 0x1f);
  local_31b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_332 = DAT_80316bc4;
  local_330 = DAT_80316bc6;
  local_32e = DAT_80316bc8;
  local_32c = DAT_80316bca;
  local_32a = DAT_80316bcc;
  local_328 = DAT_80316bce;
  local_326 = DAT_80316bd0;
  local_324 = param_4 | 0x4000484;
  if ((param_4 & 1) != 0) {
    if (local_374 == 0) {
      local_34c = FLOAT_803e1bac + *(float *)(param_3 + 0xc);
      local_348 = FLOAT_803e1bac + *(float *)(param_3 + 0x10);
      local_344 = FLOAT_803e1bac + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = FLOAT_803e1bac + *(float *)(local_374 + 0x18);
      local_348 = FLOAT_803e1bac + *(float *)(local_374 + 0x1c);
      local_344 = FLOAT_803e1bac + *(float *)(local_374 + 0x20);
    }
  }
  local_334 = extraout_r4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0x24,&DAT_803168f8,0x10,&DAT_80316a60,0x3f,0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f7078
 * EN v1.0 Address: 0x800F6DDC
 * EN v1.0 Size: 1616b
 * EN v1.1 Address: 0x800F7078
 * EN v1.1 Size: 1624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f7078(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  double dVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
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
  undefined4 local_2a0;
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
  undefined4 local_28;
  uint uStack_24;
  
  uVar5 = FUN_80286838();
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  iVar4 = (int)uVar5;
  if (iVar4 == 4) {
    local_312 = 0;
    local_314 = 0;
    local_318 = (undefined *)0x0;
    local_328 = 0x400000;
    local_324 = FLOAT_803e1bf0;
    local_320 = FLOAT_803e1bf4;
    local_31c = FLOAT_803e1bf4;
    local_2fa = 0;
    local_2fc = 2;
    local_300 = &DAT_803dc55c;
    local_310 = 2;
    local_30c = FLOAT_803e1bf8;
    local_308 = FLOAT_803e1bfc;
    local_304 = FLOAT_803e1bf8;
    local_2e2 = 0;
    local_2e4 = 4;
    local_2e8 = &DAT_803dc55c;
    local_2f8 = 0x80;
    uStack_24 = FUN_80022264(0xffff8008,0x7ff8);
    uStack_24 = uStack_24 ^ 0x80000000;
    dVar1 = (double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1c28;
    local_2f0 = FLOAT_803e1bf4;
    local_2ec = FLOAT_803e1c00;
  }
  else {
    local_312 = 0;
    local_314 = 2;
    local_318 = &DAT_803dc550;
    local_328 = 2;
    local_308 = *(float *)(iVar2 + 8);
    local_324 = FLOAT_803e1c04 * local_308;
    local_320 = FLOAT_803e1c08 * local_308;
    local_31c = FLOAT_803e1c0c;
    local_2fa = 0;
    local_2fc = 2;
    local_300 = &DAT_803dc55c;
    local_310 = 2;
    local_308 = local_308 / *(float *)(*(int *)(iVar2 + 0x50) + 4);
    local_30c = FLOAT_803e1c10 * local_308;
    local_308 = FLOAT_803e1c08 * local_308;
    local_304 = FLOAT_803e1c0c;
    uStack_24 = FUN_80022264(0,0xfffe);
    uStack_24 = uStack_24 ^ 0x80000000;
    dVar1 = (double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1c28;
    local_2e2 = 0;
    local_2e4 = 0;
    local_2e8 = (undefined *)0x0;
    local_2f8 = 0x80;
    local_2f0 = FLOAT_803e1c14;
    local_2ec = FLOAT_803e1bf4;
  }
  local_2f4 = (float)dVar1;
  local_28 = 0x43300000;
  local_2ca = 0;
  local_2cc = 4;
  local_2d0 = &DAT_803dc554;
  local_2e0 = 4;
  local_2dc = FLOAT_803e1bf4;
  local_2d8 = FLOAT_803e1bf4;
  local_2d4 = FLOAT_803e1bf4;
  uStack_24 = FUN_80022264(0,0xfffe);
  uStack_24 = uStack_24 ^ 0x80000000;
  local_28 = 0x43300000;
  local_2ac = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1c28);
  local_2b2 = 1;
  local_2b4 = 2;
  local_2b8 = &DAT_803dc550;
  local_2c8 = 4;
  local_2c4 = FLOAT_803e1c18;
  local_2c0 = FLOAT_803e1bf4;
  local_2bc = FLOAT_803e1bf4;
  if (iVar4 == 4) {
    local_29a = 2;
    local_2b0 = 0x100;
    local_2ac = FLOAT_803e1c1c;
    local_2a8 = FLOAT_803e1bf4;
  }
  else {
    local_29a = 1;
    local_2b0 = 0x80;
    local_2a8 = FLOAT_803e1c14;
  }
  local_29c = 0;
  local_2a0 = 0;
  local_2a4 = FLOAT_803e1bf4;
  uStack_24 = FUN_80022264(0,0xfffe);
  uStack_24 = uStack_24 ^ 0x80000000;
  local_28 = 0x43300000;
  local_27c = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1c28);
  if (iVar4 == 4) {
    local_298 = 0x100;
    local_280 = 0x100;
    local_27c = FLOAT_803e1c1c;
    local_278 = FLOAT_803e1bf4;
  }
  else {
    local_298 = 0x80;
    local_280 = 0x80;
    local_278 = FLOAT_803e1c14;
  }
  local_26a = 3;
  local_26c = 0;
  local_270 = 0;
  local_282 = 2;
  local_284 = 0;
  local_288 = 0;
  local_252 = 3;
  local_254 = 2;
  local_258 = &DAT_803dc550;
  local_268 = 4;
  local_264 = FLOAT_803e1c1c;
  local_28c = FLOAT_803e1bf4;
  local_260 = FLOAT_803e1bf4;
  local_25c = FLOAT_803e1bf4;
  local_23a = 3;
  local_23c = 4;
  local_240 = &DAT_803dc554;
  local_250 = 2;
  local_24c = FLOAT_803e1bfc;
  local_248 = FLOAT_803e1c20;
  local_244 = FLOAT_803e1c0c;
  local_330 = 0;
  local_344 = (undefined2)uVar5;
  local_35c = FLOAT_803e1bf4;
  local_358 = FLOAT_803e1bf4;
  local_354 = FLOAT_803e1bf4;
  local_368 = FLOAT_803e1bf4;
  local_364 = FLOAT_803e1bf4;
  local_360 = FLOAT_803e1bf4;
  local_350 = FLOAT_803e1c0c;
  local_348 = 2;
  local_34c = 0;
  local_32f = 4;
  local_32e = 0;
  local_32d = 0x20;
  local_32b = 10;
  local_342 = DAT_80316c2c;
  local_340 = DAT_80316c2e;
  local_33e = DAT_80316c30;
  local_33c = DAT_80316c32;
  local_33a = DAT_80316c34;
  local_338 = DAT_80316c36;
  local_336 = DAT_80316c38;
  local_388 = &local_328;
  if (iVar4 == 4) {
    local_334 = 0x4004400;
  }
  else {
    local_334 = 0x4006410;
  }
  local_334 = local_334 | param_4;
  if ((param_4 & 1) != 0) {
    if ((iVar2 == 0) || (param_3 == 0)) {
      if (iVar2 == 0) {
        if (param_3 != 0) {
          local_35c = FLOAT_803e1bf4 + *(float *)(param_3 + 0xc);
          local_358 = FLOAT_803e1bf4 + *(float *)(param_3 + 0x10);
          local_354 = FLOAT_803e1bf4 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_35c = FLOAT_803e1bf4 + *(float *)(iVar2 + 0x18);
        local_358 = FLOAT_803e1bf4 + *(float *)(iVar2 + 0x1c);
        local_354 = FLOAT_803e1bf4 + *(float *)(iVar2 + 0x20);
      }
    }
    else {
      local_35c = FLOAT_803e1bf4 + *(float *)(iVar2 + 0x18) + *(float *)(param_3 + 0xc);
      local_358 = FLOAT_803e1bf4 + *(float *)(iVar2 + 0x1c) + *(float *)(param_3 + 0x10);
      local_354 = FLOAT_803e1bf4 + *(float *)(iVar2 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_384 = iVar2;
  local_294 = local_27c;
  local_290 = local_278;
  local_274 = local_28c;
  uVar3 = FUN_80022264(0,1);
  (**(code **)(*DAT_803dd6fc + 8))
            (&local_388,0,4,&DAT_80316bf8,2,&DAT_80316c20,
             (int)*(short *)(&DAT_80316c3c + (iVar4 * 2 + uVar3) * 2),0);
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f76d0
 * EN v1.0 Address: 0x800F7434
 * EN v1.0 Size: 896b
 * EN v1.1 Address: 0x800F76D0
 * EN v1.1 Size: 904b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f76d0(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  double in_f30;
  double dVar2;
  double in_f31;
  double dVar3;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar4;
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
  undefined4 local_348;
  undefined2 local_344;
  undefined local_342;
  undefined4 local_340;
  float local_33c;
  float local_338;
  float local_334;
  undefined4 local_330;
  undefined2 local_32c;
  undefined local_32a;
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
  undefined auStack_2e0 [648];
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar4 = FUN_80286840();
  local_3b4 = (int)((ulonglong)uVar4 >> 0x20);
  iVar1 = (int)uVar4;
  dVar3 = (double)FLOAT_803e1c30;
  dVar2 = (double)FLOAT_803e1c34;
  local_344 = 100;
  if (iVar1 == 0) {
    dVar3 = (double)FLOAT_803e1c38;
    dVar2 = (double)FLOAT_803e1c3c;
    local_344 = 0x410;
  }
  else if (iVar1 == 1) {
    dVar3 = (double)FLOAT_803e1c40;
    dVar2 = (double)FLOAT_803e1c44;
    local_344 = 0x410;
  }
  else if (iVar1 == 2) {
    dVar3 = (double)FLOAT_803e1c48;
    dVar2 = (double)FLOAT_803e1c4c;
    local_344 = 0x410;
  }
  else if (iVar1 == 3) {
    dVar3 = (double)FLOAT_803e1c48;
    dVar2 = (double)FLOAT_803e1c4c;
    local_344 = 0x410;
  }
  local_342 = 0;
  local_348 = 0;
  local_358 = 0x20000000;
  local_354 = FLOAT_803e1c50;
  local_350 = (float)dVar3;
  local_34c = (float)dVar2;
  local_32a = 1;
  local_32c = 0;
  local_330 = 0;
  local_340 = 0x400000;
  uStack_54 = FUN_80022264(0xffffff9c,100);
  uStack_54 = uStack_54 ^ 0x80000000;
  local_58 = 0x43300000;
  local_33c = (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e1c60);
  local_338 = FLOAT_803e1c54;
  uStack_4c = FUN_80022264(0xfffffb50,0xfffffce0);
  uStack_4c = uStack_4c ^ 0x80000000;
  local_50 = 0x43300000;
  local_334 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e1c60);
  local_312 = 1;
  local_314 = 0;
  local_318 = 0;
  local_328 = 0x40000000;
  local_324 = local_33c;
  local_320 = FLOAT_803e1c54;
  local_31c = local_338;
  local_2fa = 1;
  local_2fc = 0x65;
  local_300 = 0;
  local_310 = 0x800000;
  local_30c = FLOAT_803e1c58;
  local_308 = FLOAT_803e1c58;
  local_304 = FLOAT_803e1c54;
  local_2e2 = 2;
  local_2e4 = 0;
  local_2e8 = 0;
  local_2f8 = 0x20000000;
  local_2f4 = FLOAT_803e1c50;
  local_2f0 = (float)dVar3;
  local_2ec = (float)dVar2;
  local_360 = 0;
  local_374 = (undefined2)uVar4;
  uStack_44 = FUN_80022264(0xffffff9c,100);
  uStack_44 = uStack_44 ^ 0x80000000;
  local_48 = 0x43300000;
  local_38c = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e1c60);
  local_388 = FLOAT_803e1c54;
  local_384 = FLOAT_803e1c54;
  local_398 = FLOAT_803e1c54;
  local_394 = FLOAT_803e1c54;
  local_390 = FLOAT_803e1c54;
  local_380 = FLOAT_803e1c58;
  local_378 = 0;
  local_37c = 0;
  local_35f = 0;
  local_35e = 0;
  local_35d = 0;
  iVar1 = (int)(auStack_2e0 + -(int)&local_358) / 0x18 +
          ((int)(auStack_2e0 + -(int)&local_358) >> 0x1f);
  local_35b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_372 = DAT_80316c70;
  local_370 = DAT_80316c72;
  local_36e = DAT_80316c74;
  local_36c = DAT_80316c76;
  local_36a = DAT_80316c78;
  local_368 = DAT_80316c7a;
  local_366 = DAT_80316c7c;
  local_364 = param_4 | 0x10400;
  if ((param_4 & 1) != 0) {
    if (local_3b4 == 0) {
      local_38c = local_38c + *(float *)(param_3 + 0xc);
      local_388 = FLOAT_803e1c54 + *(float *)(param_3 + 0x10);
      local_384 = FLOAT_803e1c54 + *(float *)(param_3 + 0x14);
    }
    else {
      local_38c = local_38c + *(float *)(local_3b4 + 0x18);
      local_388 = FLOAT_803e1c54 + *(float *)(local_3b4 + 0x1c);
      local_384 = FLOAT_803e1c54 + *(float *)(local_3b4 + 0x20);
    }
  }
  local_3b8 = &local_358;
  (**(code **)(*DAT_803dd6fc + 8))(&local_3b8,0,0,0,0,0,0,0);
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f7a58
 * EN v1.0 Address: 0x800F77BC
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x800F7A58
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f7a58(int param_1,undefined2 param_2,int param_3,uint param_4)
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
  undefined auStack_228 [540];
  
  local_378 = &local_318;
  local_302 = 0;
  local_304 = 10;
  local_308 = &DAT_80316e4c;
  local_318 = 2;
  local_314 = FLOAT_803e1c68;
  local_310 = FLOAT_803e1c6c;
  local_30c = FLOAT_803e1c68;
  local_2ea = 0;
  local_2ec = 10;
  local_2f0 = &DAT_80316e4c;
  local_300 = 4;
  local_2fc = FLOAT_803e1c70;
  local_2f8 = FLOAT_803e1c70;
  local_2f4 = FLOAT_803e1c70;
  local_2d2 = 0;
  local_2d4 = 0;
  local_2d8 = 0;
  local_2e8 = 0x400000;
  local_2e4 = FLOAT_803e1c74;
  local_2e0 = FLOAT_803e1c78;
  local_2dc = FLOAT_803e1c7c;
  local_2ba = 1;
  local_2bc = 10;
  local_2c0 = &DAT_80316e4c;
  local_2d0 = 0x4000;
  local_2cc = FLOAT_803e1c80;
  local_2c8 = FLOAT_803e1c80;
  local_2c4 = FLOAT_803e1c70;
  local_2a2 = 0;
  local_2a4 = 9;
  local_2a8 = &DAT_80316e38;
  local_2b8 = 2;
  local_2b4 = FLOAT_803e1c84;
  local_2b0 = FLOAT_803e1c6c;
  local_2ac = FLOAT_803e1c84;
  local_28a = 2;
  local_28c = 1;
  local_290 = &DAT_803dc560;
  local_2a0 = 4;
  local_29c = FLOAT_803e1c88;
  local_298 = FLOAT_803e1c70;
  local_294 = FLOAT_803e1c70;
  local_272 = 2;
  local_274 = 10;
  local_278 = &DAT_80316e4c;
  local_288 = 0x4000;
  local_284 = FLOAT_803e1c80;
  local_280 = FLOAT_803e1c80;
  local_27c = FLOAT_803e1c70;
  local_25a = 3;
  local_25c = 10;
  local_260 = &DAT_80316e4c;
  local_270 = 0x4000;
  local_26c = FLOAT_803e1c80;
  local_268 = FLOAT_803e1c80;
  local_264 = FLOAT_803e1c70;
  local_242 = 4;
  local_244 = 10;
  local_248 = &DAT_80316e4c;
  local_258 = 0x4000;
  local_254 = FLOAT_803e1c80;
  local_250 = FLOAT_803e1c80;
  local_24c = FLOAT_803e1c70;
  local_22a = 4;
  local_22c = 10;
  local_230 = &DAT_80316e4c;
  local_240 = 4;
  local_23c = FLOAT_803e1c70;
  local_238 = FLOAT_803e1c70;
  local_234 = FLOAT_803e1c70;
  local_320 = 0;
  local_34c = FLOAT_803e1c70;
  local_348 = FLOAT_803e1c70;
  local_344 = FLOAT_803e1c70;
  local_358 = FLOAT_803e1c70;
  local_354 = FLOAT_803e1c70;
  local_350 = FLOAT_803e1c70;
  local_340 = FLOAT_803e1c80;
  local_338 = 1;
  local_33c = 10;
  local_31f = 10;
  local_31e = 0;
  local_31d = 0x10;
  iVar1 = (int)(auStack_228 + -(int)local_378) / 0x18 +
          ((int)(auStack_228 + -(int)local_378) >> 0x1f);
  local_31b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_332 = DAT_80316e60;
  local_330 = DAT_80316e62;
  local_32e = DAT_80316e64;
  local_32c = DAT_80316e66;
  local_32a = DAT_80316e68;
  local_328 = DAT_80316e6a;
  local_326 = DAT_80316e6c;
  local_324 = param_4 | 0x4000494;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = FLOAT_803e1c70 + *(float *)(param_3 + 0xc);
      local_348 = FLOAT_803e1c70 + *(float *)(param_3 + 0x10);
      local_344 = FLOAT_803e1c70 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = FLOAT_803e1c70 + *(float *)(param_1 + 0x18);
      local_348 = FLOAT_803e1c70 + *(float *)(param_1 + 0x1c);
      local_344 = FLOAT_803e1c70 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_334 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,10,&DAT_80316ca0,8,&DAT_80316e08,0x1fd,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f7d5c
 * EN v1.0 Address: 0x800F7AC0
 * EN v1.0 Size: 712b
 * EN v1.1 Address: 0x800F7D5C
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f7d5c(int param_1,undefined2 param_2,int param_3,uint param_4)
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
  undefined auStack_230 [552];
  
  local_368 = &local_308;
  local_2f2 = 0;
  local_2f4 = 0x19;
  local_2f8 = &DAT_8031704c;
  local_308 = 2;
  local_304 = FLOAT_803e1c90;
  local_300 = FLOAT_803e1c90;
  local_2fc = FLOAT_803e1c90;
  local_2da = 0;
  local_2dc = 0x19;
  local_2e0 = &DAT_8031704c;
  local_2f0 = 0x80;
  local_2ec = FLOAT_803e1c94;
  local_2e8 = FLOAT_803e1c94;
  local_2e4 = FLOAT_803e1c94;
  local_2c2 = 0;
  local_2c4 = 0x7a;
  local_2c8 = 0;
  local_2d8 = 0x10000;
  local_2d4 = FLOAT_803e1c94;
  local_2d0 = FLOAT_803e1c94;
  local_2cc = FLOAT_803e1c94;
  local_2aa = 0;
  local_2ac = 0x19;
  local_2b0 = &DAT_8031704c;
  local_2c0 = 4;
  local_2bc = FLOAT_803e1c94;
  local_2b8 = FLOAT_803e1c94;
  local_2b4 = FLOAT_803e1c94;
  local_292 = 1;
  local_294 = 0x19;
  local_298 = &DAT_8031704c;
  local_2a8 = 4;
  local_2a4 = FLOAT_803e1c98;
  local_2a0 = FLOAT_803e1c94;
  local_29c = FLOAT_803e1c94;
  local_27a = 1;
  local_27c = 0x19;
  local_280 = &DAT_8031704c;
  local_290 = 2;
  local_28c = FLOAT_803e1c9c;
  local_288 = FLOAT_803e1c9c;
  local_284 = FLOAT_803e1ca0;
  local_262 = 2;
  local_264 = 0x19;
  local_268 = &DAT_8031704c;
  local_278 = 2;
  local_274 = FLOAT_803e1ca4;
  local_270 = FLOAT_803e1ca4;
  local_26c = FLOAT_803e1ca0;
  local_24a = 3;
  local_24c = 0x19;
  local_250 = &DAT_8031704c;
  local_260 = 2;
  local_25c = FLOAT_803e1ca4;
  local_258 = FLOAT_803e1ca4;
  local_254 = FLOAT_803e1ca0;
  local_232 = 3;
  local_234 = 0x19;
  local_238 = &DAT_8031704c;
  local_248 = 4;
  local_244 = FLOAT_803e1c94;
  local_240 = FLOAT_803e1c94;
  local_23c = FLOAT_803e1c94;
  local_310 = 0;
  local_33c = FLOAT_803e1c94;
  local_338 = FLOAT_803e1c94;
  local_334 = FLOAT_803e1c94;
  local_348 = FLOAT_803e1c94;
  local_344 = FLOAT_803e1c94;
  local_340 = FLOAT_803e1c94;
  local_330 = FLOAT_803e1ca0;
  local_328 = 1;
  local_32c = 0x19;
  local_30f = 0x19;
  local_30e = 0xff;
  local_30d = 0x10;
  iVar1 = (int)(auStack_230 + -(int)local_368) / 0x18 +
          ((int)(auStack_230 + -(int)local_368) >> 0x1f);
  local_30b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_322 = DAT_80317080;
  local_320 = DAT_80317082;
  local_31e = DAT_80317084;
  local_31c = DAT_80317086;
  local_31a = DAT_80317088;
  local_318 = DAT_8031708a;
  local_316 = DAT_8031708c;
  local_314 = param_4 | 0x4000480;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = FLOAT_803e1c94 + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1c94 + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1c94 + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = FLOAT_803e1c94 + *(float *)(param_1 + 0x18);
      local_338 = FLOAT_803e1c94 + *(float *)(param_1 + 0x1c);
      local_334 = FLOAT_803e1c94 + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  local_324 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,0x19,&DAT_80316e90,0x20,&DAT_80316f8c,0x205,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f802c
 * EN v1.0 Address: 0x800F7D90
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x800F802C
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f802c(int param_1,undefined2 param_2,int param_3,uint param_4)
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
  undefined auStack_228 [540];
  
  local_378 = &local_318;
  local_302 = 0;
  local_304 = 10;
  local_308 = &DAT_8031725c;
  local_318 = 2;
  local_314 = FLOAT_803e1ca8;
  local_310 = FLOAT_803e1cac;
  local_30c = FLOAT_803e1ca8;
  local_2ea = 0;
  local_2ec = 10;
  local_2f0 = &DAT_8031725c;
  local_300 = 4;
  local_2fc = FLOAT_803e1cb0;
  local_2f8 = FLOAT_803e1cb0;
  local_2f4 = FLOAT_803e1cb0;
  local_2d2 = 0;
  local_2d4 = 0;
  local_2d8 = 0;
  local_2e8 = 0x400000;
  local_2e4 = FLOAT_803e1cb4;
  local_2e0 = FLOAT_803e1cb8;
  local_2dc = FLOAT_803e1cbc;
  local_2ba = 1;
  local_2bc = 10;
  local_2c0 = &DAT_8031725c;
  local_2d0 = 0x4000;
  local_2cc = FLOAT_803e1cc0;
  local_2c8 = FLOAT_803e1cc0;
  local_2c4 = FLOAT_803e1cb0;
  local_2a2 = 0;
  local_2a4 = 9;
  local_2a8 = &DAT_80317248;
  local_2b8 = 2;
  local_2b4 = FLOAT_803e1cc4;
  local_2b0 = FLOAT_803e1cac;
  local_2ac = FLOAT_803e1cc4;
  local_28a = 2;
  local_28c = 1;
  local_290 = &DAT_803dc568;
  local_2a0 = 4;
  local_29c = FLOAT_803e1cc8;
  local_298 = FLOAT_803e1cb0;
  local_294 = FLOAT_803e1cb0;
  local_272 = 2;
  local_274 = 10;
  local_278 = &DAT_8031725c;
  local_288 = 0x4000;
  local_284 = FLOAT_803e1cc0;
  local_280 = FLOAT_803e1cc0;
  local_27c = FLOAT_803e1cb0;
  local_25a = 3;
  local_25c = 10;
  local_260 = &DAT_8031725c;
  local_270 = 0x4000;
  local_26c = FLOAT_803e1cc0;
  local_268 = FLOAT_803e1cc0;
  local_264 = FLOAT_803e1cb0;
  local_242 = 4;
  local_244 = 10;
  local_248 = &DAT_8031725c;
  local_258 = 0x4000;
  local_254 = FLOAT_803e1cc0;
  local_250 = FLOAT_803e1cc0;
  local_24c = FLOAT_803e1cb0;
  local_22a = 4;
  local_22c = 10;
  local_230 = &DAT_8031725c;
  local_240 = 4;
  local_23c = FLOAT_803e1cb0;
  local_238 = FLOAT_803e1cb0;
  local_234 = FLOAT_803e1cb0;
  local_320 = 0;
  local_34c = FLOAT_803e1cb0;
  local_348 = FLOAT_803e1cb0;
  local_344 = FLOAT_803e1cb0;
  local_358 = FLOAT_803e1cb0;
  local_354 = FLOAT_803e1cb0;
  local_350 = FLOAT_803e1cb0;
  local_340 = FLOAT_803e1cb0;
  local_338 = 1;
  local_33c = 10;
  local_31f = 10;
  local_31e = 0;
  local_31d = 0x10;
  iVar1 = (int)(auStack_228 + -(int)local_378) / 0x18 +
          ((int)(auStack_228 + -(int)local_378) >> 0x1f);
  local_31b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_332 = DAT_80317270;
  local_330 = DAT_80317272;
  local_32e = DAT_80317274;
  local_32c = DAT_80317276;
  local_32a = DAT_80317278;
  local_328 = DAT_8031727a;
  local_326 = DAT_8031727c;
  local_324 = param_4 | 0x4000494;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = FLOAT_803e1cb0 + *(float *)(param_3 + 0xc);
      local_348 = FLOAT_803e1cb0 + *(float *)(param_3 + 0x10);
      local_344 = FLOAT_803e1cb0 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = FLOAT_803e1cb0 + *(float *)(param_1 + 0x18);
      local_348 = FLOAT_803e1cb0 + *(float *)(param_1 + 0x1c);
      local_344 = FLOAT_803e1cb0 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_334 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,10,&DAT_803170b0,8,&DAT_80317218,0x1fd,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f8330
 * EN v1.0 Address: 0x800F8094
 * EN v1.0 Size: 436b
 * EN v1.1 Address: 0x800F8330
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f8330(int param_1,undefined2 param_2,int param_3,uint param_4)
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
  undefined *local_2f8;
  undefined2 local_2f4;
  undefined local_2f2;
  undefined auStack_2f0 [752];
  
  local_368 = &local_308;
  local_2f2 = 0;
  local_2f4 = 8;
  local_2f8 = &DAT_80317338;
  local_308 = 2;
  local_304 = FLOAT_803e1cd0;
  local_300 = FLOAT_803e1cd0;
  local_2fc = FLOAT_803e1cd0;
  local_310 = 0;
  local_33c = FLOAT_803e1cd4;
  local_338 = FLOAT_803e1cd4;
  local_334 = FLOAT_803e1cd4;
  local_348 = FLOAT_803e1cd4;
  local_344 = FLOAT_803e1cd4;
  local_340 = FLOAT_803e1cd4;
  local_330 = FLOAT_803e1cd8;
  local_328 = 1;
  local_32c = 0;
  local_30f = 8;
  local_30e = 0;
  local_30d = 0x10;
  iVar1 = (int)(auStack_2f0 + -(int)local_368) / 0x18 +
          ((int)(auStack_2f0 + -(int)local_368) >> 0x1f);
  local_30b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_322 = DAT_80317348;
  local_320 = DAT_8031734a;
  local_31e = DAT_8031734c;
  local_31c = DAT_8031734e;
  local_31a = DAT_80317350;
  local_318 = DAT_80317352;
  local_316 = DAT_80317354;
  local_314 = param_4 | 0x2000492;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_33c = FLOAT_803e1cd4 + *(float *)(param_3 + 0xc);
      local_338 = FLOAT_803e1cd4 + *(float *)(param_3 + 0x10);
      local_334 = FLOAT_803e1cd4 + *(float *)(param_3 + 0x14);
    }
    else {
      local_33c = FLOAT_803e1cd4 + *(float *)(param_1 + 0x18);
      local_338 = FLOAT_803e1cd4 + *(float *)(param_1 + 0x1c);
      local_334 = FLOAT_803e1cd4 + *(float *)(param_1 + 0x20);
    }
  }
  local_364 = param_1;
  local_324 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_368,0,8,&DAT_803172a0,0xc,&DAT_803172f0,0x1fd,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f84ec
 * EN v1.0 Address: 0x800F8250
 * EN v1.0 Size: 1424b
 * EN v1.1 Address: 0x800F84EC
 * EN v1.1 Size: 1432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f84ec(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,undefined4 param_5,
                 float *param_6)
{
  float fVar1;
  int iVar2;
  short *psVar3;
  int iVar4;
  int iVar5;
  double in_f20;
  double dVar6;
  double in_f21;
  double dVar7;
  double in_f22;
  double dVar8;
  double in_f23;
  double dVar9;
  double in_f24;
  double dVar10;
  double in_f25;
  double dVar11;
  double in_f26;
  double dVar12;
  double in_f27;
  double dVar13;
  double in_f28;
  double dVar14;
  double in_f29;
  double dVar15;
  double in_f30;
  double dVar16;
  double in_f31;
  double dVar17;
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
  undefined8 uVar18;
  undefined4 *local_468;
  short *local_464;
  float local_448;
  float local_444;
  float local_440;
  float local_43c;
  float local_438;
  float local_434;
  float local_430;
  undefined4 local_42c;
  undefined4 local_428;
  undefined2 local_424;
  undefined2 local_422;
  undefined2 local_420;
  undefined2 local_41e;
  undefined2 local_41c;
  undefined2 local_41a;
  undefined2 local_418;
  undefined2 local_416;
  uint local_414;
  undefined local_410;
  undefined local_40f;
  undefined local_40e;
  undefined local_40d;
  char local_40b;
  undefined4 local_408;
  float local_404;
  float local_400;
  float local_3fc;
  undefined *local_3f8;
  undefined2 local_3f4;
  undefined local_3f2;
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
  undefined *local_3c8;
  undefined2 local_3c4;
  undefined local_3c2;
  undefined4 local_3c0;
  float local_3bc;
  float local_3b8;
  float local_3b4;
  undefined4 local_3b0;
  undefined2 local_3ac;
  undefined local_3aa;
  undefined4 local_3a8;
  float local_3a4;
  float local_3a0;
  float local_39c;
  undefined *local_398;
  undefined2 local_394;
  undefined local_392;
  undefined4 local_390;
  float local_38c;
  float local_388;
  float local_384;
  undefined *local_380;
  undefined2 local_37c;
  undefined local_37a;
  undefined4 local_378;
  float local_374;
  float local_370;
  float local_36c;
  undefined *local_368;
  undefined2 local_364;
  undefined local_362;
  undefined4 local_360;
  float local_35c;
  float local_358;
  float local_354;
  undefined *local_350;
  undefined2 local_34c;
  undefined local_34a;
  undefined4 local_348;
  float local_344;
  float local_340;
  float local_33c;
  undefined *local_338;
  undefined2 local_334;
  undefined local_332;
  undefined4 local_330;
  float local_32c;
  float local_328;
  float local_324;
  undefined *local_320;
  undefined2 local_31c;
  undefined local_31a;
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
  undefined auStack_2e8 [480];
  undefined4 local_108;
  uint uStack_104;
  undefined4 local_100;
  uint uStack_fc;
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
  uVar18 = FUN_8028681c();
  psVar3 = (short *)((ulonglong)uVar18 >> 0x20);
  iVar4 = (int)uVar18;
  dVar7 = (double)FLOAT_803e1ce0;
  dVar6 = (double)FLOAT_803e1ce4;
  fVar1 = FLOAT_803e1ce8;
  if (param_6 != (float *)0x0) {
    fVar1 = *param_6;
  }
  iVar5 = 0;
  dVar8 = (double)(FLOAT_803e1cec + fVar1);
  dVar9 = (double)FLOAT_803e1cf4;
  dVar11 = (double)FLOAT_803e1cf8;
  dVar12 = (double)FLOAT_803e1cfc;
  dVar13 = (double)FLOAT_803e1d18;
  dVar14 = (double)FLOAT_803e1d1c;
  dVar15 = (double)FLOAT_803e1d20;
  dVar16 = (double)FLOAT_803e1d14;
  dVar17 = (double)FLOAT_803e1d24;
  dVar10 = DOUBLE_803e1d28;
  do {
    if (iVar5 == 1) {
      dVar7 = (double)FLOAT_803e1ce0;
      dVar6 = (double)FLOAT_803e1cf0;
    }
    local_3f2 = 0;
    local_3f4 = 0x15;
    local_3f8 = &DAT_80317528;
    local_408 = 4;
    local_404 = (float)dVar9;
    local_400 = (float)dVar9;
    local_3fc = (float)dVar9;
    local_3da = 0;
    local_3dc = 0x15;
    local_3e0 = &DAT_80317528;
    local_3f0 = 0x80;
    local_3ec = (float)dVar9;
    uStack_104 = (int)psVar3[1] ^ 0x80000000;
    local_108 = 0x43300000;
    local_3e8 = (float)((double)CONCAT44(0x43300000,uStack_104) - dVar10);
    uStack_fc = (int)*psVar3 ^ 0x80000000;
    local_100 = 0x43300000;
    local_3e4 = (float)(dVar11 + (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                  uStack_fc) -
                                                                dVar10) - dVar12));
    if (iVar5 == 0) {
      if (iVar4 == 4) {
        local_3d0 = FLOAT_803e1d00;
      }
      else {
        local_3d0 = FLOAT_803e1d04;
      }
    }
    else if (iVar4 == 4) {
      local_3d0 = FLOAT_803e1d08;
    }
    else {
      local_3d0 = FLOAT_803e1cec;
    }
    local_3cc = (float)dVar8;
    local_3c2 = 0;
    local_3c4 = 0x15;
    local_3c8 = &DAT_80317528;
    local_3d8 = 2;
    local_3aa = 0;
    local_3ac = 0;
    local_3b0 = 0;
    local_3c0 = 0x400000;
    if (iVar4 == 2) {
      local_3bc = FLOAT_803e1d0c;
      local_3b8 = FLOAT_803e1cf4;
      local_3b4 = FLOAT_803e1cf4;
    }
    else if (iVar4 < 2) {
      if (iVar4 == 0) {
        local_3bc = FLOAT_803e1cf4;
        local_3b8 = FLOAT_803e1d0c;
        local_3b4 = FLOAT_803e1cf4;
      }
      else if (-1 < iVar4) {
        local_3bc = FLOAT_803e1cf4;
        local_3b8 = FLOAT_803e1d10;
        local_3b4 = FLOAT_803e1cf4;
      }
    }
    else if (iVar4 == 4) {
      local_3bc = FLOAT_803e1cf4;
      local_3b8 = FLOAT_803e1d14;
      local_3b4 = FLOAT_803e1cf4;
    }
    else if (iVar4 < 4) {
      local_3bc = FLOAT_803e1d10;
      local_3b8 = FLOAT_803e1cf4;
      local_3b4 = FLOAT_803e1cf4;
    }
    local_392 = 1;
    local_394 = 0x15;
    local_398 = &DAT_80317528;
    local_3a8 = 4;
    local_3a4 = (float)dVar13;
    local_3a0 = (float)dVar9;
    local_39c = (float)dVar9;
    local_37a = 1;
    local_37c = 0x15;
    local_380 = &DAT_80317528;
    local_390 = 2;
    local_38c = (float)dVar14;
    local_388 = (float)dVar14;
    local_384 = (float)dVar15;
    local_362 = 1;
    local_364 = 0x15;
    local_368 = &DAT_80317528;
    local_378 = 0x4000;
    local_374 = (float)dVar7;
    local_370 = (float)dVar6;
    local_36c = (float)dVar9;
    local_34a = 2;
    local_34c = 0x15;
    local_350 = &DAT_80317528;
    local_360 = 4;
    local_35c = (float)dVar13;
    local_358 = (float)dVar9;
    local_354 = (float)dVar9;
    local_332 = 2;
    local_334 = 0x15;
    local_338 = &DAT_80317528;
    local_348 = 0x4000;
    local_344 = (float)dVar7;
    local_340 = (float)dVar6;
    local_33c = (float)dVar9;
    local_31a = 3;
    local_31c = 0x15;
    local_320 = &DAT_80317528;
    local_330 = 0x4000;
    local_32c = (float)dVar7;
    local_328 = (float)dVar6;
    local_324 = (float)dVar9;
    local_302 = 3;
    local_304 = 0x15;
    local_308 = &DAT_80317528;
    local_318 = 4;
    local_314 = (float)dVar9;
    local_310 = (float)dVar9;
    local_30c = (float)dVar9;
    local_2ea = 3;
    local_2ec = 0x15;
    local_2f0 = &DAT_80317528;
    local_300 = 2;
    local_2fc = (float)dVar16;
    local_2f8 = (float)dVar16;
    local_2f4 = (float)dVar16;
    local_410 = 0;
    local_43c = (float)dVar9;
    local_438 = (float)dVar9;
    local_434 = (float)dVar9;
    local_448 = (float)dVar9;
    local_444 = (float)dVar9;
    local_440 = (float)dVar9;
    local_430 = (float)dVar17;
    local_428 = 2;
    local_42c = 7;
    local_40f = 0xe;
    local_40e = 0;
    local_40d = 0x28;
    iVar2 = (int)(auStack_2e8 + -(int)&local_408) / 0x18 +
            ((int)(auStack_2e8 + -(int)&local_408) >> 0x1f);
    local_40b = (char)iVar2 - (char)(iVar2 >> 0x1f);
    local_422 = DAT_80317570;
    local_420 = DAT_80317572;
    local_41e = DAT_80317574;
    local_41c = DAT_80317576;
    local_41a = DAT_80317578;
    local_418 = DAT_8031757a;
    local_416 = DAT_8031757c;
    if ((param_4 & 1) != 0) {
      if (psVar3 == (short *)0x0) {
        local_43c = (float)(dVar9 + (double)*(float *)(param_3 + 0xc));
        local_438 = (float)(dVar9 + (double)*(float *)(param_3 + 0x10));
        local_434 = (float)(dVar9 + (double)*(float *)(param_3 + 0x14));
      }
      else {
        local_43c = (float)(dVar9 + (double)*(float *)(psVar3 + 0xc));
        local_438 = (float)(dVar9 + (double)*(float *)(psVar3 + 0xe));
        local_434 = (float)(dVar9 + (double)*(float *)(psVar3 + 0x10));
      }
    }
    local_468 = &local_408;
    local_464 = psVar3;
    local_424 = (short)uVar18;
    local_414 = param_4 | 0xc0104c0;
    local_3d4 = local_3d0;
    (**(code **)(*DAT_803dd6fc + 8))(&local_468,0,0x15,&DAT_80317378,0x18,&DAT_8031744c,0xd9,0);
    iVar5 = iVar5 + 1;
  } while (iVar5 < 2);
  FUN_80286868();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f8a84
 * EN v1.0 Address: 0x800F87E8
 * EN v1.0 Size: 1400b
 * EN v1.1 Address: 0x800F8A84
 * EN v1.1 Size: 1408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f8a84(int param_1,undefined2 param_2,short *param_3,uint param_4)
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
  undefined4 local_248;
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
  undefined *local_1e8;
  undefined2 local_1e4;
  undefined local_1e2;
  undefined4 local_1e0;
  float local_1dc;
  float local_1d8;
  float local_1d4;
  undefined *local_1d0;
  undefined2 local_1cc;
  undefined local_1ca;
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  undefined4 local_8;
  uint uStack_4;
  
  local_302 = 0;
  local_304 = 0x15;
  local_308 = &DAT_80317750;
  local_318 = 4;
  local_314 = FLOAT_803e1d30;
  local_310 = FLOAT_803e1d30;
  local_30c = FLOAT_803e1d30;
  local_2ea = 0;
  local_2ec = 0xe;
  local_2f0 = &DAT_80317734;
  local_300 = 2;
  if (param_3 == (short *)0x0) {
    local_2fc = FLOAT_803e1d38;
    local_2f8 = FLOAT_803e1d3c;
    local_2f4 = FLOAT_803e1d38;
  }
  else {
    uStack_14 = (int)param_3[2] ^ 0x80000000;
    local_18 = 0x43300000;
    local_2fc = FLOAT_803e1d34 *
                FLOAT_803e1d38 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e1d58);
    uStack_c = (int)*param_3 ^ 0x80000000;
    local_10 = 0x43300000;
    local_2f8 = FLOAT_803e1d34 *
                FLOAT_803e1d3c * (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e1d58);
    local_8 = 0x43300000;
    local_2f4 = FLOAT_803e1d34 *
                FLOAT_803e1d38 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e1d58);
    uStack_4 = uStack_14;
  }
  local_2d2 = 0;
  local_2d4 = 7;
  local_2d8 = &DAT_80317714;
  local_2e8 = 2;
  if (param_3 == (short *)0x0) {
    local_2e4 = FLOAT_803e1d38;
    local_2e0 = FLOAT_803e1d3c;
    local_2dc = FLOAT_803e1d38;
  }
  else {
    uStack_14 = (int)param_3[2] ^ 0x80000000;
    local_8 = 0x43300000;
    local_2e4 = FLOAT_803e1d34 *
                FLOAT_803e1d38 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e1d58);
    uStack_c = (int)*param_3 ^ 0x80000000;
    local_10 = 0x43300000;
    local_2e0 = FLOAT_803e1d34 *
                FLOAT_803e1d40 * (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e1d58);
    local_18 = 0x43300000;
    local_2dc = FLOAT_803e1d34 *
                FLOAT_803e1d38 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e1d58);
    uStack_4 = uStack_14;
  }
  local_2ba = 1;
  local_2bc = 7;
  local_2c0 = &DAT_80317714;
  local_2d0 = 4;
  local_2cc = FLOAT_803e1d44;
  local_2c8 = FLOAT_803e1d30;
  local_2c4 = FLOAT_803e1d30;
  local_2a2 = 1;
  local_2a4 = 7;
  local_2a8 = &DAT_80317724;
  local_2b8 = 4;
  local_2b4 = FLOAT_803e1d44;
  local_2b0 = FLOAT_803e1d30;
  local_2ac = FLOAT_803e1d30;
  local_28a = 1;
  local_28c = 0x15;
  local_290 = &DAT_80317750;
  local_2a0 = 0x100;
  local_29c = FLOAT_803e1d30;
  local_298 = FLOAT_803e1d30;
  if (param_3 == (short *)0x0) {
    local_294 = FLOAT_803e1d48;
  }
  else {
    uStack_4 = (int)param_3[1] ^ 0x80000000;
    local_8 = 0x43300000;
    local_294 = (float)((double)CONCAT44(0x43300000,uStack_4) - DOUBLE_803e1d58);
  }
  local_272 = 2;
  local_274 = 0x3a;
  local_278 = 0;
  local_288 = 0x1800000;
  local_284 = FLOAT_803e1d4c;
  local_280 = FLOAT_803e1d30;
  local_27c = FLOAT_803e1d50;
  local_25a = 2;
  local_25c = 0x15;
  local_260 = &DAT_80317750;
  local_270 = 0x100;
  local_26c = FLOAT_803e1d30;
  local_268 = FLOAT_803e1d30;
  if (param_3 == (short *)0x0) {
    local_264 = FLOAT_803e1d48;
  }
  else {
    uStack_4 = (int)param_3[1] ^ 0x80000000;
    local_8 = 0x43300000;
    local_264 = (float)((double)CONCAT44(0x43300000,uStack_4) - DOUBLE_803e1d58);
  }
  local_242 = 3;
  local_244 = 0x3b8;
  local_248 = 0;
  local_258 = 0x1800000;
  local_254 = FLOAT_803e1d4c;
  local_250 = FLOAT_803e1d30;
  local_24c = FLOAT_803e1d50;
  local_22a = 3;
  local_22c = 0x15;
  local_230 = &DAT_80317750;
  local_240 = 0x100;
  local_23c = FLOAT_803e1d30;
  local_238 = FLOAT_803e1d30;
  if (param_3 == (short *)0x0) {
    local_234 = FLOAT_803e1d48;
  }
  else {
    uStack_4 = (int)param_3[1] ^ 0x80000000;
    local_8 = 0x43300000;
    local_234 = (float)((double)CONCAT44(0x43300000,uStack_4) - DOUBLE_803e1d58);
  }
  local_212 = 4;
  local_214 = 0;
  local_218 = 0;
  local_228 = 0x1000;
  local_224 = FLOAT_803e1d54;
  local_220 = FLOAT_803e1d30;
  local_21c = FLOAT_803e1d30;
  local_1fa = 5;
  local_1fc = 7;
  local_200 = &DAT_80317714;
  local_210 = 4;
  local_20c = FLOAT_803e1d30;
  local_208 = FLOAT_803e1d30;
  local_204 = FLOAT_803e1d30;
  local_1e2 = 5;
  local_1e4 = 7;
  local_1e8 = &DAT_80317724;
  local_1f8 = 4;
  local_1f4 = FLOAT_803e1d30;
  local_1f0 = FLOAT_803e1d30;
  local_1ec = FLOAT_803e1d30;
  local_1ca = 5;
  local_1cc = 0x15;
  local_1d0 = &DAT_80317750;
  local_1e0 = 0x100;
  local_1dc = FLOAT_803e1d30;
  local_1d8 = FLOAT_803e1d30;
  local_1d4 = FLOAT_803e1d48;
  local_320 = 0;
  local_34c = FLOAT_803e1d30;
  local_348 = FLOAT_803e1d30;
  local_344 = FLOAT_803e1d30;
  local_358 = FLOAT_803e1d30;
  local_354 = FLOAT_803e1d30;
  local_350 = FLOAT_803e1d30;
  local_340 = FLOAT_803e1d4c;
  local_338 = 2;
  local_33c = 7;
  local_31f = 0xe;
  local_31e = 0;
  local_31d = 0x1e;
  local_31b = 0xe;
  local_332 = DAT_8031777c;
  local_330 = DAT_8031777e;
  local_32e = DAT_80317780;
  local_32c = DAT_80317782;
  local_32a = DAT_80317784;
  local_328 = DAT_80317786;
  local_326 = DAT_80317788;
  local_378 = &local_318;
  local_324 = param_4 | 0xc0400c0;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = FLOAT_803e1d30 + *(float *)(param_3 + 6);
      local_348 = FLOAT_803e1d30 + *(float *)(param_3 + 8);
      local_344 = FLOAT_803e1d30 + *(float *)(param_3 + 10);
    }
    else {
      local_34c = FLOAT_803e1d30 + *(float *)(param_1 + 0x18);
      local_348 = FLOAT_803e1d30 + *(float *)(param_1 + 0x1c);
      local_344 = FLOAT_803e1d30 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_334 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0x15,&DAT_803175a0,0x18,&DAT_80317674,0x5e0,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f9004
 * EN v1.0 Address: 0x800F8D68
 * EN v1.0 Size: 2572b
 * EN v1.1 Address: 0x800F9004
 * EN v1.1 Size: 2580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f9004(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined8 uVar6;
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
  undefined4 local_318;
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
  undefined4 local_2c8;
  float local_2c4;
  float local_2c0;
  float local_2bc;
  undefined *local_2b8;
  undefined2 local_2b4;
  undefined local_2b2;
  undefined4 local_2b0 [162];
  undefined4 local_28;
  uint uStack_24;
  
  uVar6 = FUN_80286834();
  iVar2 = (int)((ulonglong)uVar6 >> 0x20);
  iVar3 = (int)uVar6;
  if (iVar3 == 0) {
    local_312[0] = 0;
    local_314 = 0x8c;
    local_318 = 0;
    local_328 = 0x20000000;
    local_324 = FLOAT_803e1d60;
    local_320 = FLOAT_803e1d64;
    local_31c = FLOAT_803e1d68;
    local_2fa[0] = 0;
    local_2fc = 9;
    local_300 = &DAT_8031783c;
    local_310 = 0x80;
    if (param_3 == 0) {
      local_30c = FLOAT_803e1d6c;
      local_308 = FLOAT_803e1d70;
      local_304 = FLOAT_803e1d6c;
    }
    else {
      local_30c = *(float *)(param_3 + 0xc);
      local_308 = *(float *)(param_3 + 0x10);
      local_304 = *(float *)(param_3 + 0x14);
    }
    local_2e2[0] = 0;
    local_2e4 = 8;
    local_2e8 = &DAT_8031783c;
    local_2f8 = 2;
    local_2f4 = FLOAT_803e1d74;
    local_2f0 = FLOAT_803e1d74;
    local_2ec = FLOAT_803e1d78;
    puVar4 = &local_2e0;
  }
  else if (iVar3 == 1) {
    DAT_80317862 = 0x50;
    DAT_80317864 = 0x50;
    local_312[0] = 0;
    local_314 = 2;
    local_318 = 0;
    local_328 = 0x1800000;
    local_324 = FLOAT_803e1d7c;
    local_320 = FLOAT_803e1d6c;
    local_31c = FLOAT_803e1d6c;
    local_2fa[0] = 0;
    local_2fc = 0x69;
    local_300 = (undefined *)0x0;
    local_310 = 0x1800000;
    local_30c = FLOAT_803e1d7c;
    local_308 = FLOAT_803e1d6c;
    local_304 = FLOAT_803e1d6c;
    local_2e2[0] = 0;
    local_2e4 = 8;
    local_2e8 = &DAT_8031783c;
    local_2f8 = 2;
    uStack_24 = FUN_80022264(0,0xc);
    uStack_24 = uStack_24 ^ 0x80000000;
    local_28 = 0x43300000;
    local_2ec = FLOAT_803e1d80 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1db0);
    local_2f4 = FLOAT_803e1d84 + local_2ec;
    local_2ec = FLOAT_803e1d88 + local_2ec;
    local_2ca = 0;
    local_2cc = 0x8c;
    local_2d0 = (undefined *)0x0;
    local_2e0 = 0x20000000;
    local_2dc = FLOAT_803e1d60;
    local_2d8 = FLOAT_803e1d8c;
    local_2d4 = FLOAT_803e1d90;
    local_2b2 = 0;
    local_2b4 = 9;
    local_2b8 = &DAT_8031783c;
    local_2c8 = 0x80;
    local_2f0 = local_2f4;
    if (param_3 == 0) {
      local_2c4 = FLOAT_803e1d6c;
      local_2c0 = FLOAT_803e1d70;
      local_2bc = FLOAT_803e1d6c;
      puVar4 = local_2b0;
    }
    else {
      local_2c4 = *(float *)(param_3 + 0xc);
      local_2c0 = *(float *)(param_3 + 0x10);
      local_2bc = *(float *)(param_3 + 0x14);
      puVar4 = local_2b0;
    }
  }
  else {
    puVar4 = &local_328;
    if (iVar3 == 2) {
      DAT_80317862 = 0x50;
      DAT_80317864 = 0x50;
      local_312[0] = 0;
      local_314 = 0x1fc;
      local_318 = 0;
      local_328 = 0x1800000;
      local_324 = FLOAT_803e1d7c;
      local_320 = FLOAT_803e1d6c;
      local_31c = FLOAT_803e1d6c;
      local_2fa[0] = 0;
      local_2fc = 8;
      local_300 = &DAT_8031783c;
      local_310 = 2;
      uStack_24 = FUN_80022264(0,0xc);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_304 = FLOAT_803e1d80 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1db0)
      ;
      local_30c = FLOAT_803e1d94 + local_304;
      local_304 = FLOAT_803e1d98 + local_304;
      local_2e2[0] = 0;
      local_2e4 = 0x8c;
      local_2e8 = (undefined *)0x0;
      local_2f8 = 0x20000000;
      local_2f4 = FLOAT_803e1d60;
      local_2f0 = FLOAT_803e1d8c;
      local_2ec = FLOAT_803e1d90;
      local_2ca = 0;
      local_2cc = 9;
      local_2d0 = &DAT_8031783c;
      local_2e0 = 0x80;
      local_308 = local_30c;
      if (param_3 == 0) {
        local_2dc = FLOAT_803e1d6c;
        local_2d8 = FLOAT_803e1d70;
        local_2d4 = FLOAT_803e1d6c;
        puVar4 = &local_2c8;
      }
      else {
        local_2dc = *(float *)(param_3 + 0xc);
        local_2d8 = *(float *)(param_3 + 0x10);
        local_2d4 = *(float *)(param_3 + 0x14);
        puVar4 = &local_2c8;
      }
    }
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x4000;
    puVar4[1] = FLOAT_803e1d6c;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 0x68;
    puVar4[10] = 0;
    puVar4[6] = 0x800000;
    puVar4[7] = FLOAT_803e1d7c;
    puVar4[8] = FLOAT_803e1d6c;
    puVar4[9] = FLOAT_803e1d6c;
    *(undefined *)((int)puVar4 + 0x46) = 1;
    *(undefined2 *)(puVar4 + 0x11) = 8;
    puVar4[0x10] = (undefined4)&DAT_8031783c;
    puVar4[0xc] = 2;
    puVar4[0xd] = FLOAT_803e1d9c;
    puVar4[0xe] = FLOAT_803e1d9c;
    puVar4[0xf] = FLOAT_803e1d9c;
    puVar4 = puVar4 + 0x12;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x4000;
    puVar4[1] = FLOAT_803e1d6c;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 0x8f;
    puVar4[10] = 0;
    puVar4[6] = 0x1800000;
    puVar4[7] = FLOAT_803e1da0;
    puVar4[8] = FLOAT_803e1d6c;
    puVar4[9] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 0xc;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x4000;
    puVar4[1] = FLOAT_803e1d6c;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 0x1fd;
    puVar4[10] = 0;
    puVar4[6] = 0x1800000;
    puVar4[7] = FLOAT_803e1da0;
    puVar4[8] = FLOAT_803e1d6c;
    puVar4[9] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 0xc;
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1da4;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1da8;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1da8;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 6;
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1da4;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1da8;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = FLOAT_803e1da8;
    puVar4[2] = FLOAT_803e1d6c;
    puVar4[3] = FLOAT_803e1d6c;
    puVar4 = puVar4 + 6;
  }
  *(undefined *)((int)puVar4 + 0x16) = 2;
  *(undefined2 *)(puVar4 + 5) = 9;
  puVar4[4] = (undefined4)&DAT_8031783c;
  *puVar4 = 4;
  puVar4[1] = FLOAT_803e1d6c;
  puVar4[2] = FLOAT_803e1d6c;
  puVar4[3] = FLOAT_803e1d6c;
  puVar5 = puVar4 + 6;
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x2e) = 3;
    *(undefined2 *)(puVar4 + 0xb) = 0;
    puVar4[10] = 0;
    *puVar5 = 0x20000000;
    puVar4[7] = FLOAT_803e1d60;
    puVar4[8] = FLOAT_803e1d64;
    puVar4[9] = FLOAT_803e1d68;
    puVar5 = puVar4 + 0xc;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x2e) = 3;
    *(undefined2 *)(puVar4 + 0xb) = 0;
    puVar4[10] = 0;
    *puVar5 = 0x20000000;
    puVar4[7] = FLOAT_803e1d60;
    puVar4[8] = FLOAT_803e1d8c;
    puVar4[9] = FLOAT_803e1d90;
    puVar5 = puVar4 + 0xc;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x2e) = 3;
    *(undefined2 *)(puVar4 + 0xb) = 0;
    puVar4[10] = 0;
    *puVar5 = 0x20000000;
    puVar4[7] = FLOAT_803e1d60;
    puVar4[8] = FLOAT_803e1d8c;
    puVar4[9] = FLOAT_803e1d90;
    puVar5 = puVar4 + 0xc;
  }
  local_344 = (undefined2)uVar6;
  local_35c = FLOAT_803e1d6c;
  local_368 = FLOAT_803e1d6c;
  local_364 = FLOAT_803e1d6c;
  local_360 = FLOAT_803e1d6c;
  local_350 = FLOAT_803e1d7c;
  local_348 = 1;
  local_34c = 0;
  local_32f = 9;
  local_32e = 0;
  local_32d = 0;
  iVar1 = (int)puVar5 - (int)&local_328;
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_80317860;
  local_340 = DAT_80317862;
  local_33e = DAT_80317864;
  local_33c = DAT_80317866;
  local_33a = DAT_80317868;
  local_338 = DAT_8031786a;
  local_336 = DAT_8031786c;
  local_388 = &local_328;
  local_334 = param_4 | 0x4000000;
  local_358 = local_35c;
  local_354 = local_35c;
  if ((param_4 & 1) != 0) {
    if (iVar2 == 0) {
      local_35c = FLOAT_803e1d6c + *(float *)(param_3 + 0xc);
      local_358 = FLOAT_803e1d6c + *(float *)(param_3 + 0x10);
      local_354 = FLOAT_803e1d6c + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = FLOAT_803e1d6c + *(float *)(iVar2 + 0x18);
      local_358 = FLOAT_803e1d6c + *(float *)(iVar2 + 0x1c);
      local_354 = FLOAT_803e1d6c + *(float *)(iVar2 + 0x20);
    }
  }
  local_384 = iVar2;
  if (iVar3 == 0) {
    local_330 = 0;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,9,&DAT_803177b0,8,&DAT_8031780c,0x156,0);
  }
  else if (iVar3 == 1) {
    local_330 = 0;
    local_334 = param_4 | 0x4000004;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,9,&DAT_803177b0,8,&DAT_8031780c,0xc0d,0);
  }
  else if (iVar3 == 2) {
    local_330 = 0;
    local_334 = param_4 | 0x4000004;
    (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,9,&DAT_803177b0,8,&DAT_8031780c,0x23b,0);
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800f9a18
 * EN v1.0 Address: 0x800F977C
 * EN v1.0 Size: 1780b
 * EN v1.1 Address: 0x800F9A18
 * EN v1.1 Size: 1788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800f9a18(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  double in_f31;
  double dVar5;
  double in_ps31_1;
  undefined8 uVar6;
  undefined4 *local_3a8;
  int local_3a4;
  float local_388;
  float local_384;
  float local_380;
  float local_37c;
  float local_378;
  float local_374;
  float local_370;
  undefined4 local_36c;
  undefined4 local_368;
  undefined2 local_364;
  undefined2 local_362;
  undefined2 local_360;
  undefined2 local_35e;
  undefined2 local_35c;
  undefined2 local_35a;
  undefined2 local_358;
  undefined2 local_356;
  uint local_354;
  undefined local_350;
  undefined local_34f;
  undefined local_34e;
  undefined local_34d;
  char local_34b;
  undefined4 local_348;
  float local_344;
  float local_340;
  float local_33c;
  undefined *local_338;
  undefined2 local_334;
  undefined local_332 [2];
  undefined4 local_330 [5];
  undefined local_31a [722];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar6 = FUN_8028683c();
  iVar2 = (int)((ulonglong)uVar6 >> 0x20);
  iVar1 = (int)uVar6;
  if (iVar1 == 0) {
    local_332[0] = 0;
    local_334 = 3;
    local_338 = &DAT_803dc578;
    local_348 = 8;
    uVar3 = FUN_80022264(0,0x69);
    uStack_44 = uVar3 + 0x8c ^ 0x80000000;
    local_48 = 0x43300000;
    local_344 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e1df0);
    uVar3 = FUN_80022264(0,0x69);
    uStack_3c = uVar3 + 0x8c ^ 0x80000000;
    local_40 = 0x43300000;
    local_340 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e1df0);
    uVar3 = FUN_80022264(0,0x1e);
    uStack_34 = uVar3 + 0xe1 ^ 0x80000000;
    local_38 = 0x43300000;
    local_33c = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e1df0);
    puVar4 = (undefined4 *)(local_332 + 2);
  }
  else {
    puVar4 = &local_348;
    if (iVar1 == 1) {
      local_332[0] = 0;
      local_334 = 3;
      local_338 = &DAT_803dc578;
      local_348 = 8;
      uVar3 = FUN_80022264(0,0x1e);
      uStack_34 = uVar3 + 0xe1 ^ 0x80000000;
      local_38 = 0x43300000;
      local_344 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e1df0);
      uVar3 = FUN_80022264(0,0x69);
      uStack_3c = uVar3 + 0x8c ^ 0x80000000;
      local_40 = 0x43300000;
      local_340 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e1df0);
      uVar3 = FUN_80022264(0,0x41);
      uStack_44 = uVar3 + 0x78 ^ 0x80000000;
      local_48 = 0x43300000;
      local_33c = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e1df0);
      puVar4 = (undefined4 *)(local_332 + 2);
    }
  }
  uStack_34 = FUN_80022264(0,0xfffe);
  uStack_34 = uStack_34 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar5 = (double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e1df0);
  uStack_3c = FUN_80022264(0xfffff448,0xffffd120);
  uStack_3c = uStack_3c ^ 0x80000000;
  local_40 = 0x43300000;
  *(undefined *)((int)puVar4 + 0x16) = 0;
  *(undefined2 *)(puVar4 + 5) = 0;
  puVar4[4] = 0;
  *puVar4 = 0x80;
  puVar4[1] = FLOAT_803e1db8;
  puVar4[2] = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e1df0);
  puVar4[3] = (float)dVar5;
  *(undefined *)((int)puVar4 + 0x2e) = 0;
  *(undefined2 *)(puVar4 + 0xb) = 3;
  puVar4[10] = (undefined4)&DAT_803dc578;
  puVar4[6] = 4;
  puVar4[7] = FLOAT_803e1db8;
  puVar4[8] = FLOAT_803e1db8;
  puVar4[9] = FLOAT_803e1db8;
  *(undefined *)((int)puVar4 + 0x46) = 0;
  *(undefined2 *)(puVar4 + 0x11) = 3;
  puVar4[0x10] = (undefined4)&DAT_803dc578;
  puVar4[0xc] = 2;
  puVar4[0xd] = FLOAT_803e1dbc;
  uStack_44 = FUN_80022264(0,0x32);
  uStack_44 = uStack_44 ^ 0x80000000;
  local_48 = 0x43300000;
  puVar4[0xe] = FLOAT_803e1dc4 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e1df0) +
                FLOAT_803e1dc0;
  uStack_2c = FUN_80022264(0,0x14);
  uStack_2c = uStack_2c ^ 0x80000000;
  local_30 = 0x43300000;
  puVar4[0xf] = FLOAT_803e1dc4 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e1df0) +
                FLOAT_803e1dc8;
  *(undefined *)((int)puVar4 + 0x5e) = 1;
  *(undefined2 *)(puVar4 + 0x17) = 3;
  puVar4[0x16] = (undefined4)&DAT_803dc578;
  puVar4[0x12] = 4;
  uVar3 = FUN_80022264(0,10);
  if (uVar3 == 0) {
    uStack_2c = FUN_80022264(0,0x1e);
    uStack_2c = uStack_2c ^ 0x80000000;
    puVar4[0x13] = FLOAT_803e1dcc +
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e1df0);
  }
  else {
    uStack_2c = FUN_80022264(0,10);
    uStack_2c = uStack_2c ^ 0x80000000;
    puVar4[0x13] = FLOAT_803e1dd0 +
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e1df0);
  }
  local_30 = 0x43300000;
  puVar4[0x14] = FLOAT_803e1db8;
  puVar4[0x15] = FLOAT_803e1db8;
  *(undefined *)((int)puVar4 + 0x76) = 2;
  *(undefined2 *)(puVar4 + 0x1d) = 0;
  puVar4[0x1c] = 0;
  puVar4[0x18] = 0x80;
  puVar4[0x19] = FLOAT_803e1db8;
  puVar4[0x1a] = FLOAT_803e1db8;
  uStack_2c = FUN_80022264(0,0xfffe);
  uStack_2c = uStack_2c ^ 0x80000000;
  local_30 = 0x43300000;
  puVar4[0x1b] = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e1df0);
  *(undefined *)((int)puVar4 + 0x8e) = 1;
  *(undefined2 *)(puVar4 + 0x23) = 3;
  puVar4[0x22] = (undefined4)&DAT_803dc578;
  puVar4[0x1e] = 2;
  puVar4[0x1f] = FLOAT_803e1dd4;
  puVar4[0x20] = FLOAT_803e1dd8;
  puVar4[0x21] = FLOAT_803e1ddc;
  *(undefined *)((int)puVar4 + 0xa6) = 2;
  *(undefined2 *)(puVar4 + 0x29) = 0;
  puVar4[0x28] = 0;
  puVar4[0x24] = 0x80;
  puVar4[0x25] = FLOAT_803e1db8;
  puVar4[0x26] = FLOAT_803e1db8;
  uStack_34 = FUN_80022264(0,0xfffe);
  uStack_34 = uStack_34 ^ 0x80000000;
  local_38 = 0x43300000;
  puVar4[0x27] = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e1df0);
  *(undefined *)((int)puVar4 + 0xbe) = 2;
  *(undefined2 *)(puVar4 + 0x2f) = 3;
  puVar4[0x2e] = (undefined4)&DAT_803dc578;
  puVar4[0x2a] = 4;
  puVar4[0x2b] = FLOAT_803e1db8;
  puVar4[0x2c] = FLOAT_803e1db8;
  puVar4[0x2d] = FLOAT_803e1db8;
  *(undefined *)((int)puVar4 + 0xd6) = 2;
  *(undefined2 *)(puVar4 + 0x35) = 3;
  puVar4[0x34] = (undefined4)&DAT_803dc578;
  puVar4[0x30] = 2;
  puVar4[0x31] = FLOAT_803e1de0;
  puVar4[0x32] = FLOAT_803e1de4;
  puVar4[0x33] = FLOAT_803e1de8;
  local_350 = 0;
  local_364 = (undefined2)uVar6;
  local_37c = FLOAT_803e1db8;
  if (iVar1 == 0) {
    local_378 = FLOAT_803e1db8;
  }
  else if (iVar1 == 1) {
    local_378 = FLOAT_803e1dec;
  }
  local_374 = FLOAT_803e1db8;
  local_388 = FLOAT_803e1db8;
  local_384 = FLOAT_803e1db8;
  local_380 = FLOAT_803e1db8;
  local_370 = FLOAT_803e1de4;
  local_368 = 1;
  local_36c = 0;
  local_34f = 3;
  local_34e = 0;
  local_34d = 0;
  iVar1 = (int)puVar4 + (0xd8 - (int)&local_348);
  iVar1 = iVar1 / 0x18 + (iVar1 >> 0x1f);
  local_34b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_362 = DAT_803178b0;
  local_360 = DAT_803178b2;
  local_35e = DAT_803178b4;
  local_35c = DAT_803178b6;
  local_35a = DAT_803178b8;
  local_358 = DAT_803178ba;
  local_356 = DAT_803178bc;
  local_3a8 = &local_348;
  local_354 = param_4 | 0x4000410;
  if ((param_4 & 1) != 0) {
    if ((iVar2 == 0) || (param_3 == 0)) {
      if (iVar2 == 0) {
        if (param_3 != 0) {
          local_37c = FLOAT_803e1db8 + *(float *)(param_3 + 0xc);
          local_378 = local_378 + *(float *)(param_3 + 0x10);
          local_374 = FLOAT_803e1db8 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_37c = FLOAT_803e1db8 + *(float *)(iVar2 + 0x18);
        local_378 = local_378 + *(float *)(iVar2 + 0x1c);
        local_374 = FLOAT_803e1db8 + *(float *)(iVar2 + 0x20);
      }
    }
    else {
      local_37c = FLOAT_803e1db8 + *(float *)(iVar2 + 0x18) + *(float *)(param_3 + 0xc);
      local_378 = local_378 + *(float *)(iVar2 + 0x1c) + *(float *)(param_3 + 0x10);
      local_374 = FLOAT_803e1db8 + *(float *)(iVar2 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_3a4 = iVar2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_3a8,0,3,&DAT_80317890,1,&DAT_803dc570,0x26a,0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa114
 * EN v1.0 Address: 0x800F9E78
 * EN v1.0 Size: 748b
 * EN v1.1 Address: 0x800FA114
 * EN v1.1 Size: 756b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa114(int param_1,undefined2 param_2,int param_3,uint param_4)
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
  undefined auStack_228 [540];
  
  local_378 = &local_318;
  local_302 = 0;
  local_304 = 0x12;
  local_308 = &DAT_80317a08;
  local_318 = 4;
  local_314 = FLOAT_803e1df8;
  local_310 = FLOAT_803e1df8;
  local_30c = FLOAT_803e1df8;
  local_2ea = 0;
  local_2ec = 0x12;
  local_2f0 = &DAT_80317a08;
  local_300 = 2;
  local_2fc = FLOAT_803e1dfc;
  local_2f8 = FLOAT_803e1e00;
  local_2f4 = FLOAT_803e1dfc;
  local_2d2 = 0;
  local_2d4 = 0x12;
  local_2d8 = &DAT_80317a08;
  local_2e8 = 0x100;
  local_2e4 = FLOAT_803e1df8;
  local_2e0 = FLOAT_803e1df8;
  local_2dc = FLOAT_803e1e04;
  local_2ba = 1;
  local_2bc = 0x12;
  local_2c0 = &DAT_80317a08;
  local_2d0 = 4;
  local_2cc = FLOAT_803e1e08;
  local_2c8 = FLOAT_803e1df8;
  local_2c4 = FLOAT_803e1df8;
  local_2a2 = 1;
  local_2a4 = 0x12;
  local_2a8 = &DAT_80317a08;
  local_2b8 = 2;
  local_2b4 = FLOAT_803e1e0c;
  local_2b0 = FLOAT_803e1e10;
  local_2ac = FLOAT_803e1e0c;
  local_28a = 1;
  local_28c = 0x12;
  local_290 = &DAT_80317a08;
  local_2a0 = 0x100;
  local_29c = FLOAT_803e1df8;
  local_298 = FLOAT_803e1df8;
  local_294 = FLOAT_803e1e04;
  local_272 = 2;
  local_274 = 0x12;
  local_278 = &DAT_80317a08;
  local_288 = 0x100;
  local_284 = FLOAT_803e1df8;
  local_280 = FLOAT_803e1df8;
  local_27c = FLOAT_803e1e04;
  local_25a = 3;
  local_25c = 0x12;
  local_260 = &DAT_80317a08;
  local_270 = 4;
  local_26c = FLOAT_803e1df8;
  local_268 = FLOAT_803e1df8;
  local_264 = FLOAT_803e1df8;
  local_242 = 3;
  local_244 = 0x12;
  local_248 = &DAT_80317a08;
  local_258 = 2;
  local_254 = FLOAT_803e1e14;
  local_250 = FLOAT_803e1e18;
  local_24c = FLOAT_803e1e14;
  local_22a = 3;
  local_22c = 0x12;
  local_230 = &DAT_80317a08;
  local_240 = 0x100;
  local_23c = FLOAT_803e1df8;
  local_238 = FLOAT_803e1df8;
  local_234 = FLOAT_803e1e04;
  local_320 = 0;
  local_34c = FLOAT_803e1df8;
  local_348 = FLOAT_803e1df8;
  local_344 = FLOAT_803e1df8;
  local_358 = FLOAT_803e1df8;
  local_354 = FLOAT_803e1df8;
  local_350 = FLOAT_803e1df8;
  local_340 = FLOAT_803e1e1c;
  local_338 = 1;
  local_33c = 0;
  local_31f = 0x12;
  local_31e = 0;
  local_31d = 0x10;
  iVar1 = (int)(auStack_228 + -(int)local_378) / 0x18 +
          ((int)(auStack_228 + -(int)local_378) >> 0x1f);
  local_31b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_332 = DAT_80317a40;
  local_330 = DAT_80317a42;
  local_32e = DAT_80317a44;
  local_32c = DAT_80317a46;
  local_32a = DAT_80317a48;
  local_328 = DAT_80317a4a;
  local_326 = DAT_80317a4c;
  local_324 = param_4 | 0x4000000;
  if ((param_4 & 1) != 0) {
    if (param_1 == 0) {
      local_34c = FLOAT_803e1df8 + *(float *)(param_3 + 0xc);
      local_348 = FLOAT_803e1df8 + *(float *)(param_3 + 0x10);
      local_344 = FLOAT_803e1df8 + *(float *)(param_3 + 0x14);
    }
    else {
      local_34c = FLOAT_803e1df8 + *(float *)(param_1 + 0x18);
      local_348 = FLOAT_803e1df8 + *(float *)(param_1 + 0x1c);
      local_344 = FLOAT_803e1df8 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_334 = param_2;
  (**(code **)(*DAT_803dd6fc + 8))(&local_378,0,0x12,&DAT_803178e0,0x10,&DAT_80317994,0x2e,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800fa408
 * EN v1.0 Address: 0x800FA16C
 * EN v1.0 Size: 1124b
 * EN v1.1 Address: 0x800FA408
 * EN v1.1 Size: 1124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800fa408(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
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
  undefined4 local_270;
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
  undefined4 local_178;
  float local_174;
  float local_170;
  float local_16c;
  undefined4 local_168;
  undefined2 local_164;
  undefined local_162;
  undefined4 local_160;
  float local_15c;
  float local_158;
  float local_154;
  undefined *local_150;
  undefined2 local_14c;
  undefined local_14a;
  undefined4 local_148;
  float local_144;
  float local_140;
  float local_13c;
  undefined *local_138;
  undefined2 local_134;
  undefined local_132;
  undefined auStack_130 [304];
  
  local_384 = FUN_80286834();
  local_388 = &local_328;
  local_312 = 0;
  local_314 = 0x12;
  local_318 = &DAT_80317bd0;
  local_328 = 4;
  local_324 = FLOAT_803e1e20;
  local_320 = FLOAT_803e1e20;
  local_31c = FLOAT_803e1e20;
  local_2fa = 0;
  local_2fc = 9;
  local_300 = &DAT_80317b94;
  local_310 = 8;
  local_30c = FLOAT_803e1e24;
  local_308 = FLOAT_803e1e24;
  local_304 = FLOAT_803e1e20;
  local_2e2 = 0;
  local_2e4 = 9;
  local_2e8 = &DAT_80317ba8;
  local_2f8 = 2;
  local_2f4 = FLOAT_803e1e28;
  local_2f0 = FLOAT_803e1e2c;
  local_2ec = FLOAT_803e1e28;
  local_2ca = 0;
  local_2cc = 0x12;
  local_2d0 = &DAT_80317bd0;
  local_2e0 = 2;
  local_2dc = FLOAT_803e1e30;
  local_2d8 = FLOAT_803e1e34;
  local_2d4 = FLOAT_803e1e30;
  local_2b2 = 0;
  local_2b4 = 9;
  local_2b8 = &DAT_80317ba8;
  local_2c8 = 8;
  local_2c4 = FLOAT_803e1e38;
  local_2c0 = FLOAT_803e1e20;
  local_2bc = FLOAT_803e1e20;
  local_29a = 1;
  local_29c = 0x12;
  local_2a0 = &DAT_80317bd0;
  local_2b0 = 4;
  local_2ac = FLOAT_803e1e24;
  local_2a8 = FLOAT_803e1e20;
  local_2a4 = FLOAT_803e1e20;
  local_282 = 1;
  local_284 = 9;
  local_288 = &DAT_80317ba8;
  local_298 = 2;
  local_294 = FLOAT_803e1e28;
  local_290 = FLOAT_803e1e3c;
  local_28c = FLOAT_803e1e28;
  local_26a = 1;
  local_26c = 0x7a;
  local_270 = 0;
  local_280 = 0x10000;
  local_27c = FLOAT_803e1e20;
  local_278 = FLOAT_803e1e20;
  local_274 = FLOAT_803e1e20;
  local_252 = 1;
  local_254 = 0;
  local_258 = 0;
  local_268 = 0x80000;
  local_264 = FLOAT_803e1e20;
  local_260 = FLOAT_803e1e40;
  local_25c = FLOAT_803e1e20;
  local_23a = 2;
  local_23c = 0x9d;
  local_240 = 0;
  local_250 = 0x20000;
  local_24c = FLOAT_803e1e20;
  local_248 = FLOAT_803e1e20;
  local_244 = FLOAT_803e1e20;
  local_222 = 3;
  local_224 = 9;
  local_228 = &DAT_80317b94;
  local_238 = 8;
  local_234 = FLOAT_803e1e24;
  local_230 = FLOAT_803e1e44;
  local_22c = FLOAT_803e1e20;
  local_20a = 3;
  local_20c = 0x12;
  local_210 = &DAT_80317bd0;
  local_220 = 0x100;
  local_21c = FLOAT_803e1e20;
  local_218 = FLOAT_803e1e20;
  local_214 = FLOAT_803e1e48;
  local_1f2 = 3;
  local_1f4 = 5;
  local_1f8 = &DAT_80317c08;
  local_208 = 2;
  local_204 = FLOAT_803e1e4c;
  local_200 = FLOAT_803e1e28;
  local_1fc = FLOAT_803e1e4c;
  local_1da = 3;
  local_1dc = 4;
  local_1e0 = &DAT_803dc580;
  local_1f0 = 2;
  local_1ec = FLOAT_803e1e50;
  local_1e8 = FLOAT_803e1e28;
  local_1e4 = FLOAT_803e1e50;
  local_1c2 = 4;
  local_1c4 = 9;
  local_1c8 = &DAT_80317b94;
  local_1d8 = 8;
  local_1d4 = FLOAT_803e1e24;
  local_1d0 = FLOAT_803e1e24;
  local_1cc = FLOAT_803e1e20;
  local_1aa = 4;
  local_1ac = 0x12;
  local_1b0 = &DAT_80317bd0;
  local_1c0 = 0x100;
  local_1bc = FLOAT_803e1e20;
  local_1b8 = FLOAT_803e1e20;
  local_1b4 = FLOAT_803e1e48;
  local_192 = 4;
  local_194 = 5;
  local_198 = &DAT_80317c08;
  local_1a8 = 2;
  local_1a4 = FLOAT_803e1e50;
  local_1a0 = FLOAT_803e1e28;
  local_19c = FLOAT_803e1e50;
  local_17a = 4;
  local_17c = 4;
  local_180 = &DAT_803dc580;
  local_190 = 2;
  local_18c = FLOAT_803e1e4c;
  local_188 = FLOAT_803e1e28;
  local_184 = FLOAT_803e1e4c;
  local_162 = 5;
  local_164 = 1;
  local_168 = 0;
  local_178 = 0x1000;
  local_174 = FLOAT_803e1e28;
  local_170 = FLOAT_803e1e20;
  local_16c = FLOAT_803e1e20;
  local_14a = 6;
  local_14c = 0x12;
  local_150 = &DAT_80317bd0;
  local_160 = 4;
  local_15c = FLOAT_803e1e20;
  local_158 = FLOAT_803e1e20;
  local_154 = FLOAT_803e1e20;
  local_132 = 6;
  local_134 = 0x12;
  local_138 = &DAT_80317bd0;
  local_148 = 2;
  local_144 = FLOAT_803e1e54;
  local_140 = FLOAT_803e1e28;
  local_13c = FLOAT_803e1e54;
  local_330 = 0;
  local_35c = FLOAT_803e1e20;
  local_358 = FLOAT_803e1e20;
  local_354 = FLOAT_803e1e20;
  local_368 = FLOAT_803e1e20;
  local_364 = FLOAT_803e1e20;
  local_360 = FLOAT_803e1e20;
  local_350 = FLOAT_803e1e28;
  local_348 = 1;
  local_34c = 0;
  local_32f = 0x12;
  local_32e = 0;
  local_32d = 0xc;
  iVar1 = (int)(auStack_130 + -(int)local_388) / 0x18 +
          ((int)(auStack_130 + -(int)local_388) >> 0x1f);
  local_32b = (char)iVar1 - (char)(iVar1 >> 0x1f);
  local_342 = DAT_80317c14;
  local_340 = DAT_80317c16;
  local_33e = DAT_80317c18;
  local_33c = DAT_80317c1a;
  local_33a = DAT_80317c1c;
  local_338 = DAT_80317c1e;
  local_336 = DAT_80317c20;
  local_334 = param_4 | 0x1000082;
  if ((param_4 & 1) != 0) {
    if (local_384 == 0) {
      local_35c = FLOAT_803e1e20 + *(float *)(param_3 + 0xc);
      local_358 = FLOAT_803e1e20 + *(float *)(param_3 + 0x10);
      local_354 = FLOAT_803e1e20 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = FLOAT_803e1e20 + *(float *)(local_384 + 0x18);
      local_358 = FLOAT_803e1e20 + *(float *)(local_384 + 0x1c);
      local_354 = FLOAT_803e1e20 + *(float *)(local_384 + 0x20);
    }
  }
  local_344 = extraout_r4;
  (**(code **)(*DAT_803dd6fc + 8))(&local_388,0,0x12,&DAT_80317a80,0x10,&DAT_80317b34,0x45,0);
  FUN_80286880();
  return;
}
