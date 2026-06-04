#include "ghidra_import.h"
#include "main/dll/foodbag.h"


#pragma peephole off
#pragma scheduling off
extern u32 randomGetRange(int min, int max);
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
extern undefined4* gModgfxInterface;
extern undefined4 DAT_803de128;
extern f64 DOUBLE_803e1c28;
extern f64 DOUBLE_803e1c60;
extern f64 DOUBLE_803e1d28;
extern f64 DOUBLE_803e1d58;
extern f64 DOUBLE_803e1db0;
extern f64 DOUBLE_803e1df0;
extern f32 lbl_803E1A08;
extern f32 lbl_803E1A0C;
extern f32 lbl_803E1A10;
extern f32 lbl_803E1A14;
extern f32 lbl_803E1A18;
extern f32 lbl_803E1A1C;
extern f32 lbl_803E1A20;
extern f32 lbl_803E1A24;
extern f32 lbl_803E1A28;
extern f32 lbl_803E1A2C;
extern f32 lbl_803E1A30;
extern f32 lbl_803E1A34;
extern f32 lbl_803E1A38;
extern f32 lbl_803E1A3C;
extern f32 lbl_803E1A40;
extern f32 lbl_803E1A44;
extern f32 lbl_803E1A48;
extern f32 lbl_803E1A4C;
extern f32 lbl_803E1A50;
extern f32 lbl_803E1A58;
extern f32 lbl_803E1A5C;
extern f32 lbl_803E1A60;
extern f32 lbl_803E1A64;
extern f32 lbl_803E1A68;
extern f32 lbl_803E1A6C;
extern f32 lbl_803E1A70;
extern f32 lbl_803E1A74;
extern f32 lbl_803E1A78;
extern f32 lbl_803E1A80;
extern f32 lbl_803E1A84;
extern f32 lbl_803E1A88;
extern f32 lbl_803E1A8C;
extern f32 lbl_803E1A90;
extern f32 lbl_803E1A94;
extern f32 lbl_803E1A98;
extern f32 lbl_803E1A9C;
extern f32 lbl_803E1AA0;
extern f32 lbl_803E1AA4;
extern f32 lbl_803E1AA8;
extern f32 lbl_803E1AAC;
extern f32 lbl_803E1AB0;
extern f32 lbl_803E1AB4;
extern f32 lbl_803E1AB8;
extern f32 lbl_803E1ABC;
extern f32 lbl_803E1AC0;
extern f32 lbl_803E1AC4;
extern f32 lbl_803E1AC8;
extern f32 lbl_803E1ACC;
extern u8 lbl_80314E08[];
extern f32 lbl_803E0D88;
extern f32 lbl_803E0D8C;
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
extern u8 lbl_80315030[];
extern int lbl_803DD4B0;
extern f32 lbl_803E0DD4;
extern f32 lbl_803E0DD8;
extern f32 lbl_803E0DDC;
extern f32 lbl_803E0DE0;
extern f32 lbl_803E0DE4;
extern f32 lbl_803E0DE8;
extern f32 lbl_803E0DEC;
extern f32 lbl_803E0DF0;
extern f32 lbl_803E0DF4;
extern f32 lbl_803E0DF8;
extern u8 lbl_80315258[];
extern u8 lbl_803DB8E0;
extern f32 lbl_803E0E00;
extern f32 lbl_803E0E04;
extern f32 lbl_803E0E08;
extern f32 lbl_803E0E0C;
extern f32 lbl_803E0E10;
extern f32 lbl_803E0E14;
extern f32 lbl_803E0E18;
extern f32 lbl_803E0E1C;
extern u8 lbl_80315328[];
extern u8 lbl_803DB8E8;
extern f32 lbl_803E0E20;
extern f32 lbl_803E0E24;
extern f32 lbl_803E0E28;
extern f32 lbl_803E0E2C;
extern f32 lbl_803E0E30;
extern f32 lbl_803E0E34;
extern f32 lbl_803E0E38;
extern f32 lbl_803E0E3C;
extern f32 lbl_803E0E40;
extern f32 lbl_803E0E44;
extern f32 lbl_803E0E48;
extern f32 lbl_803E0E4C;
extern f32 lbl_803E0E50;
extern f32 lbl_803E0E54;
extern u8 lbl_80315548[];
extern f32 lbl_803E0E78;
extern f32 lbl_803E0E7C;
extern f32 lbl_803E0E80;
extern f32 lbl_803E0E84;
extern f32 lbl_803E0E88;
extern f32 lbl_803E0E8C;
extern f32 lbl_803E0E90;
extern f32 lbl_803E0E94;
extern f32 lbl_803E0E98;
extern f32 lbl_803E0E9C;
extern f32 lbl_803E0EA0;
extern f32 lbl_803E0EA4;
extern f32 lbl_803E0EA8;
extern u8 lbl_80315770[];
extern f32 lbl_803E0EB0;
extern f32 lbl_803E0EB4;
extern f32 lbl_803E0EB8;
extern f32 lbl_803E0EBC;
extern f32 lbl_803E0EC0;
extern f32 lbl_803E0EC4;
extern f32 lbl_803E0EC8;
extern f32 lbl_803E0ECC;
extern f32 lbl_803E0ED0;
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
extern u8 lbl_80315998[];
extern u8 lbl_80315CA8[];
extern f32 lbl_803E0F20;
extern f32 lbl_803E0F24;
extern f32 lbl_803E0F28;
extern f32 lbl_803E0F2C;
extern f32 lbl_803E0F30;
extern f32 lbl_803E0F34;
extern f32 lbl_803E0F38;
extern f32 lbl_803E0F3C;
extern f32 lbl_803E0F40;
extern f32 lbl_803E0F44;
extern f32 lbl_803E0F48;
extern f32 lbl_803E0F4C;
extern f32 lbl_803E0F50;
extern f32 lbl_803E0F54;
extern f32 lbl_803E0F58;
extern f32 lbl_803E0F5C;
extern f32 lbl_803E0F60;
extern f32 lbl_803E0F64;
extern f32 lbl_803E0F68;
extern f32 lbl_803E0F6C;
extern u8 lbl_80316650[];
extern f32 lbl_803E1050;
extern f32 lbl_803E1054;
extern f32 lbl_803E1058;
extern u8 lbl_80316020[];
extern f32 lbl_803E0FB0;
extern f32 lbl_803E0FB4;
extern f32 lbl_803E0FB8;
extern f32 lbl_803E0FBC;
extern f32 lbl_803E0FC0;
extern f32 lbl_803E0FC4;
extern f32 lbl_803E0FC8;
extern f32 lbl_803E0FCC;
extern f32 lbl_803E0FD0;
extern f32 lbl_803E0FD4;
extern f32 lbl_803E0FD8;
extern u8 lbl_80315468[];
extern u8 lbl_80316240[];
extern f32 lbl_803E1010;
extern f32 lbl_803E1014;
extern f32 lbl_803E1018;
extern f32 lbl_803E101C;
extern f32 lbl_803E1020;
extern f32 lbl_803E1024;
extern u8 lbl_80316460[];
extern u8 lbl_803DB908;
extern f32 lbl_803E1028;
extern f32 lbl_803E102C;
extern f32 lbl_803E1030;
extern f32 lbl_803E1034;
extern f32 lbl_803E1038;
extern f32 lbl_803E103C;
extern f32 lbl_803E1040;
extern f32 lbl_803E1044;
extern f32 lbl_803E1048;
extern u8 lbl_80316050[];
extern u8 lbl_803DB900;
extern f32 lbl_803E0FE8;
extern f32 lbl_803E0FEC;
extern f32 lbl_803E0FF0;
extern f32 lbl_803E0FF4;
extern f32 lbl_803E0FF8;
extern f32 lbl_803E0FFC;
extern f32 lbl_803E1000;
extern f32 lbl_803E1004;
extern f32 lbl_803E1008;
extern u8 lbl_80316C90[];
extern f32 lbl_803E1178;
extern f32 lbl_803E117C;
extern f32 lbl_803E1180;
extern f32 lbl_803E1184;
extern f32 lbl_803E1188;
extern f32 lbl_803E118C;
extern f32 lbl_803E1190;
extern f32 lbl_803E1194;
extern f32 lbl_803E1198;
extern f32 lbl_803E119C;
extern f32 lbl_803E0E58;
extern f32 lbl_803E0E5C;
extern f32 lbl_803E0E60;
extern f32 lbl_803E0E64;
extern f32 lbl_803E0E68;
extern f32 lbl_803E0E6C;
extern f32 lbl_803E0E70;
extern f32 lbl_803E0E74;
extern f32 lbl_803E1AD0;
extern f32 lbl_803E1AD4;
extern f32 lbl_803E1AD8;
extern f32 lbl_803E1ADC;
extern f32 lbl_803E1AE0;
extern f32 lbl_803E1AE4;
extern f32 lbl_803E1AE8;
extern f32 lbl_803E1AEC;
extern f32 lbl_803E1AF0;
extern f32 lbl_803E1AF4;
extern f32 lbl_803E1AF8;
extern f32 lbl_803E1AFC;
extern f32 lbl_803E1B00;
extern f32 lbl_803E1B04;
extern f32 lbl_803E1B08;
extern f32 lbl_803E1B0C;
extern f32 lbl_803E1B10;
extern f32 lbl_803E1B14;
extern f32 lbl_803E1B18;
extern f32 lbl_803E1B1C;
extern f32 lbl_803E1B20;
extern f32 lbl_803E1B24;
extern f32 lbl_803E1B28;
extern f32 lbl_803E1B30;
extern f32 lbl_803E1B34;
extern f32 lbl_803E1B38;
extern f32 lbl_803E1B3C;
extern f32 lbl_803E1B40;
extern f32 lbl_803E1B44;
extern f32 lbl_803E1B48;
extern f32 lbl_803E1B4C;
extern f32 lbl_803E1B50;
extern f32 lbl_803E1B58;
extern f32 lbl_803E1B5C;
extern f32 lbl_803E1B60;
extern f32 lbl_803E1B64;
extern f32 lbl_803E1B68;
extern f32 lbl_803E1B6C;
extern f32 lbl_803E1B70;
extern f32 lbl_803E1B74;
extern f32 lbl_803E1B78;
extern f32 lbl_803E1B7C;
extern f32 lbl_803E1B80;
extern f32 lbl_803E1B84;
extern f32 lbl_803E1B88;
extern f32 lbl_803E1B8C;
extern f32 lbl_803E1B90;
extern f32 lbl_803E1B94;
extern f32 lbl_803E1B98;
extern f32 lbl_803E1BA0;
extern f32 lbl_803E1BA4;
extern f32 lbl_803E1BA8;
extern f32 lbl_803E1BAC;
extern f32 lbl_803E1BB0;
extern f32 lbl_803E1BB4;
extern f32 lbl_803E1BB8;
extern f32 lbl_803E1BBC;
extern f32 lbl_803E1BC0;
extern f32 lbl_803E1BC4;
extern f32 lbl_803E1BC8;
extern f32 lbl_803E1BCC;
extern f32 lbl_803E1BD0;
extern f32 lbl_803E1BD4;
extern f32 lbl_803E1BD8;
extern f32 lbl_803E1BDC;
extern f32 lbl_803E1BE0;
extern f32 lbl_803E1BE4;
extern f32 lbl_803E1BE8;
extern f32 lbl_803E1BEC;
extern f32 lbl_803E1BF0;
extern f32 lbl_803E1BF4;
extern f32 lbl_803E1BF8;
extern f32 lbl_803E1BFC;
extern f32 lbl_803E1C00;
extern f32 lbl_803E1C04;
extern f32 lbl_803E1C08;
extern f32 lbl_803E1C0C;
extern f32 lbl_803E1C10;
extern f32 lbl_803E1C14;
extern f32 lbl_803E1C18;
extern f32 lbl_803E1C1C;
extern f32 lbl_803E1C20;
extern f32 lbl_803E1C30;
extern f32 lbl_803E1C34;
extern f32 lbl_803E1C38;
extern f32 lbl_803E1C3C;
extern f32 lbl_803E1C40;
extern f32 lbl_803E1C44;
extern f32 lbl_803E1C48;
extern f32 lbl_803E1C4C;
extern f32 lbl_803E1C50;
extern f32 lbl_803E1C54;
extern f32 lbl_803E1C58;
extern f32 lbl_803E1C68;
extern f32 lbl_803E1C6C;
extern f32 lbl_803E1C70;
extern f32 lbl_803E1C74;
extern f32 lbl_803E1C78;
extern f32 lbl_803E1C7C;
extern f32 lbl_803E1C80;
extern f32 lbl_803E1C84;
extern f32 lbl_803E1C88;
extern f32 lbl_803E1C90;
extern f32 lbl_803E1C94;
extern f32 lbl_803E1C98;
extern f32 lbl_803E1C9C;
extern f32 lbl_803E1CA0;
extern f32 lbl_803E1CA4;
extern f32 lbl_803E1CA8;
extern f32 lbl_803E1CAC;
extern f32 lbl_803E1CB0;
extern f32 lbl_803E1CB4;
extern f32 lbl_803E1CB8;
extern f32 lbl_803E1CBC;
extern f32 lbl_803E1CC0;
extern f32 lbl_803E1CC4;
extern f32 lbl_803E1CC8;
extern f32 lbl_803E1050;
extern f32 lbl_803E1054;
extern f32 lbl_803E1058;
extern f32 lbl_803E1CE0;
extern f32 lbl_803E1CE4;
extern f32 lbl_803E1CE8;
extern f32 lbl_803E1CEC;
extern f32 lbl_803E1CF0;
extern f32 lbl_803E1CF4;
extern f32 lbl_803E1CF8;
extern f32 lbl_803E1CFC;
extern f32 lbl_803E1D00;
extern f32 lbl_803E1D04;
extern f32 lbl_803E1D08;
extern f32 lbl_803E1D0C;
extern f32 lbl_803E1D10;
extern f32 lbl_803E1D14;
extern f32 lbl_803E1D18;
extern f32 lbl_803E1D1C;
extern f32 lbl_803E1D20;
extern f32 lbl_803E1D24;
extern f32 lbl_803E1D30;
extern f32 lbl_803E1D34;
extern f32 lbl_803E1D38;
extern f32 lbl_803E1D3C;
extern f32 lbl_803E1D40;
extern f32 lbl_803E1D44;
extern f32 lbl_803E1D48;
extern f32 lbl_803E1D4C;
extern f32 lbl_803E1D50;
extern f32 lbl_803E1D54;
extern f32 lbl_803E1D60;
extern f32 lbl_803E1D64;
extern f32 lbl_803E1D68;
extern f32 lbl_803E1D6C;
extern f32 lbl_803E1D70;
extern f32 lbl_803E1D74;
extern f32 lbl_803E1D78;
extern f32 lbl_803E1D7C;
extern f32 lbl_803E1D80;
extern f32 lbl_803E1D84;
extern f32 lbl_803E1D88;
extern f32 lbl_803E1D8C;
extern f32 lbl_803E1D90;
extern f32 lbl_803E1D94;
extern f32 lbl_803E1D98;
extern f32 lbl_803E1D9C;
extern f32 lbl_803E1DA0;
extern f32 lbl_803E1DA4;
extern f32 lbl_803E1DA8;
extern f32 lbl_803E1DB8;
extern f32 lbl_803E1DBC;
extern f32 lbl_803E1DC0;
extern f32 lbl_803E1DC4;
extern f32 lbl_803E1DC8;
extern f32 lbl_803E1DCC;
extern f32 lbl_803E1DD0;
extern f32 lbl_803E1DD4;
extern f32 lbl_803E1DD8;
extern f32 lbl_803E1DDC;
extern f32 lbl_803E1DE0;
extern f32 lbl_803E1DE4;
extern f32 lbl_803E1DE8;
extern f32 lbl_803E1DEC;
extern f32 lbl_803E1DF8;
extern f32 lbl_803E1DFC;
extern f32 lbl_803E1E00;
extern f32 lbl_803E1E04;
extern f32 lbl_803E1E08;
extern f32 lbl_803E1E0C;
extern f32 lbl_803E1E10;
extern f32 lbl_803E1E14;
extern f32 lbl_803E1E18;
extern f32 lbl_803E1E1C;
extern f32 lbl_803E1E20;
extern f32 lbl_803E1E24;
extern f32 lbl_803E1E28;
extern f32 lbl_803E1E2C;
extern f32 lbl_803E1E30;
extern f32 lbl_803E1E34;
extern f32 lbl_803E1E38;
extern f32 lbl_803E1E3C;
extern f32 lbl_803E1E40;
extern f32 lbl_803E1E44;
extern f32 lbl_803E1E48;
extern f32 lbl_803E1E4C;
extern f32 lbl_803E1E50;
extern f32 lbl_803E1E54;

typedef struct {
  u32 mode;
  f32 x, y, z;
  void *tex;
  u16 flags;
  u8 layer;
} FbCmd;

typedef struct {
  FbCmd *cmds;
  int ctx;
  u8 pad0[0x18];
  f32 col[3];
  f32 pos[3];
  f32 scale;
  u32 v3c;
  u32 v40;
  s16 v44;
  s16 hw[7];
  u32 flags;
  u8 v58, v59, v5a, v5b, v5c;
  s8 count;
  u8 pad1[2];
  FbCmd entries[32];
} FbBuf;

/*
 * --INFO--
 *
 * Function: dll_7C_func03
 * EN v1.0 Address: 0x800F472C
 * EN v1.0 Size: 1340b
 * EN v1.1 Address: 0x800F49C8
 * EN v1.1 Size: 1348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_7C_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  u8 *base = lbl_80314E08;
  FbCmd *e = buf.entries;
  FbCmd *p = &e[1];

  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = base + 0x1b0; e[0].mode = 4;
  e[0].x = lbl_803E0D88; e[0].y = lbl_803E0D88; e[0].z = lbl_803E0D88;
  if (param_2 == 0 || param_2 == 3) {
    p->layer = 0; p->flags = 0x15; p->tex = base + 0x1b0; p->mode = 2;
    p->x = lbl_803E0D8C; p->y = lbl_803E0D90; p->z = lbl_803E0D8C;
    p++;
  } else if (param_2 == 1 || param_2 == 2) {
    p->layer = 0; p->flags = 0x15; p->tex = base + 0x1b0; p->mode = 2;
    p->x = lbl_803E0D94; p->y = lbl_803E0D90; p->z = lbl_803E0D94;
    p++;
  } else {
    p->layer = 0; p->flags = 0x15; p->tex = base + 0x1b0; p->mode = 2;
    p->x = lbl_803E0D94; p->y = lbl_803E0D90; p->z = lbl_803E0D94;
    p++;
  }
  p[0].layer = 0; p[0].flags = 0; p[0].tex = (void *)0; p[0].mode = 0x40;
  p[0].x = lbl_803E0D88; p[0].y = lbl_803E0D98; p[0].z = lbl_803E0D88;
  p[1].layer = 1; p[1].flags = 0x15; p[1].tex = base + 0x1b0; p[1].mode = 2;
  p[1].x = lbl_803E0D9C; p[1].y = lbl_803E0DA0; p[1].z = lbl_803E0D9C;
  p[2].layer = 1; p[2].flags = 7; p[2].tex = base + 0x164; p[2].mode = 4;
  p[2].x = lbl_803E0DA4; p[2].y = lbl_803E0D88; p[2].z = lbl_803E0D88;
  p[3].layer = 1; p[3].flags = 7; p[3].tex = base + 0x174; p[3].mode = 4;
  p[3].x = lbl_803E0DA8; p[3].y = lbl_803E0D88; p[3].z = lbl_803E0D88;
  p[4].layer = 1; p[4].flags = 0x15; p[4].tex = base + 0x1b0; p[4].mode = 0x4000;
  p[4].x = lbl_803E0DAC; p[4].y = lbl_803E0DB0; p[4].z = lbl_803E0D88;
  p[5].layer = 1; p[5].flags = 0; p[5].tex = (void *)0; p[5].mode = 0x40;
  p[5].x = lbl_803E0D88; p[5].y = lbl_803E0DB4; p[5].z = lbl_803E0D88;
  p[6].layer = 2; p[6].flags = 0x1e; p[6].tex = (void *)0; p[6].mode = 2;
  p[6].x = lbl_803E0D9C; p[6].y = lbl_803E0D88; p[6].z = lbl_803E0D88;
  p[7].layer = 2; p[7].flags = 0x15; p[7].tex = base + 0x1b0; p[7].mode = 0x4000;
  p[7].x = lbl_803E0DAC; p[7].y = lbl_803E0DB0; p[7].z = lbl_803E0D88;
  p[8].layer = 2; p[8].flags = 0; p[8].tex = (void *)0; p[8].mode = 0x40;
  p[8].x = lbl_803E0D88; p[8].y = lbl_803E0DB8; p[8].z = lbl_803E0D88;
  p[9].layer = 3; p[9].flags = 0x15; p[9].tex = base + 0x1b0; p[9].mode = 0x4000;
  p[9].x = lbl_803E0DAC; p[9].y = lbl_803E0DB0; p[9].z = lbl_803E0D88;
  p[10].layer = 3; p[10].flags = 7; p[10].tex = base + 0x164; p[10].mode = 4;
  p[10].x = lbl_803E0D88; p[10].y = lbl_803E0D88; p[10].z = lbl_803E0D88;
  p[11].layer = 3; p[11].flags = 7; p[11].tex = base + 0x174; p[11].mode = 4;
  p[11].x = lbl_803E0D88; p[11].y = lbl_803E0D88; p[11].z = lbl_803E0D88;
  p[12].layer = 3; p[12].flags = 0x1e; p[12].tex = (void *)0; p[12].mode = 2;
  p[12].x = lbl_803E0D9C; p[12].y = lbl_803E0D88; p[12].z = lbl_803E0D88;
  p[13].layer = 3; p[13].flags = 0; p[13].tex = (void *)0; p[13].mode = 0x40;
  p[13].x = lbl_803E0D88; p[13].y = lbl_803E0DB4; p[13].z = lbl_803E0D88;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E0D88; buf.pos[1] = lbl_803E0D88; buf.pos[2] = lbl_803E0D88;
  switch (param_2) {
  case 0:
    buf.pos[0] = lbl_803E0D88; buf.pos[2] = lbl_803E0DBC;
    break;
  case 1:
    buf.pos[0] = lbl_803E0DC0; buf.pos[2] = lbl_803E0DC4;
    break;
  case 2:
    buf.pos[0] = lbl_803E0DC8; buf.pos[2] = lbl_803E0DC4;
    break;
  case 3:
    buf.pos[0] = lbl_803E0D88; buf.pos[2] = lbl_803E0DCC;
    break;
  case 4:
    buf.pos[0] = lbl_803E0DC0; buf.pos[2] = lbl_803E0DD0;
    break;
  case 5:
    buf.pos[0] = lbl_803E0DC8; buf.pos[2] = lbl_803E0DD0;
    break;
  }
  buf.col[0] = lbl_803E0D88; buf.col[1] = lbl_803E0D88; buf.col[2] = lbl_803E0D88;
  buf.scale = lbl_803E0D9C;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0xa;
  buf.count = (FbCmd *)((u8 *)p + 0x150) - e;
  buf.hw[0] = *(s16 *)(base + 0x1f8); buf.hw[1] = *(s16 *)(base + 0x1fa);
  buf.hw[2] = *(s16 *)(base + 0x1fc); buf.hw[3] = *(s16 *)(base + 0x1fe);
  buf.hw[4] = *(s16 *)(base + 0x200); buf.hw[5] = *(s16 *)(base + 0x202);
  buf.hw[6] = *(s16 *)(base + 0x204);
  buf.cmds = buf.entries;
  buf.flags = 0xc010080;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)buf.ctx != 0) {
      buf.pos[0] += *(f32 *)(buf.ctx + 0x18);
      buf.pos[1] += *(f32 *)(buf.ctx + 0x1c);
      buf.pos[2] += *(f32 *)(buf.ctx + 0x20);
    } else {
      buf.pos[0] += *(f32 *)(param_3 + 0xc);
      buf.pos[1] += *(f32 *)(param_3 + 0x10);
      buf.pos[2] += *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,base,0x18,base + 0xd4,0x2e,0);
}

/*
 * --INFO--
 *
 * Function: dll_7D_func03
 * EN v1.0 Address: 0x800F4C70
 * EN v1.0 Size: 812b
 * EN v1.1 Address: 0x800F4F0C
 * EN v1.1 Size: 820b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_7D_func03(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,
                 f32 *param_6)
{
  FbBuf buf;
  u8 *base = lbl_80315030;
  f32 s = lbl_803E0DD8;
  FbCmd *e;
  if (param_6 != (f32 *)0) {
    s = *param_6;
  }
  e = buf.entries;
  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = base + 0x1b0; e[0].mode = 4;
  e[0].x = lbl_803E0DDC; e[0].y = lbl_803E0DDC; e[0].z = lbl_803E0DDC;
  e[1].layer = 0; e[1].flags = 0x15; e[1].tex = base + 0x1b0; e[1].mode = 2;
  e[1].y = e[1].x = lbl_803E0DE0 * s; e[1].z = lbl_803E0DE4 * s;
  e[2].layer = 1; e[2].flags = 7; e[2].tex = base + 0x184; e[2].mode = 2;
  e[2].x = lbl_803E0DE8; e[2].y = lbl_803E0DE8; e[2].z = lbl_803E0DD8;
  e[3].layer = 2; e[3].flags = 7; e[3].tex = base + 0x164; e[3].mode = 4;
  e[3].x = lbl_803E0DEC; e[3].y = lbl_803E0DDC; e[3].z = lbl_803E0DDC;
  e[4].layer = 2; e[4].flags = 7; e[4].tex = base + 0x174; e[4].mode = 4;
  e[4].x = lbl_803E0DEC; e[4].y = lbl_803E0DDC; e[4].z = lbl_803E0DDC;
  e[5].layer = 2; e[5].flags = 7; e[5].tex = base + 0x174; e[5].mode = 2;
  e[5].x = lbl_803E0DF0; e[5].y = lbl_803E0DF0; e[5].z = lbl_803E0DD8;
  e[6].layer = 2; e[6].flags = 0x15; e[6].tex = base + 0x1b0; e[6].mode = 0x4000;
  e[6].x = lbl_803E0DF4; e[6].y = lbl_803E0DF8; e[6].z = lbl_803E0DDC;
  e[7].layer = 3; e[7].flags = 0x15; e[7].tex = base + 0x1b0; e[7].mode = 0x4000;
  e[7].x = lbl_803E0DF4; e[7].y = lbl_803E0DF8; e[7].z = lbl_803E0DDC;
  e[8].layer = 3; e[8].flags = 7; e[8].tex = base + 0x164; e[8].mode = 4;
  e[8].x = lbl_803E0DDC; e[8].y = lbl_803E0DDC; e[8].z = lbl_803E0DDC;
  e[9].layer = 3; e[9].flags = 7; e[9].tex = base + 0x174; e[9].mode = 4;
  e[9].x = lbl_803E0DDC; e[9].y = lbl_803E0DDC; e[9].z = lbl_803E0DDC;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E0DDC; buf.pos[1] = lbl_803E0DDC; buf.pos[2] = lbl_803E0DDC;
  buf.col[0] = lbl_803E0DDC; buf.col[1] = lbl_803E0DDC; buf.col[2] = lbl_803E0DDC;
  buf.scale = lbl_803E0DD8;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0xa;
  buf.count = (FbCmd *)((u8 *)e + 0xf0) - e;
  buf.hw[0] = *(s16 *)(base + 0x1f8); buf.hw[1] = *(s16 *)(base + 0x1fa);
  buf.hw[2] = *(s16 *)(base + 0x1fc); buf.hw[3] = *(s16 *)(base + 0x1fe);
  buf.hw[4] = *(s16 *)(base + 0x200); buf.hw[5] = *(s16 *)(base + 0x202);
  buf.hw[6] = *(s16 *)(base + 0x204);
  buf.cmds = e;
  buf.flags = 0xc010080;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E0DDC + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E0DDC + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E0DDC + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E0DDC + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E0DDC + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E0DDC + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,base,0x18,base + 0xd4,0x89,0);
  lbl_803DD4B0 += 1;
  if (lbl_803DD4B0 == 5) {
    lbl_803DD4B0 = 0;
  }
}

/*
 * --INFO--
 *
 * Function: dll_7E_func03
 * EN v1.0 Address: 0x800F4FA4
 * EN v1.0 Size: 820b
 * EN v1.1 Address: 0x800F5240
 * EN v1.1 Size: 828b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_7E_func03(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,f32 *param_6
                 )
{
  FbBuf buf;
  u8 *base = lbl_80315258;
  f32 s = lbl_803E0E00;
  FbCmd *e;
  FbCmd *p;
  if (param_6 != (f32 *)0) {
    s = *param_6;
  }
  if (param_3 != 0) {
    s = *(f32 *)(param_3 + 8);
  }
  e = buf.entries;
  p = &e[2];
  e[0].layer = 0; e[0].flags = 5; e[0].tex = base + 0x90; e[0].mode = 0x4000;
  e[0].x = lbl_803E0E04; e[0].y = lbl_803E0E08; e[0].z = lbl_803E0E04;
  e[1].layer = 0; e[1].flags = 9; e[1].tex = base + 0x7c; e[1].mode = 4;
  e[1].x = lbl_803E0E04; e[1].y = lbl_803E0E04; e[1].z = lbl_803E0E04;
  if (param_2 == 1) {
    p->layer = 0; p->flags = 9; p->tex = base + 0x7c; p->mode = 2;
    p->x = lbl_803E0E0C * s; p->y = lbl_803E0E00; p->z = lbl_803E0E10;
    p++;
  } else {
    p->layer = 0; p->flags = 9; p->tex = base + 0x7c; p->mode = 2;
    p->x = lbl_803E0E14 * s; p->y = lbl_803E0E00; p->z = lbl_803E0E10;
    p++;
  }
  p[0].layer = 1; p[0].flags = 3; p[0].tex = &lbl_803DB8E0; p[0].mode = 4;
  p[0].x = lbl_803E0E18; p[0].y = lbl_803E0E04; p[0].z = lbl_803E0E04;
  p[1].layer = 1; p[1].flags = 5; p[1].tex = base + 0x90; p[1].mode = 0x4000;
  p[1].x = lbl_803E0E1C; p[1].y = lbl_803E0E08; p[1].z = lbl_803E0E04;
  p[2].layer = 2; p[2].flags = 5; p[2].tex = base + 0x90; p[2].mode = 0x4000;
  p[2].x = lbl_803E0E1C; p[2].y = lbl_803E0E08; p[2].z = lbl_803E0E04;
  p[3].layer = 2; p[3].flags = 3; p[3].tex = &lbl_803DB8E0; p[3].mode = 4;
  p[3].x = lbl_803E0E04; p[3].y = lbl_803E0E04; p[3].z = lbl_803E0E04;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E0E04; buf.pos[1] = lbl_803E0E04; buf.pos[2] = lbl_803E0E04;
  buf.col[0] = lbl_803E0E04; buf.col[1] = lbl_803E0E04; buf.col[2] = lbl_803E0E04;
  buf.scale = lbl_803E0E00;
  buf.v40 = 1;
  buf.v3c = 9;
  buf.v59 = 9;
  buf.v5a = 0;
  buf.v5b = 0xa;
  buf.count = (FbCmd *)((u8 *)p + 0x60) - e;
  buf.hw[0] = *(s16 *)(base + 0x9c); buf.hw[1] = *(s16 *)(base + 0x9e);
  buf.hw[2] = *(s16 *)(base + 0xa0); buf.hw[3] = *(s16 *)(base + 0xa2);
  buf.hw[4] = *(s16 *)(base + 0xa4); buf.hw[5] = *(s16 *)(base + 0xa6);
  buf.hw[6] = *(s16 *)(base + 0xa8);
  buf.cmds = buf.entries;
  buf.flags = 0x4010080;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E0E04 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E0E04 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E0E04 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E0E04 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E0E04 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E0E04 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,9,base,5,base + 0x5c,0x3c,0);
}

/*
 * --INFO--
 *
 * Function: dll_7F_func03
 * EN v1.0 Address: 0x800F52E0
 * EN v1.0 Size: 1264b
 * EN v1.1 Address: 0x800F557C
 * EN v1.1 Size: 1272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_7F_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  u8 *base = lbl_80315328;
  FbCmd *e = buf.entries;
  FbCmd *p = &e[1];

  e[0].layer = 0; e[0].flags = 0x8c; e[0].tex = (void *)0; e[0].mode = 0x2000;
  e[0].x = lbl_803E0E20; e[0].y = lbl_803E0E24; e[0].z = lbl_803E0E28;
  if (param_2 != 2) {
    p->layer = 0; p->flags = 9; p->tex = base + 0xe8; p->mode = 0x80;
    p->x = lbl_803E0E2C; p->y = lbl_803E0E2C; p->z = lbl_803E0E30;
    p++;
  }
  if (param_2 == 0) {
    p->layer = 0; p->flags = 8; p->tex = base + 0xfc; p->mode = 2;
    p->x = lbl_803E0E34; p->y = lbl_803E0E34; p->z = lbl_803E0E38;
    p++;
  } else {
    p->layer = 0; p->flags = 8; p->tex = base + 0xfc; p->mode = 2;
    p->x = lbl_803E0E3C; p->y = lbl_803E0E3C; p->z = lbl_803E0E40;
    p++;
  }
  if (param_2 == 0) {
    p->layer = 1; p->flags = 8; p->tex = base + 0xe8; p->mode = 2;
    p->x = lbl_803E0E44; p->y = lbl_803E0E44; p->z = lbl_803E0E44;
    p++;
  } else {
    p->layer = 1; p->flags = 8; p->tex = base + 0xe8; p->mode = 2;
    p->x = lbl_803E0E44; p->y = lbl_803E0E44; p->z = lbl_803E0E44;
    p++;
  }
  if (param_2 == 0) {
    p->layer = 1; p->flags = 9; p->tex = base + 0xe8; p->mode = 0x100;
    p->x = lbl_803E0E48; p->y = lbl_803E0E2C; p->z = lbl_803E0E2C;
    p++;
    p->layer = 1; p->flags = 1; p->tex = &lbl_803DB8E8; p->mode = 0x4000;
    p->x = lbl_803E0E4C; p->y = lbl_803E0E4C; p->z = lbl_803E0E2C;
    p++;
  } else if (param_2 == 1) {
    p->layer = 1; p->flags = 9; p->tex = base + 0xe8; p->mode = 0x100;
    p->x = lbl_803E0E50; p->y = lbl_803E0E2C; p->z = lbl_803E0E2C;
    p++;
  }
  if (param_2 == 0) {
    p->layer = 2; p->flags = 9; p->tex = base + 0xe8; p->mode = 0x100;
    p->x = lbl_803E0E48; p->y = lbl_803E0E2C; p->z = lbl_803E0E2C;
    p++;
    p->layer = 2; p->flags = 1; p->tex = &lbl_803DB8E8; p->mode = 0x4000;
    p->x = lbl_803E0E4C; p->y = lbl_803E0E4C; p->z = lbl_803E0E2C;
    p++;
  } else if (param_2 == 1) {
    p->layer = 2; p->flags = 9; p->tex = base + 0xe8; p->mode = 0x100;
    p->x = lbl_803E0E50; p->y = lbl_803E0E2C; p->z = lbl_803E0E2C;
    p++;
  }
  p[0].layer = 2; p[0].flags = 9; p[0].tex = base + 0xe8; p[0].mode = 4;
  p[0].x = lbl_803E0E2C; p[0].y = lbl_803E0E2C; p[0].z = lbl_803E0E2C;
  p[1].layer = 3; p[1].flags = 0; p[1].tex = (void *)0; p[1].mode = 0x2000;
  p[1].x = lbl_803E0E20; p[1].y = lbl_803E0E24; p[1].z = lbl_803E0E28;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E0E2C; buf.pos[1] = lbl_803E0E2C; buf.pos[2] = lbl_803E0E2C;
  buf.col[0] = lbl_803E0E2C; buf.col[1] = lbl_803E0E2C; buf.col[2] = lbl_803E0E2C;
  buf.scale = lbl_803E0E54;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 9;
  buf.v5a = 0;
  buf.v5b = 0x20;
  buf.count = (FbCmd *)((u8 *)p + 0x30) - e;
  buf.hw[0] = *(s16 *)(base + 0x10c); buf.hw[1] = *(s16 *)(base + 0x10e);
  buf.hw[2] = *(s16 *)(base + 0x110); buf.hw[3] = *(s16 *)(base + 0x112);
  buf.hw[4] = *(s16 *)(base + 0x114); buf.hw[5] = *(s16 *)(base + 0x116);
  buf.hw[6] = *(s16 *)(base + 0x118);
  buf.cmds = buf.entries;
  buf.flags = 0x400;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E0E2C + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E0E2C + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E0E2C + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E0E2C + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E0E2C + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E0E2C + *(f32 *)(param_3 + 0x14);
    }
  }
  if (param_2 == 0) {
    buf.v58 = 0;
    (*(code *)(*gModgfxInterface + 8))(&buf,0,9,base,8,base + 0xb8,0x156,0);
  } else {
    buf.v58 = 0;
    (*(code *)(*gModgfxInterface + 8))(&buf,0,9,base + 0x5c,8,base + 0xb8,0x8a,0);
  }
}

/*
 * --INFO--
 *
 * Function: dll_80_func03
 * EN v1.0 Address: 0x800F57D8
 * EN v1.0 Size: 684b
 * EN v1.1 Address: 0x800F5A74
 * EN v1.1 Size: 692b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_80_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  u8 *base = lbl_80315468;
  FbCmd *e = buf.entries;

  e[0].layer = 0; e[0].flags = 9; e[0].tex = base + 0x8c; e[0].mode = 0x80;
  e[0].x = lbl_803E0E58; e[0].y = lbl_803E0E58; e[0].z = lbl_803E0E5C;
  if (param_2 == 1) {
    e[1].layer = 0; e[1].flags = 8; e[1].tex = base + 0xa0; e[1].mode = 2;
    e[1].x = lbl_803E0E60; e[1].y = lbl_803E0E60; e[1].z = lbl_803E0E64;
  } else {
    e[1].layer = 0; e[1].flags = 8; e[1].tex = base + 0xa0; e[1].mode = 2;
    e[1].x = lbl_803E0E68; e[1].y = lbl_803E0E68; e[1].z = lbl_803E0E6C;
  }
  e[2].layer = 1; e[2].flags = 8; e[2].tex = base + 0x8c; e[2].mode = 2;
  e[2].x = lbl_803E0E6C; e[2].y = lbl_803E0E6C; e[2].z = lbl_803E0E70;
  e[3].layer = 1; e[3].flags = 9; e[3].tex = base + 0x8c; e[3].mode = 0x100;
  e[3].x = lbl_803E0E74; e[3].y = lbl_803E0E58; e[3].z = lbl_803E0E58;
  e[4].layer = 1; e[4].flags = 9; e[4].tex = base + 0x8c; e[4].mode = 4;
  e[4].x = lbl_803E0E58; e[4].y = lbl_803E0E58; e[4].z = lbl_803E0E58;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E0E58; buf.pos[1] = lbl_803E0E58; buf.pos[2] = lbl_803E0E58;
  buf.col[0] = lbl_803E0E58; buf.col[1] = lbl_803E0E58; buf.col[2] = lbl_803E0E58;
  buf.scale = lbl_803E0E70;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 9;
  buf.v5a = 0;
  buf.v5b = 0x20;
  buf.flags = 0x4000010;
  buf.count = (FbCmd *)((u8 *)e + 120) - e;
  buf.hw[0] = *(s16 *)(base + 0xb0); buf.hw[1] = *(s16 *)(base + 0xb2);
  buf.hw[2] = *(s16 *)(base + 0xb4); buf.hw[3] = *(s16 *)(base + 0xb6);
  buf.hw[4] = *(s16 *)(base + 0xb8); buf.hw[5] = *(s16 *)(base + 0xba);
  buf.hw[6] = *(s16 *)(base + 0xbc);
  buf.cmds = e;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E0E58 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E0E58 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E0E58 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E0E58 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E0E58 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E0E58 + *(f32 *)(param_3 + 0x14);
    }
  }
  buf.v58 = 0;
  (*(code *)(*gModgfxInterface + 8))(&buf,0,9,base,8,base + 0x5c,0x156,0);
}

/*
 * --INFO--
 *
 * Function: dll_81_func03
 * EN v1.0 Address: 0x800F5A8C
 * EN v1.0 Size: 1724b
 * EN v1.1 Address: 0x800F5D28
 * EN v1.1 Size: 1732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_81_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  u8 *base = lbl_80315548;
  f32 sy = lbl_803E0E78;
  FbCmd *e;
  FbCmd *p;
  if (param_2 == 0 || param_2 == 2 || param_2 == 0x1e) {
    *(s16 *)(base + 0x1fa) = 0xc;
  } else if (param_2 == 1 || param_2 == 3) {
    sy *= lbl_803E0E7C;
    *(s16 *)(base + 0x1fa) = 4;
    *(s16 *)(base + 0x200) = 0x32;
  }
  e = buf.entries;
  p = &e[1];
  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = base + 0x1b0; e[0].mode = 4;
  e[0].x = lbl_803E0E80; e[0].y = lbl_803E0E80; e[0].z = lbl_803E0E80;
  if (param_2 == 0 || param_2 == 2) {
    p->layer = 0; p->flags = 0x15; p->tex = base + 0x1b0; p->mode = 2;
    p->x = lbl_803E0E84; p->y = lbl_803E0E84; p->z = lbl_803E0E88;
    p++;
  } else if (param_2 == 0xe) {
    p->layer = 0; p->flags = 0x15; p->tex = base + 0x1b0; p->mode = 2;
    p->x = lbl_803E0E8C; p->y = lbl_803E0E8C; p->z = lbl_803E0E90;
    p++;
  } else if (param_2 == 0x1e) {
    p->layer = 0; p->flags = 0x15; p->tex = base + 0x1b0; p->mode = 2;
    p->x = lbl_803E0E94; p->y = lbl_803E0E94; p->z = lbl_803E0E88;
    p++;
  } else {
    p->layer = 0; p->flags = 0x15; p->tex = base + 0x1b0; p->mode = 2;
    p->x = lbl_803E0E84; p->y = lbl_803E0E84; p->z = lbl_803E0E98;
    p++;
  }
  p[0].layer = 0; p[0].flags = 0x77; p[0].tex = (void *)0; p[0].mode = 1;
  p[0].x = lbl_803E0E80; p[0].y = lbl_803E0E80; p[0].z = lbl_803E0E80;
  p[1].layer = 0; p[1].flags = 0x79; p[1].tex = (void *)0; p[1].mode = 1;
  p[1].x = lbl_803E0E80; p[1].y = lbl_803E0E80; p[1].z = lbl_803E0E80;
  p[2].layer = 1; p[2].flags = 0x15; p[2].tex = base + 0x1b0; p[2].mode = 4;
  p[2].x = lbl_803E0E9C; p[2].y = lbl_803E0E80; p[2].z = lbl_803E0E80;
  p += 3;
  if (param_2 == 0 || param_2 == 2) {
    p->layer = 1; p->flags = 0x15; p->tex = base + 0x1b0; p->mode = 2;
    p->x = lbl_803E0EA0; p->y = lbl_803E0EA0; p->z = lbl_803E0EA4;
    p++;
  } else if (param_2 == 0x1e) {
    p->layer = 1; p->flags = 0x15; p->tex = base + 0x1b0; p->mode = 2;
    p->x = lbl_803E0EA0; p->y = lbl_803E0EA0; p->z = lbl_803E0EA8;
    p++;
  }
  p[0].layer = 1; p[0].flags = 0x15; p[0].tex = base + 0x1b0; p[0].mode = 0x4000;
  p[0].x = lbl_803E0EA0; p[0].y = sy; p[0].z = lbl_803E0E80;
  p[1].layer = 2; p[1].flags = 0x15; p[1].tex = base + 0x1b0; p[1].mode = 4;
  p[1].x = lbl_803E0E9C; p[1].y = lbl_803E0E80; p[1].z = lbl_803E0E80;
  p[2].layer = 2; p[2].flags = 0x15; p[2].tex = base + 0x1b0; p[2].mode = 0x4000;
  p[2].x = lbl_803E0EA0; p[2].y = sy; p[2].z = lbl_803E0E80;
  p[3].layer = 3; p[3].flags = 0x15; p[3].tex = base + 0x1b0; p[3].mode = 0x4000;
  p[3].x = lbl_803E0EA0; p[3].y = sy; p[3].z = lbl_803E0E80;
  p[4].layer = 4; p[4].flags = 0x15; p[4].tex = base + 0x1b0; p[4].mode = 0x4000;
  p[4].x = lbl_803E0EA0; p[4].y = sy; p[4].z = lbl_803E0E80;
  p += 5;
  if (param_2 == 0 || param_2 == 0x1e) {
    p->layer = 4; p->flags = 2; p->tex = (void *)0; p->mode = 0x2000;
    p->x = lbl_803E0E80; p->y = lbl_803E0E80; p->z = lbl_803E0E80;
    p++;
  }
  p[0].layer = 5; p[0].flags = 0x15; p[0].tex = base + 0x1b0; p[0].mode = 0x4000;
  p[0].x = lbl_803E0EA0; p[0].y = sy; p[0].z = lbl_803E0E80;
  p[1].layer = 5; p[1].flags = 0x15; p[1].tex = base + 0x1b0; p[1].mode = 4;
  p[1].x = lbl_803E0E80; p[1].y = lbl_803E0E80; p[1].z = lbl_803E0E80;
  p += 2;
  if (param_2 == 1 || param_2 == 3) {
    p->layer = 5; p->flags = 0x15; p->tex = base + 0x1b0; p->mode = 2;
    p->x = lbl_803E0EA0; p->y = lbl_803E0EA0; p->z = lbl_803E0E88;
    p++;
  }
  p[0].layer = 5; p[0].flags = 0x78; p[0].tex = (void *)0; p[0].mode = 1;
  p[0].x = lbl_803E0E80; p[0].y = lbl_803E0E80; p[0].z = lbl_803E0E80;
  p[1].layer = 5; p[1].flags = 0xffff; p[1].tex = (void *)0; p[1].mode = 1;
  p[1].x = lbl_803E0E80; p[1].y = lbl_803E0E80; p[1].z = lbl_803E0E80;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E0E80; buf.pos[1] = lbl_803E0E80; buf.pos[2] = lbl_803E0E80;
  buf.col[0] = lbl_803E0E80; buf.col[1] = lbl_803E0E80; buf.col[2] = lbl_803E0E80;
  buf.scale = lbl_803E0EA0;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0xa;
  buf.count = (FbCmd *)((u8 *)p + 0x30) - e;
  buf.hw[0] = *(s16 *)(base + 0x1f8); buf.hw[1] = *(s16 *)(base + 0x1fa);
  buf.hw[2] = *(s16 *)(base + 0x1fc); buf.hw[3] = *(s16 *)(base + 0x1fe);
  buf.hw[4] = *(s16 *)(base + 0x200); buf.hw[5] = *(s16 *)(base + 0x202);
  buf.hw[6] = *(s16 *)(base + 0x204);
  buf.cmds = buf.entries;
  buf.flags = 0xc0104c0;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E0E80 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E0E80 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E0E80 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E0E80 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E0E80 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E0E80 + *(f32 *)(param_3 + 0x14);
    }
  }
  if (param_2 == 0x1e) {
    (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,base,0x18,base + 0xd4,0x3e9,0);
  } else if (param_2 == 2 || param_2 == 3) {
    (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,base,0x18,base + 0xd4,0x23d,0);
  } else if ((uint)(param_2 - 10) <= 3 || param_2 == 0xe) {
    (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,base,0x18,base + 0xd4,0x2e,0);
  } else {
    (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,base,0x18,base + 0xd4,0xd9,0);
  }
}

/*
 * --INFO--
 *
 * Function: dll_82_func03
 * EN v1.0 Address: 0x800F6150
 * EN v1.0 Size: 988b
 * EN v1.1 Address: 0x800F63EC
 * EN v1.1 Size: 996b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_82_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  u8 *base = lbl_80315770;
  FbCmd *e;
  if (param_2 == 1 || param_2 == 4) {
    *(s16 *)(base + 0x1fc) = 0x50;
  }
  if (param_2 == 2) {
    *(s16 *)(base + 0x1fc) = 0x6e;
  }
  e = buf.entries;
  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = base + 0x1b0; e[0].mode = 0x4;
  e[0].x = lbl_803E0EB0; e[0].y = lbl_803E0EB0; e[0].z = lbl_803E0EB0;
  e[1].layer = 0; e[1].flags = 0x15; e[1].tex = base + 0x1b0; e[1].mode = 0x2;
  e[1].x = lbl_803E0EB4; e[1].y = lbl_803E0EB8; e[1].z = lbl_803E0EB4;
  e[2].layer = 1; e[2].flags = 0x15; e[2].tex = base + 0x1b0; e[2].mode = 0x2;
  e[2].x = lbl_803E0EBC; e[2].y = lbl_803E0EC0; e[2].z = lbl_803E0EBC;
  e[3].layer = 1; e[3].flags = 0x7; e[3].tex = base + 0x164; e[3].mode = 0x4;
  e[3].x = lbl_803E0EC4; e[3].y = lbl_803E0EB0; e[3].z = lbl_803E0EB0;
  e[4].layer = 1; e[4].flags = 0x7; e[4].tex = base + 0x174; e[4].mode = 0x4;
  e[4].x = lbl_803E0EC8; e[4].y = lbl_803E0EB0; e[4].z = lbl_803E0EB0;
  e[5].layer = 1; e[5].flags = 0x15; e[5].tex = base + 0x1b0; e[5].mode = 0x4000;
  e[5].x = lbl_803E0ECC; e[5].y = lbl_803E0ED0; e[5].z = lbl_803E0EB0;
  e[6].layer = 2; e[6].flags = 0x1e; e[6].tex = (void *)0; e[6].mode = 0x2;
  e[6].x = lbl_803E0EBC; e[6].y = lbl_803E0EB0; e[6].z = lbl_803E0EB0;
  e[7].layer = 2; e[7].flags = 0x15; e[7].tex = base + 0x1b0; e[7].mode = 0x2;
  e[7].x = lbl_803E0ED0; e[7].y = lbl_803E0EBC; e[7].z = lbl_803E0ED0;
  e[8].layer = 2; e[8].flags = 0x15; e[8].tex = base + 0x1b0; e[8].mode = 0x4000;
  e[8].x = lbl_803E0ECC; e[8].y = lbl_803E0ED0; e[8].z = lbl_803E0EB0;
  e[9].layer = 3; e[9].flags = 0x15; e[9].tex = base + 0x1b0; e[9].mode = 0x2;
  e[9].x = lbl_803E0ED0; e[9].y = lbl_803E0EBC; e[9].z = lbl_803E0ED0;
  e[10].layer = 3; e[10].flags = 0x15; e[10].tex = base + 0x1b0; e[10].mode = 0x4000;
  e[10].x = lbl_803E0ECC; e[10].y = lbl_803E0ED0; e[10].z = lbl_803E0EB0;
  e[11].layer = 3; e[11].flags = 0x7; e[11].tex = base + 0x164; e[11].mode = 0x4;
  e[11].x = lbl_803E0EB0; e[11].y = lbl_803E0EB0; e[11].z = lbl_803E0EB0;
  e[12].layer = 3; e[12].flags = 0x7; e[12].tex = base + 0x174; e[12].mode = 0x4;
  e[12].x = lbl_803E0EB0; e[12].y = lbl_803E0EB0; e[12].z = lbl_803E0EB0;
  e[13].layer = 3; e[13].flags = 0x1e; e[13].tex = (void *)0; e[13].mode = 0x2;
  e[13].x = lbl_803E0EBC; e[13].y = lbl_803E0EB0; e[13].z = lbl_803E0EB0;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E0EB0; buf.pos[1] = lbl_803E0EB0; buf.pos[2] = lbl_803E0EB0;
  buf.col[0] = lbl_803E0EB0; buf.col[1] = lbl_803E0EB0; buf.col[2] = lbl_803E0EB0;
  buf.scale = lbl_803E0EBC;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0xa;
  buf.count = (FbCmd *)((u8 *)e + 0x150) - e;
  buf.hw[0] = *(s16 *)(base + 0x1f8); buf.hw[1] = *(s16 *)(base + 0x1fa);
  buf.hw[2] = *(s16 *)(base + 0x1fc); buf.hw[3] = *(s16 *)(base + 0x1fe);
  buf.hw[4] = *(s16 *)(base + 0x200); buf.hw[5] = *(s16 *)(base + 0x202);
  buf.hw[6] = *(s16 *)(base + 0x204);
  buf.cmds = e;
  buf.flags = 0xc010480;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E0EB0 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E0EB0 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E0EB0 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E0EB0 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E0EB0 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E0EB0 + *(f32 *)(param_3 + 0x14);
    }
  }
  if (param_2 == 3 || param_2 == 4) {
    (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,base,0x18,base + 0xd4,0xd9,0);
  } else {
    (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,base,0x18,base + 0xd4,0x2e,0);
  }
}

/*
 * --INFO--
 *
 * Function: dll_83_func03
 * EN v1.0 Address: 0x800F6534
 * EN v1.0 Size: 1100b
 * EN v1.1 Address: 0x800F67D0
 * EN v1.1 Size: 1108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_83_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  u8 *base = lbl_80315998;
  FbCmd *e = buf.entries;

  e[0].layer = 0; e[0].flags = 0x9; e[0].tex = base + 0x1c8; e[0].mode = 0x2;
  e[0].x = lbl_803E0ED8; e[0].y = lbl_803E0EDC; e[0].z = lbl_803E0ED8;
  e[1].layer = 0; e[1].flags = 0x9; e[1].tex = base + 0x1dc; e[1].mode = 0x2;
  e[1].x = lbl_803E0EE0; e[1].y = lbl_803E0EDC; e[1].z = lbl_803E0EE0;
  e[2].layer = 0; e[2].flags = 0x9; e[2].tex = base + 0x1f0; e[2].mode = 0x2;
  e[2].x = lbl_803E0EE0; e[2].y = lbl_803E0EDC; e[2].z = lbl_803E0EE0;
  e[3].layer = 0; e[3].flags = 0x9; e[3].tex = base + 0x204; e[3].mode = 0x2;
  e[3].x = lbl_803E0EE0; e[3].y = lbl_803E0EDC; e[3].z = lbl_803E0EE0;
  e[4].layer = 0; e[4].flags = 0x24; e[4].tex = base + 0x260; e[4].mode = 0x4;
  e[4].x = lbl_803E0EE4; e[4].y = lbl_803E0EE4; e[4].z = lbl_803E0EE4;
  e[5].layer = 0; e[5].flags = 0x0; e[5].tex = (void *)0; e[5].mode = 0x40;
  e[5].x = lbl_803E0EE8; e[5].y = lbl_803E0EEC; e[5].z = lbl_803E0EF0;
  e[6].layer = 1; e[6].flags = 0x24; e[6].tex = base + 0x260; e[6].mode = 0x2;
  e[6].x = lbl_803E0EF4; e[6].y = lbl_803E0EF8; e[6].z = lbl_803E0EF4;
  e[7].layer = 1; e[7].flags = 0x24; e[7].tex = base + 0x260; e[7].mode = 0x4000;
  e[7].x = lbl_803E0EE4; e[7].y = lbl_803E0EE4; e[7].z = lbl_803E0EE4;
  e[8].layer = 1; e[8].flags = 0x24; e[8].tex = base + 0x260; e[8].mode = 0x100;
  e[8].x = lbl_803E0EE4; e[8].y = lbl_803E0EE4; e[8].z = lbl_803E0EFC;
  e[9].layer = 2; e[9].flags = 0x12; e[9].tex = base + 0x2a8; e[9].mode = 0x4;
  e[9].x = lbl_803E0F00; e[9].y = lbl_803E0EE4; e[9].z = lbl_803E0EE4;
  e[10].layer = 2; e[10].flags = 0x24; e[10].tex = base + 0x260; e[10].mode = 0x2;
  e[10].x = lbl_803E0F04; e[10].y = lbl_803E0F04; e[10].z = lbl_803E0F04;
  e[11].layer = 2; e[11].flags = 0x24; e[11].tex = base + 0x260; e[11].mode = 0x4000;
  e[11].x = lbl_803E0EE4; e[11].y = lbl_803E0EE4; e[11].z = lbl_803E0EE4;
  e[12].layer = 2; e[12].flags = 0x0; e[12].tex = (void *)0; e[12].mode = 0x40;
  e[12].x = lbl_803E0F08; e[12].y = lbl_803E0F0C; e[12].z = lbl_803E0F10;
  e[13].layer = 2; e[13].flags = 0x24; e[13].tex = base + 0x260; e[13].mode = 0x100;
  e[13].x = lbl_803E0EE4; e[13].y = lbl_803E0EE4; e[13].z = lbl_803E0EFC;
  e[14].layer = 3; e[14].flags = 0x24; e[14].tex = base + 0x260; e[14].mode = 0x100;
  e[14].x = lbl_803E0EE4; e[14].y = lbl_803E0EE4; e[14].z = lbl_803E0EFC;
  e[15].layer = 3; e[15].flags = 0x24; e[15].tex = base + 0x260; e[15].mode = 0x4000;
  e[15].x = lbl_803E0EE4; e[15].y = lbl_803E0EE4; e[15].z = lbl_803E0EE4;
  e[16].layer = 4; e[16].flags = 0x24; e[16].tex = base + 0x260; e[16].mode = 0x4000;
  e[16].x = lbl_803E0EE4; e[16].y = lbl_803E0EE4; e[16].z = lbl_803E0EE4;
  e[17].layer = 4; e[17].flags = 0x24; e[17].tex = base + 0x260; e[17].mode = 0x100;
  e[17].x = lbl_803E0EE4; e[17].y = lbl_803E0EE4; e[17].z = lbl_803E0F00;
  e[18].layer = 4; e[18].flags = 0x12; e[18].tex = base + 0x2a8; e[18].mode = 0x4;
  e[18].x = lbl_803E0EE4; e[18].y = lbl_803E0EE4; e[18].z = lbl_803E0EE4;
  e[19].layer = 4; e[19].flags = 0x24; e[19].tex = base + 0x260; e[19].mode = 0x2;
  e[19].x = lbl_803E0F14; e[19].y = lbl_803E0F18; e[19].z = lbl_803E0F14;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E0EE4; buf.pos[1] = lbl_803E0EE4; buf.pos[2] = lbl_803E0EE4;
  buf.col[0] = lbl_803E0EE4; buf.col[1] = lbl_803E0EE4; buf.col[2] = lbl_803E0EE4;
  buf.scale = lbl_803E0F18;
  buf.v40 = 3;
  buf.v3c = 9;
  buf.v59 = 0x12;
  buf.v5a = 0;
  buf.v5b = 0x10;
  buf.flags = 0x4000484;
  buf.count = (FbCmd *)((u8 *)e + 0x1e0) - e;
  buf.hw[0] = *(s16 *)(base + 0x2cc); buf.hw[1] = *(s16 *)(base + 0x2ce);
  buf.hw[2] = *(s16 *)(base + 0x2d0); buf.hw[3] = *(s16 *)(base + 0x2d2);
  buf.hw[4] = *(s16 *)(base + 0x2d4); buf.hw[5] = *(s16 *)(base + 0x2d6);
  buf.hw[6] = *(s16 *)(base + 0x2d8);
  buf.cmds = e;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E0EE4 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E0EE4 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E0EE4 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E0EE4 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E0EE4 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E0EE4 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x24,base,0x10,base + 0x168,*(int *)((base + param_2 * 4) + 0x2dc),0);
}

/*
 * --INFO--
 *
 * Function: dll_84_func03
 * EN v1.0 Address: 0x800F6988
 * EN v1.0 Size: 1100b
 * EN v1.1 Address: 0x800F6C24
 * EN v1.1 Size: 1108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_84_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  u8 *base = lbl_80315CA8;
  FbCmd *e = buf.entries;

  e[0].layer = 0; e[0].flags = 0x9; e[0].tex = base + 0x1c8; e[0].mode = 0x2;
  e[0].x = lbl_803E0F20; e[0].y = lbl_803E0F24; e[0].z = lbl_803E0F20;
  e[1].layer = 0; e[1].flags = 0x9; e[1].tex = base + 0x1dc; e[1].mode = 0x2;
  e[1].x = lbl_803E0F28; e[1].y = lbl_803E0F24; e[1].z = lbl_803E0F28;
  e[2].layer = 0; e[2].flags = 0x9; e[2].tex = base + 0x1f0; e[2].mode = 0x2;
  e[2].x = lbl_803E0F28; e[2].y = lbl_803E0F24; e[2].z = lbl_803E0F28;
  e[3].layer = 0; e[3].flags = 0x9; e[3].tex = base + 0x204; e[3].mode = 0x2;
  e[3].x = lbl_803E0F28; e[3].y = lbl_803E0F24; e[3].z = lbl_803E0F28;
  e[4].layer = 0; e[4].flags = 0x24; e[4].tex = base + 0x260; e[4].mode = 0x4;
  e[4].x = lbl_803E0F2C; e[4].y = lbl_803E0F2C; e[4].z = lbl_803E0F2C;
  e[5].layer = 0; e[5].flags = 0x0; e[5].tex = (void *)0; e[5].mode = 0x40;
  e[5].x = lbl_803E0F30; e[5].y = lbl_803E0F34; e[5].z = lbl_803E0F38;
  e[6].layer = 1; e[6].flags = 0x24; e[6].tex = base + 0x260; e[6].mode = 0x2;
  e[6].x = lbl_803E0F3C; e[6].y = lbl_803E0F40; e[6].z = lbl_803E0F3C;
  e[7].layer = 1; e[7].flags = 0x24; e[7].tex = base + 0x260; e[7].mode = 0x4000;
  e[7].x = lbl_803E0F2C; e[7].y = lbl_803E0F2C; e[7].z = lbl_803E0F2C;
  e[8].layer = 1; e[8].flags = 0x24; e[8].tex = base + 0x260; e[8].mode = 0x100;
  e[8].x = lbl_803E0F2C; e[8].y = lbl_803E0F2C; e[8].z = lbl_803E0F44;
  e[9].layer = 2; e[9].flags = 0x12; e[9].tex = base + 0x2a8; e[9].mode = 0x4;
  e[9].x = lbl_803E0F48; e[9].y = lbl_803E0F2C; e[9].z = lbl_803E0F2C;
  e[10].layer = 2; e[10].flags = 0x24; e[10].tex = base + 0x260; e[10].mode = 0x2;
  e[10].x = lbl_803E0F4C; e[10].y = lbl_803E0F50; e[10].z = lbl_803E0F4C;
  e[11].layer = 2; e[11].flags = 0x24; e[11].tex = base + 0x260; e[11].mode = 0x4000;
  e[11].x = lbl_803E0F2C; e[11].y = lbl_803E0F2C; e[11].z = lbl_803E0F2C;
  e[12].layer = 2; e[12].flags = 0x0; e[12].tex = (void *)0; e[12].mode = 0x40;
  e[12].x = lbl_803E0F54; e[12].y = lbl_803E0F58; e[12].z = lbl_803E0F5C;
  e[13].layer = 2; e[13].flags = 0x24; e[13].tex = base + 0x260; e[13].mode = 0x100;
  e[13].x = lbl_803E0F2C; e[13].y = lbl_803E0F2C; e[13].z = lbl_803E0F44;
  e[14].layer = 3; e[14].flags = 0x24; e[14].tex = base + 0x260; e[14].mode = 0x100;
  e[14].x = lbl_803E0F2C; e[14].y = lbl_803E0F2C; e[14].z = lbl_803E0F44;
  e[15].layer = 3; e[15].flags = 0x24; e[15].tex = base + 0x260;
  e[15].y = lbl_803E0F2C; e[15].x = lbl_803E0F2C; e[15].y = lbl_803E0F60; e[15].z = lbl_803E0F2C;
  e[16].layer = 4; e[16].flags = 0x24; e[16].tex = base + 0x260;
  e[16].y = lbl_803E0F2C; e[16].x = lbl_803E0F2C; e[16].y = lbl_803E0F60; e[16].z = lbl_803E0F2C;
  e[17].layer = 4; e[17].flags = 0x24; e[17].tex = base + 0x260; e[17].mode = 0x100;
  e[17].x = lbl_803E0F2C; e[17].y = lbl_803E0F2C; e[17].z = lbl_803E0F64;
  e[18].layer = 4; e[18].flags = 0x12; e[18].tex = base + 0x2a8; e[18].mode = 0x4;
  e[18].x = lbl_803E0F2C; e[18].y = lbl_803E0F2C; e[18].z = lbl_803E0F2C;
  e[19].layer = 4; e[19].flags = 0x24; e[19].tex = base + 0x260; e[19].mode = 0x2;
  e[19].x = lbl_803E0F68; e[19].y = lbl_803E0F6C; e[19].z = lbl_803E0F68;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E0F2C; buf.pos[1] = lbl_803E0F2C; buf.pos[2] = lbl_803E0F2C;
  buf.col[0] = lbl_803E0F2C; buf.col[1] = lbl_803E0F2C; buf.col[2] = lbl_803E0F2C;
  buf.scale = lbl_803E0F6C;
  buf.v40 = 3;
  buf.v3c = 9;
  buf.v59 = 0x12;
  buf.v5a = 0;
  buf.v5b = 0x10;
  buf.flags = 0x4000484;
  buf.count = (FbCmd *)((u8 *)e + 0x1e0) - e;
  buf.hw[0] = *(s16 *)(base + 0x2cc); buf.hw[1] = *(s16 *)(base + 0x2ce);
  buf.hw[2] = *(s16 *)(base + 0x2d0); buf.hw[3] = *(s16 *)(base + 0x2d2);
  buf.hw[4] = *(s16 *)(base + 0x2d4); buf.hw[5] = *(s16 *)(base + 0x2d6);
  buf.hw[6] = *(s16 *)(base + 0x2d8);
  buf.cmds = e;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E0F2C + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E0F2C + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E0F2C + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E0F2C + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E0F2C + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E0F2C + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x24,base,0x10,base + 0x168,0x3f,0);
}

/*
 * --INFO--
 *
 * Function: dll_85_func03
 * EN v1.0 Address: 0x800F6DDC
 * EN v1.0 Size: 1616b
 * EN v1.1 Address: 0x800F7078
 * EN v1.1 Size: 1624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_85_func03(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
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
    local_324 = lbl_803E1BF0;
    local_320 = lbl_803E1BF4;
    local_31c = lbl_803E1BF4;
    local_2fa = 0;
    local_2fc = 2;
    local_300 = &DAT_803dc55c;
    local_310 = 2;
    local_30c = lbl_803E1BF8;
    local_308 = lbl_803E1BFC;
    local_304 = lbl_803E1BF8;
    local_2e2 = 0;
    local_2e4 = 4;
    local_2e8 = &DAT_803dc55c;
    local_2f8 = 0x80;
    uStack_24 = randomGetRange(0xffff8008,0x7ff8);
    uStack_24 = uStack_24 ^ 0x80000000;
    dVar1 = (double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1c28;
    local_2f0 = lbl_803E1BF4;
    local_2ec = lbl_803E1C00;
  }
  else {
    local_312 = 0;
    local_314 = 2;
    local_318 = &DAT_803dc550;
    local_328 = 2;
    local_308 = *(float *)(iVar2 + 8);
    local_324 = lbl_803E1C04 * local_308;
    local_320 = lbl_803E1C08 * local_308;
    local_31c = lbl_803E1C0C;
    local_2fa = 0;
    local_2fc = 2;
    local_300 = &DAT_803dc55c;
    local_310 = 2;
    local_308 = local_308 / *(float *)(*(int *)(iVar2 + 0x50) + 4);
    local_30c = lbl_803E1C10 * local_308;
    local_308 = lbl_803E1C08 * local_308;
    local_304 = lbl_803E1C0C;
    uStack_24 = randomGetRange(0,0xfffe);
    uStack_24 = uStack_24 ^ 0x80000000;
    dVar1 = (double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1c28;
    local_2e2 = 0;
    local_2e4 = 0;
    local_2e8 = (undefined *)0x0;
    local_2f8 = 0x80;
    local_2f0 = lbl_803E1C14;
    local_2ec = lbl_803E1BF4;
  }
  local_2f4 = (float)dVar1;
  local_28 = 0x43300000;
  local_2ca = 0;
  local_2cc = 4;
  local_2d0 = &DAT_803dc554;
  local_2e0 = 4;
  local_2dc = lbl_803E1BF4;
  local_2d8 = lbl_803E1BF4;
  local_2d4 = lbl_803E1BF4;
  uStack_24 = randomGetRange(0,0xfffe);
  local_2ac = (f32)(s32)uStack_24;
  local_2b2 = 1;
  local_2b4 = 2;
  local_2b8 = &DAT_803dc550;
  local_2c8 = 4;
  local_2c4 = lbl_803E1C18;
  local_2c0 = lbl_803E1BF4;
  local_2bc = lbl_803E1BF4;
  if (iVar4 == 4) {
    local_29a = 2;
    local_2b0 = 0x100;
    local_2ac = lbl_803E1C1C;
    local_2a8 = lbl_803E1BF4;
  }
  else {
    local_29a = 1;
    local_2b0 = 0x80;
    local_2a8 = lbl_803E1C14;
  }
  local_29c = 0;
  local_2a0 = 0;
  local_2a4 = lbl_803E1BF4;
  uStack_24 = randomGetRange(0,0xfffe);
  local_27c = (f32)(s32)uStack_24;
  if (iVar4 == 4) {
    local_298 = 0x100;
    local_280 = 0x100;
    local_27c = lbl_803E1C1C;
    local_278 = lbl_803E1BF4;
  }
  else {
    local_298 = 0x80;
    local_280 = 0x80;
    local_278 = lbl_803E1C14;
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
  local_264 = lbl_803E1C1C;
  local_28c = lbl_803E1BF4;
  local_260 = lbl_803E1BF4;
  local_25c = lbl_803E1BF4;
  local_23a = 3;
  local_23c = 4;
  local_240 = &DAT_803dc554;
  local_250 = 2;
  local_24c = lbl_803E1BFC;
  local_248 = lbl_803E1C20;
  local_244 = lbl_803E1C0C;
  local_330 = 0;
  local_344 = (undefined2)uVar5;
  local_35c = lbl_803E1BF4;
  local_358 = lbl_803E1BF4;
  local_354 = lbl_803E1BF4;
  local_368 = lbl_803E1BF4;
  local_364 = lbl_803E1BF4;
  local_360 = lbl_803E1BF4;
  local_350 = lbl_803E1C0C;
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
          local_35c = lbl_803E1BF4 + *(float *)(param_3 + 0xc);
          local_358 = lbl_803E1BF4 + *(float *)(param_3 + 0x10);
          local_354 = lbl_803E1BF4 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_35c = lbl_803E1BF4 + *(float *)(iVar2 + 0x18);
        local_358 = lbl_803E1BF4 + *(float *)(iVar2 + 0x1c);
        local_354 = lbl_803E1BF4 + *(float *)(iVar2 + 0x20);
      }
    }
    else {
      local_35c = lbl_803E1BF4 + *(float *)(iVar2 + 0x18) + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E1BF4 + *(float *)(iVar2 + 0x1c) + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E1BF4 + *(float *)(iVar2 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_384 = iVar2;
  local_294 = local_27c;
  local_290 = local_278;
  local_274 = local_28c;
  uVar3 = randomGetRange(0,1);
  (**(code **)(*gModgfxInterface + 8))
            (&local_388,0,4,&DAT_80316bf8,2,&DAT_80316c20,
             (int)*(short *)(&DAT_80316c3c + (iVar4 * 2 + uVar3) * 2),0);
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: dll_86_func03
 * EN v1.0 Address: 0x800F7434
 * EN v1.0 Size: 896b
 * EN v1.1 Address: 0x800F76D0
 * EN v1.1 Size: 904b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_86_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  FbCmd *e;
  u8 *base;
  f32 fx = lbl_803E0FB0;
  f32 fy = lbl_803E0FB4;
  int fl = 0x64;
  f32 rx;
  if (param_2 == 0) {
    fx = lbl_803E0FB8; fy = lbl_803E0FBC; fl = 0x410;
  } else if (param_2 == 1) {
    fx = lbl_803E0FC0; fy = lbl_803E0FC4; fl = 0x410;
  } else if (param_2 == 2) {
    fx = lbl_803E0FC8; fy = lbl_803E0FCC; fl = 0x410;
  } else if (param_2 == 3) {
    fx = lbl_803E0FC8; fy = lbl_803E0FCC; fl = 0x410;
  }
  e = buf.entries;
  e[0].layer = 0; e[0].flags = (s16)fl; e[0].tex = (void *)0; e[0].mode = 0x2000;
  e[0].x = lbl_803E0FD0; e[0].y = fx; e[0].z = fy;
  e[1].layer = 1; e[1].flags = 0; e[1].tex = (void *)0; e[1].mode = 0x40;
  e[1].x = (f32)(int)randomGetRange(-0x64, 0x64);
  e[1].y = lbl_803E0FD4;
  e[1].z = (f32)(int)randomGetRange(-0x4b0, -0x320);
  e[2].layer = 1; e[2].flags = 0; e[2].tex = (void *)0; e[2].mode = 0x4000;
  e[2].x = e[1].x; e[2].y = lbl_803E0FD4; e[2].z = e[1].z;
  e[3].layer = 1; e[3].flags = 0x65; e[3].tex = (void *)0; e[3].mode = 0x80;
  e[3].x = lbl_803E0FD8; e[3].y = lbl_803E0FD8; e[3].z = lbl_803E0FD4;
  e[4].layer = 2; e[4].flags = 0; e[4].tex = (void *)0; e[4].mode = 0x2000;
  e[4].x = lbl_803E0FD0; e[4].y = fx; e[4].z = fy;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  rx = (f32)(int)randomGetRange(-0x64, 0x64);
  buf.pos[0] = rx;
  buf.pos[1] = lbl_803E0FD4; buf.pos[2] = lbl_803E0FD4;
  buf.col[0] = lbl_803E0FD4; buf.col[1] = lbl_803E0FD4; buf.col[2] = lbl_803E0FD4;
  buf.scale = lbl_803E0FD8;
  buf.v40 = 0;
  buf.v3c = 0;
  buf.v59 = 0;
  buf.v5a = 0;
  buf.v5b = 0;
  buf.count = (FbCmd *)((u8 *)e + 0x78) - e;
  base = lbl_80316020;
  buf.hw[0] = *(s16 *)(base + 0); buf.hw[1] = *(s16 *)(base + 2);
  buf.hw[2] = *(s16 *)(base + 4); buf.hw[3] = *(s16 *)(base + 6);
  buf.hw[4] = *(s16 *)(base + 8); buf.hw[5] = *(s16 *)(base + 0xa);
  buf.hw[6] = *(s16 *)(base + 0xc);
  buf.cmds = e;
  buf.flags = 0x10400;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)buf.ctx != 0) {
      buf.pos[0] = rx + *(f32 *)(buf.ctx + 0x18);
      buf.pos[1] = lbl_803E0FD4 + *(f32 *)(buf.ctx + 0x1c);
      buf.pos[2] = lbl_803E0FD4 + *(f32 *)(buf.ctx + 0x20);
    } else {
      buf.pos[0] = rx + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E0FD4 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E0FD4 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0,0,0,0,0,0);
}

/*
 * --INFO--
 *
 * Function: dll_87_func03
 * EN v1.0 Address: 0x800F77BC
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x800F7A58
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_87_func03(int param_1,int param_2,int param_3,uint param_4)
{
  typedef struct {
    FbCmd *cmds; int ctx; u8 pad0[0x18];
    f32 col[3]; f32 pos[3]; f32 scale;
    u32 v3c; u32 v40; s16 v44; s16 hw[7]; u32 flags;
    u8 v58, v59, v5a, v5b, v5c;
    s8 count; u8 pad1[2];
    FbCmd entries[33];
  } FbBuf87;
  FbBuf87 buf;
  u8 *base = lbl_80316050;
  FbCmd *e = buf.entries;

  e[0].layer = 0; e[0].flags = 10; e[0].tex = base + 0x1ac; e[0].mode = 2;
  e[0].x = lbl_803E0FE8; e[0].y = lbl_803E0FEC; e[0].z = lbl_803E0FE8;
  e[1].layer = 0; e[1].flags = 10; e[1].tex = base + 0x1ac; e[1].mode = 4;
  e[1].x = lbl_803E0FF0; e[1].y = lbl_803E0FF0; e[1].z = lbl_803E0FF0;
  e[2].layer = 0; e[2].flags = 0; e[2].tex = (void *)0; e[2].mode = 0x400000;
  e[2].x = lbl_803E0FF4; e[2].y = lbl_803E0FF8; e[2].z = lbl_803E0FFC;
  e[3].layer = 1; e[3].flags = 10; e[3].tex = base + 0x1ac; e[3].mode = 0x4000;
  e[3].x = lbl_803E1000; e[3].y = lbl_803E1000; e[3].z = lbl_803E0FF0;
  e[4].layer = 0; e[4].flags = 9; e[4].tex = base + 0x198; e[4].mode = 2;
  e[4].x = lbl_803E1004; e[4].y = lbl_803E0FEC; e[4].z = lbl_803E1004;
  e[5].layer = 2; e[5].flags = 1; e[5].tex = &lbl_803DB900; e[5].mode = 4;
  e[5].x = lbl_803E1008; e[5].y = lbl_803E0FF0; e[5].z = lbl_803E0FF0;
  e[6].layer = 2; e[6].flags = 10; e[6].tex = base + 0x1ac; e[6].mode = 0x4000;
  e[6].x = lbl_803E1000; e[6].y = lbl_803E1000; e[6].z = lbl_803E0FF0;
  e[7].layer = 3; e[7].flags = 10; e[7].tex = base + 0x1ac; e[7].mode = 0x4000;
  e[7].x = lbl_803E1000; e[7].y = lbl_803E1000; e[7].z = lbl_803E0FF0;
  e[8].layer = 4; e[8].flags = 10; e[8].tex = base + 0x1ac; e[8].mode = 0x4000;
  e[8].x = lbl_803E1000; e[8].y = lbl_803E1000; e[8].z = lbl_803E0FF0;
  e[9].layer = 4; e[9].flags = 10; e[9].tex = base + 0x1ac; e[9].mode = 4;
  e[9].x = lbl_803E0FF0; e[9].y = lbl_803E0FF0; e[9].z = lbl_803E0FF0;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E0FF0; buf.pos[1] = lbl_803E0FF0; buf.pos[2] = lbl_803E0FF0;
  buf.col[0] = lbl_803E0FF0; buf.col[1] = lbl_803E0FF0; buf.col[2] = lbl_803E0FF0;
  buf.scale = lbl_803E1000;
  buf.v40 = 1;
  buf.v3c = 10;
  buf.v59 = 10;
  buf.v5a = 0;
  buf.v5b = 16;
  buf.flags = 0x4000494;
  buf.count = (FbCmd *)((u8 *)e + 240) - e;
  buf.hw[0] = *(s16 *)(base + 0x1c0); buf.hw[1] = *(s16 *)(base + 0x1c2);
  buf.hw[2] = *(s16 *)(base + 0x1c4); buf.hw[3] = *(s16 *)(base + 0x1c6);
  buf.hw[4] = *(s16 *)(base + 0x1c8); buf.hw[5] = *(s16 *)(base + 0x1ca);
  buf.hw[6] = *(s16 *)(base + 0x1cc);
  buf.cmds = e;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E0FF0 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E0FF0 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E0FF0 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E0FF0 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E0FF0 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E0FF0 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,10,base,8,base + 0x168,0x1fd,0);
}

/*
 * --INFO--
 *
 * Function: dll_88_func03
 * EN v1.0 Address: 0x800F7AC0
 * EN v1.0 Size: 712b
 * EN v1.1 Address: 0x800F7D5C
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_88_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  u8 *base = lbl_80316240;
  FbCmd *e = buf.entries;

  e[0].layer = 0; e[0].flags = 25; e[0].tex = base + 0x1bc; e[0].mode = 2;
  e[0].x = lbl_803E1010; e[0].y = lbl_803E1010; e[0].z = lbl_803E1010;
  e[1].layer = 0; e[1].flags = 25; e[1].tex = base + 0x1bc; e[1].mode = 0x80;
  e[1].x = lbl_803E1014; e[1].y = lbl_803E1014; e[1].z = lbl_803E1014;
  e[2].layer = 0; e[2].flags = 122; e[2].tex = (void *)0; e[2].mode = 0x10000;
  e[2].x = lbl_803E1014; e[2].y = lbl_803E1014; e[2].z = lbl_803E1014;
  e[3].layer = 0; e[3].flags = 25; e[3].tex = base + 0x1bc; e[3].mode = 4;
  e[3].x = lbl_803E1014; e[3].y = lbl_803E1014; e[3].z = lbl_803E1014;
  e[4].layer = 1; e[4].flags = 25; e[4].tex = base + 0x1bc; e[4].mode = 4;
  e[4].x = lbl_803E1018; e[4].y = lbl_803E1014; e[4].z = lbl_803E1014;
  e[5].layer = 1; e[5].flags = 25; e[5].tex = base + 0x1bc; e[5].mode = 2;
  e[5].x = lbl_803E101C; e[5].y = lbl_803E101C; e[5].z = lbl_803E1020;
  e[6].layer = 2; e[6].flags = 25; e[6].tex = base + 0x1bc; e[6].mode = 2;
  e[6].x = lbl_803E1024; e[6].y = lbl_803E1024; e[6].z = lbl_803E1020;
  e[7].layer = 3; e[7].flags = 25; e[7].tex = base + 0x1bc; e[7].mode = 2;
  e[7].x = lbl_803E1024; e[7].y = lbl_803E1024; e[7].z = lbl_803E1020;
  e[8].layer = 3; e[8].flags = 25; e[8].tex = base + 0x1bc; e[8].mode = 4;
  e[8].x = lbl_803E1014; e[8].y = lbl_803E1014; e[8].z = lbl_803E1014;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E1014; buf.pos[1] = lbl_803E1014; buf.pos[2] = lbl_803E1014;
  buf.col[0] = lbl_803E1014; buf.col[1] = lbl_803E1014; buf.col[2] = lbl_803E1014;
  buf.scale = lbl_803E1020;
  buf.v40 = 1;
  buf.v3c = 25;
  buf.v59 = 25;
  buf.v5a = 255;
  buf.v5b = 16;
  buf.flags = 0x4000480;
  buf.count = (FbCmd *)((u8 *)e + 216) - e; /*88*/
  buf.hw[0] = *(s16 *)(base + 0x1f0); buf.hw[1] = *(s16 *)(base + 0x1f2);
  buf.hw[2] = *(s16 *)(base + 0x1f4); buf.hw[3] = *(s16 *)(base + 0x1f6);
  buf.hw[4] = *(s16 *)(base + 0x1f8); buf.hw[5] = *(s16 *)(base + 0x1fa);
  buf.hw[6] = *(s16 *)(base + 0x1fc);
  buf.cmds = e;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E1014 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E1014 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E1014 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E1014 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E1014 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E1014 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x19,base,0x20,base + 0xfc,0x205,0);
}

/*
 * --INFO--
 *
 * Function: dll_89_func03
 * EN v1.0 Address: 0x800F7D90
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x800F802C
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_89_func03(int param_1,int param_2,int param_3,uint param_4)
{
  typedef struct {
    FbCmd *cmds;
    int ctx;
    u8 pad0[0x18];
    f32 col[3];
    f32 pos[3];
    f32 scale;
    u32 v3c;
    u32 v40;
    s16 v44;
    s16 hw[7];
    u32 flags;
    u8 v58, v59, v5a, v5b, v5c;
    s8 count;
    u8 pad1[2];
    FbCmd entries[33];
  } FbBuf89;
  FbBuf89 buf;
  u8 *base = lbl_80316460;
  FbCmd *e = buf.entries;

  e[0].layer = 0; e[0].flags = 10; e[0].tex = base + 0x1ac; e[0].mode = 2;
  e[0].x = lbl_803E1028; e[0].y = lbl_803E102C; e[0].z = lbl_803E1028;
  e[1].layer = 0; e[1].flags = 10; e[1].tex = base + 0x1ac; e[1].mode = 4;
  e[1].x = lbl_803E1030; e[1].y = lbl_803E1030; e[1].z = lbl_803E1030;
  e[2].layer = 0; e[2].flags = 0; e[2].tex = (void *)0; e[2].mode = 0x400000;
  e[2].x = lbl_803E1034; e[2].y = lbl_803E1038; e[2].z = lbl_803E103C;
  e[3].layer = 1; e[3].flags = 10; e[3].tex = base + 0x1ac; e[3].mode = 0x4000;
  e[3].x = lbl_803E1040; e[3].y = lbl_803E1040; e[3].z = lbl_803E1030;
  e[4].layer = 0; e[4].flags = 9; e[4].tex = base + 0x198; e[4].mode = 2;
  e[4].x = lbl_803E1044; e[4].y = lbl_803E102C; e[4].z = lbl_803E1044;
  e[5].layer = 2; e[5].flags = 1; e[5].tex = &lbl_803DB908; e[5].mode = 4;
  e[5].x = lbl_803E1048; e[5].y = lbl_803E1030; e[5].z = lbl_803E1030;
  e[6].layer = 2; e[6].flags = 10; e[6].tex = base + 0x1ac; e[6].mode = 0x4000;
  e[6].x = lbl_803E1040; e[6].y = lbl_803E1040; e[6].z = lbl_803E1030;
  e[7].layer = 3; e[7].flags = 10; e[7].tex = base + 0x1ac; e[7].mode = 0x4000;
  e[7].x = lbl_803E1040; e[7].y = lbl_803E1040; e[7].z = lbl_803E1030;
  e[8].layer = 4; e[8].flags = 10; e[8].tex = base + 0x1ac; e[8].mode = 0x4000;
  e[8].x = lbl_803E1040; e[8].y = lbl_803E1040; e[8].z = lbl_803E1030;
  e[9].layer = 4; e[9].flags = 10; e[9].tex = base + 0x1ac; e[9].mode = 4;
  e[9].x = lbl_803E1030; e[9].y = lbl_803E1030; e[9].z = lbl_803E1030;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E1030; buf.pos[1] = lbl_803E1030; buf.pos[2] = lbl_803E1030;
  buf.col[0] = lbl_803E1030; buf.col[1] = lbl_803E1030; buf.col[2] = lbl_803E1030;
  buf.scale = lbl_803E1030;
  buf.v40 = 1;
  buf.v3c = 10;
  buf.v59 = 10;
  buf.v5a = 0;
  buf.v5b = 16;
  buf.flags = 0x4000494;
  buf.count = (FbCmd *)((u8 *)e + 240) - e;
  buf.hw[0] = *(s16 *)(base + 0x1c0); buf.hw[1] = *(s16 *)(base + 0x1c2);
  buf.hw[2] = *(s16 *)(base + 0x1c4); buf.hw[3] = *(s16 *)(base + 0x1c6);
  buf.hw[4] = *(s16 *)(base + 0x1c8); buf.hw[5] = *(s16 *)(base + 0x1ca);
  buf.hw[6] = *(s16 *)(base + 0x1cc);
  buf.cmds = e;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E1030 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E1030 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E1030 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E1030 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E1030 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E1030 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,10,base,8,base + 0x168,0x1fd,0);
}

/*
 * --INFO--
 *
 * Function: dll_8A_func03
 * EN v1.0 Address: 0x800F8094
 * EN v1.0 Size: 436b
 * EN v1.1 Address: 0x800F8330
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_8A_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  u8 *base = lbl_80316650;
  FbCmd *e = buf.entries;

  e[0].layer = 0; e[0].flags = 8; e[0].tex = base + 0x98; e[0].mode = 2;
  e[0].x = lbl_803E1050; e[0].y = lbl_803E1050; e[0].z = lbl_803E1050;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E1054; buf.pos[1] = lbl_803E1054; buf.pos[2] = lbl_803E1054;
  buf.col[0] = lbl_803E1054; buf.col[1] = lbl_803E1054; buf.col[2] = lbl_803E1054;
  buf.scale = lbl_803E1058;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 8;
  buf.v5a = 0;
  buf.v5b = 0x10;
  buf.flags = 0x2000492;
  buf.count = (FbCmd *)((u8 *)e + 0x18) - e;
  buf.hw[0] = *(s16 *)(base + 0xa8); buf.hw[1] = *(s16 *)(base + 0xaa);
  buf.hw[2] = *(s16 *)(base + 0xac); buf.hw[3] = *(s16 *)(base + 0xae);
  buf.hw[4] = *(s16 *)(base + 0xb0); buf.hw[5] = *(s16 *)(base + 0xb2);
  buf.hw[6] = *(s16 *)(base + 0xb4);
  buf.cmds = e;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E1054 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E1054 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E1054 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E1054 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E1054 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E1054 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,8,base,0xc,base + 0x50,0x1fd,0);
}

/*
 * --INFO--
 *
 * Function: dll_8B_func03
 * EN v1.0 Address: 0x800F8250
 * EN v1.0 Size: 1424b
 * EN v1.1 Address: 0x800F84EC
 * EN v1.1 Size: 1432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_8B_func03(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,undefined4 param_5,
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
  dVar7 = (double)lbl_803E1CE0;
  dVar6 = (double)lbl_803E1CE4;
  fVar1 = lbl_803E1CE8;
  if (param_6 != (float *)0x0) {
    fVar1 = *param_6;
  }
  iVar5 = 0;
  dVar8 = (double)(lbl_803E1CEC + fVar1);
  dVar9 = (double)lbl_803E1CF4;
  dVar11 = (double)lbl_803E1CF8;
  dVar12 = (double)lbl_803E1CFC;
  dVar13 = (double)lbl_803E1D18;
  dVar14 = (double)lbl_803E1D1C;
  dVar15 = (double)lbl_803E1D20;
  dVar16 = (double)lbl_803E1D14;
  dVar17 = (double)lbl_803E1D24;
  dVar10 = DOUBLE_803e1d28;
  do {
    if (iVar5 == 1) {
      dVar7 = (double)lbl_803E1CE0;
      dVar6 = (double)lbl_803E1CF0;
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
        local_3d0 = lbl_803E1D00;
      }
      else {
        local_3d0 = lbl_803E1D04;
      }
    }
    else if (iVar4 == 4) {
      local_3d0 = lbl_803E1D08;
    }
    else {
      local_3d0 = lbl_803E1CEC;
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
      local_3bc = lbl_803E1D0C;
      local_3b8 = lbl_803E1CF4;
      local_3b4 = lbl_803E1CF4;
    }
    else if (iVar4 < 2) {
      if (iVar4 == 0) {
        local_3bc = lbl_803E1CF4;
        local_3b8 = lbl_803E1D0C;
        local_3b4 = lbl_803E1CF4;
      }
      else if (-1 < iVar4) {
        local_3bc = lbl_803E1CF4;
        local_3b8 = lbl_803E1D10;
        local_3b4 = lbl_803E1CF4;
      }
    }
    else if (iVar4 == 4) {
      local_3bc = lbl_803E1CF4;
      local_3b8 = lbl_803E1D14;
      local_3b4 = lbl_803E1CF4;
    }
    else if (iVar4 < 4) {
      local_3bc = lbl_803E1D10;
      local_3b8 = lbl_803E1CF4;
      local_3b4 = lbl_803E1CF4;
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
    (**(code **)(*gModgfxInterface + 8))(&local_468,0,0x15,&DAT_80317378,0x18,&DAT_8031744c,0xd9,0);
    iVar5 = iVar5 + 1;
  } while (iVar5 < 2);
  FUN_80286868();
  return;
}

/*
 * --INFO--
 *
 * Function: dll_8C_func03
 * EN v1.0 Address: 0x800F87E8
 * EN v1.0 Size: 1400b
 * EN v1.1 Address: 0x800F8A84
 * EN v1.1 Size: 1408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_8C_func03(int param_1,undefined2 param_2,short *param_3,uint param_4)
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
  local_314 = lbl_803E1D30;
  local_310 = lbl_803E1D30;
  local_30c = lbl_803E1D30;
  local_2ea = 0;
  local_2ec = 0xe;
  local_2f0 = &DAT_80317734;
  local_300 = 2;
  if (param_3 == (short *)0x0) {
    local_2fc = lbl_803E1D38;
    local_2f8 = lbl_803E1D3C;
    local_2f4 = lbl_803E1D38;
  }
  else {
    uStack_14 = (int)param_3[2] ^ 0x80000000;
    local_18 = 0x43300000;
    local_2fc = lbl_803E1D34 *
                lbl_803E1D38 * (f32)(s32)uStack_14;
    uStack_c = (int)*param_3 ^ 0x80000000;
    local_10 = 0x43300000;
    local_2f8 = lbl_803E1D34 *
                lbl_803E1D3C * (f32)(s32)uStack_c;
    local_8 = 0x43300000;
    local_2f4 = lbl_803E1D34 *
                lbl_803E1D38 * (f32)(s32)uStack_14;
    uStack_4 = uStack_14;
  }
  local_2d2 = 0;
  local_2d4 = 7;
  local_2d8 = &DAT_80317714;
  local_2e8 = 2;
  if (param_3 == (short *)0x0) {
    local_2e4 = lbl_803E1D38;
    local_2e0 = lbl_803E1D3C;
    local_2dc = lbl_803E1D38;
  }
  else {
    uStack_14 = (int)param_3[2] ^ 0x80000000;
    local_8 = 0x43300000;
    local_2e4 = lbl_803E1D34 *
                lbl_803E1D38 * (f32)(s32)uStack_14;
    uStack_c = (int)*param_3 ^ 0x80000000;
    local_10 = 0x43300000;
    local_2e0 = lbl_803E1D34 *
                lbl_803E1D40 * (f32)(s32)uStack_c;
    local_18 = 0x43300000;
    local_2dc = lbl_803E1D34 *
                lbl_803E1D38 * (f32)(s32)uStack_14;
    uStack_4 = uStack_14;
  }
  local_2ba = 1;
  local_2bc = 7;
  local_2c0 = &DAT_80317714;
  local_2d0 = 4;
  local_2cc = lbl_803E1D44;
  local_2c8 = lbl_803E1D30;
  local_2c4 = lbl_803E1D30;
  local_2a2 = 1;
  local_2a4 = 7;
  local_2a8 = &DAT_80317724;
  local_2b8 = 4;
  local_2b4 = lbl_803E1D44;
  local_2b0 = lbl_803E1D30;
  local_2ac = lbl_803E1D30;
  local_28a = 1;
  local_28c = 0x15;
  local_290 = &DAT_80317750;
  local_2a0 = 0x100;
  local_29c = lbl_803E1D30;
  local_298 = lbl_803E1D30;
  if (param_3 == (short *)0x0) {
    local_294 = lbl_803E1D48;
  }
  else {
    uStack_4 = (int)param_3[1] ^ 0x80000000;
    local_8 = 0x43300000;
    local_294 = (f32)(s32)uStack_4;
  }
  local_272 = 2;
  local_274 = 0x3a;
  local_278 = 0;
  local_288 = 0x1800000;
  local_284 = lbl_803E1D4C;
  local_280 = lbl_803E1D30;
  local_27c = lbl_803E1D50;
  local_25a = 2;
  local_25c = 0x15;
  local_260 = &DAT_80317750;
  local_270 = 0x100;
  local_26c = lbl_803E1D30;
  local_268 = lbl_803E1D30;
  if (param_3 == (short *)0x0) {
    local_264 = lbl_803E1D48;
  }
  else {
    uStack_4 = (int)param_3[1] ^ 0x80000000;
    local_8 = 0x43300000;
    local_264 = (f32)(s32)uStack_4;
  }
  local_242 = 3;
  local_244 = 0x3b8;
  local_248 = 0;
  local_258 = 0x1800000;
  local_254 = lbl_803E1D4C;
  local_250 = lbl_803E1D30;
  local_24c = lbl_803E1D50;
  local_22a = 3;
  local_22c = 0x15;
  local_230 = &DAT_80317750;
  local_240 = 0x100;
  local_23c = lbl_803E1D30;
  local_238 = lbl_803E1D30;
  if (param_3 == (short *)0x0) {
    local_234 = lbl_803E1D48;
  }
  else {
    uStack_4 = (int)param_3[1] ^ 0x80000000;
    local_8 = 0x43300000;
    local_234 = (f32)(s32)uStack_4;
  }
  local_212 = 4;
  local_214 = 0;
  local_218 = 0;
  local_228 = 0x1000;
  local_224 = lbl_803E1D54;
  local_220 = lbl_803E1D30;
  local_21c = lbl_803E1D30;
  local_1fa = 5;
  local_1fc = 7;
  local_200 = &DAT_80317714;
  local_210 = 4;
  local_20c = lbl_803E1D30;
  local_208 = lbl_803E1D30;
  local_204 = lbl_803E1D30;
  local_1e2 = 5;
  local_1e4 = 7;
  local_1e8 = &DAT_80317724;
  local_1f8 = 4;
  local_1f4 = lbl_803E1D30;
  local_1f0 = lbl_803E1D30;
  local_1ec = lbl_803E1D30;
  local_1ca = 5;
  local_1cc = 0x15;
  local_1d0 = &DAT_80317750;
  local_1e0 = 0x100;
  local_1dc = lbl_803E1D30;
  local_1d8 = lbl_803E1D30;
  local_1d4 = lbl_803E1D48;
  local_320 = 0;
  local_34c = lbl_803E1D30;
  local_348 = lbl_803E1D30;
  local_344 = lbl_803E1D30;
  local_358 = lbl_803E1D30;
  local_354 = lbl_803E1D30;
  local_350 = lbl_803E1D30;
  local_340 = lbl_803E1D4C;
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
      local_34c = lbl_803E1D30 + *(float *)(param_3 + 6);
      local_348 = lbl_803E1D30 + *(float *)(param_3 + 8);
      local_344 = lbl_803E1D30 + *(float *)(param_3 + 10);
    }
    else {
      local_34c = lbl_803E1D30 + *(float *)(param_1 + 0x18);
      local_348 = lbl_803E1D30 + *(float *)(param_1 + 0x1c);
      local_344 = lbl_803E1D30 + *(float *)(param_1 + 0x20);
    }
  }
  local_374 = param_1;
  local_334 = param_2;
  (**(code **)(*gModgfxInterface + 8))(&local_378,0,0x15,&DAT_803175a0,0x18,&DAT_80317674,0x5e0,0);
  return;
}

/*
 * --INFO--
 *
 * Function: dll_8D_func03
 * EN v1.0 Address: 0x800F8D68
 * EN v1.0 Size: 2572b
 * EN v1.1 Address: 0x800F9004
 * EN v1.1 Size: 2580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_8D_func03(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
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
    local_324 = lbl_803E1D60;
    local_320 = lbl_803E1D64;
    local_31c = lbl_803E1D68;
    local_2fa[0] = 0;
    local_2fc = 9;
    local_300 = &DAT_8031783c;
    local_310 = 0x80;
    if (param_3 == 0) {
      local_30c = lbl_803E1D6C;
      local_308 = lbl_803E1D70;
      local_304 = lbl_803E1D6C;
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
    local_2f4 = lbl_803E1D74;
    local_2f0 = lbl_803E1D74;
    local_2ec = lbl_803E1D78;
    puVar4 = &local_2e0;
  }
  else if (iVar3 == 1) {
    DAT_80317862 = 0x50;
    DAT_80317864 = 0x50;
    local_312[0] = 0;
    local_314 = 2;
    local_318 = 0;
    local_328 = 0x1800000;
    local_324 = lbl_803E1D7C;
    local_320 = lbl_803E1D6C;
    local_31c = lbl_803E1D6C;
    local_2fa[0] = 0;
    local_2fc = 0x69;
    local_300 = (undefined *)0x0;
    local_310 = 0x1800000;
    local_30c = lbl_803E1D7C;
    local_308 = lbl_803E1D6C;
    local_304 = lbl_803E1D6C;
    local_2e2[0] = 0;
    local_2e4 = 8;
    local_2e8 = &DAT_8031783c;
    local_2f8 = 2;
    uStack_24 = randomGetRange(0,0xc);
    local_2ec = lbl_803E1D80 * (f32)(s32)uStack_24;
    local_2f4 = lbl_803E1D84 + local_2ec;
    local_2ec = lbl_803E1D88 + local_2ec;
    local_2ca = 0;
    local_2cc = 0x8c;
    local_2d0 = (undefined *)0x0;
    local_2e0 = 0x20000000;
    local_2dc = lbl_803E1D60;
    local_2d8 = lbl_803E1D8C;
    local_2d4 = lbl_803E1D90;
    local_2b2 = 0;
    local_2b4 = 9;
    local_2b8 = &DAT_8031783c;
    local_2c8 = 0x80;
    local_2f0 = local_2f4;
    if (param_3 == 0) {
      local_2c4 = lbl_803E1D6C;
      local_2c0 = lbl_803E1D70;
      local_2bc = lbl_803E1D6C;
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
      local_324 = lbl_803E1D7C;
      local_320 = lbl_803E1D6C;
      local_31c = lbl_803E1D6C;
      local_2fa[0] = 0;
      local_2fc = 8;
      local_300 = &DAT_8031783c;
      local_310 = 2;
      uStack_24 = randomGetRange(0,0xc);
      local_304 = lbl_803E1D80 * (f32)(s32)uStack_24
      ;
      local_30c = lbl_803E1D94 + local_304;
      local_304 = lbl_803E1D98 + local_304;
      local_2e2[0] = 0;
      local_2e4 = 0x8c;
      local_2e8 = (undefined *)0x0;
      local_2f8 = 0x20000000;
      local_2f4 = lbl_803E1D60;
      local_2f0 = lbl_803E1D8C;
      local_2ec = lbl_803E1D90;
      local_2ca = 0;
      local_2cc = 9;
      local_2d0 = &DAT_8031783c;
      local_2e0 = 0x80;
      local_308 = local_30c;
      if (param_3 == 0) {
        local_2dc = lbl_803E1D6C;
        local_2d8 = lbl_803E1D70;
        local_2d4 = lbl_803E1D6C;
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
    puVar4[1] = lbl_803E1D6C;
    puVar4[2] = lbl_803E1D6C;
    puVar4[3] = lbl_803E1D6C;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 0x68;
    puVar4[10] = 0;
    puVar4[6] = 0x800000;
    puVar4[7] = lbl_803E1D7C;
    puVar4[8] = lbl_803E1D6C;
    puVar4[9] = lbl_803E1D6C;
    *(undefined *)((int)puVar4 + 0x46) = 1;
    *(undefined2 *)(puVar4 + 0x11) = 8;
    puVar4[0x10] = (undefined4)&DAT_8031783c;
    puVar4[0xc] = 2;
    puVar4[0xd] = lbl_803E1D9C;
    puVar4[0xe] = lbl_803E1D9C;
    puVar4[0xf] = lbl_803E1D9C;
    puVar4 = puVar4 + 0x12;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x4000;
    puVar4[1] = lbl_803E1D6C;
    puVar4[2] = lbl_803E1D6C;
    puVar4[3] = lbl_803E1D6C;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 0x8f;
    puVar4[10] = 0;
    puVar4[6] = 0x1800000;
    puVar4[7] = lbl_803E1DA0;
    puVar4[8] = lbl_803E1D6C;
    puVar4[9] = lbl_803E1D6C;
    puVar4 = puVar4 + 0xc;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x4000;
    puVar4[1] = lbl_803E1D6C;
    puVar4[2] = lbl_803E1D6C;
    puVar4[3] = lbl_803E1D6C;
    *(undefined *)((int)puVar4 + 0x2e) = 1;
    *(undefined2 *)(puVar4 + 0xb) = 0x1fd;
    puVar4[10] = 0;
    puVar4[6] = 0x1800000;
    puVar4[7] = lbl_803E1DA0;
    puVar4[8] = lbl_803E1D6C;
    puVar4[9] = lbl_803E1D6C;
    puVar4 = puVar4 + 0xc;
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = lbl_803E1DA4;
    puVar4[2] = lbl_803E1D6C;
    puVar4[3] = lbl_803E1D6C;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = lbl_803E1DA8;
    puVar4[2] = lbl_803E1D6C;
    puVar4[3] = lbl_803E1D6C;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 1;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = lbl_803E1DA8;
    puVar4[2] = lbl_803E1D6C;
    puVar4[3] = lbl_803E1D6C;
    puVar4 = puVar4 + 6;
  }
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = lbl_803E1DA4;
    puVar4[2] = lbl_803E1D6C;
    puVar4[3] = lbl_803E1D6C;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = lbl_803E1DA8;
    puVar4[2] = lbl_803E1D6C;
    puVar4[3] = lbl_803E1D6C;
    puVar4 = puVar4 + 6;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x16) = 2;
    *(undefined2 *)(puVar4 + 5) = 9;
    puVar4[4] = (undefined4)&DAT_8031783c;
    *puVar4 = 0x100;
    puVar4[1] = lbl_803E1DA8;
    puVar4[2] = lbl_803E1D6C;
    puVar4[3] = lbl_803E1D6C;
    puVar4 = puVar4 + 6;
  }
  *(undefined *)((int)puVar4 + 0x16) = 2;
  *(undefined2 *)(puVar4 + 5) = 9;
  puVar4[4] = (undefined4)&DAT_8031783c;
  *puVar4 = 4;
  puVar4[1] = lbl_803E1D6C;
  puVar4[2] = lbl_803E1D6C;
  puVar4[3] = lbl_803E1D6C;
  puVar5 = puVar4 + 6;
  if (iVar3 == 0) {
    *(undefined *)((int)puVar4 + 0x2e) = 3;
    *(undefined2 *)(puVar4 + 0xb) = 0;
    puVar4[10] = 0;
    *puVar5 = 0x20000000;
    puVar4[7] = lbl_803E1D60;
    puVar4[8] = lbl_803E1D64;
    puVar4[9] = lbl_803E1D68;
    puVar5 = puVar4 + 0xc;
  }
  else if (iVar3 == 1) {
    *(undefined *)((int)puVar4 + 0x2e) = 3;
    *(undefined2 *)(puVar4 + 0xb) = 0;
    puVar4[10] = 0;
    *puVar5 = 0x20000000;
    puVar4[7] = lbl_803E1D60;
    puVar4[8] = lbl_803E1D8C;
    puVar4[9] = lbl_803E1D90;
    puVar5 = puVar4 + 0xc;
  }
  else if (iVar3 == 2) {
    *(undefined *)((int)puVar4 + 0x2e) = 3;
    *(undefined2 *)(puVar4 + 0xb) = 0;
    puVar4[10] = 0;
    *puVar5 = 0x20000000;
    puVar4[7] = lbl_803E1D60;
    puVar4[8] = lbl_803E1D8C;
    puVar4[9] = lbl_803E1D90;
    puVar5 = puVar4 + 0xc;
  }
  local_344 = (undefined2)uVar6;
  local_35c = lbl_803E1D6C;
  local_368 = lbl_803E1D6C;
  local_364 = lbl_803E1D6C;
  local_360 = lbl_803E1D6C;
  local_350 = lbl_803E1D7C;
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
      local_35c = lbl_803E1D6C + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E1D6C + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E1D6C + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E1D6C + *(float *)(iVar2 + 0x18);
      local_358 = lbl_803E1D6C + *(float *)(iVar2 + 0x1c);
      local_354 = lbl_803E1D6C + *(float *)(iVar2 + 0x20);
    }
  }
  local_384 = iVar2;
  if (iVar3 == 0) {
    local_330 = 0;
    (**(code **)(*gModgfxInterface + 8))(&local_388,0,9,&DAT_803177b0,8,&DAT_8031780c,0x156,0);
  }
  else if (iVar3 == 1) {
    local_330 = 0;
    local_334 = param_4 | 0x4000004;
    (**(code **)(*gModgfxInterface + 8))(&local_388,0,9,&DAT_803177b0,8,&DAT_8031780c,0xc0d,0);
  }
  else if (iVar3 == 2) {
    local_330 = 0;
    local_334 = param_4 | 0x4000004;
    (**(code **)(*gModgfxInterface + 8))(&local_388,0,9,&DAT_803177b0,8,&DAT_8031780c,0x23b,0);
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: dll_8E_func03
 * EN v1.0 Address: 0x800F977C
 * EN v1.0 Size: 1780b
 * EN v1.1 Address: 0x800F9A18
 * EN v1.1 Size: 1788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_8E_func03(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
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
    uVar3 = randomGetRange(0,0x69);
    uStack_44 = uVar3 + 0x8c ^ 0x80000000;
    local_48 = 0x43300000;
    local_344 = (f32)(s32)uStack_44;
    uVar3 = randomGetRange(0,0x69);
    uStack_3c = uVar3 + 0x8c ^ 0x80000000;
    local_40 = 0x43300000;
    local_340 = (f32)(s32)uStack_3c;
    uVar3 = randomGetRange(0,0x1e);
    uStack_34 = uVar3 + 0xe1 ^ 0x80000000;
    local_38 = 0x43300000;
    local_33c = (f32)(s32)uStack_34;
    puVar4 = (undefined4 *)(local_332 + 2);
  }
  else {
    puVar4 = &local_348;
    if (iVar1 == 1) {
      local_332[0] = 0;
      local_334 = 3;
      local_338 = &DAT_803dc578;
      local_348 = 8;
      uVar3 = randomGetRange(0,0x1e);
      uStack_34 = uVar3 + 0xe1 ^ 0x80000000;
      local_38 = 0x43300000;
      local_344 = (f32)(s32)uStack_34;
      uVar3 = randomGetRange(0,0x69);
      uStack_3c = uVar3 + 0x8c ^ 0x80000000;
      local_40 = 0x43300000;
      local_340 = (f32)(s32)uStack_3c;
      uVar3 = randomGetRange(0,0x41);
      uStack_44 = uVar3 + 0x78 ^ 0x80000000;
      local_48 = 0x43300000;
      local_33c = (f32)(s32)uStack_44;
      puVar4 = (undefined4 *)(local_332 + 2);
    }
  }
  uStack_34 = randomGetRange(0,0xfffe);
  dVar5 = (double)(f32)(s32)uStack_34;
  uStack_3c = randomGetRange(0xfffff448,0xffffd120);
  *(undefined *)((int)puVar4 + 0x16) = 0;
  *(undefined2 *)(puVar4 + 5) = 0;
  puVar4[4] = 0;
  *puVar4 = 0x80;
  puVar4[1] = lbl_803E1DB8;
  puVar4[2] = (f32)(s32)uStack_3c;
  puVar4[3] = (float)dVar5;
  *(undefined *)((int)puVar4 + 0x2e) = 0;
  *(undefined2 *)(puVar4 + 0xb) = 3;
  puVar4[10] = (undefined4)&DAT_803dc578;
  puVar4[6] = 4;
  puVar4[7] = lbl_803E1DB8;
  puVar4[8] = lbl_803E1DB8;
  puVar4[9] = lbl_803E1DB8;
  *(undefined *)((int)puVar4 + 0x46) = 0;
  *(undefined2 *)(puVar4 + 0x11) = 3;
  puVar4[0x10] = (undefined4)&DAT_803dc578;
  puVar4[0xc] = 2;
  puVar4[0xd] = lbl_803E1DBC;
  uStack_44 = randomGetRange(0,0x32);
  puVar4[0xe] = lbl_803E1DC4 * (f32)(s32)uStack_44 +
                lbl_803E1DC0;
  uStack_2c = randomGetRange(0,0x14);
  puVar4[0xf] = lbl_803E1DC4 * (f32)(s32)uStack_2c +
                lbl_803E1DC8;
  *(undefined *)((int)puVar4 + 0x5e) = 1;
  *(undefined2 *)(puVar4 + 0x17) = 3;
  puVar4[0x16] = (undefined4)&DAT_803dc578;
  puVar4[0x12] = 4;
  uVar3 = randomGetRange(0,10);
  if (uVar3 == 0) {
    uStack_2c = randomGetRange(0,0x1e);
    uStack_2c = uStack_2c ^ 0x80000000;
    puVar4[0x13] = lbl_803E1DCC +
                   (f32)(s32)uStack_2c;
  }
  else {
    uStack_2c = randomGetRange(0,10);
    uStack_2c = uStack_2c ^ 0x80000000;
    puVar4[0x13] = lbl_803E1DD0 +
                   (f32)(s32)uStack_2c;
  }
  local_30 = 0x43300000;
  puVar4[0x14] = lbl_803E1DB8;
  puVar4[0x15] = lbl_803E1DB8;
  *(undefined *)((int)puVar4 + 0x76) = 2;
  *(undefined2 *)(puVar4 + 0x1d) = 0;
  puVar4[0x1c] = 0;
  puVar4[0x18] = 0x80;
  puVar4[0x19] = lbl_803E1DB8;
  puVar4[0x1a] = lbl_803E1DB8;
  uStack_2c = randomGetRange(0,0xfffe);
  puVar4[0x1b] = (f32)(s32)uStack_2c;
  *(undefined *)((int)puVar4 + 0x8e) = 1;
  *(undefined2 *)(puVar4 + 0x23) = 3;
  puVar4[0x22] = (undefined4)&DAT_803dc578;
  puVar4[0x1e] = 2;
  puVar4[0x1f] = lbl_803E1DD4;
  puVar4[0x20] = lbl_803E1DD8;
  puVar4[0x21] = lbl_803E1DDC;
  *(undefined *)((int)puVar4 + 0xa6) = 2;
  *(undefined2 *)(puVar4 + 0x29) = 0;
  puVar4[0x28] = 0;
  puVar4[0x24] = 0x80;
  puVar4[0x25] = lbl_803E1DB8;
  puVar4[0x26] = lbl_803E1DB8;
  uStack_34 = randomGetRange(0,0xfffe);
  puVar4[0x27] = (f32)(s32)uStack_34;
  *(undefined *)((int)puVar4 + 0xbe) = 2;
  *(undefined2 *)(puVar4 + 0x2f) = 3;
  puVar4[0x2e] = (undefined4)&DAT_803dc578;
  puVar4[0x2a] = 4;
  puVar4[0x2b] = lbl_803E1DB8;
  puVar4[0x2c] = lbl_803E1DB8;
  puVar4[0x2d] = lbl_803E1DB8;
  *(undefined *)((int)puVar4 + 0xd6) = 2;
  *(undefined2 *)(puVar4 + 0x35) = 3;
  puVar4[0x34] = (undefined4)&DAT_803dc578;
  puVar4[0x30] = 2;
  puVar4[0x31] = lbl_803E1DE0;
  puVar4[0x32] = lbl_803E1DE4;
  puVar4[0x33] = lbl_803E1DE8;
  local_350 = 0;
  local_364 = (undefined2)uVar6;
  local_37c = lbl_803E1DB8;
  if (iVar1 == 0) {
    local_378 = lbl_803E1DB8;
  }
  else if (iVar1 == 1) {
    local_378 = lbl_803E1DEC;
  }
  local_374 = lbl_803E1DB8;
  local_388 = lbl_803E1DB8;
  local_384 = lbl_803E1DB8;
  local_380 = lbl_803E1DB8;
  local_370 = lbl_803E1DE4;
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
          local_37c = lbl_803E1DB8 + *(float *)(param_3 + 0xc);
          local_378 = local_378 + *(float *)(param_3 + 0x10);
          local_374 = lbl_803E1DB8 + *(float *)(param_3 + 0x14);
        }
      }
      else {
        local_37c = lbl_803E1DB8 + *(float *)(iVar2 + 0x18);
        local_378 = local_378 + *(float *)(iVar2 + 0x1c);
        local_374 = lbl_803E1DB8 + *(float *)(iVar2 + 0x20);
      }
    }
    else {
      local_37c = lbl_803E1DB8 + *(float *)(iVar2 + 0x18) + *(float *)(param_3 + 0xc);
      local_378 = local_378 + *(float *)(iVar2 + 0x1c) + *(float *)(param_3 + 0x10);
      local_374 = lbl_803E1DB8 + *(float *)(iVar2 + 0x20) + *(float *)(param_3 + 0x14);
    }
  }
  local_3a4 = iVar2;
  (**(code **)(*gModgfxInterface + 8))(&local_3a8,0,3,&DAT_80317890,1,&DAT_803dc570,0x26a,0);
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: dll_8F_func03
 * EN v1.0 Address: 0x800F9E78
 * EN v1.0 Size: 748b
 * EN v1.1 Address: 0x800FA114
 * EN v1.1 Size: 756b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_8F_func03(int param_1,int param_2,int param_3,uint param_4)
{
  typedef struct {
    FbCmd *cmds; int ctx; u8 pad0[0x18];
    f32 col[3]; f32 pos[3]; f32 scale;
    u32 v3c; u32 v40; s16 v44; s16 hw[7]; u32 flags;
    u8 v58, v59, v5a, v5b, v5c;
    s8 count; u8 pad1[2];
    FbCmd entries[33];
  } FbBuf8F;
  FbBuf8F buf;
  u8 *base = lbl_80316C90;
  FbCmd *e = buf.entries;

  e[0].layer = 0; e[0].flags = 18; e[0].tex = base + 0x128; e[0].mode = 4;
  e[0].x = lbl_803E1178; e[0].y = lbl_803E1178; e[0].z = lbl_803E1178;
  e[1].layer = 0; e[1].flags = 18; e[1].tex = base + 0x128; e[1].mode = 2;
  e[1].x = lbl_803E117C; e[1].y = lbl_803E1180; e[1].z = lbl_803E117C;
  e[2].layer = 0; e[2].flags = 18; e[2].tex = base + 0x128; e[2].mode = 256;
  e[2].x = lbl_803E1178; e[2].y = lbl_803E1178; e[2].z = lbl_803E1184;
  e[3].layer = 1; e[3].flags = 18; e[3].tex = base + 0x128; e[3].mode = 4;
  e[3].x = lbl_803E1188; e[3].y = lbl_803E1178; e[3].z = lbl_803E1178;
  e[4].layer = 1; e[4].flags = 18; e[4].tex = base + 0x128; e[4].mode = 2;
  e[4].x = lbl_803E118C; e[4].y = lbl_803E1190; e[4].z = lbl_803E118C;
  e[5].layer = 2; e[5].flags = 18; e[5].tex = base + 0x128; e[5].mode = 256;
  e[5].x = lbl_803E1178; e[5].y = lbl_803E1178; e[5].z = lbl_803E1184;
  e[6].layer = 2; e[6].flags = 18; e[6].tex = base + 0x128; e[6].mode = 256;
  e[6].x = lbl_803E1178; e[6].y = lbl_803E1178; e[6].z = lbl_803E1184;
  e[7].layer = 3; e[7].flags = 18; e[7].tex = base + 0x128; e[7].mode = 4;
  e[7].x = lbl_803E1178; e[7].y = lbl_803E1178; e[7].z = lbl_803E1178;
  e[8].layer = 3; e[8].flags = 18; e[8].tex = base + 0x128; e[8].mode = 2;
  e[8].x = lbl_803E1194; e[8].y = lbl_803E1198; e[8].z = lbl_803E1194;
  e[9].layer = 3; e[9].flags = 18; e[9].tex = base + 0x128; e[9].mode = 256;
  e[9].x = lbl_803E1178; e[9].y = lbl_803E1178; e[9].z = lbl_803E1184;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E1178; buf.pos[1] = lbl_803E1178; buf.pos[2] = lbl_803E1178;
  buf.col[0] = lbl_803E1178; buf.col[1] = lbl_803E1178; buf.col[2] = lbl_803E1178;
  buf.scale = lbl_803E119C;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 18;
  buf.v5a = 0;
  buf.v5b = 16;
  buf.flags = 0x4000000;
  buf.count = (FbCmd *)((u8 *)e + 240) - e;
  buf.hw[0] = *(s16 *)(base + 0x160); buf.hw[1] = *(s16 *)(base + 0x162);
  buf.hw[2] = *(s16 *)(base + 0x164); buf.hw[3] = *(s16 *)(base + 0x166);
  buf.hw[4] = *(s16 *)(base + 0x168); buf.hw[5] = *(s16 *)(base + 0x16a);
  buf.hw[6] = *(s16 *)(base + 0x16c);
  buf.cmds = e;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E1178 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E1178 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E1178 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E1178 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E1178 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E1178 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,18,base,16,base + 0xb4,0x2e,0);
}

/*
 * --INFO--
 *
 * Function: dll_90_func03
 * EN v1.0 Address: 0x800FA16C
 * EN v1.0 Size: 1124b
 * EN v1.1 Address: 0x800FA408
 * EN v1.1 Size: 1124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_90_func03(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)
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
  local_324 = lbl_803E1E20;
  local_320 = lbl_803E1E20;
  local_31c = lbl_803E1E20;
  local_2fa = 0;
  local_2fc = 9;
  local_300 = &DAT_80317b94;
  local_310 = 8;
  local_30c = lbl_803E1E24;
  local_308 = lbl_803E1E24;
  local_304 = lbl_803E1E20;
  local_2e2 = 0;
  local_2e4 = 9;
  local_2e8 = &DAT_80317ba8;
  local_2f8 = 2;
  local_2f4 = lbl_803E1E28;
  local_2f0 = lbl_803E1E2C;
  local_2ec = lbl_803E1E28;
  local_2ca = 0;
  local_2cc = 0x12;
  local_2d0 = &DAT_80317bd0;
  local_2e0 = 2;
  local_2dc = lbl_803E1E30;
  local_2d8 = lbl_803E1E34;
  local_2d4 = lbl_803E1E30;
  local_2b2 = 0;
  local_2b4 = 9;
  local_2b8 = &DAT_80317ba8;
  local_2c8 = 8;
  local_2c4 = lbl_803E1E38;
  local_2c0 = lbl_803E1E20;
  local_2bc = lbl_803E1E20;
  local_29a = 1;
  local_29c = 0x12;
  local_2a0 = &DAT_80317bd0;
  local_2b0 = 4;
  local_2ac = lbl_803E1E24;
  local_2a8 = lbl_803E1E20;
  local_2a4 = lbl_803E1E20;
  local_282 = 1;
  local_284 = 9;
  local_288 = &DAT_80317ba8;
  local_298 = 2;
  local_294 = lbl_803E1E28;
  local_290 = lbl_803E1E3C;
  local_28c = lbl_803E1E28;
  local_26a = 1;
  local_26c = 0x7a;
  local_270 = 0;
  local_280 = 0x10000;
  local_27c = lbl_803E1E20;
  local_278 = lbl_803E1E20;
  local_274 = lbl_803E1E20;
  local_252 = 1;
  local_254 = 0;
  local_258 = 0;
  local_268 = 0x80000;
  local_264 = lbl_803E1E20;
  local_260 = lbl_803E1E40;
  local_25c = lbl_803E1E20;
  local_23a = 2;
  local_23c = 0x9d;
  local_240 = 0;
  local_250 = 0x20000;
  local_24c = lbl_803E1E20;
  local_248 = lbl_803E1E20;
  local_244 = lbl_803E1E20;
  local_222 = 3;
  local_224 = 9;
  local_228 = &DAT_80317b94;
  local_238 = 8;
  local_234 = lbl_803E1E24;
  local_230 = lbl_803E1E44;
  local_22c = lbl_803E1E20;
  local_20a = 3;
  local_20c = 0x12;
  local_210 = &DAT_80317bd0;
  local_220 = 0x100;
  local_21c = lbl_803E1E20;
  local_218 = lbl_803E1E20;
  local_214 = lbl_803E1E48;
  local_1f2 = 3;
  local_1f4 = 5;
  local_1f8 = &DAT_80317c08;
  local_208 = 2;
  local_204 = lbl_803E1E4C;
  local_200 = lbl_803E1E28;
  local_1fc = lbl_803E1E4C;
  local_1da = 3;
  local_1dc = 4;
  local_1e0 = &DAT_803dc580;
  local_1f0 = 2;
  local_1ec = lbl_803E1E50;
  local_1e8 = lbl_803E1E28;
  local_1e4 = lbl_803E1E50;
  local_1c2 = 4;
  local_1c4 = 9;
  local_1c8 = &DAT_80317b94;
  local_1d8 = 8;
  local_1d4 = lbl_803E1E24;
  local_1d0 = lbl_803E1E24;
  local_1cc = lbl_803E1E20;
  local_1aa = 4;
  local_1ac = 0x12;
  local_1b0 = &DAT_80317bd0;
  local_1c0 = 0x100;
  local_1bc = lbl_803E1E20;
  local_1b8 = lbl_803E1E20;
  local_1b4 = lbl_803E1E48;
  local_192 = 4;
  local_194 = 5;
  local_198 = &DAT_80317c08;
  local_1a8 = 2;
  local_1a4 = lbl_803E1E50;
  local_1a0 = lbl_803E1E28;
  local_19c = lbl_803E1E50;
  local_17a = 4;
  local_17c = 4;
  local_180 = &DAT_803dc580;
  local_190 = 2;
  local_18c = lbl_803E1E4C;
  local_188 = lbl_803E1E28;
  local_184 = lbl_803E1E4C;
  local_162 = 5;
  local_164 = 1;
  local_168 = 0;
  local_178 = 0x1000;
  local_174 = lbl_803E1E28;
  local_170 = lbl_803E1E20;
  local_16c = lbl_803E1E20;
  local_14a = 6;
  local_14c = 0x12;
  local_150 = &DAT_80317bd0;
  local_160 = 4;
  local_15c = lbl_803E1E20;
  local_158 = lbl_803E1E20;
  local_154 = lbl_803E1E20;
  local_132 = 6;
  local_134 = 0x12;
  local_138 = &DAT_80317bd0;
  local_148 = 2;
  local_144 = lbl_803E1E54;
  local_140 = lbl_803E1E28;
  local_13c = lbl_803E1E54;
  local_330 = 0;
  local_35c = lbl_803E1E20;
  local_358 = lbl_803E1E20;
  local_354 = lbl_803E1E20;
  local_368 = lbl_803E1E20;
  local_364 = lbl_803E1E20;
  local_360 = lbl_803E1E20;
  local_350 = lbl_803E1E28;
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
      local_35c = lbl_803E1E20 + *(float *)(param_3 + 0xc);
      local_358 = lbl_803E1E20 + *(float *)(param_3 + 0x10);
      local_354 = lbl_803E1E20 + *(float *)(param_3 + 0x14);
    }
    else {
      local_35c = lbl_803E1E20 + *(float *)(local_384 + 0x18);
      local_358 = lbl_803E1E20 + *(float *)(local_384 + 0x1c);
      local_354 = lbl_803E1E20 + *(float *)(local_384 + 0x20);
    }
  }
  local_344 = extraout_r4;
  (**(code **)(*gModgfxInterface + 8))(&local_388,0,0x12,&DAT_80317a80,0x10,&DAT_80317b34,0x45,0);
  FUN_80286880();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void dll_7C_func01_nop(void) {}
void dll_7C_func00_nop(void) {}
void dll_7D_func01_nop(void) {}
void dll_7D_func00_nop(void) {}
void dll_7E_func01_nop(void) {}
void dll_7E_func00_nop(void) {}
void dll_7F_func01_nop(void) {}
void dll_7F_func00_nop(void) {}
void dll_80_func01_nop(void) {}
void dll_80_func00_nop(void) {}
void dll_81_func01_nop(void) {}
void dll_81_func00_nop(void) {}
void dll_82_func01_nop(void) {}
void dll_82_func00_nop(void) {}
void dll_83_func01_nop(void) {}
void dll_83_func00_nop(void) {}
void dll_84_func01_nop(void) {}
void dll_84_func00_nop(void) {}
void dll_85_func01_nop(void) {}
void dll_85_func00_nop(void) {}
void dll_86_func01_nop(void) {}
void dll_86_func00_nop(void) {}
void dll_87_func01_nop(void) {}
void dll_87_func00_nop(void) {}
void dll_88_func01_nop(void) {}
void dll_88_func00_nop(void) {}
void dll_89_func01_nop(void) {}
void dll_89_func00_nop(void) {}
void dll_8A_func01_nop(void) {}
void dll_8A_func00_nop(void) {}
void dll_8B_func01_nop(void) {}
void dll_8B_func00_nop(void) {}
void dll_8C_func01_nop(void) {}
void dll_8C_func00_nop(void) {}
void dll_8D_func01_nop(void) {}
void dll_8D_func00_nop(void) {}
void dll_8E_func01_nop(void) {}
void dll_8E_func00_nop(void) {}
void dll_8F_func01_nop(void) {}
void dll_8F_func00_nop(void) {}
void dll_90_func01_nop(void) {}
void dll_90_func00_nop(void) {}
