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
extern u8 lbl_80316E30[];
extern u8 lbl_803DB920;
extern f32 lbl_803E11A0;
extern f32 lbl_803E11A4;
extern f32 lbl_803E11A8;
extern f32 lbl_803E11AC;
extern f32 lbl_803E11B0;
extern f32 lbl_803E11B4;
extern f32 lbl_803E11B8;
extern f32 lbl_803E11BC;
extern f32 lbl_803E11C0;
extern f32 lbl_803E11C4;
extern f32 lbl_803E11C8;
extern f32 lbl_803E11CC;
extern f32 lbl_803E11D0;
extern f32 lbl_803E11D4;
extern u8 lbl_80316950[];
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
extern u8 lbl_80316728[];
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
extern u8 lbl_80315FA8[];
extern u8 lbl_803DB8F0;
extern u8 lbl_803DB8F4;
extern u8 lbl_803DB8FC;
extern f32 lbl_803E0F70;
extern f32 lbl_803E0F74;
extern f32 lbl_803E0F78;
extern f32 lbl_803E0F7C;
extern f32 lbl_803E0F80;
extern f32 lbl_803E0F84;
extern f32 lbl_803E0F88;
extern f32 lbl_803E0F8C;
extern f32 lbl_803E0F90;
extern f32 lbl_803E0F94;
extern f32 lbl_803E0F98;
extern f32 lbl_803E0F9C;
extern f32 lbl_803E0FA0;
extern u8 lbl_80316C60[];
extern u8 lbl_80316C40[];
extern u8 lbl_803DB918;
extern u8 lbl_803DB910;
extern f32 lbl_803E1138;
extern f32 lbl_803E113C;
extern f32 lbl_803E1140;
extern f32 lbl_803E1144;
extern f32 lbl_803E1148;
extern f32 lbl_803E114C;
extern f32 lbl_803E1150;
extern f32 lbl_803E1154;
extern f32 lbl_803E1158;
extern f32 lbl_803E115C;
extern f32 lbl_803E1160;
extern f32 lbl_803E1164;
extern f32 lbl_803E1168;
extern f32 lbl_803E116C;
extern u8 lbl_80316B60[];
extern f32 lbl_803E10E0;
extern f32 lbl_803E10E4;
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
void dll_85_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  u8 *base = lbl_80315FA8;
  FbCmd *e = buf.entries;
  FbCmd *p;
  f32 t;
  f32 rv;

  if (param_2 == 4) {
    e[0].layer = 0; e[0].flags = 0; e[0].tex = (void *)0; e[0].mode = 0x40;
    e[0].x = lbl_803E0F70; e[0].y = lbl_803E0F74; e[0].z = lbl_803E0F74;
    e[1].layer = 0; e[1].flags = 2; e[1].tex = &lbl_803DB8FC; e[1].mode = 2;
    e[1].x = lbl_803E0F78; e[1].y = lbl_803E0F7C; e[1].z = lbl_803E0F78;
    e[2].layer = 0; e[2].flags = 4; e[2].tex = &lbl_803DB8FC; e[2].mode = 0x80;
    e[2].x = (f32)(int)randomGetRange(-0x7ff8, 0x7ff8);
    e[2].y = lbl_803E0F74; e[2].z = lbl_803E0F80;
    p = &e[3];
  } else {
    t = *(f32 *)(param_1 + 8);
    e[0].layer = 0; e[0].flags = 2; e[0].tex = &lbl_803DB8F0; e[0].mode = 2;
    e[0].x = lbl_803E0F84 * t; e[0].y = lbl_803E0F88 * t; e[0].z = lbl_803E0F8C;
    e[1].layer = 0; e[1].flags = 2; e[1].tex = &lbl_803DB8FC; e[1].mode = 2;
    t /= *(f32 *)(*(int *)(param_1 + 0x50) + 4);
    e[1].x = lbl_803E0F90 * t; e[1].y = lbl_803E0F88 * t; e[1].z = lbl_803E0F8C;
    rv = (f32)(int)randomGetRange(0, 0xfffe);
    e[2].layer = 0; e[2].flags = 0; e[2].tex = (void *)0; e[2].mode = 0x80;
    e[2].x = rv; e[2].y = lbl_803E0F94; e[2].z = lbl_803E0F74;
    p = &e[3];
  }
  p[0].layer = 0; p[0].flags = 4; p[0].tex = &lbl_803DB8F4; p[0].mode = 4;
  p[0].x = lbl_803E0F74; p[0].y = lbl_803E0F74; p[0].z = lbl_803E0F74;
  rv = (f32)(int)randomGetRange(0, 0xfffe);
  p[1].layer = 1; p[1].flags = 2; p[1].tex = &lbl_803DB8F0; p[1].mode = 4;
  p[1].x = lbl_803E0F98; p[1].y = lbl_803E0F74; p[1].z = lbl_803E0F74;
  if (param_2 == 4) {
    p[2].layer = 2; p[2].flags = 0; p[2].tex = (void *)0; p[2].mode = 0x100;
    p[2].x = lbl_803E0F9C; p[2].y = lbl_803E0F74; p[2].z = lbl_803E0F74;
  } else {
    p[2].layer = 1; p[2].flags = 0; p[2].tex = (void *)0; p[2].mode = 0x80;
    p[2].x = rv; p[2].y = lbl_803E0F94; p[2].z = lbl_803E0F74;
  }
  p += 3;
  rv = (f32)(int)randomGetRange(0, 0xfffe);
  if (param_2 == 4) {
    p->layer = 2; p->flags = 0; p->tex = (void *)0; p->mode = 0x100;
    p->x = lbl_803E0F9C; p->y = lbl_803E0F74; p->z = lbl_803E0F74;
    p++;
  } else {
    p->layer = 2; p->flags = 0; p->tex = (void *)0; p->mode = 0x80;
    p->x = rv; p->y = lbl_803E0F94; p->z = lbl_803E0F74;
    p++;
  }
  if (param_2 == 4) {
    p->layer = 3; p->flags = 0; p->tex = (void *)0; p->mode = 0x100;
    p->x = lbl_803E0F9C; p->y = lbl_803E0F74; p->z = lbl_803E0F74;
    p++;
  } else {
    p->layer = 3; p->flags = 0; p->tex = (void *)0; p->mode = 0x80;
    p->x = rv; p->y = lbl_803E0F94; p->z = lbl_803E0F74;
    p++;
  }
  p[0].layer = 3; p[0].flags = 2; p[0].tex = &lbl_803DB8F0; p[0].mode = 4;
  p[0].x = lbl_803E0F9C; p[0].y = lbl_803E0F74; p[0].z = lbl_803E0F74;
  p[1].layer = 3; p[1].flags = 4; p[1].tex = &lbl_803DB8F4; p[1].mode = 2;
  p[1].x = lbl_803E0F7C; p[1].y = lbl_803E0FA0; p[1].z = lbl_803E0F8C;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E0F74; buf.pos[1] = lbl_803E0F74; buf.pos[2] = lbl_803E0F74;
  buf.col[0] = lbl_803E0F74; buf.col[1] = lbl_803E0F74; buf.col[2] = lbl_803E0F74;
  buf.scale = lbl_803E0F8C;
  buf.v40 = 2;
  buf.v3c = 0;
  buf.v59 = 4;
  buf.v5a = 0;
  buf.v5b = 0x20;
  buf.count = (FbCmd *)((u8 *)p + 0x30) - e;
  buf.hw[0] = *(s16 *)(base + 0x34); buf.hw[1] = *(s16 *)(base + 0x36);
  buf.hw[2] = *(s16 *)(base + 0x38); buf.hw[3] = *(s16 *)(base + 0x3a);
  buf.hw[4] = *(s16 *)(base + 0x3c); buf.hw[5] = *(s16 *)(base + 0x3e);
  buf.hw[6] = *(s16 *)(base + 0x40);
  buf.cmds = buf.entries;
  if (param_2 == 4) {
    buf.flags = 0x4004400;
  } else {
    buf.flags = 0x4006410;
  }
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)buf.ctx != 0 && (uint)param_3 != 0) {
      buf.pos[0] += *(f32 *)(buf.ctx + 0x18) + *(f32 *)(param_3 + 0xc);
      buf.pos[1] += *(f32 *)(buf.ctx + 0x1c) + *(f32 *)(param_3 + 0x10);
      buf.pos[2] += *(f32 *)(buf.ctx + 0x20) + *(f32 *)(param_3 + 0x14);
    } else if ((uint)buf.ctx != 0) {
      buf.pos[0] += *(f32 *)(buf.ctx + 0x18);
      buf.pos[1] += *(f32 *)(buf.ctx + 0x1c);
      buf.pos[2] += *(f32 *)(buf.ctx + 0x20);
    } else if ((uint)param_3 != 0) {
      buf.pos[0] += *(f32 *)(param_3 + 0xc);
      buf.pos[1] += *(f32 *)(param_3 + 0x10);
      buf.pos[2] += *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,4,base,2,base + 0x28,
      *(s16 *)(base + (param_2 * 2 + (int)randomGetRange(0, 1)) * 2 + 0x44),0);
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
void dll_8B_func03(int param_1,int param_2,int param_3,uint param_4,undefined4 param_5,
                 f32 *param_6)
{
  FbBuf buf;
  u8 *base = lbl_80316728;
  f32 va = lbl_803E1060;
  f32 vb = lbl_803E1064;
  f32 s = lbl_803E1068;
  f32 zoff;
  FbCmd *e;
  FbCmd *p;
  int i;
  if (param_6 != (f32 *)0) {
    s = *param_6;
  }
  zoff = lbl_803E106C + s;
  e = buf.entries;
  for (i = 0; i < 2; i++) {
    if (i == 1) {
      va = lbl_803E1060;
      vb = lbl_803E1070;
    }
    e[0].layer = 0; e[0].flags = 0x15; e[0].tex = base + 0x1b0; e[0].mode = 4;
    e[0].x = lbl_803E1074; e[0].y = lbl_803E1074; e[0].z = lbl_803E1074;
    e[1].layer = 0; e[1].flags = 0x15; e[1].tex = base + 0x1b0; e[1].mode = 0x80;
    e[1].x = lbl_803E1074;
    e[1].y = (f32)*(s16 *)(param_1 + 2);
    e[1].z = lbl_803E1078 + ((f32)*(s16 *)(param_1 + 0) - lbl_803E107C);
    p = &e[2];
    if (i == 0) {
      p->layer = 0; p->flags = 0x15; p->tex = base + 0x1b0; p->mode = 2;
      if (param_2 == 4) {
        p->x = lbl_803E1080; p->y = lbl_803E1080; p->z = zoff;
      } else {
        p->x = lbl_803E1084; p->y = lbl_803E1084; p->z = zoff;
      }
      p++;
    } else {
      p->layer = 0; p->flags = 0x15; p->tex = base + 0x1b0; p->mode = 2;
      if (param_2 == 4) {
        p->x = lbl_803E1088; p->y = lbl_803E1088; p->z = zoff;
      } else {
        p->x = lbl_803E106C; p->y = lbl_803E106C; p->z = zoff;
      }
      p++;
    }
    p[0].layer = 0; p[0].flags = 0; p[0].tex = (void *)0; p[0].mode = 0x40;
    switch (param_2) {
    case 0:
      p[0].x = lbl_803E1074; p[0].y = lbl_803E108C; p[0].z = lbl_803E1074;
      break;
    case 1:
      p[0].x = lbl_803E1074; p[0].y = lbl_803E1090; p[0].z = lbl_803E1074;
      break;
    case 2:
      p[0].x = lbl_803E108C; p[0].y = lbl_803E1074; p[0].z = lbl_803E1074;
      break;
    case 3:
      p[0].x = lbl_803E1090; p[0].y = lbl_803E1074; p[0].z = lbl_803E1074;
      break;
    case 4:
      p[0].x = lbl_803E1074; p[0].y = lbl_803E1094; p[0].z = lbl_803E1074;
      break;
    }
    p[1].layer = 1; p[1].flags = 0x15; p[1].tex = base + 0x1b0; p[1].mode = 4;
    p[1].x = lbl_803E1098; p[1].y = lbl_803E1074; p[1].z = lbl_803E1074;
    p[2].layer = 1; p[2].flags = 0x15; p[2].tex = base + 0x1b0; p[2].mode = 2;
    p[2].x = lbl_803E109C; p[2].y = lbl_803E109C; p[2].z = lbl_803E10A0;
    p[3].layer = 1; p[3].flags = 0x15; p[3].tex = base + 0x1b0; p[3].mode = 0x4000;
    p[3].x = va; p[3].y = vb; p[3].z = lbl_803E1074;
    p[4].layer = 2; p[4].flags = 0x15; p[4].tex = base + 0x1b0; p[4].mode = 4;
    p[4].x = lbl_803E1098; p[4].y = lbl_803E1074; p[4].z = lbl_803E1074;
    p[5].layer = 2; p[5].flags = 0x15; p[5].tex = base + 0x1b0; p[5].mode = 0x4000;
    p[5].x = va; p[5].y = vb; p[5].z = lbl_803E1074;
    p[6].layer = 3; p[6].flags = 0x15; p[6].tex = base + 0x1b0; p[6].mode = 0x4000;
    p[6].x = va; p[6].y = vb; p[6].z = lbl_803E1074;
    p[7].layer = 3; p[7].flags = 0x15; p[7].tex = base + 0x1b0; p[7].mode = 4;
    p[7].x = lbl_803E1074; p[7].y = lbl_803E1074; p[7].z = lbl_803E1074;
    p[8].layer = 3; p[8].flags = 0x15; p[8].tex = base + 0x1b0; p[8].mode = 2;
    p[8].x = lbl_803E1094; p[8].y = lbl_803E1094; p[8].z = lbl_803E1094;
    buf.v58 = 0;
    buf.ctx = param_1;
    buf.v44 = (s16)param_2;
    buf.pos[0] = lbl_803E1074; buf.pos[1] = lbl_803E1074; buf.pos[2] = lbl_803E1074;
    buf.col[0] = lbl_803E1074; buf.col[1] = lbl_803E1074; buf.col[2] = lbl_803E1074;
    buf.scale = lbl_803E10A4;
    buf.v40 = 2;
    buf.v3c = 7;
    buf.v59 = 0xe;
    buf.v5a = 0;
    buf.v5b = 0x28;
    buf.count = (FbCmd *)((u8 *)p + 0xd8) - e;
    buf.hw[0] = *(s16 *)(base + 0x1f8); buf.hw[1] = *(s16 *)(base + 0x1fa);
    buf.hw[2] = *(s16 *)(base + 0x1fc); buf.hw[3] = *(s16 *)(base + 0x1fe);
    buf.hw[4] = *(s16 *)(base + 0x200); buf.hw[5] = *(s16 *)(base + 0x202);
    buf.hw[6] = *(s16 *)(base + 0x204);
    buf.cmds = e;
    buf.flags = 0xc0104c0;
    buf.flags |= param_4;
    if ((buf.flags & 1) != 0) {
      if ((uint)param_1 != 0) {
        buf.pos[0] = lbl_803E1074 + *(f32 *)(param_1 + 0x18);
        buf.pos[1] = lbl_803E1074 + *(f32 *)(param_1 + 0x1c);
        buf.pos[2] = lbl_803E1074 + *(f32 *)(param_1 + 0x20);
      } else {
        buf.pos[0] = lbl_803E1074 + *(f32 *)(param_3 + 0xc);
        buf.pos[1] = lbl_803E1074 + *(f32 *)(param_3 + 0x10);
        buf.pos[2] = lbl_803E1074 + *(f32 *)(param_3 + 0x14);
      }
    }
    (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,base,0x18,base + 0xd4,0xd9,0);
  }
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
void dll_8C_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  u8 *base = lbl_80316950;
  FbCmd *e = buf.entries;

  e[0].layer = 0; e[0].flags = 0x15; e[0].tex = base + 0x1b0; e[0].mode = 4;
  e[0].x = lbl_803E10B0; e[0].y = lbl_803E10B0; e[0].z = lbl_803E10B0;
  e[1].layer = 0; e[1].flags = 0xe; e[1].tex = base + 0x194; e[1].mode = 2;
  if ((uint)param_3 != 0) {
    e[1].x = lbl_803E10B4 * (lbl_803E10B8 * (f32)*(s16 *)(param_3 + 4));
    e[1].y = lbl_803E10B4 * (lbl_803E10BC * (f32)*(s16 *)(param_3 + 0));
    e[1].z = lbl_803E10B4 * (lbl_803E10B8 * (f32)*(s16 *)(param_3 + 4));
  } else {
    e[1].x = lbl_803E10B8; e[1].y = lbl_803E10BC; e[1].z = lbl_803E10B8;
  }
  e[2].layer = 0; e[2].flags = 7; e[2].tex = base + 0x174; e[2].mode = 2;
  if ((uint)param_3 != 0) {
    e[2].x = lbl_803E10B4 * (lbl_803E10B8 * (f32)*(s16 *)(param_3 + 4));
    e[2].y = lbl_803E10B4 * (lbl_803E10C0 * (f32)*(s16 *)(param_3 + 0));
    e[2].z = lbl_803E10B4 * (lbl_803E10B8 * (f32)*(s16 *)(param_3 + 4));
  } else {
    e[2].x = lbl_803E10B8; e[2].y = lbl_803E10BC; e[2].z = lbl_803E10B8;
  }
  e[3].layer = 1; e[3].flags = 7; e[3].tex = base + 0x174; e[3].mode = 4;
  e[3].x = lbl_803E10C4; e[3].y = lbl_803E10B0; e[3].z = lbl_803E10B0;
  e[4].layer = 1; e[4].flags = 7; e[4].tex = base + 0x184; e[4].mode = 4;
  e[4].x = lbl_803E10C4; e[4].y = lbl_803E10B0; e[4].z = lbl_803E10B0;
  e[5].layer = 1; e[5].flags = 0x15; e[5].tex = base + 0x1b0; e[5].mode = 0x100;
  e[5].x = lbl_803E10B0; e[5].y = lbl_803E10B0;
  if ((uint)param_3 != 0) {
    e[5].z = (f32)*(s16 *)(param_3 + 2);
  } else {
    e[5].z = lbl_803E10C8;
  }
  e[6].layer = 2; e[6].flags = 0x3a; e[6].tex = (void *)0; e[6].mode = 0x180;
  e[6].x = lbl_803E10CC; e[6].y = lbl_803E10B0; e[6].z = lbl_803E10D0;
  e[7].layer = 2; e[7].flags = 0x15; e[7].tex = base + 0x1b0; e[7].mode = 0x100;
  e[7].x = lbl_803E10B0; e[7].y = lbl_803E10B0;
  if ((uint)param_3 != 0) {
    e[7].z = (f32)*(s16 *)(param_3 + 2);
  } else {
    e[7].z = lbl_803E10C8;
  }
  e[8].layer = 3; e[8].flags = 0x3b8; e[8].tex = (void *)0; e[8].mode = 0x180;
  e[8].x = lbl_803E10CC; e[8].y = lbl_803E10B0; e[8].z = lbl_803E10D0;
  e[9].layer = 3; e[9].flags = 0x15; e[9].tex = base + 0x1b0; e[9].mode = 0x100;
  e[9].x = lbl_803E10B0; e[9].y = lbl_803E10B0;
  if ((uint)param_3 != 0) {
    e[9].z = (f32)*(s16 *)(param_3 + 2);
  } else {
    e[9].z = lbl_803E10C8;
  }
  e[10].layer = 4; e[10].flags = 0; e[10].tex = (void *)0; e[10].mode = 0x1000;
  e[10].x = lbl_803E10D4; e[10].y = lbl_803E10B0; e[10].z = lbl_803E10B0;
  e[11].layer = 5; e[11].flags = 7; e[11].tex = base + 0x174; e[11].mode = 4;
  e[11].x = lbl_803E10B0; e[11].y = lbl_803E10B0; e[11].z = lbl_803E10B0;
  e[12].layer = 5; e[12].flags = 7; e[12].tex = base + 0x184; e[12].mode = 4;
  e[12].x = lbl_803E10B0; e[12].y = lbl_803E10B0; e[12].z = lbl_803E10B0;
  e[13].layer = 5; e[13].flags = 0x15; e[13].tex = base + 0x1b0; e[13].mode = 0x100;
  e[13].x = lbl_803E10B0; e[13].y = lbl_803E10B0; e[13].z = lbl_803E10C8;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E10B0; buf.pos[1] = lbl_803E10B0; buf.pos[2] = lbl_803E10B0;
  buf.col[0] = lbl_803E10B0; buf.col[1] = lbl_803E10B0; buf.col[2] = lbl_803E10B0;
  buf.scale = lbl_803E10CC;
  buf.v40 = 2;
  buf.v3c = 7;
  buf.v59 = 0xe;
  buf.v5a = 0;
  buf.v5b = 0x1e;
  buf.count = 0xe;
  buf.hw[0] = *(s16 *)(base + 0x1dc); buf.hw[1] = *(s16 *)(base + 0x1de);
  buf.hw[2] = *(s16 *)(base + 0x1e0); buf.hw[3] = *(s16 *)(base + 0x1e2);
  buf.hw[4] = *(s16 *)(base + 0x1e4); buf.hw[5] = *(s16 *)(base + 0x1e6);
  buf.hw[6] = *(s16 *)(base + 0x1e8);
  buf.cmds = buf.entries;
  buf.flags = 0xc0400c0;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E10B0 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E10B0 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E10B0 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E10B0 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E10B0 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E10B0 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x15,base,0x18,base + 0xd4,0x5e0,0);
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
void dll_8D_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  u8 *base = lbl_80316B60;
  FbCmd *e = buf.entries;
  FbCmd *p = e;
  f32 q;

  if (param_2 == 0) {
    p->layer = 0; p->flags = 0x8c; p->tex = (void *)0; p->mode = 0x2000;
    p->x = lbl_803E10E0; p->y = lbl_803E10E4; p->z = lbl_803E10E8;
    p++;
    p->layer = 0; p->flags = 9; p->tex = base + 0x8c; p->mode = 0x80;
    if ((uint)param_3 != 0) {
      p->x = *(f32 *)(param_3 + 0xc); p->y = *(f32 *)(param_3 + 0x10); p->z = *(f32 *)(param_3 + 0x14);
      p++;
    } else {
      p->x = lbl_803E10EC; p->y = lbl_803E10F0; p->z = lbl_803E10EC;
      p++;
    }
    p->layer = 0; p->flags = 8; p->tex = base + 0x8c; p->mode = 2;
    p->x = lbl_803E10F4; p->y = lbl_803E10F4; p->z = lbl_803E10F8;
    p++;
  } else if (param_2 == 1) {
    *(s16 *)(base + 0xb2) = 0x50;
    *(s16 *)(base + 0xb4) = 0x50;
    p->layer = 0; p->flags = 2; p->tex = (void *)0; p->mode = 0x180;
    p->x = lbl_803E10FC; p->y = lbl_803E10EC; p->z = lbl_803E10EC;
    p++;
    p->layer = 0; p->flags = 0x69; p->tex = (void *)0; p->mode = 0x180;
    p->x = lbl_803E10FC; p->y = lbl_803E10EC; p->z = lbl_803E10EC;
    p++;
    p->layer = 0; p->flags = 8; p->tex = base + 0x8c; p->mode = 2;
    q = lbl_803E1100 * (f32)(int)randomGetRange(0, 0xc);
    p->y = p->x = lbl_803E1104 + q;
    p->z = lbl_803E1108 + q;
    p++;
    p->layer = 0; p->flags = 0x8c; p->tex = (void *)0; p->mode = 0x2000;
    p->x = lbl_803E10E0; p->y = lbl_803E110C; p->z = lbl_803E1110;
    p++;
    p->layer = 0; p->flags = 9; p->tex = base + 0x8c; p->mode = 0x80;
    if ((uint)param_3 != 0) {
      p->x = *(f32 *)(param_3 + 0xc); p->y = *(f32 *)(param_3 + 0x10); p->z = *(f32 *)(param_3 + 0x14);
      p++;
    } else {
      p->x = lbl_803E10EC; p->y = lbl_803E10F0; p->z = lbl_803E10EC;
      p++;
    }
  } else if (param_2 == 2) {
    *(s16 *)(base + 0xb2) = 0x50;
    *(s16 *)(base + 0xb4) = 0x50;
    p->layer = 0; p->flags = 0x1fc; p->tex = (void *)0; p->mode = 0x180;
    p->x = lbl_803E10FC; p->y = lbl_803E10EC; p->z = lbl_803E10EC;
    p++;
    p->layer = 0; p->flags = 8; p->tex = base + 0x8c; p->mode = 2;
    q = lbl_803E1100 * (f32)(int)randomGetRange(0, 0xc);
    p->y = p->x = lbl_803E1114 + q;
    p->z = lbl_803E1118 + q;
    p++;
    p->layer = 0; p->flags = 0x8c; p->tex = (void *)0; p->mode = 0x2000;
    p->x = lbl_803E10E0; p->y = lbl_803E110C; p->z = lbl_803E1110;
    p++;
    p->layer = 0; p->flags = 9; p->tex = base + 0x8c; p->mode = 0x80;
    if ((uint)param_3 != 0) {
      p->x = *(f32 *)(param_3 + 0xc); p->y = *(f32 *)(param_3 + 0x10); p->z = *(f32 *)(param_3 + 0x14);
      p++;
    } else {
      p->x = lbl_803E10EC; p->y = lbl_803E10F0; p->z = lbl_803E10EC;
      p++;
    }
  }
  if (param_2 == 0) {
    p[0].layer = 1; p[0].flags = 9; p[0].tex = base + 0x8c; p[0].mode = 0x4000;
    p[0].x = lbl_803E10EC; p[0].y = lbl_803E10EC; p[0].z = lbl_803E10EC;
    p[1].layer = 1; p[1].flags = 0x68; p[1].tex = (void *)0; p[1].mode = 0x80;
    p[1].x = lbl_803E10FC; p[1].y = lbl_803E10EC; p[1].z = lbl_803E10EC;
    p[2].layer = 1; p[2].flags = 8; p[2].tex = base + 0x8c; p[2].mode = 2;
    p[2].x = lbl_803E111C; p[2].y = lbl_803E111C; p[2].z = lbl_803E111C;
    p += 3;
  } else if (param_2 == 1) {
    p[0].layer = 1; p[0].flags = 9; p[0].tex = base + 0x8c; p[0].mode = 0x4000;
    p[0].x = lbl_803E10EC; p[0].y = lbl_803E10EC; p[0].z = lbl_803E10EC;
    p[1].layer = 1; p[1].flags = 0x8f; p[1].tex = (void *)0; p[1].mode = 0x180;
    p[1].x = lbl_803E1120; p[1].y = lbl_803E10EC; p[1].z = lbl_803E10EC;
    p += 2;
  } else if (param_2 == 2) {
    p[0].layer = 1; p[0].flags = 9; p[0].tex = base + 0x8c; p[0].mode = 0x4000;
    p[0].x = lbl_803E10EC; p[0].y = lbl_803E10EC; p[0].z = lbl_803E10EC;
    p[1].layer = 1; p[1].flags = 0x1fd; p[1].tex = (void *)0; p[1].mode = 0x180;
    p[1].x = lbl_803E1120; p[1].y = lbl_803E10EC; p[1].z = lbl_803E10EC;
    p += 2;
  }
  if (param_2 == 0) {
    p->layer = 1; p->flags = 9; p->tex = base + 0x8c; p->mode = 0x100;
    p->x = lbl_803E1124; p->y = lbl_803E10EC; p->z = lbl_803E10EC;
    p++;
  } else if (param_2 == 1) {
    p->layer = 1; p->flags = 9; p->tex = base + 0x8c; p->mode = 0x100;
    p->x = lbl_803E1128; p->y = lbl_803E10EC; p->z = lbl_803E10EC;
    p++;
  } else if (param_2 == 2) {
    p->layer = 1; p->flags = 9; p->tex = base + 0x8c; p->mode = 0x100;
    p->x = lbl_803E1128; p->y = lbl_803E10EC; p->z = lbl_803E10EC;
    p++;
  }
  if (param_2 == 0) {
    p->layer = 2; p->flags = 9; p->tex = base + 0x8c; p->mode = 0x100;
    p->x = lbl_803E1124; p->y = lbl_803E10EC; p->z = lbl_803E10EC;
    p++;
  } else if (param_2 == 1) {
    p->layer = 2; p->flags = 9; p->tex = base + 0x8c; p->mode = 0x100;
    p->x = lbl_803E1128; p->y = lbl_803E10EC; p->z = lbl_803E10EC;
    p++;
  } else if (param_2 == 2) {
    p->layer = 2; p->flags = 9; p->tex = base + 0x8c; p->mode = 0x100;
    p->x = lbl_803E1128; p->y = lbl_803E10EC; p->z = lbl_803E10EC;
    p++;
  }
  p->layer = 2; p->flags = 9; p->tex = base + 0x8c; p->mode = 4;
  p->x = lbl_803E10EC; p->y = lbl_803E10EC; p->z = lbl_803E10EC;
  p++;
  if (param_2 == 0) {
    p->layer = 3; p->flags = 0; p->tex = (void *)0; p->mode = 0x2000;
    p->x = lbl_803E10E0; p->y = lbl_803E10E4; p->z = lbl_803E10E8;
    p++;
  } else if (param_2 == 1) {
    p->layer = 3; p->flags = 0; p->tex = (void *)0; p->mode = 0x2000;
    p->x = lbl_803E10E0; p->y = lbl_803E110C; p->z = lbl_803E1110;
    p++;
  } else if (param_2 == 2) {
    p->layer = 3; p->flags = 0; p->tex = (void *)0; p->mode = 0x2000;
    p->x = lbl_803E10E0; p->y = lbl_803E110C; p->z = lbl_803E1110;
    p++;
  }
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  if (param_2 == 0) {
    buf.pos[0] = lbl_803E10EC; buf.pos[1] = lbl_803E10EC; buf.pos[2] = lbl_803E10EC;
  } else {
    buf.pos[0] = lbl_803E10EC; buf.pos[1] = lbl_803E10EC; buf.pos[2] = lbl_803E10EC;
  }
  buf.col[0] = lbl_803E10EC; buf.col[1] = lbl_803E10EC; buf.col[2] = lbl_803E10EC;
  buf.scale = lbl_803E10FC;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 9;
  buf.v5a = 0;
  buf.v5b = 0;
  buf.count = p - e;
  buf.hw[0] = *(s16 *)(base + 0xb0); buf.hw[1] = *(s16 *)(base + 0xb2);
  buf.hw[2] = *(s16 *)(base + 0xb4); buf.hw[3] = *(s16 *)(base + 0xb6);
  buf.hw[4] = *(s16 *)(base + 0xb8); buf.hw[5] = *(s16 *)(base + 0xba);
  buf.hw[6] = *(s16 *)(base + 0xbc);
  buf.cmds = buf.entries;
  buf.flags = 0x400;
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
  if (param_2 == 0) {
    buf.v58 = 0;
    (*(code *)(*gModgfxInterface + 8))(&buf,0,9,base,8,base + 0x5c,0x156,0);
  } else if (param_2 == 1) {
    buf.v58 = 0;
    buf.flags |= 4;
    (*(code *)(*gModgfxInterface + 8))(&buf,0,9,base,8,base + 0x5c,0xc0d,0);
  } else if (param_2 == 2) {
    buf.v58 = 0;
    buf.flags |= 4;
    (*(code *)(*gModgfxInterface + 8))(&buf,0,9,base,8,base + 0x5c,0x23b,0);
  }
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
void dll_8E_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  FbCmd *e = buf.entries;
  FbCmd *p = e;
  u8 *base;
  f32 rz;
  f32 ry;

  if (param_2 == 0) {
    p->layer = 0; p->flags = 3; p->tex = &lbl_803DB918; p->mode = 8;
    p->x = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
    p->y = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
    p->z = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
    p++;
  } else if (param_2 == 1) {
    p->layer = 0; p->flags = 3; p->tex = &lbl_803DB918; p->mode = 8;
    p->x = (f32)(int)(randomGetRange(0, 0x1e) + 0xe1);
    p->y = (f32)(int)(randomGetRange(0, 0x69) + 0x8c);
    p->z = (f32)(int)(randomGetRange(0, 0x41) + 0x78);
    p++;
  }
  rz = (f32)(int)randomGetRange(0, 0xfffe);
  ry = (f32)(int)randomGetRange(-0xbb8, -0x2ee0);
  p[0].layer = 0; p[0].flags = 0; p[0].tex = (void *)0; p[0].mode = 0x80;
  p[0].x = lbl_803E1138; p[0].y = ry; p[0].z = rz;
  p[1].layer = 0; p[1].flags = 3; p[1].tex = &lbl_803DB918; p[1].mode = 4;
  p[1].x = lbl_803E1138; p[1].y = lbl_803E1138; p[1].z = lbl_803E1138;
  p[2].layer = 0; p[2].flags = 3; p[2].tex = &lbl_803DB918; p[2].mode = 2;
  p[2].x = lbl_803E113C;
  p[2].y = lbl_803E1144 * (f32)(int)randomGetRange(0, 0x32) + lbl_803E1140;
  p[2].z = lbl_803E1144 * (f32)(int)randomGetRange(0, 0x14) + lbl_803E1148;
  p[3].layer = 1; p[3].flags = 3; p[3].tex = &lbl_803DB918; p[3].mode = 4;
  if (randomGetRange(0, 0xa) == 0) {
    p[3].x = lbl_803E114C + (f32)(int)randomGetRange(0, 0x1e);
  } else {
    p[3].x = lbl_803E1150 + (f32)(int)randomGetRange(0, 0xa);
  }
  p[3].y = lbl_803E1138; p[3].z = lbl_803E1138;
  p[4].layer = 2; p[4].flags = 0; p[4].tex = (void *)0; p[4].mode = 0x80;
  p[4].x = lbl_803E1138; p[4].y = lbl_803E1138;
  p[4].z = (f32)(int)randomGetRange(0, 0xfffe);
  p[5].layer = 1; p[5].flags = 3; p[5].tex = &lbl_803DB918; p[5].mode = 2;
  p[5].x = lbl_803E1154; p[5].y = lbl_803E1158; p[5].z = lbl_803E115C;
  p[6].layer = 2; p[6].flags = 0; p[6].tex = (void *)0; p[6].mode = 0x80;
  p[6].x = lbl_803E1138; p[6].y = lbl_803E1138;
  p[6].z = (f32)(int)randomGetRange(0, 0xfffe);
  p[7].layer = 2; p[7].flags = 3; p[7].tex = &lbl_803DB918; p[7].mode = 4;
  p[7].x = lbl_803E1138; p[7].y = lbl_803E1138; p[7].z = lbl_803E1138;
  p[8].layer = 2; p[8].flags = 3; p[8].tex = &lbl_803DB918; p[8].mode = 2;
  p[8].x = lbl_803E1160; p[8].y = lbl_803E1164; p[8].z = lbl_803E1168;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E1138;
  if (param_2 == 0) {
    buf.pos[1] = lbl_803E1138;
  } else if (param_2 == 1) {
    buf.pos[1] = lbl_803E116C;
  }
  buf.pos[2] = lbl_803E1138;
  buf.col[0] = lbl_803E1138; buf.col[1] = lbl_803E1138; buf.col[2] = lbl_803E1138;
  buf.scale = lbl_803E1164;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 3;
  buf.v5a = 0;
  buf.v5b = 0;
  buf.count = (FbCmd *)((u8 *)p + 0xd8) - e;
  base = lbl_80316C60;
  buf.hw[0] = *(s16 *)(base + 0); buf.hw[1] = *(s16 *)(base + 2);
  buf.hw[2] = *(s16 *)(base + 4); buf.hw[3] = *(s16 *)(base + 6);
  buf.hw[4] = *(s16 *)(base + 8); buf.hw[5] = *(s16 *)(base + 0xa);
  buf.hw[6] = *(s16 *)(base + 0xc);
  buf.cmds = buf.entries;
  buf.flags = 0x4000410;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)buf.ctx != 0 && (uint)param_3 != 0) {
      buf.pos[0] += *(f32 *)(buf.ctx + 0x18) + *(f32 *)(param_3 + 0xc);
      buf.pos[1] += *(f32 *)(buf.ctx + 0x1c) + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E1138 + (*(f32 *)(buf.ctx + 0x20) + *(f32 *)(param_3 + 0x14));
    } else if ((uint)buf.ctx != 0) {
      buf.pos[0] += *(f32 *)(buf.ctx + 0x18);
      buf.pos[1] += *(f32 *)(buf.ctx + 0x1c);
      buf.pos[2] += *(f32 *)(buf.ctx + 0x20);
    } else if ((uint)param_3 != 0) {
      buf.pos[0] += *(f32 *)(param_3 + 0xc);
      buf.pos[1] += *(f32 *)(param_3 + 0x10);
      buf.pos[2] += *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,3,lbl_80316C40,1,&lbl_803DB910,0x26a,0);
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
void dll_90_func03(int param_1,int param_2,int param_3,uint param_4)
{
  FbBuf buf;
  u8 *base = lbl_80316E30;
  FbCmd *e = buf.entries;

  e[0].layer = 0; e[0].flags = 0x12; e[0].tex = base + 0x150; e[0].mode = 0x4;
  e[0].x = lbl_803E11A0; e[0].y = lbl_803E11A0; e[0].z = lbl_803E11A0;
  e[1].layer = 0; e[1].flags = 0x9; e[1].tex = base + 0x114; e[1].mode = 0x8;
  e[1].x = lbl_803E11A4; e[1].y = lbl_803E11A4; e[1].z = lbl_803E11A0;
  e[2].layer = 0; e[2].flags = 0x9; e[2].tex = base + 0x128; e[2].mode = 0x2;
  e[2].x = lbl_803E11A8; e[2].y = lbl_803E11AC; e[2].z = lbl_803E11A8;
  e[3].layer = 0; e[3].flags = 0x12; e[3].tex = base + 0x150; e[3].mode = 0x2;
  e[3].x = lbl_803E11B0; e[3].y = lbl_803E11B4; e[3].z = lbl_803E11B0;
  e[4].layer = 0; e[4].flags = 0x9; e[4].tex = base + 0x128; e[4].mode = 0x8;
  e[4].x = lbl_803E11B8; e[4].y = lbl_803E11A0; e[4].z = lbl_803E11A0;
  e[5].layer = 1; e[5].flags = 0x12; e[5].tex = base + 0x150; e[5].mode = 0x4;
  e[5].x = lbl_803E11A4; e[5].y = lbl_803E11A0; e[5].z = lbl_803E11A0;
  e[6].layer = 1; e[6].flags = 0x9; e[6].tex = base + 0x128; e[6].mode = 0x2;
  e[6].x = lbl_803E11A8; e[6].y = lbl_803E11BC; e[6].z = lbl_803E11A8;
  e[7].layer = 1; e[7].flags = 0x7a; e[7].tex = (void *)0; e[7].mode = 0x1;
  e[7].x = lbl_803E11A0; e[7].y = lbl_803E11A0; e[7].z = lbl_803E11A0;
  e[8].layer = 1; e[8].flags = 0x0; e[8].tex = (void *)0; e[8].mode = 0x8;
  e[8].x = lbl_803E11A0; e[8].y = lbl_803E11C0; e[8].z = lbl_803E11A0;
  e[9].layer = 2; e[9].flags = 0x9d; e[9].tex = (void *)0; e[9].mode = 0x2;
  e[9].x = lbl_803E11A0; e[9].y = lbl_803E11A0; e[9].z = lbl_803E11A0;
  e[10].layer = 3; e[10].flags = 0x9; e[10].tex = base + 0x114; e[10].mode = 0x8;
  e[10].x = lbl_803E11A4; e[10].y = lbl_803E11C4; e[10].z = lbl_803E11A0;
  e[11].layer = 3; e[11].flags = 0x12; e[11].tex = base + 0x150; e[11].mode = 0x100;
  e[11].x = lbl_803E11A0; e[11].y = lbl_803E11A0; e[11].z = lbl_803E11C8;
  e[12].layer = 3; e[12].flags = 0x5; e[12].tex = base + 0x188; e[12].mode = 0x2;
  e[12].x = lbl_803E11CC; e[12].y = lbl_803E11A8; e[12].z = lbl_803E11CC;
  e[13].layer = 3; e[13].flags = 0x4; e[13].tex = &lbl_803DB920; e[13].mode = 0x2;
  e[13].x = lbl_803E11D0; e[13].y = lbl_803E11A8; e[13].z = lbl_803E11D0;
  e[14].layer = 4; e[14].flags = 0x9; e[14].tex = base + 0x114; e[14].mode = 0x8;
  e[14].x = lbl_803E11A4; e[14].y = lbl_803E11A4; e[14].z = lbl_803E11A0;
  e[15].layer = 4; e[15].flags = 0x12; e[15].tex = base + 0x150; e[15].mode = 0x100;
  e[15].x = lbl_803E11A0; e[15].y = lbl_803E11A0; e[15].z = lbl_803E11C8;
  e[16].layer = 4; e[16].flags = 0x5; e[16].tex = base + 0x188; e[16].mode = 0x2;
  e[16].x = lbl_803E11D0; e[16].y = lbl_803E11A8; e[16].z = lbl_803E11D0;
  e[17].layer = 4; e[17].flags = 0x4; e[17].tex = &lbl_803DB920; e[17].mode = 0x2;
  e[17].x = lbl_803E11CC; e[17].y = lbl_803E11A8; e[17].z = lbl_803E11CC;
  e[18].layer = 5; e[18].flags = 0x1; e[18].tex = (void *)0; e[18].mode = 0x1000;
  e[18].x = lbl_803E11A8; e[18].y = lbl_803E11A0; e[18].z = lbl_803E11A0;
  e[19].layer = 6; e[19].flags = 0x12; e[19].tex = base + 0x150; e[19].mode = 0x4;
  e[19].x = lbl_803E11A0; e[19].y = lbl_803E11A0; e[19].z = lbl_803E11A0;
  e[20].layer = 6; e[20].flags = 0x12; e[20].tex = base + 0x150; e[20].mode = 0x2;
  e[20].x = lbl_803E11D4; e[20].y = lbl_803E11A8; e[20].z = lbl_803E11D4;
  buf.v58 = 0;
  buf.ctx = param_1;
  buf.v44 = (s16)param_2;
  buf.pos[0] = lbl_803E11A0; buf.pos[1] = lbl_803E11A0; buf.pos[2] = lbl_803E11A0;
  buf.col[0] = lbl_803E11A0; buf.col[1] = lbl_803E11A0; buf.col[2] = lbl_803E11A0;
  buf.scale = lbl_803E11A8;
  buf.v40 = 1;
  buf.v3c = 0;
  buf.v59 = 0x12;
  buf.v5a = 0;
  buf.v5b = 0xc;
  buf.flags = 0x10082;
  buf.count = (FbCmd *)((u8 *)e + 0x1f8) - e;
  buf.hw[0] = *(s16 *)(base + 0x194); buf.hw[1] = *(s16 *)(base + 0x196);
  buf.hw[2] = *(s16 *)(base + 0x198); buf.hw[3] = *(s16 *)(base + 0x19a);
  buf.hw[4] = *(s16 *)(base + 0x19c); buf.hw[5] = *(s16 *)(base + 0x19e);
  buf.hw[6] = *(s16 *)(base + 0x1a0);
  buf.cmds = e;
  buf.flags |= param_4;
  if ((buf.flags & 1) != 0) {
    if ((uint)param_1 != 0) {
      buf.pos[0] = lbl_803E11A0 + *(f32 *)(param_1 + 0x18);
      buf.pos[1] = lbl_803E11A0 + *(f32 *)(param_1 + 0x1c);
      buf.pos[2] = lbl_803E11A0 + *(f32 *)(param_1 + 0x20);
    } else {
      buf.pos[0] = lbl_803E11A0 + *(f32 *)(param_3 + 0xc);
      buf.pos[1] = lbl_803E11A0 + *(f32 *)(param_3 + 0x10);
      buf.pos[2] = lbl_803E11A0 + *(f32 *)(param_3 + 0x14);
    }
  }
  (*(code *)(*gModgfxInterface + 8))(&buf,0,0x12,base,0x10,base + 0xb4,0x45,0);
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
