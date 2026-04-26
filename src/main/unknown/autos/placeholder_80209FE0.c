#include "ghidra_import.h"
#include "main/objanim.h"
#include "main/unknown/autos/placeholder_80209FE0.h"

extern undefined4 ABS();
extern undefined4 FUN_80003494();
extern undefined8 FUN_80006724();
extern undefined8 FUN_80006728();
extern undefined4 FUN_80006770();
extern undefined4 FUN_800067bc();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_800067e8();
extern bool FUN_800067f0();
extern undefined8 FUN_8000680c();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006814();
extern undefined4 FUN_80006818();
extern undefined8 FUN_80006824();
extern char FUN_80006884();
extern undefined8 FUN_80006894();
extern undefined4 FUN_800068a0();
extern undefined4 FUN_800068c0();
extern undefined8 FUN_800068c4();
extern undefined4 FUN_80006920();
extern undefined4 FUN_80006948();
extern undefined4 FUN_8000696c();
extern undefined4 FUN_80006974();
extern undefined4 FUN_8000697c();
extern void* FUN_800069a8();
extern undefined4 FUN_800069bc();
extern double FUN_800069f8();
extern int FUN_80006a10();
extern undefined4 FUN_80006a18();
extern int FUN_80006a64();
extern undefined8 FUN_80006a68();
extern undefined4 FUN_80006a6c();
extern uint FUN_80006ab0();
extern uint FUN_80006ab8();
extern undefined4 FUN_80006ac0();
extern undefined4 FUN_80006ac4();
extern undefined4 FUN_80006ac8();
extern undefined4 FUN_80006acc();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern byte FUN_80006b20();
extern undefined4 FUN_80006b2c();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined4 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern undefined8 FUN_80006b84();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_80006ba8();
extern char FUN_80006bc8();
extern char FUN_80006bd0();
extern uint FUN_80006bd8();
extern uint FUN_80006be0();
extern uint FUN_80006bf8();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern undefined4 FUN_80006c88();
extern undefined8 FUN_80017484();
extern undefined4 FUN_80017520();
extern int FUN_80017524();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017540();
extern undefined4 FUN_80017544();
extern undefined4 FUN_80017548();
extern undefined4 FUN_8001754c();
extern undefined4 FUN_80017554();
extern undefined4 FUN_80017560();
extern undefined4 FUN_80017564();
extern undefined4 FUN_80017568();
extern undefined4 FUN_8001756c();
extern undefined4 FUN_80017578();
extern undefined4 FUN_80017580();
extern undefined4 FUN_80017588();
extern undefined4 FUN_80017590();
extern undefined4 FUN_80017594();
extern undefined4 FUN_80017598();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175a0();
extern undefined4 FUN_800175ac();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175b4();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175c0();
extern int FUN_800175c4();
extern undefined8 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d4();
extern undefined4 FUN_800175d8();
extern undefined8 FUN_800175ec();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern uint FUN_80017688();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined8 FUN_800176a4();
extern uint FUN_800176d0();
extern double FUN_800176f4();
extern undefined4 FUN_80017700();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern int FUN_80017730();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017754();
extern uint FUN_80017758();
extern uint FUN_80017760();
extern undefined4 FUN_8001776c();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017818();
extern undefined4 FUN_800178bc();
extern undefined4 FUN_8001791c();
extern int FUN_80017920();
extern undefined4 FUN_80017924();
extern int FUN_8001792c();
extern int FUN_80017944();
extern undefined4 FUN_80017954();
extern undefined4 FUN_80017958();
extern undefined4 FUN_80017970();
extern byte FUN_80017a20();
extern undefined4 FUN_80017a28();
extern byte FUN_80017a34();
extern undefined4 FUN_80017a3c();
extern undefined4 FUN_80017a50();
extern int FUN_80017a54();
extern uint FUN_80017a5c();
extern undefined4 FUN_80017a6c();
extern undefined8 FUN_80017a78();
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined8 FUN_80017ac8();
extern undefined4 FUN_80017acc();
extern undefined4 FUN_80017ad0();
extern undefined8 FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern int FUN_80017b00();
extern undefined4 fn_8002EE64();
extern undefined4 FUN_8002f6ac();
extern int FUN_8002fc3c();
extern undefined8 FUN_800305f8();
extern undefined8 FUN_800339b4();
extern char objHitReact_update();
extern undefined4 ObjHitbox_SetStateIndex();
extern undefined4 ObjHits_SetTargetMask();
extern undefined4 FUN_80035b84();
extern undefined4 FUN_80035d58();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeMasks();
extern undefined8 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_ClearSourceMask();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined8 ObjHits_DisableObject();
extern undefined8 ObjHits_EnableObject();
extern undefined4 ObjHits_RecordObjectHit();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjMsg_SendToObject();
extern int FUN_80037d50();
extern int FUN_80037fa8();
extern undefined4 ObjLink_DetachChild();
extern undefined8 ObjLink_AttachChild();
extern int FUN_80038470();
extern int FUN_800384ec();
extern int FUN_80038598();
extern undefined4 FUN_80038730();
extern undefined4 FUN_800387ac();
extern uint FUN_8003882c();
extern undefined8 FUN_800388b4();
extern int FUN_80038a34();
extern undefined4 FUN_80038f38();
extern undefined4 FUN_80039130();
extern undefined4 FUN_800392e0();
extern undefined4 FUN_800392ec();
extern undefined4 FUN_80039370();
extern void* FUN_80039518();
extern int FUN_80039520();
extern int FUN_8003964c();
extern undefined4 FUN_8003aa48();
extern undefined4 FUN_8003aaf0();
extern undefined8 FUN_8003b280();
extern undefined4 FUN_8003b540();
extern undefined4 FUN_8003b56c();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8003b870();
extern undefined4 FUN_800400b0();
extern undefined4 FUN_8004036c();
extern undefined4 FUN_80041ff8();
extern undefined8 FUN_800427c8();
extern undefined4 FUN_80042800();
extern int FUN_80042838();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80043030();
extern int FUN_80044404();
extern undefined4 FUN_800533cc();
extern undefined4 FUN_80053604();
extern undefined4 FUN_80053754();
extern int FUN_8005398c();
extern undefined4 FUN_80053ae4();
extern undefined4 FUN_80053af0();
extern undefined4 FUN_80053b3c();
extern undefined4 FUN_80053b70();
extern undefined4 FUN_80053c20();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_800562d0();
extern int FUN_80056600();
extern int FUN_80056c8c();
extern int FUN_80057690();
extern int FUN_8005af70();
extern undefined4 FUN_8005b12c();
extern int FUN_8005b398();
extern undefined8 FUN_8005d0ac();
extern undefined4 FUN_8005d144();
extern undefined4 FUN_8005d17c();
extern undefined4 FUN_8005fe14();
extern int FUN_800600e4();
extern undefined4 FUN_800616c0();
extern undefined4 FUN_800631d4();
extern int FUN_80063298();
extern undefined4 FUN_800632e8();
extern undefined4 FUN_8006b540();
extern undefined4 FUN_8006b56c();
extern int FUN_8007f3c8();
extern int FUN_8007f56c();
extern undefined4 FUN_8007f5ec();
extern uint FUN_8007f66c();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f6e4();
extern undefined8 FUN_8007f718();
extern int FUN_8007f764();
extern undefined4 FUN_8007f7cc();
extern int FUN_8007f924();
extern undefined4 FUN_80080f14();
extern undefined8 FUN_80080f28();
extern undefined4 FUN_80080f3c();
extern undefined8 FUN_80080f70();
extern undefined4 FUN_80080f74();
extern undefined4 FUN_80080f78();
extern undefined4 FUN_80080f7c();
extern undefined4 FUN_80080f80();
extern undefined4 FUN_80080f8c();
extern undefined4 FUN_80081028();
extern uint FUN_80081030();
extern undefined4 FUN_80081038();
extern undefined4 FUN_8008107c();
extern undefined8 FUN_80081080();
extern undefined4 FUN_800810e4();
extern undefined4 FUN_800810ec();
extern undefined4 FUN_800810f0();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_800810f8();
extern undefined4 FUN_800810fc();
extern undefined4 FUN_80081104();
extern undefined4 FUN_80081108();
extern undefined4 FUN_8008110c();
extern undefined4 FUN_80081110();
extern undefined4 FUN_80081114();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_80081120();
extern undefined4 FUN_80081124();
extern undefined4 FUN_80081128();
extern undefined4 FUN_8008112c();
extern undefined4 gameplay_registerDebugOption();
extern undefined4 FUN_800e8630();
extern ushort FUN_800ea9ac();
extern undefined4 FUN_801141dc();
extern undefined4 FUN_801141e8();
extern int FUN_80114340();
extern int FUN_801149b8();
extern undefined4 FUN_801149bc();
extern undefined4 FUN_80114b10();
extern undefined4 FUN_80115094();
extern undefined4 FUN_801150ac();
extern undefined8 FUN_8011e7c8();
extern undefined4 FUN_8011e800();
extern undefined4 FUN_8011e824();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_80125b7c();
extern undefined4 FUN_80125d3c();
extern undefined4 FUN_80125e30();
extern undefined4 FUN_801299d4();
extern undefined8 FUN_8012e0b8();
extern ushort FUN_8012e0e8();
extern undefined4 FUN_8012e114();
extern int FUN_8012efc4();
extern undefined4 FUN_80130298();
extern undefined4 FUN_80133a04();
extern undefined4 FUN_8013577c();
extern undefined4 FUN_80135814();
extern int FUN_80136538();
extern uint FUN_801365a0();
extern undefined4 FUN_8016d994();
extern int FUN_8016fef4();
extern undefined4 FUN_80170048();
extern byte FUN_8019f0ec();
extern int FUN_8019f0fc();
extern undefined4 FUN_8019f16c();
extern undefined4 FUN_8019f1ac();
extern undefined4 FUN_801a1310();
extern undefined4 FUN_801d8308();
extern undefined4 FUN_801d8480();
extern int FUN_801ecf58();
extern uint FUN_801ecf94();
extern undefined4 FUN_8024782c();
extern undefined4 FUN_80247944();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80247cd8();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined8 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double FUN_80247f54();
extern double FUN_80247f90();
extern undefined4 FUN_80247fb0();
extern undefined4 FUN_80247fec();
extern double FUN_802480e8();
extern undefined4 FUN_8025da88();
extern undefined4 FUN_80286820();
extern undefined8 FUN_80286824();
extern int FUN_80286828();
extern int FUN_8028682c();
extern undefined8 FUN_80286830();
extern int FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286874();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80292754();
extern double FUN_80293900();
extern undefined4 FUN_80293994();
extern undefined4 FUN_80293eac();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern double FUN_802949f0();
extern uint FUN_80294ca0();
extern int FUN_80294cf8();
extern uint FUN_80294d30();
extern undefined4 FUN_80294d4c();
extern int FUN_80294d6c();
extern int FUN_80294dbc();
extern undefined4 SUB81();
extern uint countLeadingZeros();

extern undefined4 DAT_802c2ca0;
extern undefined4 DAT_802c2ca4;
extern undefined4 DAT_802c2ca8;
extern undefined4 DAT_802c2cac;
extern undefined4 DAT_802c2cb0;
extern undefined4 DAT_802c2cb4;
extern undefined4 DAT_802c2cb8;
extern undefined4 DAT_802c2cbc;
extern undefined4 DAT_802c2cc0;
extern undefined4 DAT_802c2cc4;
extern undefined4 DAT_802c2cc8;
extern undefined4 DAT_802c2cd0;
extern undefined4 DAT_802c2cd4;
extern undefined4 DAT_802c2cd8;
extern undefined4 DAT_802c2cdc;
extern undefined4 DAT_802c2ce0;
extern undefined4 DAT_802c2ce4;
extern undefined4 DAT_802c2ce8;
extern undefined4 DAT_802c2cec;
extern undefined4 DAT_802c2cf0;
extern undefined4 DAT_802c2cf4;
extern undefined4 DAT_802c2cf8;
extern undefined4 DAT_802c2cfc;
extern undefined4 DAT_802c2d00;
extern undefined4 DAT_802c2d04;
extern undefined4 DAT_802c2d08;
extern undefined4 DAT_802c2d0c;
extern undefined4 DAT_802c2d10;
extern undefined4 DAT_802c2d14;
extern undefined4 DAT_802c2d18;
extern undefined4 DAT_802c2d1c;
extern undefined4 DAT_802c2d20;
extern undefined4 DAT_802c2d24;
extern undefined4 DAT_802c2d28;
extern undefined4 DAT_802c2d2c;
extern undefined4 DAT_802c2d30;
extern undefined4 DAT_802c2d34;
extern undefined4 DAT_802c2d38;
extern undefined4 DAT_802c2d3c;
extern undefined4 DAT_802c2d40;
extern undefined4 DAT_802c2d44;
extern undefined4 DAT_802c2d48;
extern undefined4 DAT_802c2d4c;
extern undefined4 DAT_802c2d50;
extern undefined4 DAT_802c2d54;
extern undefined4 DAT_802c2d58;
extern undefined4 DAT_802c2d5c;
extern undefined4 DAT_802c2d60;
extern undefined4 DAT_802c2d68;
extern undefined4 DAT_802c2d6c;
extern undefined4 DAT_802c2d70;
extern undefined4 DAT_802c2d78;
extern undefined4 DAT_802c2d7c;
extern undefined4 DAT_802c2d80;
extern undefined4 DAT_802c2d88;
extern undefined4 DAT_802c2d8c;
extern undefined4 DAT_802c2d90;
extern undefined4 DAT_802c2d98;
extern undefined4 DAT_802c2d9c;
extern undefined4 DAT_802c2da0;
extern undefined4 DAT_8032abd0;
extern undefined4 DAT_8032abe4;
extern undefined4 DAT_8032abf8;
extern undefined4 DAT_8032ac44;
extern undefined4 DAT_8032ac54;
extern undefined4 DAT_8032ac58;
extern undefined4 DAT_8032ac5c;
extern undefined4 DAT_8032ac60;
extern undefined4 DAT_8032ac64;
extern undefined4 DAT_8032ac68;
extern undefined4 DAT_8032add0;
extern undefined4 DAT_8032ade4;
extern undefined4 DAT_8032adf8;
extern uint DAT_8032ae0c;
extern undefined4 DAT_8032ae14;
extern undefined4 DAT_8032ae58;
extern undefined4 DAT_8032ae68;
extern undefined4 DAT_8032ae6c;
extern undefined4 DAT_8032ae70;
extern undefined4 DAT_8032ae74;
extern undefined4 DAT_8032ae78;
extern undefined4 DAT_8032ae79;
extern undefined4 DAT_8032af68;
extern undefined4 DAT_8032af94;
extern undefined4 DAT_8032afa4;
extern undefined4 DAT_8032afa8;
extern undefined4 DAT_8032afbc;
extern undefined4 DAT_8032afc0;
extern undefined4 DAT_8032afc4;
extern undefined4 DAT_8032b168;
extern undefined4 DAT_8032b174;
extern undefined4 DAT_8032b180;
extern undefined4 DAT_8032b18c;
extern undefined4 DAT_8032b198;
extern undefined4 DAT_8032b1a4;
extern undefined4 DAT_8032b1b4;
extern undefined4 DAT_8032b1c4;
extern undefined4 DAT_8032b1d4;
extern short DAT_8032b388;
extern undefined4 DAT_8032b39c;
extern undefined4 DAT_8032b3b0;
extern undefined4 DAT_8032b3c0;
extern undefined4 DAT_8032b418;
extern undefined4 DAT_8032b424;
extern undefined4 DAT_8032b430;
extern undefined4 DAT_8032b43c;
extern undefined4 DAT_8032b454;
extern undefined4 DAT_8032b788;
extern int DAT_8032b794;
extern undefined4 DAT_8032b7a0;
extern undefined4 DAT_8032b7b0;
extern undefined4 DAT_8032b7e0;
extern undefined4 DAT_8032b7f0;
extern undefined4 DAT_8032b808;
extern undefined4 DAT_8032b80c;
extern undefined4 DAT_8032bb18;
extern undefined4 DAT_8032bfa0;
extern undefined4 DAT_8032bfac;
extern undefined4 DAT_8032c060;
extern undefined4 DAT_8032c0d8;
extern undefined4 DAT_8032c100;
extern undefined4 DAT_8032c378;
extern undefined4 DAT_8032c37c;
extern undefined4 DAT_8032c380;
extern undefined4 DAT_8032c384;
extern undefined4 DAT_8032c388;
extern undefined4 DAT_8032c38c;
extern undefined4 DAT_8032c838;
extern undefined4 DAT_8032c83c;
extern undefined4 DAT_8032c840;
extern undefined4 DAT_8032c958;
extern undefined4 DAT_8032c968;
extern undefined4 DAT_8032c9a8;
extern byte DAT_8032c9a9;
extern byte DAT_8032c9aa;
extern undefined4 DAT_8032ca78;
extern undefined4 DAT_8032ca84;
extern undefined4 DAT_8032ca90;
extern undefined4 DAT_8032ca9c;
extern undefined4 DAT_8032cce0;
extern undefined4 DAT_8032ccf0;
extern undefined4 DAT_8032ccf4;
extern undefined4 DAT_8032ccf8;
extern undefined4 DAT_8032ccfc;
extern undefined4 DAT_8032cd00;
extern undefined4 DAT_8032cd20;
extern undefined4 DAT_8032cd24;
extern undefined4 DAT_8032cd28;
extern undefined4 DAT_8032cd30;
extern undefined4 DAT_8032cd34;
extern undefined4 DAT_8032cd38;
extern undefined4 DAT_8032cd3c;
extern undefined4 DAT_8032cd40;
extern undefined4 DAT_8032cd44;
extern undefined4 DAT_8032cd48;
extern undefined4 DAT_8032cec8;
extern undefined4 DAT_8032cecc;
extern undefined4 DAT_8032ced0;
extern undefined4 DAT_8032ced4;
extern undefined4 DAT_8032ced8;
extern undefined4 DAT_8032cedc;
extern undefined4 DAT_803addb8;
extern undefined4 DAT_803addba;
extern undefined4 DAT_803addbc;
extern undefined4 DAT_803addc0;
extern undefined4 DAT_803addc4;
extern undefined4 DAT_803addc8;
extern undefined4 DAT_803addcc;
extern undefined4 DAT_803addd0;
extern undefined4 DAT_803addd4;
extern undefined4 DAT_803addd8;
extern undefined4 DAT_803adddc;
extern undefined4 DAT_803adde0;
extern undefined4 DAT_803adde4;
extern undefined4 DAT_803adde8;
extern undefined4 DAT_803addec;
extern undefined4 DAT_803addf0;
extern undefined4 DAT_803addf4;
extern undefined4 DAT_803addf8;
extern undefined4 DAT_803addfc;
extern undefined4 DAT_803ade00;
extern undefined4 DAT_803ade04;
extern undefined4 DAT_803ade08;
extern undefined4 DAT_803ade0c;
extern undefined4 DAT_803ade10;
extern undefined4 DAT_803ade14;
extern undefined4 DAT_803ade18;
extern undefined4 DAT_803ade1c;
extern undefined4 DAT_803ade20;
extern undefined4 DAT_803ade28;
extern undefined4 DAT_803ade68;
extern undefined4 DAT_803adea8;
extern undefined4 DAT_803aded8;
extern undefined4 DAT_803adee8;
extern char DAT_803adef8;
extern char DAT_803adf38;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dce00;
extern undefined4 DAT_803dce02;
extern undefined4 DAT_803dce08;
extern undefined4 DAT_803dce10;
extern char DAT_803dce20;
extern byte DAT_803dce28;
extern undefined4 DAT_803dce30;
extern undefined4 DAT_803dce38;
extern undefined4 DAT_803dce40;
extern undefined4 DAT_803dce48;
extern undefined4 DAT_803dce50;
extern undefined4 DAT_803dce58;
extern undefined4 DAT_803dce5c;
extern undefined4 DAT_803dce60;
extern undefined4 DAT_803dce64;
extern undefined4 DAT_803dce68;
extern undefined4 DAT_803dce6c;
extern undefined4 DAT_803dce70;
extern undefined4 DAT_803dce78;
extern undefined4 DAT_803dce88;
extern undefined4 DAT_803dce90;
extern undefined4 DAT_803dce98;
extern undefined4 DAT_803dcea0;
extern undefined4 DAT_803dcea8;
extern undefined4 DAT_803dceb8;
extern undefined4 DAT_803dcec0;
extern undefined4 DAT_803dcec8;
extern undefined4 DAT_803dced0;
extern undefined4 DAT_803dced8;
extern undefined4 DAT_803dcee0;
extern undefined4 DAT_803dcee8;
extern undefined4 DAT_803dcef0;
extern undefined4 DAT_803dcef8;
extern undefined4 DAT_803dcf00;
extern undefined4 DAT_803dcf08;
extern undefined4 DAT_803dcf14;
extern undefined4 DAT_803dcf16;
extern undefined4 DAT_803dcf30;
extern undefined4 DAT_803dcf38;
extern undefined4 DAT_803dcf58;
extern undefined4 DAT_803dcf64;
extern undefined4 DAT_803dcf70;
extern undefined4 DAT_803dcf78;
extern undefined4 DAT_803dcf80;
extern undefined4 DAT_803dcf88;
extern undefined4 DAT_803dcf90;
extern short DAT_803dcf94;
extern undefined4 DAT_803dcf98;
extern undefined4 DAT_803dcfb0;
extern undefined4 DAT_803dcfb8;
extern undefined4 DAT_803dcfe8;
extern undefined4 DAT_803dd000;
extern undefined4 DAT_803dd014;
extern undefined4 DAT_803dd020;
extern undefined4 DAT_803dd028;
extern undefined4 DAT_803dd030;
extern undefined4 DAT_803dd048;
extern undefined4 DAT_803dd050;
extern undefined4 DAT_803dd058;
extern undefined4 DAT_803dd060;
extern undefined4 DAT_803dd068;
extern undefined4 DAT_803dd070;
extern undefined4 DAT_803dd078;
extern undefined4 DAT_803dd07c;
extern undefined4 DAT_803dd090;
extern undefined4 DAT_803dd094;
extern undefined4 DAT_803dd098;
extern undefined4 DAT_803dd09c;
extern undefined4 DAT_803dd0a0;
extern undefined4 DAT_803dd0a4;
extern undefined4 DAT_803dd0b4;
extern undefined4 DAT_803dd0b8;
extern undefined4 DAT_803dd0c8;
extern undefined4 DAT_803dd0cc;
extern undefined4 DAT_803dd0d4;
extern undefined4 DAT_803dd0ec;
extern undefined4 DAT_803dd0f4;
extern undefined4 DAT_803dd124;
extern undefined4 DAT_803dd126;
extern undefined4 DAT_803dd130;
extern undefined4 DAT_803dd134;
extern undefined4 DAT_803dd140;
extern undefined4 DAT_803dd144;
extern undefined4 DAT_803dd148;
extern undefined4 DAT_803dd150;
extern undefined4 DAT_803dd154;
extern undefined4 DAT_803dd164;
extern undefined4 DAT_803dd168;
extern undefined4 DAT_803dd16c;
extern undefined4 DAT_803dd170;
extern undefined4 DAT_803dd174;
extern undefined4 DAT_803dd178;
extern undefined4 DAT_803dd4e8;
extern undefined4 DAT_803dd5e8;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de984;
extern undefined4 DAT_803de988;
extern undefined4 DAT_803de98a;
extern undefined4 DAT_803de98c;
extern undefined4 DAT_803de990;
extern undefined4 DAT_803de998;
extern undefined4 DAT_803de99c;
extern undefined4 DAT_803de9a0;
extern undefined4 DAT_803de9a4;
extern undefined4 DAT_803de9a8;
extern undefined4 DAT_803de9b0;
extern undefined4 DAT_803de9b4;
extern undefined4 DAT_803de9b8;
extern undefined4 DAT_803de9c0;
extern undefined4* DAT_803de9c8;
extern undefined4 DAT_803de9cc;
extern undefined4 DAT_803de9d0;
extern undefined4* DAT_803de9d4;
extern undefined4 DAT_803de9d8;
extern undefined4 DAT_803de9e0;
extern undefined4 DAT_803de9f0;
extern undefined4 DAT_803de9f8;
extern undefined4* DAT_803dea00;
extern undefined4 DAT_803dea08;
extern undefined4 DAT_803dea10;
extern undefined4 DAT_803dea14;
extern undefined4 DAT_803dea18;
extern undefined4 DAT_803dea28;
extern undefined4 DAT_803dea3c;
extern undefined4 DAT_803dea40;
extern undefined4 DAT_803dea44;
extern undefined4 DAT_803dea46;
extern undefined4 DAT_803dea48;
extern undefined4 DAT_803dea4a;
extern undefined4 DAT_803dea50;
extern undefined4 DAT_803e7448;
extern undefined4 DAT_803e7738;
extern undefined4 DAT_803e7970;
extern undefined4 DAT_803e7df8;
extern f64 DOUBLE_803e7188;
extern f64 DOUBLE_803e71c0;
extern f64 DOUBLE_803e7218;
extern f64 DOUBLE_803e7238;
extern f64 DOUBLE_803e7250;
extern f64 DOUBLE_803e7270;
extern f64 DOUBLE_803e72a8;
extern f64 DOUBLE_803e72d0;
extern f64 DOUBLE_803e7308;
extern f64 DOUBLE_803e7358;
extern f64 DOUBLE_803e7398;
extern f64 DOUBLE_803e73b0;
extern f64 DOUBLE_803e7428;
extern f64 DOUBLE_803e7478;
extern f64 DOUBLE_803e7498;
extern f64 DOUBLE_803e74f8;
extern f64 DOUBLE_803e7500;
extern f64 DOUBLE_803e7520;
extern f64 DOUBLE_803e7528;
extern f64 DOUBLE_803e7540;
extern f64 DOUBLE_803e7560;
extern f64 DOUBLE_803e7568;
extern f64 DOUBLE_803e7570;
extern f64 DOUBLE_803e75c8;
extern f64 DOUBLE_803e7608;
extern f64 DOUBLE_803e7618;
extern f64 DOUBLE_803e7648;
extern f64 DOUBLE_803e76b8;
extern f64 DOUBLE_803e76f8;
extern f64 DOUBLE_803e7700;
extern f64 DOUBLE_803e7768;
extern f64 DOUBLE_803e7790;
extern f64 DOUBLE_803e7838;
extern f64 DOUBLE_803e78e0;
extern f64 DOUBLE_803e78e8;
extern f64 DOUBLE_803e7960;
extern f64 DOUBLE_803e7998;
extern f64 DOUBLE_803e79e0;
extern f64 DOUBLE_803e7a30;
extern f64 DOUBLE_803e7a60;
extern f64 DOUBLE_803e7aa0;
extern f64 DOUBLE_803e7ae8;
extern f64 DOUBLE_803e7b18;
extern f64 DOUBLE_803e7b20;
extern f64 DOUBLE_803e7b58;
extern f64 DOUBLE_803e7b78;
extern f64 DOUBLE_803e7b80;
extern f64 DOUBLE_803e7be0;
extern f64 DOUBLE_803e7be8;
extern f64 DOUBLE_803e7cb8;
extern f64 DOUBLE_803e7ce8;
extern f64 DOUBLE_803e7d00;
extern f64 DOUBLE_803e7d08;
extern f64 DOUBLE_803e7d28;
extern f64 DOUBLE_803e7d30;
extern f64 DOUBLE_803e7d68;
extern f64 DOUBLE_803e7d90;
extern f64 DOUBLE_803e7da8;
extern f64 DOUBLE_803e7dc0;
extern f64 DOUBLE_803e7dc8;
extern f64 DOUBLE_803e7de0;
extern f64 DOUBLE_803e7df0;
extern f64 DOUBLE_803e7e10;
extern f64 DOUBLE_803e7e18;
extern f64 DOUBLE_803e7ea0;
extern f64 DOUBLE_803e7ea8;
extern f64 DOUBLE_803e7ec0;
extern f64 DOUBLE_803e7ed0;
extern f64 DOUBLE_803e7ee0;
extern f64 DOUBLE_803e7ef0;
extern f64 DOUBLE_803e7f00;
extern f64 DOUBLE_803e7f10;
extern f64 DOUBLE_803e7f18;
extern f64 DOUBLE_803e7f38;
extern f64 DOUBLE_803e7f40;
extern f64 DOUBLE_803e7f70;
extern f64 DOUBLE_803e7f78;
extern f64 DOUBLE_803e7f98;
extern f64 DOUBLE_803e7fc8;
extern f64 DOUBLE_803e7fe0;
extern f64 DOUBLE_803e7fe8;
extern f64 DOUBLE_803e7ff0;
extern f64 DOUBLE_803e8038;
extern f64 DOUBLE_803e8060;
extern f64 DOUBLE_803e8088;
extern f64 DOUBLE_803e8090;
extern f64 DOUBLE_803e80a8;
extern f64 DOUBLE_803e80c0;
extern f64 DOUBLE_803e80d0;
extern f64 DOUBLE_803e80e0;
extern f64 DOUBLE_803e8130;
extern f64 DOUBLE_803e81d8;
extern f64 DOUBLE_803e8200;
extern f64 DOUBLE_803e8208;
extern f64 DOUBLE_803e8220;
extern f64 DOUBLE_803e8238;
extern f64 DOUBLE_803e8268;
extern f64 DOUBLE_803e8280;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803dcdf0;
extern f32 FLOAT_803dcdf4;
extern f32 FLOAT_803dcdf8;
extern f32 FLOAT_803dcdfc;
extern f32 FLOAT_803dce18;
extern f32 FLOAT_803dce84;
extern f32 FLOAT_803dce8c;
extern f32 FLOAT_803dce9c;
extern f32 FLOAT_803dcea4;
extern f32 FLOAT_803dceac;
extern f32 FLOAT_803dceb0;
extern f32 FLOAT_803dceb4;
extern f32 FLOAT_803dcf10;
extern f32 FLOAT_803dcf18;
extern f32 FLOAT_803dcf1c;
extern f32 FLOAT_803dcf20;
extern f32 FLOAT_803dcf24;
extern f32 FLOAT_803dcf60;
extern f32 FLOAT_803dcf68;
extern f32 FLOAT_803dcf6c;
extern f32 FLOAT_803dcf8c;
extern f32 FLOAT_803dcfa8;
extern f32 FLOAT_803dcfac;
extern f32 FLOAT_803dcfb4;
extern f32 FLOAT_803dd008;
extern f32 FLOAT_803dd00c;
extern f32 FLOAT_803dd010;
extern f32 FLOAT_803dd018;
extern f32 FLOAT_803dd01c;
extern f32 FLOAT_803dd038;
extern f32 FLOAT_803dd03c;
extern f32 FLOAT_803dd040;
extern f32 FLOAT_803dd080;
extern f32 FLOAT_803dd084;
extern f32 FLOAT_803dd0a8;
extern f32 FLOAT_803dd0ac;
extern f32 FLOAT_803dd0b0;
extern f32 FLOAT_803dd0bc;
extern f32 FLOAT_803dd0c0;
extern f32 FLOAT_803dd0c4;
extern f32 FLOAT_803dd0d0;
extern f32 FLOAT_803dd0d8;
extern f32 FLOAT_803dd0dc;
extern f32 FLOAT_803dd0e0;
extern f32 FLOAT_803dd0e4;
extern f32 FLOAT_803dd0e8;
extern f32 FLOAT_803dd0f0;
extern f32 FLOAT_803dd0f8;
extern f32 FLOAT_803dd0fc;
extern f32 FLOAT_803dd100;
extern f32 FLOAT_803dd104;
extern f32 FLOAT_803dd108;
extern f32 FLOAT_803dd10c;
extern f32 FLOAT_803dd110;
extern f32 FLOAT_803dd114;
extern f32 FLOAT_803dd118;
extern f32 FLOAT_803dd11c;
extern f32 FLOAT_803dd120;
extern f32 FLOAT_803dd128;
extern f32 FLOAT_803dd12c;
extern f32 FLOAT_803dd138;
extern f32 FLOAT_803dd13c;
extern f32 FLOAT_803dd14c;
extern f32 FLOAT_803dd158;
extern f32 FLOAT_803dd15c;
extern f32 FLOAT_803dd160;
extern f32 FLOAT_803dd180;
extern f32 FLOAT_803dd184;
extern f32 FLOAT_803dd188;
extern f32 FLOAT_803dd18c;
extern f32 FLOAT_803dd190;
extern f32 FLOAT_803dd194;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803de980;
extern f32 FLOAT_803de994;
extern f32 FLOAT_803de9ac;
extern f32 FLOAT_803de9e8;
extern f32 FLOAT_803dea1c;
extern f32 FLOAT_803dea20;
extern f32 FLOAT_803dea2c;
extern f32 FLOAT_803dea30;
extern f32 FLOAT_803dea38;
extern f32 FLOAT_803e7178;
extern f32 FLOAT_803e717c;
extern f32 FLOAT_803e7180;
extern f32 FLOAT_803e7190;
extern f32 FLOAT_803e7194;
extern f32 FLOAT_803e7198;
extern f32 FLOAT_803e719c;
extern f32 FLOAT_803e71a0;
extern f32 FLOAT_803e71a4;
extern f32 FLOAT_803e71a8;
extern f32 FLOAT_803e71ac;
extern f32 FLOAT_803e71b0;
extern f32 FLOAT_803e71b4;
extern f32 FLOAT_803e71b8;
extern f32 FLOAT_803e71c8;
extern f32 FLOAT_803e71cc;
extern f32 FLOAT_803e71d0;
extern f32 FLOAT_803e71d4;
extern f32 FLOAT_803e71d8;
extern f32 FLOAT_803e71dc;
extern f32 FLOAT_803e71e0;
extern f32 FLOAT_803e71e4;
extern f32 FLOAT_803e71e8;
extern f32 FLOAT_803e71f0;
extern f32 FLOAT_803e71f4;
extern f32 FLOAT_803e71f8;
extern f32 FLOAT_803e71fc;
extern f32 FLOAT_803e7200;
extern f32 FLOAT_803e7204;
extern f32 FLOAT_803e7208;
extern f32 FLOAT_803e720c;
extern f32 FLOAT_803e7210;
extern f32 FLOAT_803e7214;
extern f32 FLOAT_803e7224;
extern f32 FLOAT_803e7228;
extern f32 FLOAT_803e722c;
extern f32 FLOAT_803e7240;
extern f32 FLOAT_803e7244;
extern f32 FLOAT_803e7248;
extern f32 FLOAT_803e7258;
extern f32 FLOAT_803e725c;
extern f32 FLOAT_803e7260;
extern f32 FLOAT_803e7278;
extern f32 FLOAT_803e727c;
extern f32 FLOAT_803e7280;
extern f32 FLOAT_803e7284;
extern f32 FLOAT_803e7288;
extern f32 FLOAT_803e7290;
extern f32 FLOAT_803e7294;
extern f32 FLOAT_803e7298;
extern f32 FLOAT_803e729c;
extern f32 FLOAT_803e72a0;
extern f32 FLOAT_803e72b0;
extern f32 FLOAT_803e72b4;
extern f32 FLOAT_803e72b8;
extern f32 FLOAT_803e72bc;
extern f32 FLOAT_803e72c0;
extern f32 FLOAT_803e72c4;
extern f32 FLOAT_803e72c8;
extern f32 FLOAT_803e72d8;
extern f32 FLOAT_803e72dc;
extern f32 FLOAT_803e72e0;
extern f32 FLOAT_803e72e4;
extern f32 FLOAT_803e72e8;
extern f32 FLOAT_803e72ec;
extern f32 FLOAT_803e72f0;
extern f32 FLOAT_803e72f4;
extern f32 FLOAT_803e72f8;
extern f32 FLOAT_803e72fc;
extern f32 FLOAT_803e7300;
extern f32 FLOAT_803e7304;
extern f32 FLOAT_803e7310;
extern f32 FLOAT_803e7314;
extern f32 FLOAT_803e7320;
extern f32 FLOAT_803e7324;
extern f32 FLOAT_803e7328;
extern f32 FLOAT_803e732c;
extern f32 FLOAT_803e7330;
extern f32 FLOAT_803e7334;
extern f32 FLOAT_803e7338;
extern f32 FLOAT_803e733c;
extern f32 FLOAT_803e7340;
extern f32 FLOAT_803e7344;
extern f32 FLOAT_803e7348;
extern f32 FLOAT_803e734c;
extern f32 FLOAT_803e7350;
extern f32 FLOAT_803e7360;
extern f32 FLOAT_803e7364;
extern f32 FLOAT_803e7368;
extern f32 FLOAT_803e736c;
extern f32 FLOAT_803e7370;
extern f32 FLOAT_803e7378;
extern f32 FLOAT_803e737c;
extern f32 FLOAT_803e7380;
extern f32 FLOAT_803e7384;
extern f32 FLOAT_803e7388;
extern f32 FLOAT_803e738c;
extern f32 FLOAT_803e7390;
extern f32 FLOAT_803e73a0;
extern f32 FLOAT_803e73a4;
extern f32 FLOAT_803e73a8;
extern f32 FLOAT_803e73b8;
extern f32 FLOAT_803e73bc;
extern f32 FLOAT_803e73c0;
extern f32 FLOAT_803e73cc;
extern f32 FLOAT_803e73d0;
extern f32 FLOAT_803e73d8;
extern f32 FLOAT_803e73dc;
extern f32 FLOAT_803e73f0;
extern f32 FLOAT_803e73f8;
extern f32 FLOAT_803e7400;
extern f32 FLOAT_803e7404;
extern f32 FLOAT_803e7408;
extern f32 FLOAT_803e740c;
extern f32 FLOAT_803e7410;
extern f32 FLOAT_803e7414;
extern f32 FLOAT_803e7418;
extern f32 FLOAT_803e741c;
extern f32 FLOAT_803e7420;
extern f32 FLOAT_803e7430;
extern f32 FLOAT_803e7434;
extern f32 FLOAT_803e743c;
extern f32 FLOAT_803e7440;
extern f32 FLOAT_803e744c;
extern f32 FLOAT_803e7450;
extern f32 FLOAT_803e7454;
extern f32 FLOAT_803e7458;
extern f32 FLOAT_803e745c;
extern f32 FLOAT_803e7460;
extern f32 FLOAT_803e7464;
extern f32 FLOAT_803e7468;
extern f32 FLOAT_803e746c;
extern f32 FLOAT_803e7470;
extern f32 FLOAT_803e7480;
extern f32 FLOAT_803e7484;
extern f32 FLOAT_803e7488;
extern f32 FLOAT_803e748c;
extern f32 FLOAT_803e7490;
extern f32 FLOAT_803e74a0;
extern f32 FLOAT_803e74a4;
extern f32 FLOAT_803e74a8;
extern f32 FLOAT_803e74ac;
extern f32 FLOAT_803e74b0;
extern f32 FLOAT_803e74b4;
extern f32 FLOAT_803e74b8;
extern f32 FLOAT_803e74bc;
extern f32 FLOAT_803e74c4;
extern f32 FLOAT_803e74c8;
extern f32 FLOAT_803e74cc;
extern f32 FLOAT_803e74d0;
extern f32 FLOAT_803e74d4;
extern f32 FLOAT_803e74d8;
extern f32 FLOAT_803e74dc;
extern f32 FLOAT_803e74e0;
extern f32 FLOAT_803e74e4;
extern f32 FLOAT_803e74e8;
extern f32 FLOAT_803e7508;
extern f32 FLOAT_803e750c;
extern f32 FLOAT_803e7510;
extern f32 FLOAT_803e7514;
extern f32 FLOAT_803e7518;
extern f32 FLOAT_803e7530;
extern f32 FLOAT_803e7534;
extern f32 FLOAT_803e7538;
extern f32 FLOAT_803e753c;
extern f32 FLOAT_803e7548;
extern f32 FLOAT_803e754c;
extern f32 FLOAT_803e7550;
extern f32 FLOAT_803e7554;
extern f32 FLOAT_803e7558;
extern f32 FLOAT_803e7578;
extern f32 FLOAT_803e757c;
extern f32 FLOAT_803e7584;
extern f32 FLOAT_803e758c;
extern f32 FLOAT_803e7590;
extern f32 FLOAT_803e7594;
extern f32 FLOAT_803e7598;
extern f32 FLOAT_803e759c;
extern f32 FLOAT_803e75a0;
extern f32 FLOAT_803e75a4;
extern f32 FLOAT_803e75a8;
extern f32 FLOAT_803e75ac;
extern f32 FLOAT_803e75b0;
extern f32 FLOAT_803e75b4;
extern f32 FLOAT_803e75b8;
extern f32 FLOAT_803e75bc;
extern f32 FLOAT_803e75d0;
extern f32 FLOAT_803e75d8;
extern f32 FLOAT_803e75dc;
extern f32 FLOAT_803e75e0;
extern f32 FLOAT_803e75e4;
extern f32 FLOAT_803e75e8;
extern f32 FLOAT_803e75ec;
extern f32 FLOAT_803e75f0;
extern f32 FLOAT_803e75f4;
extern f32 FLOAT_803e75f8;
extern f32 FLOAT_803e7600;
extern f32 FLOAT_803e7620;
extern f32 FLOAT_803e7624;
extern f32 FLOAT_803e7628;
extern f32 FLOAT_803e7630;
extern f32 FLOAT_803e7634;
extern f32 FLOAT_803e7638;
extern f32 FLOAT_803e7640;
extern f32 FLOAT_803e7650;
extern f32 FLOAT_803e7654;
extern f32 FLOAT_803e7660;
extern f32 FLOAT_803e767c;
extern f32 FLOAT_803e7680;
extern f32 FLOAT_803e7688;
extern f32 FLOAT_803e768c;
extern f32 FLOAT_803e7690;
extern f32 FLOAT_803e7694;
extern f32 FLOAT_803e7698;
extern f32 FLOAT_803e769c;
extern f32 FLOAT_803e76a0;
extern f32 FLOAT_803e76a4;
extern f32 FLOAT_803e76a8;
extern f32 FLOAT_803e76ac;
extern f32 FLOAT_803e76b0;
extern f32 FLOAT_803e76b4;
extern f32 FLOAT_803e76c0;
extern f32 FLOAT_803e76c8;
extern f32 FLOAT_803e76d0;
extern f32 FLOAT_803e76d4;
extern f32 FLOAT_803e76d8;
extern f32 FLOAT_803e76e0;
extern f32 FLOAT_803e76e4;
extern f32 FLOAT_803e76e8;
extern f32 FLOAT_803e76ec;
extern f32 FLOAT_803e7708;
extern f32 FLOAT_803e770c;
extern f32 FLOAT_803e7710;
extern f32 FLOAT_803e7714;
extern f32 FLOAT_803e7718;
extern f32 FLOAT_803e771c;
extern f32 FLOAT_803e7720;
extern f32 FLOAT_803e7724;
extern f32 FLOAT_803e7728;
extern f32 FLOAT_803e772c;
extern f32 FLOAT_803e7730;
extern f32 FLOAT_803e7734;
extern f32 FLOAT_803e773c;
extern f32 FLOAT_803e7740;
extern f32 FLOAT_803e7744;
extern f32 FLOAT_803e7748;
extern f32 FLOAT_803e774c;
extern f32 FLOAT_803e7750;
extern f32 FLOAT_803e7754;
extern f32 FLOAT_803e7758;
extern f32 FLOAT_803e775c;
extern f32 FLOAT_803e7760;
extern f32 FLOAT_803e7770;
extern f32 FLOAT_803e7774;
extern f32 FLOAT_803e7778;
extern f32 FLOAT_803e777c;
extern f32 FLOAT_803e7780;
extern f32 FLOAT_803e7784;
extern f32 FLOAT_803e7788;
extern f32 FLOAT_803e7798;
extern f32 FLOAT_803e779c;
extern f32 FLOAT_803e77a0;
extern f32 FLOAT_803e77a4;
extern f32 FLOAT_803e77a8;
extern f32 FLOAT_803e77ac;
extern f32 FLOAT_803e77b8;
extern f32 FLOAT_803e77bc;
extern f32 FLOAT_803e77c0;
extern f32 FLOAT_803e77c4;
extern f32 FLOAT_803e77c8;
extern f32 FLOAT_803e77d0;
extern f32 FLOAT_803e77d4;
extern f32 FLOAT_803e77dc;
extern f32 FLOAT_803e77e0;
extern f32 FLOAT_803e77e4;
extern f32 FLOAT_803e77e8;
extern f32 FLOAT_803e77ec;
extern f32 FLOAT_803e77f8;
extern f32 FLOAT_803e77fc;
extern f32 FLOAT_803e7800;
extern f32 FLOAT_803e7804;
extern f32 FLOAT_803e7808;
extern f32 FLOAT_803e780c;
extern f32 FLOAT_803e7810;
extern f32 FLOAT_803e7814;
extern f32 FLOAT_803e7818;
extern f32 FLOAT_803e781c;
extern f32 FLOAT_803e7820;
extern f32 FLOAT_803e7824;
extern f32 FLOAT_803e7828;
extern f32 FLOAT_803e782c;
extern f32 FLOAT_803e7830;
extern f32 FLOAT_803e7840;
extern f32 FLOAT_803e7848;
extern f32 FLOAT_803e7850;
extern f32 FLOAT_803e7854;
extern f32 FLOAT_803e7858;
extern f32 FLOAT_803e7864;
extern f32 FLOAT_803e7868;
extern f32 FLOAT_803e786c;
extern f32 FLOAT_803e7870;
extern f32 FLOAT_803e7874;
extern f32 FLOAT_803e7878;
extern f32 FLOAT_803e787c;
extern f32 FLOAT_803e7880;
extern f32 FLOAT_803e7890;
extern f32 FLOAT_803e78a0;
extern f32 FLOAT_803e78a4;
extern f32 FLOAT_803e78a8;
extern f32 FLOAT_803e78ac;
extern f32 FLOAT_803e78b0;
extern f32 FLOAT_803e78b4;
extern f32 FLOAT_803e78bc;
extern f32 FLOAT_803e78c0;
extern f32 FLOAT_803e78c4;
extern f32 FLOAT_803e78c8;
extern f32 FLOAT_803e78cc;
extern f32 FLOAT_803e78d0;
extern f32 FLOAT_803e78d4;
extern f32 FLOAT_803e78d8;
extern f32 FLOAT_803e78dc;
extern f32 FLOAT_803e78f0;
extern f32 FLOAT_803e78f4;
extern f32 FLOAT_803e78fc;
extern f32 FLOAT_803e7904;
extern f32 FLOAT_803e7908;
extern f32 FLOAT_803e790c;
extern f32 FLOAT_803e7910;
extern f32 FLOAT_803e7914;
extern f32 FLOAT_803e7918;
extern f32 FLOAT_803e791c;
extern f32 FLOAT_803e7920;
extern f32 FLOAT_803e7924;
extern f32 FLOAT_803e7928;
extern f32 FLOAT_803e792c;
extern f32 FLOAT_803e7930;
extern f32 FLOAT_803e7938;
extern f32 FLOAT_803e793c;
extern f32 FLOAT_803e7940;
extern f32 FLOAT_803e7944;
extern f32 FLOAT_803e7948;
extern f32 FLOAT_803e794c;
extern f32 FLOAT_803e7950;
extern f32 FLOAT_803e7954;
extern f32 FLOAT_803e7958;
extern f32 FLOAT_803e7968;
extern f32 FLOAT_803e7974;
extern f32 FLOAT_803e797c;
extern f32 FLOAT_803e7980;
extern f32 FLOAT_803e7988;
extern f32 FLOAT_803e798c;
extern f32 FLOAT_803e7990;
extern f32 FLOAT_803e79a0;
extern f32 FLOAT_803e79a4;
extern f32 FLOAT_803e79a8;
extern f32 FLOAT_803e79b0;
extern f32 FLOAT_803e79b4;
extern f32 FLOAT_803e79b8;
extern f32 FLOAT_803e79bc;
extern f32 FLOAT_803e79c0;
extern f32 FLOAT_803e79c4;
extern f32 FLOAT_803e79c8;
extern f32 FLOAT_803e79cc;
extern f32 FLOAT_803e79d0;
extern f32 FLOAT_803e79d4;
extern f32 FLOAT_803e79d8;
extern f32 FLOAT_803e79e8;
extern f32 FLOAT_803e79ec;
extern f32 FLOAT_803e79f0;
extern f32 FLOAT_803e79f4;
extern f32 FLOAT_803e79f8;
extern f32 FLOAT_803e79fc;
extern f32 FLOAT_803e7a00;
extern f32 FLOAT_803e7a04;
extern f32 FLOAT_803e7a08;
extern f32 FLOAT_803e7a0c;
extern f32 FLOAT_803e7a10;
extern f32 FLOAT_803e7a14;
extern f32 FLOAT_803e7a18;
extern f32 FLOAT_803e7a1c;
extern f32 FLOAT_803e7a20;
extern f32 FLOAT_803e7a24;
extern f32 FLOAT_803e7a38;
extern f32 FLOAT_803e7a40;
extern f32 FLOAT_803e7a44;
extern f32 FLOAT_803e7a48;
extern f32 FLOAT_803e7a4c;
extern f32 FLOAT_803e7a50;
extern f32 FLOAT_803e7a54;
extern f32 FLOAT_803e7a58;
extern f32 FLOAT_803e7a68;
extern f32 FLOAT_803e7a6c;
extern f32 FLOAT_803e7a74;
extern f32 FLOAT_803e7a7c;
extern f32 FLOAT_803e7a80;
extern f32 FLOAT_803e7a8c;
extern f32 FLOAT_803e7a90;
extern f32 FLOAT_803e7a94;
extern f32 FLOAT_803e7a9c;
extern f32 FLOAT_803e7aac;
extern f32 FLOAT_803e7abc;
extern f32 FLOAT_803e7ac0;
extern f32 FLOAT_803e7ac4;
extern f32 FLOAT_803e7ac8;
extern f32 FLOAT_803e7acc;
extern f32 FLOAT_803e7ad0;
extern f32 FLOAT_803e7ad4;
extern f32 FLOAT_803e7ad8;
extern f32 FLOAT_803e7ae0;
extern f32 FLOAT_803e7af4;
extern f32 FLOAT_803e7af8;
extern f32 FLOAT_803e7afc;
extern f32 FLOAT_803e7b00;
extern f32 FLOAT_803e7b0c;
extern f32 FLOAT_803e7b2c;
extern f32 FLOAT_803e7b30;
extern f32 FLOAT_803e7b34;
extern f32 FLOAT_803e7b38;
extern f32 FLOAT_803e7b3c;
extern f32 FLOAT_803e7b40;
extern f32 FLOAT_803e7b44;
extern f32 FLOAT_803e7b48;
extern f32 FLOAT_803e7b4c;
extern f32 FLOAT_803e7b50;
extern f32 FLOAT_803e7b54;
extern f32 FLOAT_803e7b60;
extern f32 FLOAT_803e7b64;
extern f32 FLOAT_803e7b68;
extern f32 FLOAT_803e7b6c;
extern f32 FLOAT_803e7b70;
extern f32 FLOAT_803e7b88;
extern f32 FLOAT_803e7b8c;
extern f32 FLOAT_803e7b90;
extern f32 FLOAT_803e7b9c;
extern f32 FLOAT_803e7ba0;
extern f32 FLOAT_803e7ba4;
extern f32 FLOAT_803e7ba8;
extern f32 FLOAT_803e7bac;
extern f32 FLOAT_803e7bb0;
extern f32 FLOAT_803e7bb4;
extern f32 FLOAT_803e7bb8;
extern f32 FLOAT_803e7bbc;
extern f32 FLOAT_803e7bc0;
extern f32 FLOAT_803e7bc4;
extern f32 FLOAT_803e7bc8;
extern f32 FLOAT_803e7bcc;
extern f32 FLOAT_803e7bd0;
extern f32 FLOAT_803e7bd4;
extern f32 FLOAT_803e7bd8;
extern f32 FLOAT_803e7bf0;
extern f32 FLOAT_803e7bf4;
extern f32 FLOAT_803e7bf8;
extern f32 FLOAT_803e7bfc;
extern f32 FLOAT_803e7c00;
extern f32 FLOAT_803e7c04;
extern f32 FLOAT_803e7c08;
extern f32 FLOAT_803e7c0c;
extern f32 FLOAT_803e7c10;
extern f32 FLOAT_803e7c14;
extern f32 FLOAT_803e7c18;
extern f32 FLOAT_803e7c1c;
extern f32 FLOAT_803e7c20;
extern f32 FLOAT_803e7c24;
extern f32 FLOAT_803e7c28;
extern f32 FLOAT_803e7c2c;
extern f32 FLOAT_803e7c30;
extern f32 FLOAT_803e7c34;
extern f32 FLOAT_803e7c38;
extern f32 FLOAT_803e7c3c;
extern f32 FLOAT_803e7c40;
extern f32 FLOAT_803e7c44;
extern f32 FLOAT_803e7c48;
extern f32 FLOAT_803e7c4c;
extern f32 FLOAT_803e7c50;
extern f32 FLOAT_803e7c54;
extern f32 FLOAT_803e7c58;
extern f32 FLOAT_803e7c5c;
extern f32 FLOAT_803e7c60;
extern f32 FLOAT_803e7c64;
extern f32 FLOAT_803e7c68;
extern f32 FLOAT_803e7c6c;
extern f32 FLOAT_803e7c70;
extern f32 FLOAT_803e7c74;
extern f32 FLOAT_803e7c78;
extern f32 FLOAT_803e7c7c;
extern f32 FLOAT_803e7c80;
extern f32 FLOAT_803e7c84;
extern f32 FLOAT_803e7c88;
extern f32 FLOAT_803e7c8c;
extern f32 FLOAT_803e7c90;
extern f32 FLOAT_803e7c94;
extern f32 FLOAT_803e7c98;
extern f32 FLOAT_803e7ca0;
extern f32 FLOAT_803e7ca4;
extern f32 FLOAT_803e7ca8;
extern f32 FLOAT_803e7cac;
extern f32 FLOAT_803e7cb0;
extern f32 FLOAT_803e7cb4;
extern f32 FLOAT_803e7cc0;
extern f32 FLOAT_803e7cc4;
extern f32 FLOAT_803e7cd0;
extern f32 FLOAT_803e7cd4;
extern f32 FLOAT_803e7cd8;
extern f32 FLOAT_803e7cdc;
extern f32 FLOAT_803e7ce0;
extern f32 FLOAT_803e7ce4;
extern f32 FLOAT_803e7cf0;
extern f32 FLOAT_803e7cf4;
extern f32 FLOAT_803e7cf8;
extern f32 FLOAT_803e7d14;
extern f32 FLOAT_803e7d18;
extern f32 FLOAT_803e7d1c;
extern f32 FLOAT_803e7d20;
extern f32 FLOAT_803e7d24;
extern f32 FLOAT_803e7d38;
extern f32 FLOAT_803e7d3c;
extern f32 FLOAT_803e7d40;
extern f32 FLOAT_803e7d44;
extern f32 FLOAT_803e7d4c;
extern f32 FLOAT_803e7d50;
extern f32 FLOAT_803e7d54;
extern f32 FLOAT_803e7d58;
extern f32 FLOAT_803e7d5c;
extern f32 FLOAT_803e7d70;
extern f32 FLOAT_803e7d78;
extern f32 FLOAT_803e7d7c;
extern f32 FLOAT_803e7d80;
extern f32 FLOAT_803e7d84;
extern f32 FLOAT_803e7d88;
extern f32 FLOAT_803e7d8c;
extern f32 FLOAT_803e7d9c;
extern f32 FLOAT_803e7da0;
extern f32 FLOAT_803e7da4;
extern f32 FLOAT_803e7db4;
extern f32 FLOAT_803e7db8;
extern f32 FLOAT_803e7dbc;
extern f32 FLOAT_803e7dd4;
extern f32 FLOAT_803e7dd8;
extern f32 FLOAT_803e7dec;
extern f32 FLOAT_803e7dfc;
extern f32 FLOAT_803e7e00;
extern f32 FLOAT_803e7e04;
extern f32 FLOAT_803e7e08;
extern f32 FLOAT_803e7e20;
extern f32 FLOAT_803e7e24;
extern f32 FLOAT_803e7e28;
extern f32 FLOAT_803e7e34;
extern f32 FLOAT_803e7e38;
extern f32 FLOAT_803e7e3c;
extern f32 FLOAT_803e7e40;
extern f32 FLOAT_803e7e44;
extern f32 FLOAT_803e7e48;
extern f32 FLOAT_803e7e4c;
extern f32 FLOAT_803e7e50;
extern f32 FLOAT_803e7e54;
extern f32 FLOAT_803e7e58;
extern f32 FLOAT_803e7e5c;
extern f32 FLOAT_803e7e60;
extern f32 FLOAT_803e7e64;
extern f32 FLOAT_803e7e68;
extern f32 FLOAT_803e7e6c;
extern f32 FLOAT_803e7e70;
extern f32 FLOAT_803e7e74;
extern f32 FLOAT_803e7e78;
extern f32 FLOAT_803e7e80;
extern f32 FLOAT_803e7e84;
extern f32 FLOAT_803e7e88;
extern f32 FLOAT_803e7e8c;
extern f32 FLOAT_803e7e90;
extern f32 FLOAT_803e7e94;
extern f32 FLOAT_803e7e98;
extern f32 FLOAT_803e7eb4;
extern f32 FLOAT_803e7eb8;
extern f32 FLOAT_803e7ec8;
extern f32 FLOAT_803e7ecc;
extern f32 FLOAT_803e7ed8;
extern f32 FLOAT_803e7ee8;
extern f32 FLOAT_803e7eec;
extern f32 FLOAT_803e7ef8;
extern f32 FLOAT_803e7f08;
extern f32 FLOAT_803e7f0c;
extern f32 FLOAT_803e7f20;
extern f32 FLOAT_803e7f24;
extern f32 FLOAT_803e7f28;
extern f32 FLOAT_803e7f2c;
extern f32 FLOAT_803e7f30;
extern f32 FLOAT_803e7f48;
extern f32 FLOAT_803e7f4c;
extern f32 FLOAT_803e7f50;
extern f32 FLOAT_803e7f54;
extern f32 FLOAT_803e7f58;
extern f32 FLOAT_803e7f64;
extern f32 FLOAT_803e7f68;
extern f32 FLOAT_803e7f6c;
extern f32 FLOAT_803e7f80;
extern f32 FLOAT_803e7f84;
extern f32 FLOAT_803e7f88;
extern f32 FLOAT_803e7f8c;
extern f32 FLOAT_803e7f90;
extern f32 FLOAT_803e7fa0;
extern f32 FLOAT_803e7fa4;
extern f32 FLOAT_803e7fa8;
extern f32 FLOAT_803e7fb0;
extern f32 FLOAT_803e7fb4;
extern f32 FLOAT_803e7fb8;
extern f32 FLOAT_803e7fbc;
extern f32 FLOAT_803e7fc0;
extern f32 FLOAT_803e7fc4;
extern f32 FLOAT_803e7fd0;
extern f32 FLOAT_803e7fd4;
extern f32 FLOAT_803e7fd8;
extern f32 FLOAT_803e7ff8;
extern f32 FLOAT_803e7ffc;
extern f32 FLOAT_803e8000;
extern f32 FLOAT_803e8004;
extern f32 FLOAT_803e8008;
extern f32 FLOAT_803e800c;
extern f32 FLOAT_803e8010;
extern f32 FLOAT_803e8014;
extern f32 FLOAT_803e8018;
extern f32 FLOAT_803e801c;
extern f32 FLOAT_803e8020;
extern f32 FLOAT_803e8024;
extern f32 FLOAT_803e8028;
extern f32 FLOAT_803e802c;
extern f32 FLOAT_803e8030;
extern f32 FLOAT_803e8040;
extern f32 FLOAT_803e8044;
extern f32 FLOAT_803e8048;
extern f32 FLOAT_803e804c;
extern f32 FLOAT_803e8050;
extern f32 FLOAT_803e8054;
extern f32 FLOAT_803e8058;
extern f32 FLOAT_803e8068;
extern f32 FLOAT_803e806c;
extern f32 FLOAT_803e8070;
extern f32 FLOAT_803e8074;
extern f32 FLOAT_803e8078;
extern f32 FLOAT_803e807c;
extern f32 FLOAT_803e8080;
extern f32 FLOAT_803e8084;
extern f32 FLOAT_803e8098;
extern f32 FLOAT_803e809c;
extern f32 FLOAT_803e80a0;
extern f32 FLOAT_803e80b4;
extern f32 FLOAT_803e80b8;
extern f32 FLOAT_803e80bc;
extern f32 FLOAT_803e80d8;
extern f32 FLOAT_803e80e8;
extern f32 FLOAT_803e80ec;
extern f32 FLOAT_803e80f0;
extern f32 FLOAT_803e80f4;
extern f32 FLOAT_803e80f8;
extern f32 FLOAT_803e80fc;
extern f32 FLOAT_803e8100;
extern f32 FLOAT_803e8104;
extern f32 FLOAT_803e8108;
extern f32 FLOAT_803e810c;
extern f32 FLOAT_803e8110;
extern f32 FLOAT_803e8114;
extern f32 FLOAT_803e8118;
extern f32 FLOAT_803e811c;
extern f32 FLOAT_803e8120;
extern f32 FLOAT_803e8124;
extern f32 FLOAT_803e8128;
extern f32 FLOAT_803e8138;
extern f32 FLOAT_803e8140;
extern f32 FLOAT_803e8144;
extern f32 FLOAT_803e8148;
extern f32 FLOAT_803e814c;
extern f32 FLOAT_803e8150;
extern f32 FLOAT_803e8154;
extern f32 FLOAT_803e8158;
extern f32 FLOAT_803e815c;
extern f32 FLOAT_803e8160;
extern f32 FLOAT_803e8164;
extern f32 FLOAT_803e8168;
extern f32 FLOAT_803e816c;
extern f32 FLOAT_803e8170;
extern f32 FLOAT_803e8174;
extern f32 FLOAT_803e8178;
extern f32 FLOAT_803e817c;
extern f32 FLOAT_803e8180;
extern f32 FLOAT_803e8184;
extern f32 FLOAT_803e8188;
extern f32 FLOAT_803e818c;
extern f32 FLOAT_803e8190;
extern f32 FLOAT_803e8194;
extern f32 FLOAT_803e8198;
extern f32 FLOAT_803e819c;
extern f32 FLOAT_803e81a0;
extern f32 FLOAT_803e81a4;
extern f32 FLOAT_803e81a8;
extern f32 FLOAT_803e81ac;
extern f32 FLOAT_803e81b0;
extern f32 FLOAT_803e81b4;
extern f32 FLOAT_803e81b8;
extern f32 FLOAT_803e81bc;
extern f32 FLOAT_803e81c0;
extern f32 FLOAT_803e81c4;
extern f32 FLOAT_803e81c8;
extern f32 FLOAT_803e81cc;
extern f32 FLOAT_803e81d0;
extern f32 FLOAT_803e81d4;
extern f32 FLOAT_803e8210;
extern f32 FLOAT_803e8214;
extern f32 FLOAT_803e8218;
extern f32 FLOAT_803e821c;
extern f32 FLOAT_803e8228;
extern f32 FLOAT_803e822c;
extern f32 FLOAT_803e8230;
extern f32 FLOAT_803e8240;
extern f32 FLOAT_803e8244;
extern f32 FLOAT_803e8248;
extern f32 FLOAT_803e824c;
extern f32 FLOAT_803e8258;
extern f32 FLOAT_803e825c;
extern f32 FLOAT_803e8260;
extern f32 FLOAT_803e8270;
extern f32 FLOAT_803e8274;
extern f32 FLOAT_803e8278;
extern f32 FLOAT_803e8288;
extern f32 FLOAT_803e828c;
extern f32 FLOAT_803e8290;
extern f32 FLOAT_803e82a0;
extern f32 FLOAT_803e82a4;
extern void* PTR_DAT_8032cb50;
extern undefined bRam803dce5d;
extern undefined2 bRam803dce5e;
extern undefined bRam803dce61;
extern undefined2 bRam803dce62;
extern undefined bRam803dce65;
extern undefined2 bRam803dce66;
extern undefined bRam803dce69;
extern undefined2 bRam803dce6a;
extern undefined bRam803dce6d;
extern undefined2 bRam803dce6e;
extern undefined bRam803dce71;
extern undefined2 bRam803dce72;
extern undefined bRam803de9a5;
extern undefined2 bRam803de9a6;
extern undefined uRam803de99d;
extern undefined2 uRam803de99e;
extern undefined uRam803de9a1;
extern undefined2 uRam803de9a2;

/*
 * --INFO--
 *
 * Function: FUN_80209fe0
 * EN v1.0 Address: 0x80209FE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80209FE0
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209fe0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80209fe4
 * EN v1.0 Address: 0x80209FE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020A0B0
 * EN v1.1 Size: 888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209fe4(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80209fe8
 * EN v1.0 Address: 0x80209FE8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020A428
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209fe8(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80209fec
 * EN v1.0 Address: 0x80209FEC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8020A56C
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80209fec(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80209ff4
 * EN v1.0 Address: 0x80209FF4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020A620
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209ff4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80209ff8
 * EN v1.0 Address: 0x80209FF8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020A658
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209ff8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80209ffc
 * EN v1.0 Address: 0x80209FFC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020A6FC
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80209ffc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a000
 * EN v1.0 Address: 0x8020A000
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020A768
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a000(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a004
 * EN v1.0 Address: 0x8020A004
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020A800
 * EN v1.1 Size: 532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a004(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a008
 * EN v1.0 Address: 0x8020A008
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020AA14
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a008(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a00c
 * EN v1.0 Address: 0x8020A00C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8020AC20
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a00c(short *param_1,float *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a014
 * EN v1.0 Address: 0x8020A014
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020AD98
 * EN v1.1 Size: 888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a014(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a018
 * EN v1.0 Address: 0x8020A018
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020B110
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a018(undefined4 param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a01c
 * EN v1.0 Address: 0x8020A01C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020B3B0
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a01c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a020
 * EN v1.0 Address: 0x8020A020
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020B428
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a020(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a024
 * EN v1.0 Address: 0x8020A024
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020B55C
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a024(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a028
 * EN v1.0 Address: 0x8020A028
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020B750
 * EN v1.1 Size: 2216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a028(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a02c
 * EN v1.0 Address: 0x8020A02C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020BFF8
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a02c(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a030
 * EN v1.0 Address: 0x8020A030
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020C13C
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a030(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a034
 * EN v1.0 Address: 0x8020A034
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020C194
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a034(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a038
 * EN v1.0 Address: 0x8020A038
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020C228
 * EN v1.1 Size: 596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a038(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a03c
 * EN v1.0 Address: 0x8020A03C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020C47C
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a03c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a040
 * EN v1.0 Address: 0x8020A040
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020C71C
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a040(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a044
 * EN v1.0 Address: 0x8020A044
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020C904
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a044(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a048
 * EN v1.0 Address: 0x8020A048
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020C938
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a048(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a04c
 * EN v1.0 Address: 0x8020A04C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020CAC4
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a04c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a050
 * EN v1.0 Address: 0x8020A050
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020CC64
 * EN v1.1 Size: 904b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a050(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a054
 * EN v1.0 Address: 0x8020A054
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020CFEC
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a054(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a058
 * EN v1.0 Address: 0x8020A058
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020D010
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a058(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a05c
 * EN v1.0 Address: 0x8020A05C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020D044
 * EN v1.1 Size: 3136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a05c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,int param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a060
 * EN v1.0 Address: 0x8020A060
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020DC84
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a060(undefined4 param_1,undefined4 param_2,undefined *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a064
 * EN v1.0 Address: 0x8020A064
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020DE64
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a064(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a068
 * EN v1.0 Address: 0x8020A068
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020E05C
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a068(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a06c
 * EN v1.0 Address: 0x8020A06C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020E23C
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a06c(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5,
                 int param_6,undefined4 param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a070
 * EN v1.0 Address: 0x8020A070
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020E3B0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a070(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a074
 * EN v1.0 Address: 0x8020A074
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020E414
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a074(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a078
 * EN v1.0 Address: 0x8020A078
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020E620
 * EN v1.1 Size: 3392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a078(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a07c
 * EN v1.0 Address: 0x8020A07C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020F360
 * EN v1.1 Size: 1324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a07c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,short *param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a080
 * EN v1.0 Address: 0x8020A080
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020F88C
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a080(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a084
 * EN v1.0 Address: 0x8020A084
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020F9FC
 * EN v1.1 Size: 528b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a084(ushort *param_1,int param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a088
 * EN v1.0 Address: 0x8020A088
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020FC0C
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a088(undefined2 *param_1,undefined2 *param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,char param_7,int param_8,int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a08c
 * EN v1.0 Address: 0x8020A08C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8020FD58
 * EN v1.1 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a08c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a090
 * EN v1.0 Address: 0x8020A090
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80210178
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a090(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a094
 * EN v1.0 Address: 0x8020A094
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802101A4
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a094(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a098
 * EN v1.0 Address: 0x8020A098
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80210428
 * EN v1.1 Size: 900b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a098(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a09c
 * EN v1.0 Address: 0x8020A09C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802107AC
 * EN v1.1 Size: 1060b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a09c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 uint *param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0a0
 * EN v1.0 Address: 0x8020A0A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80210BD0
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0a0(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0a4
 * EN v1.0 Address: 0x8020A0A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80210D38
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0a4(undefined4 param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0a8
 * EN v1.0 Address: 0x8020A0A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80210E44
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0a8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0ac
 * EN v1.0 Address: 0x8020A0AC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80210FF8
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a0ac(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            undefined4 param_10,int param_11)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0b4
 * EN v1.0 Address: 0x8020A0B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802110E0
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0b4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0b8
 * EN v1.0 Address: 0x8020A0B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80211114
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0bc
 * EN v1.0 Address: 0x8020A0BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80211200
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0bc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0c0
 * EN v1.0 Address: 0x8020A0C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802112D0
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0c0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0c4
 * EN v1.0 Address: 0x8020A0C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802112F4
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0c4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0c8
 * EN v1.0 Address: 0x8020A0C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80211338
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0c8(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0cc
 * EN v1.0 Address: 0x8020A0CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802114AC
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0cc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0d0
 * EN v1.0 Address: 0x8020A0D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021151C
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0d0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0d4
 * EN v1.0 Address: 0x8020A0D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802115D0
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0d4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0d8
 * EN v1.0 Address: 0x8020A0D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802116AC
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0d8(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0dc
 * EN v1.0 Address: 0x8020A0DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80211770
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0dc(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0e0
 * EN v1.0 Address: 0x8020A0E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802118B4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0e0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0e4
 * EN v1.0 Address: 0x8020A0E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802118E8
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0e4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0e8
 * EN v1.0 Address: 0x8020A0E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802119B4
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0e8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0ec
 * EN v1.0 Address: 0x8020A0EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80211A70
 * EN v1.1 Size: 1560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0f0
 * EN v1.0 Address: 0x8020A0F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80212088
 * EN v1.1 Size: 548b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0f0(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0f4
 * EN v1.0 Address: 0x8020A0F4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802122AC
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0f4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0f8
 * EN v1.0 Address: 0x8020A0F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021231C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0f8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a0fc
 * EN v1.0 Address: 0x8020A0FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80212350
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a0fc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a100
 * EN v1.0 Address: 0x8020A100
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021239C
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a100(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a104
 * EN v1.0 Address: 0x8020A104
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021243C
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a104(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a108
 * EN v1.0 Address: 0x8020A108
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802124E4
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a108(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a10c
 * EN v1.0 Address: 0x8020A10C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802125B0
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a10c(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a114
 * EN v1.0 Address: 0x8020A114
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802126D8
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a114(int param_1,undefined2 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a118
 * EN v1.0 Address: 0x8020A118
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802129A8
 * EN v1.1 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a118(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a11c
 * EN v1.0 Address: 0x8020A11C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80212D78
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a11c(undefined4 param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a124
 * EN v1.0 Address: 0x8020A124
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80212E4C
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a124(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a12c
 * EN v1.0 Address: 0x8020A12C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80212F90
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a12c(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a134
 * EN v1.0 Address: 0x8020A134
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80213094
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a134(undefined4 param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a13c
 * EN v1.0 Address: 0x8020A13C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80213128
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a13c(uint param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a144
 * EN v1.0 Address: 0x8020A144
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80213290
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a144(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a14c
 * EN v1.0 Address: 0x8020A14C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021339C
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a14c(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a154
 * EN v1.0 Address: 0x8020A154
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021349C
 * EN v1.1 Size: 932b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a154(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a15c
 * EN v1.0 Address: 0x8020A15C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80213840
 * EN v1.1 Size: 552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a15c(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a164
 * EN v1.0 Address: 0x8020A164
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80213A68
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a164(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a16c
 * EN v1.0 Address: 0x8020A16C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80213B30
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a16c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a174
 * EN v1.0 Address: 0x8020A174
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80213BE0
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a174(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a17c
 * EN v1.0 Address: 0x8020A17C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80213CB8
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a17c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a184
 * EN v1.0 Address: 0x8020A184
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80213D54
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a184(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a18c
 * EN v1.0 Address: 0x8020A18C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80213E70
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a18c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined2 *param_9,
            int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a194
 * EN v1.0 Address: 0x8020A194
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80213F8C
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a194(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined2 *param_9,
            int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a19c
 * EN v1.0 Address: 0x8020A19C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80214214
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a19c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1a4
 * EN v1.0 Address: 0x8020A1A4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802143C4
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a1a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1ac
 * EN v1.0 Address: 0x8020A1AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80214418
 * EN v1.1 Size: 1020b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1ac(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 *param_14,int param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1b0
 * EN v1.0 Address: 0x8020A1B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80214814
 * EN v1.1 Size: 2220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1b0(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1b4
 * EN v1.0 Address: 0x8020A1B4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802150C0
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a1b4(uint param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1bc
 * EN v1.0 Address: 0x8020A1BC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80215214
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a1bc(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1c4
 * EN v1.0 Address: 0x8020A1C4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802153B4
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a1c4(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1cc
 * EN v1.0 Address: 0x8020A1CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802154AC
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1cc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1d0
 * EN v1.0 Address: 0x8020A1D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80215598
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1d0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1d4
 * EN v1.0 Address: 0x8020A1D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80215864
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1d4(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1d8
 * EN v1.0 Address: 0x8020A1D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802158CC
 * EN v1.1 Size: 740b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1d8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1dc
 * EN v1.0 Address: 0x8020A1DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80215BB0
 * EN v1.1 Size: 980b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1dc(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1e0
 * EN v1.0 Address: 0x8020A1E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80215F84
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1e0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1e4
 * EN v1.0 Address: 0x8020A1E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80215FA4
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1e4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1e8
 * EN v1.0 Address: 0x8020A1E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802160C8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1e8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1ec
 * EN v1.0 Address: 0x8020A1EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802160FC
 * EN v1.1 Size: 2424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1ec(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1f0
 * EN v1.0 Address: 0x8020A1F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80216A74
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1f0(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1f4
 * EN v1.0 Address: 0x8020A1F4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80216B48
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1f4(double param_1,ushort *param_2,uint param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1f8
 * EN v1.0 Address: 0x8020A1F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80216CA8
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1f8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a1fc
 * EN v1.0 Address: 0x8020A1FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80216CE8
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a1fc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a200
 * EN v1.0 Address: 0x8020A200
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80216E10
 * EN v1.1 Size: 784b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a200(ushort *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a204
 * EN v1.0 Address: 0x8020A204
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80217120
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a204(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a208
 * EN v1.0 Address: 0x8020A208
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802171D0
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a208(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a20c
 * EN v1.0 Address: 0x8020A20C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80217208
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a20c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a210
 * EN v1.0 Address: 0x8020A210
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80217310
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a210(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a214
 * EN v1.0 Address: 0x8020A214
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802173A0
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a214(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a218
 * EN v1.0 Address: 0x8020A218
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802173E0
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a218(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a21c
 * EN v1.0 Address: 0x8020A21C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80217524
 * EN v1.1 Size: 940b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a21c(undefined4 param_1,undefined4 param_2,int param_3,uint param_4,float *param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a220
 * EN v1.0 Address: 0x8020A220
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802178D0
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a220(undefined4 param_1,int *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a228
 * EN v1.0 Address: 0x8020A228
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802179DC
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a228(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a22c
 * EN v1.0 Address: 0x8020A22C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80217A48
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a22c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a230
 * EN v1.0 Address: 0x8020A230
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80217ABC
 * EN v1.1 Size: 492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a230(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a234
 * EN v1.0 Address: 0x8020A234
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80217CA8
 * EN v1.1 Size: 1800b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a234(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a238
 * EN v1.0 Address: 0x8020A238
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802183B0
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a238(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a23c
 * EN v1.0 Address: 0x8020A23C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802185B8
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a23c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a240
 * EN v1.0 Address: 0x8020A240
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802185F8
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a240(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a244
 * EN v1.0 Address: 0x8020A244
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80218740
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a244(double param_1,undefined2 *param_2,int param_3,int param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a248
 * EN v1.0 Address: 0x8020A248
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80218A94
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a248(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a24c
 * EN v1.0 Address: 0x8020A24C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80218AEC
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a24c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a250
 * EN v1.0 Address: 0x8020A250
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80218C44
 * EN v1.1 Size: 1012b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a250(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a254
 * EN v1.0 Address: 0x8020A254
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80219038
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a254(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a258
 * EN v1.0 Address: 0x8020A258
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021919C
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a258(int param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a260
 * EN v1.0 Address: 0x8020A260
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80219248
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a260(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a264
 * EN v1.0 Address: 0x8020A264
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021927C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a264(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a268
 * EN v1.0 Address: 0x8020A268
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802192A0
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a268(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a26c
 * EN v1.0 Address: 0x8020A26C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80219508
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a26c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a270
 * EN v1.0 Address: 0x8020A270
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80219560
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a270(int param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a278
 * EN v1.0 Address: 0x8020A278
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80219614
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a278(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a280
 * EN v1.0 Address: 0x8020A280
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80219638
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a280(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a288
 * EN v1.0 Address: 0x8020A288
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80219790
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a288(undefined4 param_1,undefined4 param_2,ushort *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a28c
 * EN v1.0 Address: 0x8020A28C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021989C
 * EN v1.1 Size: 440b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a28c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,undefined4 param_11,int param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a294
 * EN v1.0 Address: 0x8020A294
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80219A54
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a294(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a29c
 * EN v1.0 Address: 0x8020A29C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80219AE4
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a29c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2a0
 * EN v1.0 Address: 0x8020A2A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80219BC8
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2a0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2a4
 * EN v1.0 Address: 0x8020A2A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80219C00
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2a4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2a8
 * EN v1.0 Address: 0x8020A2A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80219C34
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2a8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2ac
 * EN v1.0 Address: 0x8020A2AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80219F38
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2ac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2b0
 * EN v1.0 Address: 0x8020A2B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021A100
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2b0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2b4
 * EN v1.0 Address: 0x8020A2B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021A318
 * EN v1.1 Size: 732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2b8
 * EN v1.0 Address: 0x8020A2B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021A5F4
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2b8(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2bc
 * EN v1.0 Address: 0x8020A2BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021A6C4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2bc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2c0
 * EN v1.0 Address: 0x8020A2C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021A6F8
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2c0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2c4
 * EN v1.0 Address: 0x8020A2C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021A768
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2c4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2c8
 * EN v1.0 Address: 0x8020A2C8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021A7E4
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a2c8(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2d0
 * EN v1.0 Address: 0x8020A2D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021A904
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2d0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2d4
 * EN v1.0 Address: 0x8020A2D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021A938
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2d4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2d8
 * EN v1.0 Address: 0x8020A2D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021AA64
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2d8(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2dc
 * EN v1.0 Address: 0x8020A2DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021AB08
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2dc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2e0
 * EN v1.0 Address: 0x8020A2E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021AB38
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2e0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2e4
 * EN v1.0 Address: 0x8020A2E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021AC80
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2e4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2e8
 * EN v1.0 Address: 0x8020A2E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021AD3C
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2e8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2ec
 * EN v1.0 Address: 0x8020A2EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021ADBC
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2ec(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2f0
 * EN v1.0 Address: 0x8020A2F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021AEB4
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2f0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2f4
 * EN v1.0 Address: 0x8020A2F4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021B234
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2f4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2f8
 * EN v1.0 Address: 0x8020A2F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021B42C
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2f8(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a2fc
 * EN v1.0 Address: 0x8020A2FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021B68C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a2fc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a300
 * EN v1.0 Address: 0x8020A300
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021B6B0
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a300(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a304
 * EN v1.0 Address: 0x8020A304
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021B764
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a304(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a308
 * EN v1.0 Address: 0x8020A308
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021B820
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a308(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a30c
 * EN v1.0 Address: 0x8020A30C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021B934
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a30c(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a310
 * EN v1.0 Address: 0x8020A310
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021BA00
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a310(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a314
 * EN v1.0 Address: 0x8020A314
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021BA74
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a314(double param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a318
 * EN v1.0 Address: 0x8020A318
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021BB64
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a318(ushort *param_1,float *param_2,float *param_3,float *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a31c
 * EN v1.0 Address: 0x8020A31C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021BC80
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a31c(int param_1,int param_2,uint param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a324
 * EN v1.0 Address: 0x8020A324
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021BDE0
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a324(int param_1,int param_2,uint param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a32c
 * EN v1.0 Address: 0x8020A32C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021BF40
 * EN v1.1 Size: 1796b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a32c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            float *param_9,uint param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13
            ,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a334
 * EN v1.0 Address: 0x8020A334
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021C644
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a334(uint param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a33c
 * EN v1.0 Address: 0x8020A33C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021C778
 * EN v1.1 Size: 1492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a33c(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a340
 * EN v1.0 Address: 0x8020A340
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021CD4C
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a340(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a344
 * EN v1.0 Address: 0x8020A344
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021CD88
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a344(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a348
 * EN v1.0 Address: 0x8020A348
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021CEE8
 * EN v1.1 Size: 1532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a348(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,ushort *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a34c
 * EN v1.0 Address: 0x8020A34C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021D4E4
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a34c(undefined2 *param_1,short *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a350
 * EN v1.0 Address: 0x8020A350
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021D608
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a350(int param_1,uint *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a358
 * EN v1.0 Address: 0x8020A358
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021D740
 * EN v1.1 Size: 1216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a358(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a35c
 * EN v1.0 Address: 0x8020A35C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021DC00
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a35c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a364
 * EN v1.0 Address: 0x8020A364
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021DD90
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a364(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a36c
 * EN v1.0 Address: 0x8020A36C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021DEB4
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a36c(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a374
 * EN v1.0 Address: 0x8020A374
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021DF10
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a374(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a37c
 * EN v1.0 Address: 0x8020A37C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021DFB8
 * EN v1.1 Size: 1176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a37c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a380
 * EN v1.0 Address: 0x8020A380
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021E450
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a380(int param_1,undefined param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a388
 * EN v1.0 Address: 0x8020A388
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021E53C
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a388(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13
                ,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a390
 * EN v1.0 Address: 0x8020A390
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021E618
 * EN v1.1 Size: 1088b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a390(double param_1,undefined8 param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a398
 * EN v1.0 Address: 0x8020A398
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021EA58
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a398(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3a0
 * EN v1.0 Address: 0x8020A3A0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021EB34
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a3a0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3a8
 * EN v1.0 Address: 0x8020A3A8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021EB88
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a3a8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3b0
 * EN v1.0 Address: 0x8020A3B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021EC08
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3b0(uint param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3b4
 * EN v1.0 Address: 0x8020A3B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021ECB0
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3b4(short *param_1,int param_2,int *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3b8
 * EN v1.0 Address: 0x8020A3B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021ED8C
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3b8(double param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3bc
 * EN v1.0 Address: 0x8020A3BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021EEA8
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3bc(undefined4 param_1,float *param_2,float *param_3,float *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3c0
 * EN v1.0 Address: 0x8020A3C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021EFA0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3c0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3c4
 * EN v1.0 Address: 0x8020A3C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021EFF0
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3c4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3c8
 * EN v1.0 Address: 0x8020A3C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021F15C
 * EN v1.1 Size: 540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3c8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3cc
 * EN v1.0 Address: 0x8020A3CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021F378
 * EN v1.1 Size: 684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3cc(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3d0
 * EN v1.0 Address: 0x8020A3D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021F624
 * EN v1.1 Size: 888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3d0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3d4
 * EN v1.0 Address: 0x8020A3D4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021F99C
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a3d4(int param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3dc
 * EN v1.0 Address: 0x8020A3DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021FA3C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3dc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3e0
 * EN v1.0 Address: 0x8020A3E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021FA60
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3e0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3e4
 * EN v1.0 Address: 0x8020A3E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021FA90
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3e4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3e8
 * EN v1.0 Address: 0x8020A3E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021FBFC
 * EN v1.1 Size: 424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3e8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3ec
 * EN v1.0 Address: 0x8020A3EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8021FDA4
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3ec(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3f0
 * EN v1.0 Address: 0x8020A3F0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8021FF1C
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a3f0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int *param_9,int param_10,uint param_11)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3f8
 * EN v1.0 Address: 0x8020A3F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80220088
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a3f8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a3fc
 * EN v1.0 Address: 0x8020A3FC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80220104
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a3fc(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a404
 * EN v1.0 Address: 0x8020A404
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80220120
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a404(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a40c
 * EN v1.0 Address: 0x8020A40C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022013C
 * EN v1.1 Size: 1612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a40c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a410
 * EN v1.0 Address: 0x8020A410
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80220788
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a410(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a418
 * EN v1.0 Address: 0x8020A418
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802207B4
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a418(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a41c
 * EN v1.0 Address: 0x8020A41C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80220830
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a41c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a420
 * EN v1.0 Address: 0x8020A420
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802208D8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a420(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a424
 * EN v1.0 Address: 0x8020A424
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80220908
 * EN v1.1 Size: 876b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a424(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a428
 * EN v1.0 Address: 0x8020A428
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80220C74
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a428(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a42c
 * EN v1.0 Address: 0x8020A42C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80220D78
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a42c(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a430
 * EN v1.0 Address: 0x8020A430
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80220E68
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a430(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a434
 * EN v1.0 Address: 0x8020A434
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80220EA8
 * EN v1.1 Size: 532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a434(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a438
 * EN v1.0 Address: 0x8020A438
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802210BC
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a438(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a43c
 * EN v1.0 Address: 0x8020A43C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80221130
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a43c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a440
 * EN v1.0 Address: 0x8020A440
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80221150
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a440(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a444
 * EN v1.0 Address: 0x8020A444
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80221184
 * EN v1.1 Size: 1220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a444(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a448
 * EN v1.0 Address: 0x8020A448
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80221648
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a448(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a44c
 * EN v1.0 Address: 0x8020A44C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802217C8
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
bool FUN_8020a44c(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a454
 * EN v1.0 Address: 0x8020A454
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022186C
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a454(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a45c
 * EN v1.0 Address: 0x8020A45C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802218DC
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a45c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a460
 * EN v1.0 Address: 0x8020A460
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80221924
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a460(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a464
 * EN v1.0 Address: 0x8020A464
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80221AA4
 * EN v1.1 Size: 540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a464(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a468
 * EN v1.0 Address: 0x8020A468
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80221CC0
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a468(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a470
 * EN v1.0 Address: 0x8020A470
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80221CD0
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a470(int param_1,undefined4 param_2,short param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a474
 * EN v1.0 Address: 0x8020A474
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80221D3C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a474(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a478
 * EN v1.0 Address: 0x8020A478
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80221D60
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a478(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a47c
 * EN v1.0 Address: 0x8020A47C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80221D94
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a47c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,undefined4 param_10,undefined4 param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a480
 * EN v1.0 Address: 0x8020A480
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80221F7C
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a480(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a484
 * EN v1.0 Address: 0x8020A484
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80221FC8
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a484(undefined4 param_1,undefined4 param_2,int param_3,uint *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a488
 * EN v1.0 Address: 0x8020A488
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80222268
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8020a488(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,float *param_10,float *param_11)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a490
 * EN v1.0 Address: 0x8020A490
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802223BC
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a490(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 float *param_9,float *param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a494
 * EN v1.0 Address: 0x8020A494
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80222410
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a494(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 float *param_9,float *param_10,float *param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a498
 * EN v1.0 Address: 0x8020A498
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802224E4
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a498(undefined4 param_1,float *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a49c
 * EN v1.0 Address: 0x8020A49C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80222564
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a49c(double param_1,double param_2,double param_3,int param_4,float *param_5,
                 float *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4a0
 * EN v1.0 Address: 0x8020A4A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802227B0
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a4a0(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6,undefined4 *param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4a4
 * EN v1.0 Address: 0x8020A4A4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802229A8
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a4a4(double param_1,double param_2,double param_3,int param_4,float *param_5,
                char param_6)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4ac
 * EN v1.0 Address: 0x8020A4AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80222BA0
 * EN v1.1 Size: 684b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a4ac(double param_1,double param_2,ushort *param_3,float *param_4,uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4b0
 * EN v1.0 Address: 0x8020A4B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80222E4C
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a4b0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4b4
 * EN v1.0 Address: 0x8020A4B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80222E94
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a4b4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4b8
 * EN v1.0 Address: 0x8020A4B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022301C
 * EN v1.1 Size: 1304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a4b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4bc
 * EN v1.0 Address: 0x8020A4BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80223534
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a4bc(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4c0
 * EN v1.0 Address: 0x8020A4C0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80223654
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a4c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,char param_12,undefined4 param_13,undefined4 param_14,undefined4 param_15,
            undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4c8
 * EN v1.0 Address: 0x8020A4C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022377C
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a4c8(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4cc
 * EN v1.0 Address: 0x8020A4CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802237D4
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a4cc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4d0
 * EN v1.0 Address: 0x8020A4D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80223834
 * EN v1.1 Size: 1688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a4d0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4d4
 * EN v1.0 Address: 0x8020A4D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80223ECC
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a4d4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4d8
 * EN v1.0 Address: 0x8020A4D8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80223FF4
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a4d8(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4e0
 * EN v1.0 Address: 0x8020A4E0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022406C
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a4e0(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4e8
 * EN v1.0 Address: 0x8020A4E8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022414C
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a4e8(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4f0
 * EN v1.0 Address: 0x8020A4F0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80224214
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a4f0(undefined4 param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a4f8
 * EN v1.0 Address: 0x8020A4F8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80224284
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a4f8(undefined2 *param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a500
 * EN v1.0 Address: 0x8020A500
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80224378
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a500(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a504
 * EN v1.0 Address: 0x8020A504
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022439C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a504(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a508
 * EN v1.0 Address: 0x8020A508
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802243F8
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a508(ushort *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a50c
 * EN v1.0 Address: 0x8020A50C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80224548
 * EN v1.1 Size: 424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a50c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a510
 * EN v1.0 Address: 0x8020A510
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802246F0
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a510(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a514
 * EN v1.0 Address: 0x8020A514
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80224724
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a514(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a518
 * EN v1.0 Address: 0x8020A518
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802248F8
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a518(int param_1,int param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a520
 * EN v1.0 Address: 0x8020A520
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80224A80
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a520(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a524
 * EN v1.0 Address: 0x8020A524
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80224AB4
 * EN v1.1 Size: 3256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a524(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a528
 * EN v1.0 Address: 0x8020A528
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022576C
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a528(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a52c
 * EN v1.0 Address: 0x8020A52C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80225804
 * EN v1.1 Size: 1496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a52c(undefined4 param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a530
 * EN v1.0 Address: 0x8020A530
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80225DDC
 * EN v1.1 Size: 1100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a530(undefined4 param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a534
 * EN v1.0 Address: 0x8020A534
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80226228
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a534(int param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a53c
 * EN v1.0 Address: 0x8020A53C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022637C
 * EN v1.1 Size: 1492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a53c(undefined4 param_1,undefined4 param_2,short param_3,float *param_4,float *param_5,
                 int param_6,int param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a540
 * EN v1.0 Address: 0x8020A540
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80226950
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a540(double param_1,double param_2,undefined4 param_3,short *param_4,short *param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a544
 * EN v1.0 Address: 0x8020A544
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80226A3C
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a544(undefined4 param_1,short param_2,short param_3,float *param_4,float *param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a548
 * EN v1.0 Address: 0x8020A548
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80226B14
 * EN v1.1 Size: 1492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a548(undefined4 param_1,undefined4 param_2,short param_3,float *param_4,float *param_5,
                 int param_6,int param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a54c
 * EN v1.0 Address: 0x8020A54C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802270E8
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a54c(double param_1,double param_2,undefined4 param_3,short *param_4,short *param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a550
 * EN v1.0 Address: 0x8020A550
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802271D4
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a550(undefined4 param_1,short param_2,short param_3,float *param_4,float *param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a554
 * EN v1.0 Address: 0x8020A554
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802272BC
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a554(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a558
 * EN v1.0 Address: 0x8020A558
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80227368
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a558(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a55c
 * EN v1.0 Address: 0x8020A55C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022739C
 * EN v1.1 Size: 424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a55c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a560
 * EN v1.0 Address: 0x8020A560
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80227544
 * EN v1.1 Size: 440b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a560(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a564
 * EN v1.0 Address: 0x8020A564
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802276FC
 * EN v1.1 Size: 628b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a564(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a568
 * EN v1.0 Address: 0x8020A568
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80227970
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a568(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a570
 * EN v1.0 Address: 0x8020A570
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80227A00
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a570(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a574
 * EN v1.0 Address: 0x8020A574
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80227A30
 * EN v1.1 Size: 596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a574(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a578
 * EN v1.0 Address: 0x8020A578
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80227C84
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a578(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a57c
 * EN v1.0 Address: 0x8020A57C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80227D90
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a57c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a580
 * EN v1.0 Address: 0x8020A580
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80227DC4
 * EN v1.1 Size: 1032b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a580(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a584
 * EN v1.0 Address: 0x8020A584
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802281CC
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a584(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a588
 * EN v1.0 Address: 0x8020A588
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80228260
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a588(int param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a590
 * EN v1.0 Address: 0x8020A590
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802283B0
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a590(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a594
 * EN v1.0 Address: 0x8020A594
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802283D4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a594(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a598
 * EN v1.0 Address: 0x8020A598
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80228408
 * EN v1.1 Size: 840b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a598(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a59c
 * EN v1.0 Address: 0x8020A59C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80228750
 * EN v1.1 Size: 292b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a59c(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5a0
 * EN v1.0 Address: 0x8020A5A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80228874
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5a0(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5a4
 * EN v1.0 Address: 0x8020A5A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80228938
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5a4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5a8
 * EN v1.0 Address: 0x8020A5A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80228968
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5a8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5ac
 * EN v1.0 Address: 0x8020A5AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80228A20
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5ac(undefined2 *param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5b0
 * EN v1.0 Address: 0x8020A5B0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80228B20
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a5b0(int param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5b8
 * EN v1.0 Address: 0x8020A5B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80228C90
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5b8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5bc
 * EN v1.0 Address: 0x8020A5BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80228CC0
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5bc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5c0
 * EN v1.0 Address: 0x8020A5C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80228D00
 * EN v1.1 Size: 972b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5c0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5c4
 * EN v1.0 Address: 0x8020A5C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802290CC
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5c4(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5c8
 * EN v1.0 Address: 0x8020A5C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80229210
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5c8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5cc
 * EN v1.0 Address: 0x8020A5CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80229244
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5cc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5d0
 * EN v1.0 Address: 0x8020A5D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022933C
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5d0(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5d4
 * EN v1.0 Address: 0x8020A5D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802293A8
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5d4(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5d8
 * EN v1.0 Address: 0x8020A5D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80229494
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5d8(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5dc
 * EN v1.0 Address: 0x8020A5DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80229614
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5dc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5e0
 * EN v1.0 Address: 0x8020A5E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80229644
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5e0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5e4
 * EN v1.0 Address: 0x8020A5E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022970C
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5e4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5e8
 * EN v1.0 Address: 0x8020A5E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802297B4
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5e8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5ec
 * EN v1.0 Address: 0x8020A5EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022994C
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5f0
 * EN v1.0 Address: 0x8020A5F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80229ABC
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5f0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5f4
 * EN v1.0 Address: 0x8020A5F4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80229B90
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a5f4(int param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a5fc
 * EN v1.0 Address: 0x8020A5FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80229C38
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a5fc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a600
 * EN v1.0 Address: 0x8020A600
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80229C6C
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a600(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a604
 * EN v1.0 Address: 0x8020A604
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80229ED0
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a604(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a608
 * EN v1.0 Address: 0x8020A608
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022A060
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a608(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a60c
 * EN v1.0 Address: 0x8020A60C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022A170
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a60c(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a610
 * EN v1.0 Address: 0x8020A610
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022A440
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a610(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a614
 * EN v1.0 Address: 0x8020A614
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022A488
 * EN v1.1 Size: 704b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a614(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a618
 * EN v1.0 Address: 0x8020A618
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022A748
 * EN v1.1 Size: 552b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a618(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a61c
 * EN v1.0 Address: 0x8020A61C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022A970
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a61c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a620
 * EN v1.0 Address: 0x8020A620
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022A9A4
 * EN v1.1 Size: 912b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a620(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a624
 * EN v1.0 Address: 0x8020A624
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022AD34
 * EN v1.1 Size: 856b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a624(uint param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a628
 * EN v1.0 Address: 0x8020A628
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022B08C
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a628(ushort *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a62c
 * EN v1.0 Address: 0x8020A62C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022B22C
 * EN v1.1 Size: 692b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a62c(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a630
 * EN v1.0 Address: 0x8020A630
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022B4E0
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a630(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a634
 * EN v1.0 Address: 0x8020A634
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022B590
 * EN v1.1 Size: 2200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a634(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a638
 * EN v1.0 Address: 0x8020A638
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022BE28
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a638(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a63c
 * EN v1.0 Address: 0x8020A63C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022BF64
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a63c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a640
 * EN v1.0 Address: 0x8020A640
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022C05C
 * EN v1.1 Size: 424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a640(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,uint param_13)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a644
 * EN v1.0 Address: 0x8020A644
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022C204
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a644(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a648
 * EN v1.0 Address: 0x8020A648
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022C394
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a648(undefined4 param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a64c
 * EN v1.0 Address: 0x8020A64C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022C4D8
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a64c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a650
 * EN v1.0 Address: 0x8020A650
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022C794
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a650(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a654
 * EN v1.0 Address: 0x8020A654
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022C9D0
 * EN v1.1 Size: 884b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a654(uint param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a658
 * EN v1.0 Address: 0x8020A658
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022CD44
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a658(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a65c
 * EN v1.0 Address: 0x8020A65C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022CE78
 * EN v1.1 Size: 1592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a65c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,ushort *param_9,
            undefined4 param_10,uint param_11,int param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a664
 * EN v1.0 Address: 0x8020A664
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022D4B0
 * EN v1.1 Size: 1308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a664(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a668
 * EN v1.0 Address: 0x8020A668
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022D9CC
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a668(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a66c
 * EN v1.0 Address: 0x8020A66C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DB24
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a66c(double param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a670
 * EN v1.0 Address: 0x8020A670
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022DB30
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a670(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a678
 * EN v1.0 Address: 0x8020A678
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DB40
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a678(int param_1,short param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a67c
 * EN v1.0 Address: 0x8020A67C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DB50
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a67c(undefined4 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a680
 * EN v1.0 Address: 0x8020A680
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DB70
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a680(int param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a684
 * EN v1.0 Address: 0x8020A684
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DB90
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a684(int param_1,float *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a688
 * EN v1.0 Address: 0x8020A688
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DBBC
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a688(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a68c
 * EN v1.0 Address: 0x8020A68C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022DBCC
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_8020a68c(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a694
 * EN v1.0 Address: 0x8020A694
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022DBD8
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_8020a694(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a69c
 * EN v1.0 Address: 0x8020A69C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DBE4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a69c(int param_1,ushort param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6a0
 * EN v1.0 Address: 0x8020A6A0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022DC14
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 FUN_8020a6a0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6a8
 * EN v1.0 Address: 0x8020A6A8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022DC38
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_8020a6a8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6b0
 * EN v1.0 Address: 0x8020A6B0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022DC44
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a6b0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6b8
 * EN v1.0 Address: 0x8020A6B8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022DC54
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a6b8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6c0
 * EN v1.0 Address: 0x8020A6C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DC64
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a6c0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6c4
 * EN v1.0 Address: 0x8020A6C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DC78
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a6c4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6c8
 * EN v1.0 Address: 0x8020A6C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DC8C
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a6c8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6cc
 * EN v1.0 Address: 0x8020A6CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DCA0
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a6cc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6d0
 * EN v1.0 Address: 0x8020A6D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DCB4
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a6d0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6d4
 * EN v1.0 Address: 0x8020A6D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DCF8
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a6d4(int param_1,char param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6d8
 * EN v1.0 Address: 0x8020A6D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DD10
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a6d8(int param_1,char param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6dc
 * EN v1.0 Address: 0x8020A6DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DD94
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a6dc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6e0
 * EN v1.0 Address: 0x8020A6E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DDB4
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a6e0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6e4
 * EN v1.0 Address: 0x8020A6E4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022DDD4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a6e4(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6ec
 * EN v1.0 Address: 0x8020A6EC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022DDFC
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8020a6ec(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6f4
 * EN v1.0 Address: 0x8020A6F4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022DE14
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8020a6f4(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a6fc
 * EN v1.0 Address: 0x8020A6FC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8022DE2C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a6fc(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a704
 * EN v1.0 Address: 0x8020A704
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DE44
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a704(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a708
 * EN v1.0 Address: 0x8020A708
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DE8C
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a708(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a70c
 * EN v1.0 Address: 0x8020A70C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022DFCC
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a70c(ushort *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a710
 * EN v1.0 Address: 0x8020A710
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022E0A0
 * EN v1.1 Size: 2180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a710(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a714
 * EN v1.0 Address: 0x8020A714
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022E924
 * EN v1.1 Size: 440b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a714(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a718
 * EN v1.0 Address: 0x8020A718
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022EADC
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a718(int param_1,char param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a71c
 * EN v1.0 Address: 0x8020A71C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022EC10
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a71c(double param_1,ushort *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a720
 * EN v1.0 Address: 0x8020A720
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022ECC4
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a720(int param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a724
 * EN v1.0 Address: 0x8020A724
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022ED04
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a724(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a728
 * EN v1.0 Address: 0x8020A728
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022ED44
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a728(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a72c
 * EN v1.0 Address: 0x8020A72C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022ED74
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a72c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a730
 * EN v1.0 Address: 0x8020A730
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022F010
 * EN v1.1 Size: 540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a730(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a734
 * EN v1.0 Address: 0x8020A734
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022F22C
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a734(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a738
 * EN v1.0 Address: 0x8020A738
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022F3A4
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a738(double param_1,ushort *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a73c
 * EN v1.0 Address: 0x8020A73C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022F438
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a73c(int param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a740
 * EN v1.0 Address: 0x8020A740
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022F478
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a740(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a744
 * EN v1.0 Address: 0x8020A744
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022F4C0
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a744(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a748
 * EN v1.0 Address: 0x8020A748
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022F4F4
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a748(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a74c
 * EN v1.0 Address: 0x8020A74C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022F7B0
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a74c(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a750
 * EN v1.0 Address: 0x8020A750
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022F80C
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a750(int param_1,char param_2,char param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a754
 * EN v1.0 Address: 0x8020A754
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022F89C
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a754(int param_1,char param_2,char param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a758
 * EN v1.0 Address: 0x8020A758
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022F934
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a758(int param_1,undefined4 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a75c
 * EN v1.0 Address: 0x8020A75C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022F940
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a75c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a760
 * EN v1.0 Address: 0x8020A760
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022FA2C
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a760(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a764
 * EN v1.0 Address: 0x8020A764
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022FC1C
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a764(int param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a768
 * EN v1.0 Address: 0x8020A768
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022FC60
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a768(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a76c
 * EN v1.0 Address: 0x8020A76C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8022FC88
 * EN v1.1 Size: 1084b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a76c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a770
 * EN v1.0 Address: 0x8020A770
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802300C4
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a770(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a774
 * EN v1.0 Address: 0x8020A774
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80230220
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a774(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,char *param_10,uint param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a778
 * EN v1.0 Address: 0x8020A778
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8023039C
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a778(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            char *param_10,int param_11)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a780
 * EN v1.0 Address: 0x8020A780
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802304D4
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a780(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a784
 * EN v1.0 Address: 0x8020A784
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80230514
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a784(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a788
 * EN v1.0 Address: 0x8020A788
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80230598
 * EN v1.1 Size: 2032b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a788(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a78c
 * EN v1.0 Address: 0x8020A78C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80230D88
 * EN v1.1 Size: 496b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a78c(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a790
 * EN v1.0 Address: 0x8020A790
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80230F78
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a790(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a794
 * EN v1.0 Address: 0x8020A794
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80230FC8
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a794(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            undefined4 param_10,int param_11)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a79c
 * EN v1.0 Address: 0x8020A79C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802310E4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a79c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7a0
 * EN v1.0 Address: 0x8020A7A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80231114
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7a0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7a4
 * EN v1.0 Address: 0x8020A7A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023113C
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7a8
 * EN v1.0 Address: 0x8020A7A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023138C
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7a8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7ac
 * EN v1.0 Address: 0x8020A7AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80231504
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7ac(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7b0
 * EN v1.0 Address: 0x8020A7B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023152C
 * EN v1.1 Size: 448b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7b0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7b4
 * EN v1.0 Address: 0x8020A7B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802316EC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7b4(int param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7b8
 * EN v1.0 Address: 0x8020A7B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023171C
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7b8(int param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7bc
 * EN v1.0 Address: 0x8020A7BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80231758
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7bc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7c0
 * EN v1.0 Address: 0x8020A7C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80231788
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7c0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7c4
 * EN v1.0 Address: 0x8020A7C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023193C
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7c4(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7c8
 * EN v1.0 Address: 0x8020A7C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80231A10
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7c8(int param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7cc
 * EN v1.0 Address: 0x8020A7CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80231A40
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7cc(int param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7d0
 * EN v1.0 Address: 0x8020A7D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80231A70
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7d0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7d4
 * EN v1.0 Address: 0x8020A7D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80231A98
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7d4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7d8
 * EN v1.0 Address: 0x8020A7D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80231BF0
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7d8(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7dc
 * EN v1.0 Address: 0x8020A7DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80231CB0
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7dc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7e0
 * EN v1.0 Address: 0x8020A7E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80231E6C
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7e0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7e4
 * EN v1.0 Address: 0x8020A7E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023203C
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7e4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7e8
 * EN v1.0 Address: 0x8020A7E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80232064
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7e8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7ec
 * EN v1.0 Address: 0x8020A7EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023211C
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7ec(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7f0
 * EN v1.0 Address: 0x8020A7F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80232154
 * EN v1.1 Size: 512b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7f0(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7f4
 * EN v1.0 Address: 0x8020A7F4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80232354
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7f4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7f8
 * EN v1.0 Address: 0x8020A7F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802324F4
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7f8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a7fc
 * EN v1.0 Address: 0x8020A7FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802327FC
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a7fc(ushort *param_1,float *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a800
 * EN v1.0 Address: 0x8020A800
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023293C
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a800(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,int param_11,char param_12)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a804
 * EN v1.0 Address: 0x8020A804
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80232A70
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a804(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a808
 * EN v1.0 Address: 0x8020A808
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80232D40
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a808(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a80c
 * EN v1.0 Address: 0x8020A80C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80232ECC
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a80c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a810
 * EN v1.0 Address: 0x8020A810
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80232EF4
 * EN v1.1 Size: 1348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a810(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a814
 * EN v1.0 Address: 0x8020A814
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80233438
 * EN v1.1 Size: 1100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a814(short *param_1,short *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a818
 * EN v1.0 Address: 0x8020A818
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80233884
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a818(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a81c
 * EN v1.0 Address: 0x8020A81C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802338C4
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a81c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a820
 * EN v1.0 Address: 0x8020A820
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80233948
 * EN v1.1 Size: 1396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a820(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a824
 * EN v1.0 Address: 0x8020A824
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80233EBC
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a824(undefined2 *param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a828
 * EN v1.0 Address: 0x8020A828
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80234000
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a828(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a82c
 * EN v1.0 Address: 0x8020A82C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80234028
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a82c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a830
 * EN v1.0 Address: 0x8020A830
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023415C
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a830(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a834
 * EN v1.0 Address: 0x8020A834
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802341D0
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a834(int param_1,char param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a838
 * EN v1.0 Address: 0x8020A838
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80234214
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a838(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a83c
 * EN v1.0 Address: 0x8020A83C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023425C
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a83c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a840
 * EN v1.0 Address: 0x8020A840
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802342A8
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a840(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a844
 * EN v1.0 Address: 0x8020A844
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80234454
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a844(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a848
 * EN v1.0 Address: 0x8020A848
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80234710
 * EN v1.1 Size: 908b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a848(short *param_1,char *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a84c
 * EN v1.0 Address: 0x8020A84C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80234A9C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a84c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a850
 * EN v1.0 Address: 0x8020A850
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80234ACC
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a850(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a854
 * EN v1.0 Address: 0x8020A854
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80234AF4
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a854(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a858
 * EN v1.0 Address: 0x8020A858
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80234C80
 * EN v1.1 Size: 412b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a858(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a85c
 * EN v1.0 Address: 0x8020A85C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80234E1C
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a85c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a860
 * EN v1.0 Address: 0x8020A860
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80234E6C
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a860(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a864
 * EN v1.0 Address: 0x8020A864
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80234F64
 * EN v1.1 Size: 908b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a864(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a868
 * EN v1.0 Address: 0x8020A868
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802352F0
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a868(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a86c
 * EN v1.0 Address: 0x8020A86C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80235420
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a86c(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a870
 * EN v1.0 Address: 0x8020A870
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802354B4
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a870(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a874
 * EN v1.0 Address: 0x8020A874
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802354E8
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a874(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a878
 * EN v1.0 Address: 0x8020A878
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802355C0
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a878(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a87c
 * EN v1.0 Address: 0x8020A87C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80235700
 * EN v1.1 Size: 1116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a87c(undefined4 param_1,undefined4 param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a880
 * EN v1.0 Address: 0x8020A880
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80235B5C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a880(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a884
 * EN v1.0 Address: 0x8020A884
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80235B90
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a884(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a888
 * EN v1.0 Address: 0x8020A888
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80235CAC
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a888(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a88c
 * EN v1.0 Address: 0x8020A88C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80235D90
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a88c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,char param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a890
 * EN v1.0 Address: 0x8020A890
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80235EAC
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a890(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a894
 * EN v1.0 Address: 0x8020A894
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80235FC8
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a894(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a898
 * EN v1.0 Address: 0x8020A898
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80236090
 * EN v1.1 Size: 1220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a898(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a89c
 * EN v1.0 Address: 0x8020A89C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80236554
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a89c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8a0
 * EN v1.0 Address: 0x8020A8A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80236820
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8a0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8a4
 * EN v1.0 Address: 0x8020A8A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80236858
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8a4(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8a8
 * EN v1.0 Address: 0x8020A8A8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8023695C
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a8a8(undefined4 param_1,int *param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8b0
 * EN v1.0 Address: 0x8020A8B0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80236A4C
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a8b0(undefined4 param_1,int *param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8b8
 * EN v1.0 Address: 0x8020A8B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80236B44
 * EN v1.1 Size: 492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8b8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8bc
 * EN v1.0 Address: 0x8020A8BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80236D30
 * EN v1.1 Size: 1152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8bc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8c0
 * EN v1.0 Address: 0x8020A8C0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802371B0
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a8c0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8c8
 * EN v1.0 Address: 0x8020A8C8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802371D4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8020a8c8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8d0
 * EN v1.0 Address: 0x8020A8D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802371FC
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8d0(int param_1,char param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8d4
 * EN v1.0 Address: 0x8020A8D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80237244
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8d4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8d8
 * EN v1.0 Address: 0x8020A8D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802372A8
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8d8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8dc
 * EN v1.0 Address: 0x8020A8DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80237360
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8dc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8e0
 * EN v1.0 Address: 0x8020A8E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80237448
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8e0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8e4
 * EN v1.0 Address: 0x8020A8E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80237654
 * EN v1.1 Size: 1524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8e4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8e8
 * EN v1.0 Address: 0x8020A8E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80237C48
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8e8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8ec
 * EN v1.0 Address: 0x8020A8EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80237C88
 * EN v1.1 Size: 596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8ec(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8f0
 * EN v1.0 Address: 0x8020A8F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80237EDC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8f0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8f4
 * EN v1.0 Address: 0x8020A8F4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80237F0C
 * EN v1.1 Size: 1964b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8f4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8f8
 * EN v1.0 Address: 0x8020A8F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802386B8
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8f8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a8fc
 * EN v1.0 Address: 0x8020A8FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802387F0
 * EN v1.1 Size: 708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a8fc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a900
 * EN v1.0 Address: 0x8020A900
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80238AB4
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a900(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a904
 * EN v1.0 Address: 0x8020A904
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80238AF0
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a904(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a908
 * EN v1.0 Address: 0x8020A908
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80238BF0
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a908(int param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a90c
 * EN v1.0 Address: 0x8020A90C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80238C8C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a90c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a910
 * EN v1.0 Address: 0x8020A910
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80238CB0
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a910(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a914
 * EN v1.0 Address: 0x8020A914
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80238CC8
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8020a914(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a91c
 * EN v1.0 Address: 0x8020A91C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80238CE0
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_8020a91c(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a924
 * EN v1.0 Address: 0x8020A924
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80238CF8
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a924(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a928
 * EN v1.0 Address: 0x8020A928
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80238D40
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a928(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a92c
 * EN v1.0 Address: 0x8020A92C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80238DD4
 * EN v1.1 Size: 832b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a92c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a930
 * EN v1.0 Address: 0x8020A930
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80239114
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a930(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a934
 * EN v1.0 Address: 0x8020A934
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802391A8
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a934(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,int param_11)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a93c
 * EN v1.0 Address: 0x8020A93C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80239270
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a93c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a940
 * EN v1.0 Address: 0x8020A940
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802392B8
 * EN v1.1 Size: 424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a940(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a944
 * EN v1.0 Address: 0x8020A944
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80239460
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a944(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a948
 * EN v1.0 Address: 0x8020A948
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023952C
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a948(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a94c
 * EN v1.0 Address: 0x8020A94C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80239648
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a94c(int param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a954
 * EN v1.0 Address: 0x8020A954
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023969C
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a954(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a958
 * EN v1.0 Address: 0x8020A958
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8023974C
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a958(undefined4 param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a960
 * EN v1.0 Address: 0x8020A960
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023980C
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a960(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a964
 * EN v1.0 Address: 0x8020A964
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802398BC
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a964(int param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a96c
 * EN v1.0 Address: 0x8020A96C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802399B0
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a96c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a970
 * EN v1.0 Address: 0x8020A970
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80239A84
 * EN v1.1 Size: 340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a970(int param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a978
 * EN v1.0 Address: 0x8020A978
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80239BD8
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a978(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a97c
 * EN v1.0 Address: 0x8020A97C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80239C18
 * EN v1.1 Size: 600b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a97c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a980
 * EN v1.0 Address: 0x8020A980
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80239E70
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a980(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a984
 * EN v1.0 Address: 0x8020A984
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80239EDC
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a984(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a988
 * EN v1.0 Address: 0x8020A988
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80239F50
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a988(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a98c
 * EN v1.0 Address: 0x8020A98C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8023A02C
 * EN v1.1 Size: 1012b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8020a98c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a994
 * EN v1.0 Address: 0x8020A994
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023A420
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a994(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a998
 * EN v1.0 Address: 0x8020A998
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023A444
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a998(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a99c
 * EN v1.0 Address: 0x8020A99C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023A488
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a99c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9a0
 * EN v1.0 Address: 0x8020A9A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023A4D0
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9a4
 * EN v1.0 Address: 0x8020A9A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023A5A4
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9a4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9a8
 * EN v1.0 Address: 0x8020A9A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023A6C4
 * EN v1.1 Size: 412b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9a8(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9ac
 * EN v1.0 Address: 0x8020A9AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023A860
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9ac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9b0
 * EN v1.0 Address: 0x8020A9B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023A960
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9b0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int *param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9b4
 * EN v1.0 Address: 0x8020A9B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023AADC
 * EN v1.1 Size: 676b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9b4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9b8
 * EN v1.0 Address: 0x8020A9B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023AD80
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9b8(int param_1,byte param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9bc
 * EN v1.0 Address: 0x8020A9BC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8023AD9C
 * EN v1.1 Size: 472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a9bc(double param_1,double param_2,double param_3,int *param_4)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9c4
 * EN v1.0 Address: 0x8020A9C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023AF74
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9c4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9c8
 * EN v1.0 Address: 0x8020A9C8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8023B06C
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8020a9c8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9d0
 * EN v1.0 Address: 0x8020A9D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023B110
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9d0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9d4
 * EN v1.0 Address: 0x8020A9D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023B134
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9d4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9d8
 * EN v1.0 Address: 0x8020A9D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023B15C
 * EN v1.1 Size: 17624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9d8(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9dc
 * EN v1.0 Address: 0x8020A9DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023F634
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9dc(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9e0
 * EN v1.0 Address: 0x8020A9E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023F754
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9e0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9e4
 * EN v1.0 Address: 0x8020A9E4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023F8F4
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9e4(uint param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9e8
 * EN v1.0 Address: 0x8020A9E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023FA94
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9e8(int param_1,char param_2,char param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9ec
 * EN v1.0 Address: 0x8020A9EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023FB38
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9ec(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9f0
 * EN v1.0 Address: 0x8020A9F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8023FB60
 * EN v1.1 Size: 1932b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9f0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9f4
 * EN v1.0 Address: 0x8020A9F4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802402EC
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9f4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9f8
 * EN v1.0 Address: 0x8020A9F8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80240384
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9f8(int param_1,undefined param_2,char param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020a9fc
 * EN v1.0 Address: 0x8020A9FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80240408
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020a9fc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020aa00
 * EN v1.0 Address: 0x8020AA00
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80240430
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020aa00(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020aa04
 * EN v1.0 Address: 0x8020AA04
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802406D8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020aa04(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020aa08
 * EN v1.0 Address: 0x8020AA08
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80240708
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020aa08(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020aa0c
 * EN v1.0 Address: 0x8020AA0C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80240910
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020aa0c(int param_1,undefined param_2,char param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020aa10
 * EN v1.0 Address: 0x8020AA10
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80240958
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020aa10(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8020aa14
 * EN v1.0 Address: 0x8020AA14
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8024098C
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8020aa14(int param_1)
{
}
