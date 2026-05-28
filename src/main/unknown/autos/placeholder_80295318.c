#include "ghidra_import.h"
#include "main/dll/DB/DBbonedust.h"
#include "main/objanim.h"
#include "main/unknown/autos/placeholder_80295318.h"

extern undefined4 FUN_80003494();
extern undefined8 FUN_80006724();
extern undefined4 FUN_800067c0();
extern bool FUN_800067f8();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006820();
extern undefined8 FUN_80006824();
extern undefined8 FUN_80006894();
extern undefined4 FUN_800068a0();
extern undefined4 FUN_800068c4();
extern int FUN_800068dc();
extern int FUN_800068e4();
extern undefined4 FUN_800068ec();
extern undefined4 FUN_800068f0();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_800068f8();
extern undefined4 FUN_8000691c();
extern undefined4 FUN_80006920();
extern undefined4 FUN_80006928();
extern undefined4 FUN_80006974();
extern void* FUN_800069a8();
extern undefined4 FUN_800069bc();
extern double FUN_800069ec();
extern double FUN_800069f8();
extern double FUN_80006a28();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern int FUN_80006b7c();
extern undefined4 FUN_80006b84();
extern undefined4 FUN_80006b94();
extern undefined8 FUN_80006ba8();
extern char FUN_80006bc8();
extern char FUN_80006bd0();
extern ushort FUN_80006bf0();
extern uint FUN_80006bf8();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern undefined4 FUN_80017680();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern undefined4 FUN_800176c0();
extern undefined4 FUN_800176c4();
extern undefined4 FUN_800176c8();
extern double FUN_800176f4();
extern undefined4 FUN_80017700();
extern double FUN_80017714();
extern undefined4 FUN_8001771c();
extern uint FUN_80017730();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017754();
extern uint FUN_80017758();
extern undefined4 FUN_80017774();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017784();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_8001789c();
extern undefined4 FUN_800178a0();
extern undefined4 FUN_800178a4();
extern undefined4 FUN_800178a8();
extern undefined4 FUN_800178ac();
extern undefined4 FUN_800178b0();
extern undefined4 FUN_800178b4();
extern undefined4 FUN_800178ec();
extern undefined8 FUN_800178f4();
extern int FUN_8001792c();
extern byte FUN_80017a20();
extern undefined4 FUN_80017a28();
extern int FUN_80017a54();
extern undefined4 FUN_80017a78();
extern undefined4 FUN_80017a7c();
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined8 FUN_80017ab8();
extern undefined8 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern undefined4 fn_8002EE10();
extern undefined4 fn_8002EE64();
extern undefined4 fn_8002EEB8();
extern undefined4 fn_8002F304();
extern int FUN_8002f6ac();
extern undefined4 FUN_8002fc3c();
extern undefined4 FUN_800305c4();
extern undefined8 FUN_800305f8();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern ushort ObjHits_IsObjectEnabled();
extern undefined4 ObjHits_RecordObjectHit();
extern undefined4 ObjHits_RecordPositionHit();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern int Obj_IsObjectAlive();
extern undefined8 ObjLink_DetachChild();
extern undefined8 ObjLink_AttachChild();
extern undefined4 ObjPath_GetPointWorldPositionArray();
extern uint ObjPath_GetPointModelMtx();
extern undefined8 ObjPath_GetPointWorldPosition();
extern int Obj_GetYawDeltaToObject();
extern undefined4 playerEyeAnimFn_80038988();
extern int FUN_80039520();
extern undefined4 FUN_80039580();
extern int FUN_8003964c();
extern undefined4 FUN_8003b06c();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8004036c();
extern undefined4 FUN_80040374();
extern undefined4 FUN_80040434();
extern undefined4 FUN_800404cc();
extern undefined4 FUN_800480a0();
extern undefined4 FUN_80053bfc();
extern int FUN_8005b024();
extern int FUN_8005b220();
extern undefined8 FUN_8005d1e8();
extern void fn_8005D108();
extern undefined4 FUN_8005d370();
extern undefined4 FUN_800616a0();
extern undefined4 FUN_80061a80();
extern int FUN_800620e8();
extern int FUN_800632e8();
extern int FUN_800632f4();
extern ushort FUN_8006dc08();
extern undefined4 FUN_8006dca8();
extern undefined4 objAudioFn_8006ef38();
extern uint FUN_8006f764();
extern undefined4 FUN_80070ec8();
extern undefined4 FUN_80071d70();
extern undefined4 FUN_80071f8c();
extern undefined4 FUN_80071f90();
extern int FUN_8007f3c8();
extern int FUN_8007f7c0();
extern int FUN_8007f810();
extern uint FUN_80080f34();
extern undefined4 FUN_80080f3c();
extern undefined4 FUN_800810d8();
extern undefined4 FUN_800810dc();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_800810f8();
extern undefined4 FUN_80081110();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_80081120();
extern undefined4 FUN_80081124();
extern undefined4 objFn_800e64f4();
extern undefined4 objFn_800e67ac();
extern uint playerHasKrazoaSpirit();
extern undefined4 FUN_800eaeb8();
extern undefined4 camcontrol_applyState();
extern undefined4 FUN_8011daf8();
extern undefined4 FUN_8011e7bc();
extern undefined4 FUN_8011e800();
extern short FUN_8011e824();
extern undefined4 FUN_8011e844();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_8011eb10();
extern undefined4 FUN_8011eb1c();
extern undefined4 FUN_80130298();
extern undefined4 FUN_8013651c();
extern uint FUN_8014ca90();
extern undefined4 FUN_8014caf4();
extern undefined4 FUN_8014cc7c();
extern undefined4 FUN_8014ccac();
extern undefined4 FUN_8016d9a4();
extern undefined4 FUN_8016e5b0();
extern undefined4 FUN_8016e658();
extern undefined8 FUN_80170048();
extern undefined4 FUN_801829e4();
extern undefined4 FUN_8018a060();
extern byte FUN_8018a0d0();
extern undefined4 FUN_80189f5c();
extern byte FUN_8018a32c();
extern undefined4 FUN_8018a348();
extern uint FUN_8018a54c();
extern undefined4 FUN_8018a558();
extern byte FUN_8018a56c();
extern int FUN_801e1ee4();
extern undefined4 FUN_8020a718();
extern undefined4 FUN_8020a71c();
extern undefined4 FUN_8020a720();
extern undefined4 FUN_80247618();
extern undefined4 PSVECDotProduct();
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80247cd8();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double SeekTwiceBeforeRead();
extern double FUN_80247f90();
extern undefined4 FUN_8025cdec();
extern undefined4 FUN_8025d80c();
extern undefined8 FUN_8028680c();
extern undefined8 FUN_80286818();
extern undefined8 FUN_80286828();
extern undefined8 FUN_8028682c();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286858();
extern undefined4 FUN_80286864();
extern undefined4 FUN_80286874();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80293130();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_802949e8();
extern uint countLeadingZeros();

extern undefined4 DAT_802c3370;
extern undefined4 DAT_802c33d0;
extern undefined4 DAT_802c33d4;
extern undefined4 DAT_802c33d8;
extern undefined4 DAT_802c33dc;
extern undefined4 DAT_802c33e0;
extern undefined4 DAT_802c33e4;
extern undefined4 DAT_802c33e8;
extern undefined4 DAT_802c33ec;
extern undefined4 DAT_802c33f0;
extern undefined4 DAT_802c33f4;
extern undefined4 DAT_802c33f8;
extern undefined4 DAT_802c33fc;
extern undefined4 DAT_802c3400;
extern undefined4 DAT_802c3404;
extern undefined4 DAT_802c3408;
extern undefined4 DAT_802c340c;
extern undefined4 DAT_802c3410;
extern undefined4 DAT_802c3414;
extern undefined4 DAT_802c3418;
extern undefined4 DAT_802c341c;
extern undefined4 DAT_802c3420;
extern undefined4 DAT_80333688;
extern undefined4 DAT_803338d8;
extern undefined4 DAT_80333adc;
extern undefined4 DAT_80333ae0;
extern undefined4 DAT_80333ae4;
extern undefined4 DAT_80333ae8;
extern undefined4 DAT_80333aec;
extern undefined4 DAT_80333af0;
extern undefined4 DAT_80333af4;
extern undefined4 DAT_80333af8;
extern undefined4 DAT_80333afc;
extern int DAT_80333b34;
extern undefined4 DAT_80333b50;
extern undefined4 DAT_80333b54;
extern undefined4 DAT_80333b5c;
extern undefined4 DAT_80333b8c;
extern undefined4 DAT_80333b9c;
extern undefined4 DAT_80333ba4;
extern undefined4 DAT_80333ba8;
extern short DAT_80333bca;
extern undefined4 DAT_80333bcc;
extern undefined4 DAT_80333bce;
extern undefined4 DAT_80333bd0;
extern undefined4 DAT_80333bd2;
extern undefined4 DAT_80333bd4;
extern undefined2 DAT_80333bd8;
extern undefined2 DAT_80333be8;
extern undefined4 DAT_80333bf8;
extern undefined4 DAT_80333c20;
extern undefined4 DAT_80333c24;
extern undefined4 DAT_80333c38;
extern undefined4 DAT_80333c50;
extern undefined4 DAT_80333c5c;
extern undefined4 DAT_80333c80;
extern undefined4 DAT_80333c90;
extern undefined4 DAT_80333ca0;
extern undefined4 DAT_80333cb0;
extern undefined4 DAT_80333cf0;
extern undefined4 DAT_80333d30;
extern undefined4 DAT_80333d70;
extern undefined4 DAT_80333db0;
extern undefined4 DAT_80333df0;
extern undefined4 DAT_80333e30;
extern undefined4 DAT_80333e70;
extern undefined4 DAT_80333e74;
extern undefined4 DAT_80333e8c;
extern undefined4 DAT_80333eb0;
extern undefined4 DAT_80333eb8;
extern undefined4 DAT_80333f10;
extern undefined4 DAT_80333f28;
extern undefined4 DAT_80333f40;
extern undefined4 DAT_80333f58;
extern undefined4 DAT_80333f70;
extern undefined4 DAT_80334014;
extern undefined4 DAT_803340b8;
extern undefined4 DAT_80334170;
extern undefined4 DAT_80334214;
extern undefined4 DAT_803342cc;
extern undefined4 DAT_803342fc;
extern undefined4 DAT_8033431c;
extern undefined4 DAT_80334374;
extern undefined4 DAT_80334796;
extern undefined4 DAT_80334846;
extern undefined4 DAT_803348f6;
extern undefined4 DAT_803349a6;
extern short DAT_803356b4;
extern undefined4 DAT_803356d8;
extern undefined4 DAT_803356e8;
extern undefined4 DAT_803356f8;
extern undefined4 DAT_80335708;
extern undefined4 DAT_803358f4;
extern undefined4 DAT_80335b48;
extern undefined4 DAT_80335b58;
extern undefined4 DAT_80335b78;
extern undefined4 DAT_80335b88;
extern undefined4 DAT_80335ba8;
extern undefined4 DAT_80335bc4;
extern undefined4 DAT_80335bfc;
extern undefined4 DAT_80335c0c;
extern ushort DAT_80335c28;
extern undefined4 DAT_80335c38;
extern undefined4 DAT_80335d88;
extern undefined4 DAT_80335d90;
extern undefined4 DAT_803dbb50;
extern undefined4 DAT_803dbb5c;
extern undefined4 DAT_803dbb60;
extern undefined4 DAT_803dbb64;
extern undefined2 DAT_803dbb68;
extern undefined4 DAT_803dbbe8;
extern undefined4 DAT_803dbbec;
extern undefined4 DAT_803dbc18;
extern undefined4 DAT_803dbc1c;
extern undefined4 DAT_803dbc20;
extern undefined4 DAT_803dbc24;
extern undefined4 DAT_803dbc28;
extern undefined4 DAT_803dbc2c;
extern undefined4 DAT_803dbc30;
extern undefined4 DAT_803dbc34;
extern undefined4 DAT_803dbc38;
extern undefined4 DAT_803dbc3c;
extern undefined4 DAT_803dbc40;
extern undefined4 DAT_803dbc44;
extern undefined4 DAT_803dbc48;
extern undefined4 DAT_803dbc4c;
extern undefined4 DAT_803dbc50;
extern undefined4 DAT_803dbc54;
extern undefined4 DAT_803dbc58;
extern undefined4 DAT_803dbc5c;
extern undefined4 DAT_803dbc60;
extern undefined4 DAT_803dbc64;
extern undefined4 DAT_803dbc68;
extern undefined4 DAT_803dbc6c;
extern undefined4 DAT_803dbc70;
extern undefined4 DAT_803dbc74;
extern undefined4 DAT_803dbc78;
extern undefined4 DAT_803dbc7c;
extern undefined4 DAT_803dbc80;
extern undefined4 DAT_803dbc84;
extern undefined4 DAT_803dbc88;
extern undefined4 DAT_803dbc8c;
extern undefined4 DAT_803dbc90;
extern undefined4 DAT_803dbc94;
extern undefined4 DAT_803dbc98;
extern undefined4 DAT_803dbc9c;
extern undefined4 DAT_803dbca0;
extern undefined4 DAT_803dbca4;
extern undefined4 DAT_803dbca8;
extern undefined4 DAT_803dbcac;
extern undefined4 DAT_803dbcb0;
extern undefined4 DAT_803dbcb4;
extern undefined4 DAT_803dbcb8;
extern undefined4 DAT_803dbcbc;
extern undefined4 DAT_803dbcc0;
extern undefined4 DAT_803dbcc4;
extern undefined4 DAT_803dbcc8;
extern undefined4 DAT_803dbccc;
extern undefined4 DAT_803dbcd0;
extern undefined4 DAT_803dbcd4;
extern undefined4 DAT_803dbcd8;
extern undefined4 DAT_803dbcdc;
extern undefined4 DAT_803dbce0;
extern undefined4 DAT_803dbce4;
extern undefined4 DAT_803dbce8;
extern undefined4 DAT_803dbcec;
extern undefined4 DAT_803dbcf0;
extern undefined4 DAT_803dbcf4;
extern undefined4 DAT_803dbcf8;
extern undefined4 DAT_803dbcfc;
extern undefined4 DAT_803dbd00;
extern undefined4 DAT_803dbd04;
extern undefined4 DAT_803dbd08;
extern undefined4 DAT_803dbd0c;
extern undefined4 DAT_803dbd10;
extern undefined4 DAT_803dbd14;
extern undefined4 DAT_803dbd18;
extern undefined4 DAT_803dbd1c;
extern undefined4 DAT_803dbd20;
extern undefined4 DAT_803dbd24;
extern undefined4 DAT_803dbd28;
extern undefined4 DAT_803dbd2c;
extern undefined4 DAT_803dbd30;
extern undefined4 DAT_803dbd3c;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dd2b0;
extern undefined4 DAT_803dd2b4;
extern undefined4 DAT_803dd2c0;
extern undefined4 DAT_803dd2c4;
extern undefined4 DAT_803dd2d4;
extern undefined4 DAT_803dd300;
extern undefined4 DAT_803dd304;
extern undefined4 DAT_803dd308;
extern undefined4 DAT_803dd30a;
extern undefined4 DAT_803dd30c;
extern undefined4 DAT_803dd310;
extern undefined4 DAT_803dd318;
extern undefined4 DAT_803dd320;
extern undefined4 DAT_803dd32c;
extern undefined4 DAT_803dd334;
extern undefined4 DAT_803dd358;
extern undefined4 DAT_803dd35c;
extern undefined4 DAT_803dd364;
extern undefined4 DAT_803dd368;
extern undefined4 DAT_803dd370;
extern undefined4 DAT_803dd374;
extern undefined4 DAT_803dd37c;
extern undefined4 DAT_803dd380;
extern undefined4 DAT_803dd388;
extern undefined4 DAT_803dd38c;
extern undefined4 DAT_803dd3a4;
extern undefined4 DAT_803dd3a8;
extern short DAT_803dd3b0;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd704;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd734;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803ddbb4;
extern undefined4 DAT_803ddbb8;
extern undefined4 DAT_803df0a0;
extern undefined4 DAT_803df0a4;
extern undefined4 DAT_803df0a8;
extern undefined4 DAT_803df0ac;
extern undefined4* DAT_803df0b4;
extern undefined4 DAT_803df0c4;
extern undefined4 DAT_803df0c8;
extern undefined4 DAT_803df0cc;
extern float* DAT_803df0d0;
extern undefined4* DAT_803df0d4;
extern undefined4 DAT_803df0d8;
extern undefined4 DAT_803df0d9;
extern undefined4 DAT_803df0ec;
extern undefined4 DAT_803df0f0;
extern undefined4 DAT_803df0f4;
extern undefined4 DAT_803df0fc;
extern undefined4 DAT_803df100;
extern undefined4 DAT_803df104;
extern undefined4 DAT_803df10c;
extern undefined4 DAT_803df10d;
extern undefined4 DAT_803df120;
extern undefined4 DAT_803df124;
extern undefined4 DAT_803df128;
extern undefined4 DAT_803df12c;
extern undefined4 DAT_803df130;
extern undefined4 DAT_803df132;
extern undefined4 DAT_803df134;
extern undefined4 DAT_803df138;
extern undefined4 DAT_803e8b00;
extern undefined4 DAT_803e8b04;
extern undefined4 DAT_803e8b08;
extern undefined4 DAT_803e8b0c;
extern undefined4 DAT_803e8b10;
extern undefined4 DAT_803e8b14;
extern f64 DOUBLE_803e8af8;
extern f64 DOUBLE_803e8b58;
extern f64 DOUBLE_803e8bd0;
extern f64 DOUBLE_803e8c20;
extern f64 DOUBLE_803e8e30;
extern f64 DOUBLE_803e8e38;
extern f64 DOUBLE_803e8f08;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dd2b8;
extern f32 FLOAT_803dd2d8;
extern f32 FLOAT_803dd2dc;
extern f32 FLOAT_803dd2e0;
extern f32 FLOAT_803dd2e4;
extern f32 FLOAT_803dd2e8;
extern f32 FLOAT_803dd2ec;
extern f32 FLOAT_803dd328;
extern f32 FLOAT_803dd33c;
extern f32 FLOAT_803dd340;
extern f32 FLOAT_803dd344;
extern f32 FLOAT_803dd348;
extern f32 FLOAT_803dd34c;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803df0b0;
extern f32 FLOAT_803df0b8;
extern f32 FLOAT_803df0bc;
extern f32 FLOAT_803df0c0;
extern f32 FLOAT_803df0dc;
extern f32 FLOAT_803df0e0;
extern f32 FLOAT_803df0e4;
extern f32 FLOAT_803df0e8;
extern f32 FLOAT_803df0f8;
extern f32 FLOAT_803df108;
extern f32 FLOAT_803df110;
extern f32 FLOAT_803df114;
extern f32 FLOAT_803df118;
extern f32 FLOAT_803e8ae8;
extern f32 FLOAT_803e8aec;
extern f32 FLOAT_803e8af0;
extern f32 FLOAT_803e8b18;
extern f32 FLOAT_803e8b1c;
extern f32 FLOAT_803e8b20;
extern f32 FLOAT_803e8b24;
extern f32 FLOAT_803e8b28;
extern f32 FLOAT_803e8b30;
extern f32 FLOAT_803e8b34;
extern f32 FLOAT_803e8b38;
extern f32 FLOAT_803e8b3c;
extern f32 FLOAT_803e8b40;
extern f32 FLOAT_803e8b44;
extern f32 FLOAT_803e8b48;
extern f32 FLOAT_803e8b4c;
extern f32 FLOAT_803e8b54;
extern f32 FLOAT_803e8b60;
extern f32 FLOAT_803e8b64;
extern f32 FLOAT_803e8b68;
extern f32 FLOAT_803e8b6c;
extern f32 FLOAT_803e8b70;
extern f32 FLOAT_803e8b74;
extern f32 FLOAT_803e8b78;
extern f32 FLOAT_803e8b7c;
extern f32 FLOAT_803e8b80;
extern f32 FLOAT_803e8b84;
extern f32 FLOAT_803e8b88;
extern f32 FLOAT_803e8b8c;
extern f32 FLOAT_803e8b90;
extern f32 FLOAT_803e8b94;
extern f32 FLOAT_803e8b98;
extern f32 FLOAT_803e8b9c;
extern f32 FLOAT_803e8ba0;
extern f32 FLOAT_803e8ba4;
extern f32 FLOAT_803e8ba8;
extern f32 FLOAT_803e8bac;
extern f32 FLOAT_803e8bb0;
extern f32 FLOAT_803e8bb4;
extern f32 FLOAT_803e8bb8;
extern f32 FLOAT_803e8bbc;
extern f32 FLOAT_803e8bc0;
extern f32 FLOAT_803e8bc4;
extern f32 FLOAT_803e8bc8;
extern f32 FLOAT_803e8bcc;
extern f32 FLOAT_803e8bd8;
extern f32 FLOAT_803e8bdc;
extern f32 FLOAT_803e8be0;
extern f32 FLOAT_803e8be4;
extern f32 FLOAT_803e8be8;
extern f32 FLOAT_803e8bec;
extern f32 FLOAT_803e8bf0;
extern f32 FLOAT_803e8bf4;
extern f32 FLOAT_803e8bf8;
extern f32 FLOAT_803e8bfc;
extern f32 FLOAT_803e8c00;
extern f32 FLOAT_803e8c04;
extern f32 FLOAT_803e8c08;
extern f32 FLOAT_803e8c0c;
extern f32 FLOAT_803e8c10;
extern f32 FLOAT_803e8c14;
extern f32 FLOAT_803e8c18;
extern f32 FLOAT_803e8c1c;
extern f32 FLOAT_803e8c28;
extern f32 FLOAT_803e8c2c;
extern f32 FLOAT_803e8c30;
extern f32 FLOAT_803e8c34;
extern f32 FLOAT_803e8c38;
extern f32 FLOAT_803e8c3c;
extern f32 FLOAT_803e8c40;
extern f32 FLOAT_803e8c44;
extern f32 FLOAT_803e8c48;
extern f32 FLOAT_803e8c4c;
extern f32 FLOAT_803e8c50;
extern f32 FLOAT_803e8c54;
extern f32 FLOAT_803e8c58;
extern f32 FLOAT_803e8c5c;
extern f32 FLOAT_803e8c60;
extern f32 FLOAT_803e8c64;
extern f32 FLOAT_803e8c68;
extern f32 FLOAT_803e8c6c;
extern f32 FLOAT_803e8c70;
extern f32 FLOAT_803e8c74;
extern f32 FLOAT_803e8c78;
extern f32 FLOAT_803e8c7c;
extern f32 FLOAT_803e8c80;
extern f32 FLOAT_803e8c84;
extern f32 FLOAT_803e8c88;
extern f32 FLOAT_803e8c8c;
extern f32 FLOAT_803e8c90;
extern f32 FLOAT_803e8c94;
extern f32 FLOAT_803e8c98;
extern f32 FLOAT_803e8c9c;
extern f32 FLOAT_803e8ca0;
extern f32 FLOAT_803e8ca4;
extern f32 FLOAT_803e8ca8;
extern f32 FLOAT_803e8cac;
extern f32 FLOAT_803e8cb0;
extern f32 FLOAT_803e8cb4;
extern f32 FLOAT_803e8cb8;
extern f32 FLOAT_803e8cbc;
extern f32 FLOAT_803e8cc0;
extern f32 FLOAT_803e8cc4;
extern f32 FLOAT_803e8cc8;
extern f32 FLOAT_803e8ccc;
extern f32 FLOAT_803e8cd0;
extern f32 FLOAT_803e8cd4;
extern f32 FLOAT_803e8cd8;
extern f32 FLOAT_803e8cdc;
extern f32 FLOAT_803e8ce0;
extern f32 FLOAT_803e8ce4;
extern f32 FLOAT_803e8ce8;
extern f32 FLOAT_803e8cec;
extern f32 FLOAT_803e8cf0;
extern f32 FLOAT_803e8cf4;
extern f32 FLOAT_803e8cf8;
extern f32 FLOAT_803e8cfc;
extern f32 FLOAT_803e8d00;
extern f32 FLOAT_803e8d04;
extern f32 FLOAT_803e8d08;
extern f32 FLOAT_803e8d0c;
extern f32 FLOAT_803e8d10;
extern f32 FLOAT_803e8d14;
extern f32 FLOAT_803e8d18;
extern f32 FLOAT_803e8d1c;
extern f32 FLOAT_803e8d20;
extern f32 FLOAT_803e8d24;
extern f32 FLOAT_803e8d28;
extern f32 FLOAT_803e8d30;
extern f32 FLOAT_803e8d38;
extern f32 FLOAT_803e8d3c;
extern f32 FLOAT_803e8d40;
extern f32 FLOAT_803e8d44;
extern f32 FLOAT_803e8d48;
extern f32 FLOAT_803e8d4c;
extern f32 FLOAT_803e8d50;
extern f32 FLOAT_803e8d54;
extern f32 FLOAT_803e8d58;
extern f32 FLOAT_803e8d5c;
extern f32 FLOAT_803e8d64;
extern f32 FLOAT_803e8d68;
extern f32 FLOAT_803e8d70;
extern f32 FLOAT_803e8d74;
extern f32 FLOAT_803e8d78;
extern f32 FLOAT_803e8d7c;
extern f32 FLOAT_803e8d80;
extern f32 FLOAT_803e8d84;
extern f32 FLOAT_803e8d88;
extern f32 FLOAT_803e8d8c;
extern f32 FLOAT_803e8d90;
extern f32 FLOAT_803e8d94;
extern f32 FLOAT_803e8d98;
extern f32 FLOAT_803e8d9c;
extern f32 FLOAT_803e8da0;
extern f32 FLOAT_803e8da4;
extern f32 FLOAT_803e8da8;
extern f32 FLOAT_803e8dac;
extern f32 FLOAT_803e8db0;
extern f32 FLOAT_803e8db4;
extern f32 FLOAT_803e8db8;
extern f32 FLOAT_803e8dbc;
extern f32 FLOAT_803e8dc0;
extern f32 FLOAT_803e8dc4;
extern f32 FLOAT_803e8dc8;
extern f32 FLOAT_803e8dcc;
extern f32 FLOAT_803e8dd0;
extern f32 FLOAT_803e8dd4;
extern f32 FLOAT_803e8dd8;
extern f32 FLOAT_803e8ddc;
extern f32 FLOAT_803e8de0;
extern f32 FLOAT_803e8de4;
extern f32 FLOAT_803e8de8;
extern f32 FLOAT_803e8dec;
extern f32 FLOAT_803e8df0;
extern f32 FLOAT_803e8df4;
extern f32 FLOAT_803e8df8;
extern f32 FLOAT_803e8dfc;
extern f32 FLOAT_803e8e00;
extern f32 FLOAT_803e8e04;
extern f32 FLOAT_803e8e08;
extern f32 FLOAT_803e8e0c;
extern f32 FLOAT_803e8e10;
extern f32 FLOAT_803e8e14;
extern f32 FLOAT_803e8e18;
extern f32 FLOAT_803e8e1c;
extern f32 FLOAT_803e8e20;
extern f32 FLOAT_803e8e24;
extern f32 FLOAT_803e8e28;
extern f32 FLOAT_803e8e2c;
extern f32 FLOAT_803e8e40;
extern f32 FLOAT_803e8e44;
extern f32 FLOAT_803e8e48;
extern f32 FLOAT_803e8e4c;
extern f32 FLOAT_803e8e54;
extern f32 FLOAT_803e8e58;
extern f32 FLOAT_803e8e5c;
extern f32 FLOAT_803e8e64;
extern f32 FLOAT_803e8e68;
extern f32 FLOAT_803e8e6c;
extern f32 FLOAT_803e8e70;
extern f32 FLOAT_803e8e74;
extern f32 FLOAT_803e8e78;
extern f32 FLOAT_803e8e7c;
extern f32 FLOAT_803e8e80;
extern f32 FLOAT_803e8e84;
extern f32 FLOAT_803e8e88;
extern f32 FLOAT_803e8e8c;
extern f32 FLOAT_803e8e90;
extern f32 FLOAT_803e8e94;
extern f32 FLOAT_803e8e98;
extern f32 FLOAT_803e8e9c;
extern f32 FLOAT_803e8ea0;
extern f32 FLOAT_803e8ea4;
extern f32 FLOAT_803e8eac;
extern f32 FLOAT_803e8eb0;
extern f32 FLOAT_803e8eb4;
extern f32 FLOAT_803e8eb8;
extern f32 FLOAT_803e8ebc;
extern f32 FLOAT_803e8ec0;
extern f32 FLOAT_803e8ecc;
extern f32 FLOAT_803e8ed0;
extern f32 FLOAT_803e8ed4;
extern f32 FLOAT_803e8ed8;
extern f32 FLOAT_803e8edc;
extern f32 FLOAT_803e8ee0;
extern f32 FLOAT_803e8ee4;
extern f32 FLOAT_803e8ee8;
extern f32 FLOAT_803e8eec;
extern f32 FLOAT_803e8ef0;
extern f32 FLOAT_803e8ef4;
extern f32 FLOAT_803e8ef8;
extern f32 FLOAT_803e8f04;
extern f32 FLOAT_803e8f10;
extern f32 FLOAT_803e8f14;
extern f32 FLOAT_803e8f18;
extern f32 FLOAT_803e8f1c;
extern f32 FLOAT_803e8f20;
extern f32 FLOAT_803e8f24;
extern f32 FLOAT_803e8f28;
extern f32 FLOAT_803e8f2c;
extern void* PTR_LAB_803358c0;
extern void* PTR_LAB_80335920;
extern undefined4 _DAT_80333cb0;
extern f32 fRam803dd2bc;
extern f32 fRam803dd324;
extern short sRam803dd336;
extern short sRam803dd338;
extern short sRam803dd33a;

/*
 * --INFO--
 *
 * Function: FUN_80294bb8
 * EN v1.0 Address: 0x80294BB8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80295318
 * EN v1.1 Size: 1916b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80294bb8(double param_1,double param_2)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294bc0
 * EN v1.0 Address: 0x80294BC0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80295A94
 * EN v1.1 Size: 728b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294bc0(undefined4 param_1,undefined4 param_2,float *param_3,undefined4 param_4,
                 uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294bc4
 * EN v1.0 Address: 0x80294BC4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80295D6C
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294bc4(undefined4 param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294bc8
 * EN v1.0 Address: 0x80294BC8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80295DD4
 * EN v1.1 Size: 320b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294bc8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294bcc
 * EN v1.0 Address: 0x80294BCC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80295F14
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294bcc(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294bd4
 * EN v1.0 Address: 0x80294BD4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80296078
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294bd4(double param_1,int param_2,undefined4 param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294bd8
 * EN v1.0 Address: 0x80294BD8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296164
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294bd8(int param_1,undefined4 param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294be0
 * EN v1.0 Address: 0x80294BE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029628C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294be0(double param_1,double param_2,double param_3,int param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294be4
 * EN v1.0 Address: 0x80294BE4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296328
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294be4(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294bec
 * EN v1.0 Address: 0x80294BEC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296350
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294bec(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294bf4
 * EN v1.0 Address: 0x80294BF4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029636C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294bf4(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294bfc
 * EN v1.0 Address: 0x80294BFC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296384
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294bfc(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c04
 * EN v1.0 Address: 0x80294C04
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802963A0
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294c04(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c0c
 * EN v1.0 Address: 0x80294C0C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802963BC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294c0c(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c14
 * EN v1.0 Address: 0x80294C14
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802963E8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294c14(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294c18
 * EN v1.0 Address: 0x80294C18
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029641C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294c18(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c20
 * EN v1.0 Address: 0x80294C20
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296434
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_80294c20(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c28
 * EN v1.0 Address: 0x80294C28
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296444
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_80294c28(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c30
 * EN v1.0 Address: 0x80294C30
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80296454
 * EN v1.1 Size: 412b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294c30(int param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294c34
 * EN v1.0 Address: 0x80294C34
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802965F0
 * EN v1.1 Size: 460b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294c34(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294c38
 * EN v1.0 Address: 0x80294C38
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802967BC
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294c38(int param_1,undefined4 *param_2,undefined4 *param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c40
 * EN v1.0 Address: 0x80294C40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80296844
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294c40(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294c44
 * EN v1.0 Address: 0x80294C44
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80296848
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294c44(int param_1,undefined2 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294c48
 * EN v1.0 Address: 0x80294C48
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80296854
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294c48(int param_1,int *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294c4c
 * EN v1.0 Address: 0x80294C4C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029686C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80294c4c(int param_1)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c54
 * EN v1.0 Address: 0x80294C54
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296878
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294c54(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c5c
 * EN v1.0 Address: 0x80294C5C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80296884
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294c5c(undefined2 *param_1,undefined4 *param_2,undefined2 *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294c60
 * EN v1.0 Address: 0x80294C60
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80296904
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294c60(int param_1,int *param_2,undefined4 *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294c64
 * EN v1.0 Address: 0x80294C64
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80296934
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294c64(undefined2 *param_1,undefined2 param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294c68
 * EN v1.0 Address: 0x80294C68
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029695C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294c68(undefined4 param_1,byte param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294c6c
 * EN v1.0 Address: 0x80294C6C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296974
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80294c6c(int param_1)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c74
 * EN v1.0 Address: 0x80294C74
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80296980
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294c74(double param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294c78
 * EN v1.0 Address: 0x80294C78
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029698C
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294c78(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c80
 * EN v1.0 Address: 0x80294C80
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802969A0
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294c80(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c88
 * EN v1.0 Address: 0x80294C88
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296A14
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294c88(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c90
 * EN v1.0 Address: 0x80294C90
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296A6C
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294c90(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294c98
 * EN v1.0 Address: 0x80294C98
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296A88
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294c98(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294ca0
 * EN v1.0 Address: 0x80294CA0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296B74
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294ca0(int param_1,int param_2,undefined *param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294ca8
 * EN v1.0 Address: 0x80294CA8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296BA8
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_80294ca8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294cb0
 * EN v1.0 Address: 0x80294CB0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296BB8
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80294cb0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294cb8
 * EN v1.0 Address: 0x80294CB8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296BC4
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294cb8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294cc0
 * EN v1.0 Address: 0x80294CC0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80296BD4
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294cc0(int param_1,uint param_2,uint param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294cc4
 * EN v1.0 Address: 0x80294CC4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296C50
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294cc4(int param_1,uint param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294ccc
 * EN v1.0 Address: 0x80294CCC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80296C78
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294ccc(int param_1,byte param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294cd0
 * EN v1.0 Address: 0x80294CD0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296CB4
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294cd0(int param_1,uint param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294cd8
 * EN v1.0 Address: 0x80294CD8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296CCC
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80294cd8(int param_1,undefined4 *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294ce0
 * EN v1.0 Address: 0x80294CE0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296CE0
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294ce0(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294ce8
 * EN v1.0 Address: 0x80294CE8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296DFC
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294ce8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294cf0
 * EN v1.0 Address: 0x80294CF0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296E14
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294cf0(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294cf8
 * EN v1.0 Address: 0x80294CF8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296E2C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294cf8(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d00
 * EN v1.0 Address: 0x80294D00
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296E34
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294d00(int param_1,undefined4 *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d08
 * EN v1.0 Address: 0x80294D08
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296E54
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80294d08(int param_1)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d10
 * EN v1.0 Address: 0x80294D10
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296E60
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294d10(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d18
 * EN v1.0 Address: 0x80294D18
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80296E8C
 * EN v1.1 Size: 180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d18(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294d1c
 * EN v1.0 Address: 0x80294D1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80296F40
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d1c(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294d20
 * EN v1.0 Address: 0x80294D20
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80296FFC
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80294d20(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d28
 * EN v1.0 Address: 0x80294D28
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029700C
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d28(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294d2c
 * EN v1.0 Address: 0x80294D2C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802970DC
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d2c(int param_1,undefined2 *param_2,undefined2 *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294d30
 * EN v1.0 Address: 0x80294D30
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80297150
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294d30(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d38
 * EN v1.0 Address: 0x80294D38
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80297174
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294d38(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d40
 * EN v1.0 Address: 0x80294D40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80297184
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d40(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294d44
 * EN v1.0 Address: 0x80294D44
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802971EC
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294d44(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d4c
 * EN v1.0 Address: 0x80294D4C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802971FC
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d4c(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294d50
 * EN v1.0 Address: 0x80294D50
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80297234
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294d50(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d58
 * EN v1.0 Address: 0x80294D58
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80297248
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294d58(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d60
 * EN v1.0 Address: 0x80294D60
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029725C
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d60(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294d64
 * EN v1.0 Address: 0x80294D64
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802972D0
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d64(undefined4 param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294d68
 * EN v1.0 Address: 0x80294D68
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802972D8
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d68(uint param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294d6c
 * EN v1.0 Address: 0x80294D6C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80297300
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294d6c(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d74
 * EN v1.0 Address: 0x80294D74
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029731C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d74(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294d78
 * EN v1.0 Address: 0x80294D78
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80297334
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d78(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294d7c
 * EN v1.0 Address: 0x80294D7C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80297354
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d7c(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294d80
 * EN v1.0 Address: 0x80294D80
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029738C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80294d80(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d88
 * EN v1.0 Address: 0x80294D88
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802973AC
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_80294d88(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d90
 * EN v1.0 Address: 0x80294D90
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802973BC
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
byte FUN_80294d90(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294d98
 * EN v1.0 Address: 0x80294D98
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802973CC
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d98(int param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294d9c
 * EN v1.0 Address: 0x80294D9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802973E4
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294d9c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294da0
 * EN v1.0 Address: 0x80294DA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80297480
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294da0(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294da4
 * EN v1.0 Address: 0x80294DA4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80297614
 * EN v1.1 Size: 928b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294da4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294da8
 * EN v1.0 Address: 0x80294DA8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802979B4
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294da8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294dac
 * EN v1.0 Address: 0x80294DAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802979CC
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294dac(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294db0
 * EN v1.0 Address: 0x80294DB0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802979E4
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294db0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294db4
 * EN v1.0 Address: 0x80294DB4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802979FC
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294db4(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294dbc
 * EN v1.0 Address: 0x80294DBC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80297A08
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294dbc(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294dc4
 * EN v1.0 Address: 0x80294DC4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80297A14
 * EN v1.1 Size: 492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294dc4(int param_1,uint *param_2,undefined4 *param_3,undefined4 *param_4,
                 undefined4 *param_5,undefined2 *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294dc8
 * EN v1.0 Address: 0x80294DC8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80297C00
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294dc8(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294dd0
 * EN v1.0 Address: 0x80294DD0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80297F08
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294dd0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294dd8
 * EN v1.0 Address: 0x80294DD8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80297FB4
 * EN v1.1 Size: 636b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294dd8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294de0
 * EN v1.0 Address: 0x80294DE0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80298230
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294de0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294de8
 * EN v1.0 Address: 0x80294DE8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029846C
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294de8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294df0
 * EN v1.0 Address: 0x80294DF0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802986A8
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294df0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294df8
 * EN v1.0 Address: 0x80294DF8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802988E4
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294df8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e00
 * EN v1.0 Address: 0x80294E00
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80298AE0
 * EN v1.1 Size: 556b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294e00(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e08
 * EN v1.0 Address: 0x80294E08
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80298D0C
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294e08(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294e0c
 * EN v1.0 Address: 0x80294E0C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80298D5C
 * EN v1.1 Size: 808b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294e0c(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e14
 * EN v1.0 Address: 0x80294E14
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80299084
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294e14(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294e18
 * EN v1.0 Address: 0x80294E18
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802990A4
 * EN v1.1 Size: 904b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294e18(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e20
 * EN v1.0 Address: 0x80294E20
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029942C
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294e20(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e28
 * EN v1.0 Address: 0x80294E28
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802995B4
 * EN v1.1 Size: 1616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294e28(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e30
 * EN v1.0 Address: 0x80294E30
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80299C04
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294e30(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294e34
 * EN v1.0 Address: 0x80294E34
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80299C30
 * EN v1.1 Size: 1760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294e34(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e3c
 * EN v1.0 Address: 0x80294E3C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029A310
 * EN v1.1 Size: 660b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294e3c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294e40
 * EN v1.0 Address: 0x80294E40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029A5A4
 * EN v1.1 Size: 1500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294e40(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined *param_11,float *param_12,
                 undefined4 *param_13,undefined4 param_14,int param_15,int param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294e44
 * EN v1.0 Address: 0x80294E44
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029AB80
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294e44(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294e48
 * EN v1.0 Address: 0x80294E48
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029AC08
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294e48(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294e4c
 * EN v1.0 Address: 0x80294E4C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029AD44
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294e4c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,undefined4 param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e54
 * EN v1.0 Address: 0x80294E54
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029AECC
 * EN v1.1 Size: 1132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294e54(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294e58
 * EN v1.0 Address: 0x80294E58
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029B338
 * EN v1.1 Size: 964b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294e58(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,undefined4 param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e60
 * EN v1.0 Address: 0x80294E60
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029B6FC
 * EN v1.1 Size: 1824b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294e60(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294e64
 * EN v1.0 Address: 0x80294E64
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029BE1C
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294e64(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,undefined4 param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e6c
 * EN v1.0 Address: 0x80294E6C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029BF10
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294e6c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,undefined4 param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e74
 * EN v1.0 Address: 0x80294E74
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029C15C
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294e74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e7c
 * EN v1.0 Address: 0x80294E7C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029C368
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294e7c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294e80
 * EN v1.0 Address: 0x80294E80
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029C3AC
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294e80(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e88
 * EN v1.0 Address: 0x80294E88
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029C514
 * EN v1.1 Size: 2836b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294e88(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,float *param_12,
                 undefined4 *param_13,undefined4 param_14,int param_15,int param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294e8c
 * EN v1.0 Address: 0x80294E8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029D028
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294e8c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294e90
 * EN v1.0 Address: 0x80294E90
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029D128
 * EN v1.1 Size: 1384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294e90(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294e98
 * EN v1.0 Address: 0x80294E98
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029D690
 * EN v1.1 Size: 800b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294e98(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,undefined4 param_11,float *param_12,undefined4 *param_13
                ,undefined4 param_14,int param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294ea0
 * EN v1.0 Address: 0x80294EA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029D9B0
 * EN v1.1 Size: 516b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294ea0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294ea4
 * EN v1.0 Address: 0x80294EA4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029DBB4
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294ea4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294eac
 * EN v1.0 Address: 0x80294EAC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029DC20
 * EN v1.1 Size: 816b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294eac(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294eb4
 * EN v1.0 Address: 0x80294EB4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029DF50
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294eb4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294ebc
 * EN v1.0 Address: 0x80294EBC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029E060
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294ebc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294ec4
 * EN v1.0 Address: 0x80294EC4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029E1C0
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294ec4(undefined4 param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294ecc
 * EN v1.0 Address: 0x80294ECC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029E240
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294ecc(int param_1,uint *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294ed0
 * EN v1.0 Address: 0x80294ED0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029E2D0
 * EN v1.1 Size: 2180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294ed0(undefined8 param_1,undefined8 param_2,double param_3,double param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294ed4
 * EN v1.0 Address: 0x80294ED4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029EB54
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294ed4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294edc
 * EN v1.0 Address: 0x80294EDC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029ECC8
 * EN v1.1 Size: 1636b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294edc(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            uint *param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294ee4
 * EN v1.0 Address: 0x80294EE4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029F32C
 * EN v1.1 Size: 1340b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294ee4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294eec
 * EN v1.0 Address: 0x80294EEC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029F868
 * EN v1.1 Size: 1396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294eec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294ef0
 * EN v1.0 Address: 0x80294EF0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8029FDDC
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294ef0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294ef4
 * EN v1.0 Address: 0x80294EF4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8029FE44
 * EN v1.1 Size: 752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294ef4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294efc
 * EN v1.0 Address: 0x80294EFC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A0134
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294efc(undefined4 param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f04
 * EN v1.0 Address: 0x80294F04
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A0184
 * EN v1.1 Size: 1452b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294f04(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294f08
 * EN v1.0 Address: 0x80294F08
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A0730
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294f08(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294f0c
 * EN v1.0 Address: 0x80294F0C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A0820
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294f0c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294f10
 * EN v1.0 Address: 0x80294F10
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A0840
 * EN v1.1 Size: 732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,short *param_13,undefined4 param_14,
            undefined4 param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f18
 * EN v1.0 Address: 0x80294F18
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A0B1C
 * EN v1.1 Size: 708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f18(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,short *param_13,undefined4 param_14,
            undefined4 param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f20
 * EN v1.0 Address: 0x80294F20
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A0DE0
 * EN v1.1 Size: 2708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294f20(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294f24
 * EN v1.0 Address: 0x80294F24
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A1874
 * EN v1.1 Size: 736b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f24(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,uint *param_10)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f2c
 * EN v1.0 Address: 0x80294F2C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A1B54
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294f2c(uint param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294f30
 * EN v1.0 Address: 0x80294F30
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A1C58
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f30(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 *param_13,undefined4 param_14,
            undefined4 param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f38
 * EN v1.0 Address: 0x80294F38
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A1E2C
 * EN v1.1 Size: 1500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f38(double param_1,double param_2,double param_3,double param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f40
 * EN v1.0 Address: 0x80294F40
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A2408
 * EN v1.1 Size: 3184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f40(undefined8 param_1,undefined8 param_2,double param_3,double param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,float *param_12,short *param_13,undefined4 param_14,
            undefined4 param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f48
 * EN v1.0 Address: 0x80294F48
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A3078
 * EN v1.1 Size: 1480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294f48(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294f4c
 * EN v1.0 Address: 0x80294F4C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A3640
 * EN v1.1 Size: 2060b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f4c(double param_1,undefined8 param_2,double param_3,double param_4,double param_5,
            double param_6,undefined8 param_7,undefined8 param_8,short *param_9,uint *param_10,
            undefined4 param_11,int param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f54
 * EN v1.0 Address: 0x80294F54
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A3E4C
 * EN v1.1 Size: 1048b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f54(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            short *param_9,uint *param_10,undefined4 param_11,undefined4 param_12,
            undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f5c
 * EN v1.0 Address: 0x80294F5C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A4264
 * EN v1.1 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f5c(short *param_1,uint *param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f64
 * EN v1.0 Address: 0x80294F64
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A4684
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f64(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f6c
 * EN v1.0 Address: 0x80294F6C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A48EC
 * EN v1.1 Size: 2108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294f6c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294f70
 * EN v1.0 Address: 0x80294F70
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A5128
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f70(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f78
 * EN v1.0 Address: 0x80294F78
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A52D8
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f78(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f80
 * EN v1.0 Address: 0x80294F80
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A5494
 * EN v1.1 Size: 600b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f80(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f88
 * EN v1.0 Address: 0x80294F88
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A56EC
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f88(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f90
 * EN v1.0 Address: 0x80294F90
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A57A8
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294f90(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294f98
 * EN v1.0 Address: 0x80294F98
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A58AC
 * EN v1.1 Size: 568b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294f98(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294f9c
 * EN v1.0 Address: 0x80294F9C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A5AE4
 * EN v1.1 Size: 4880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80294f9c(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
                uint *param_10,undefined4 param_11,float *param_12,undefined4 *param_13,
                undefined4 param_14,undefined4 param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294fa4
 * EN v1.0 Address: 0x80294FA4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A6DF4
 * EN v1.1 Size: 2764b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294fa4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294fa8
 * EN v1.0 Address: 0x80294FA8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A78C0
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294fa8(undefined4 param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294fb0
 * EN v1.0 Address: 0x80294FB0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A7940
 * EN v1.1 Size: 708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294fb0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,float *param_12,
                 float *param_13,uint param_14,uint param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294fb4
 * EN v1.0 Address: 0x80294FB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A7C04
 * EN v1.1 Size: 3348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294fb4(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,uint param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294fb8
 * EN v1.0 Address: 0x80294FB8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A8918
 * EN v1.1 Size: 408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294fb8(int param_1,int param_2,float *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294fbc
 * EN v1.0 Address: 0x80294FBC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A8AB0
 * EN v1.1 Size: 816b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294fbc(int param_1,int param_2,int param_3,char *param_4,int param_5)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294fc4
 * EN v1.0 Address: 0x80294FC4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A8DE0
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80294fc4(undefined4 param_1,int param_2,int param_3,undefined4 *param_4,int param_5,int param_6)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294fcc
 * EN v1.0 Address: 0x80294FCC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A8F2C
 * EN v1.1 Size: 1816b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294fcc(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 float *param_5,float *param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294fd0
 * EN v1.0 Address: 0x80294FD0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A9644
 * EN v1.1 Size: 1296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294fd0(undefined4 param_1,undefined4 param_2,int *param_3,float *param_4,float *param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294fd4
 * EN v1.0 Address: 0x80294FD4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A9B54
 * EN v1.1 Size: 740b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294fd4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294fd8
 * EN v1.0 Address: 0x80294FD8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802A9E38
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80294fd8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80294fdc
 * EN v1.0 Address: 0x80294FDC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802A9F30
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294fdc(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294fe4
 * EN v1.0 Address: 0x80294FE4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802AA05C
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294fe4(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294fec
 * EN v1.0 Address: 0x80294FEC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802AA16C
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294fec(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294ff4
 * EN v1.0 Address: 0x80294FF4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802AA27C
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294ff4(int param_1,int param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80294ffc
 * EN v1.0 Address: 0x80294FFC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802AA36C
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80294ffc(int param_1,int param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295004
 * EN v1.0 Address: 0x80295004
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AA46C
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295004(undefined4 param_1,undefined4 param_2,undefined2 *param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,int param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295008
 * EN v1.0 Address: 0x80295008
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AA774
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295008(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8029500c
 * EN v1.0 Address: 0x8029500C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AAA10
 * EN v1.1 Size: 512b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8029500c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295010
 * EN v1.0 Address: 0x80295010
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AAC10
 * EN v1.1 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295010(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295014
 * EN v1.0 Address: 0x80295014
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AB030
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295014(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295018
 * EN v1.0 Address: 0x80295018
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AB1E0
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295018(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8029501c
 * EN v1.0 Address: 0x8029501C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AB344
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8029501c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295020
 * EN v1.0 Address: 0x80295020
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AB4A4
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295020(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295024
 * EN v1.0 Address: 0x80295024
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AB6E0
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295024(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295028
 * EN v1.0 Address: 0x80295028
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AB930
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295028(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8029502c
 * EN v1.0 Address: 0x8029502C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802ABAEC
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8029502c(uint param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295030
 * EN v1.0 Address: 0x80295030
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802ABD04
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295030(int param_1,int param_2,uint param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295034
 * EN v1.0 Address: 0x80295034
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802ABDF0
 * EN v1.1 Size: 1112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295034(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295038
 * EN v1.0 Address: 0x80295038
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AC248
 * EN v1.1 Size: 1236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295038(double param_1,undefined4 param_2,int param_3,int param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8029503c
 * EN v1.0 Address: 0x8029503C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AC71C
 * EN v1.1 Size: 880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8029503c(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295040
 * EN v1.0 Address: 0x80295040
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802ACA8C
 * EN v1.1 Size: 1200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295040(undefined4 param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295044
 * EN v1.0 Address: 0x80295044
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802ACF3C
 * EN v1.1 Size: 2600b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80295044(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                short *param_9,int param_10,int param_11,float *param_12,undefined4 *param_13,
                undefined4 param_14,undefined4 param_15,int param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8029504c
 * EN v1.0 Address: 0x8029504C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AD964
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8029504c(undefined4 param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295050
 * EN v1.0 Address: 0x80295050
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802ADA54
 * EN v1.1 Size: 2324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80295050(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            short *param_9,int param_10,int param_11,int param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295058
 * EN v1.0 Address: 0x80295058
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802AE368
 * EN v1.1 Size: 632b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80295058(uint param_1,int param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295060
 * EN v1.0 Address: 0x80295060
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AE5E0
 * EN v1.1 Size: 1536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295060(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295064
 * EN v1.0 Address: 0x80295064
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802AEBE0
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80295064(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8029506c
 * EN v1.0 Address: 0x8029506C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AEDB0
 * EN v1.1 Size: 492b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8029506c(uint param_1,int param_2,int param_3,undefined4 param_4,undefined4 param_5,
                 undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295070
 * EN v1.0 Address: 0x80295070
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AEF9C
 * EN v1.1 Size: 396b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295070(uint param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295074
 * EN v1.0 Address: 0x80295074
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AF128
 * EN v1.1 Size: 868b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295074(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,int param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295078
 * EN v1.0 Address: 0x80295078
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AF48C
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295078(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,int param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8029507c
 * EN v1.0 Address: 0x8029507C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AF694
 * EN v1.1 Size: 1244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8029507c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295080
 * EN v1.0 Address: 0x80295080
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AFB70
 * EN v1.1 Size: 1000b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295080(short *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295084
 * EN v1.0 Address: 0x80295084
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802AFF58
 * EN v1.1 Size: 788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295084(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295088
 * EN v1.0 Address: 0x80295088
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B026C
 * EN v1.1 Size: 2912b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295088(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8029508c
 * EN v1.0 Address: 0x8029508C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B0DCC
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8029508c(uint param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295090
 * EN v1.0 Address: 0x80295090
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B0F38
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295090(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295094
 * EN v1.0 Address: 0x80295094
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B1080
 * EN v1.1 Size: 1412b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295094(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295098
 * EN v1.0 Address: 0x80295098
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B1604
 * EN v1.1 Size: 2584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295098(short *param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8029509c
 * EN v1.0 Address: 0x8029509C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B201C
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8029509c(double param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950a0
 * EN v1.0 Address: 0x802950A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B2158
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950a0(double param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950a4
 * EN v1.0 Address: 0x802950A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B2288
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950a4(double param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950a8
 * EN v1.0 Address: 0x802950A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B2358
 * EN v1.1 Size: 612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950a8(int param_1,int param_2,uint *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950ac
 * EN v1.0 Address: 0x802950AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B25BC
 * EN v1.1 Size: 1600b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950ac(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950b0
 * EN v1.0 Address: 0x802950B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B2BFC
 * EN v1.1 Size: 2312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950b0(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10
                 ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
                 undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950b4
 * EN v1.0 Address: 0x802950B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B3504
 * EN v1.1 Size: 7416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,float *param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950b8
 * EN v1.0 Address: 0x802950B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B51FC
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950b8(undefined4 param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950bc
 * EN v1.0 Address: 0x802950BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B5378
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950bc(undefined8 param_1,short *param_2,uint *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950c0
 * EN v1.0 Address: 0x802950C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B5540
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950c0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950c4
 * EN v1.0 Address: 0x802950C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B5638
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950c4(int param_1,char param_2,char param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950c8
 * EN v1.0 Address: 0x802950C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B5830
 * EN v1.1 Size: 1904b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950c8(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950cc
 * EN v1.0 Address: 0x802950CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B5FA0
 * EN v1.1 Size: 2244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950cc(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950d0
 * EN v1.0 Address: 0x802950D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B6864
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950d0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950d4
 * EN v1.0 Address: 0x802950D4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B68F0
 * EN v1.1 Size: 2372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950d4(short *param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950d8
 * EN v1.0 Address: 0x802950D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B7234
 * EN v1.1 Size: 1140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950dc
 * EN v1.0 Address: 0x802950DC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B76A8
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950dc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950e0
 * EN v1.0 Address: 0x802950E0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B76C8
 * EN v1.1 Size: 816b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950e0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950e4
 * EN v1.0 Address: 0x802950E4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802B79F8
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_802950e4(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802950ec
 * EN v1.0 Address: 0x802950EC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B7ABC
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802950ec(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802950f0
 * EN v1.0 Address: 0x802950F0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802B7C24
 * EN v1.1 Size: 992b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_802950f0(int param_1,int param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802950f8
 * EN v1.0 Address: 0x802950F8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802B8004
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802950f8(undefined8 param_1,short *param_2,int param_3,undefined4 param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8,undefined4 param_9)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295100
 * EN v1.0 Address: 0x80295100
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802B826C
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80295100(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295108
 * EN v1.0 Address: 0x80295108
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802B8350
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80295108(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295110
 * EN v1.0 Address: 0x80295110
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B8488
 * EN v1.1 Size: 992b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295110(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295114
 * EN v1.0 Address: 0x80295114
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B8868
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295114(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295118
 * EN v1.0 Address: 0x80295118
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B89DC
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295118(int param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8029511c
 * EN v1.0 Address: 0x8029511C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B8AC0
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8029511c(uint param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295120
 * EN v1.0 Address: 0x80295120
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B8C30
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295120(undefined2 *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295124
 * EN v1.0 Address: 0x80295124
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B8D44
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295124(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295128
 * EN v1.0 Address: 0x80295128
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B8E18
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295128(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8029512c
 * EN v1.0 Address: 0x8029512C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B8FC4
 * EN v1.1 Size: 516b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8029512c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295130
 * EN v1.0 Address: 0x80295130
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B91C8
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295130(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295134
 * EN v1.0 Address: 0x80295134
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B9268
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295134(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295138
 * EN v1.0 Address: 0x80295138
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B92AC
 * EN v1.1 Size: 1428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295138(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8029513c
 * EN v1.0 Address: 0x8029513C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802B9840
 * EN v1.1 Size: 1708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8029513c(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295140
 * EN v1.0 Address: 0x80295140
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802B9EEC
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80295140(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295148
 * EN v1.0 Address: 0x80295148
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BA050
 * EN v1.1 Size: 980b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80295148(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            short *param_9,uint *param_10,undefined4 param_11,undefined4 param_12,
            undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295150
 * EN v1.0 Address: 0x80295150
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BA424
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80295150(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295158
 * EN v1.0 Address: 0x80295158
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BA598
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80295158(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295160
 * EN v1.0 Address: 0x80295160
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BA720
 * EN v1.1 Size: 532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80295160(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295168
 * EN v1.0 Address: 0x80295168
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BA934
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80295168(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295170
 * EN v1.0 Address: 0x80295170
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BAB4C
 * EN v1.1 Size: 756b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80295170(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80295174
 * EN v1.0 Address: 0x80295174
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BAE40
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80295174(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8029517c
 * EN v1.0 Address: 0x8029517C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BAF4C
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8029517c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295184
 * EN v1.0 Address: 0x80295184
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BB098
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80295184(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8029518c
 * EN v1.0 Address: 0x8029518C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BB1B4
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8029518c(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80295194
 * EN v1.0 Address: 0x80295194
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BB314
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80295194(int param_1)
{
    return 0;
}

/* Pattern wrappers. */
void fn_802960E4(void) {}
int fn_80297498(void) { return 0x0; }
int fn_80297824(void) { return 0x0; }
void DIMSnowHorn1_func23(void) {}
int fn_802B9784(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
int fn_80295CE4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return (*(u8 *)((char *)inner + 0x3f4) >> 6) & 1;
}

void fn_802960E8(void *playerObj, s16 p2)
{
    int inner = *(int *)((char *)playerObj + 0xb8);
    *(s16 *)((char *)inner + 0x81c) = p2;
}

void fn_802960F4(int obj, int *out)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (out == NULL) {
        return;
    }
    *out = (int)((char *)inner + 0x3c4);
}

f32 fn_8029610C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(f32 *)((char *)inner + 0x280);
}

int fn_80296118(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(int *)((char *)inner + 0x2d0);
}

f32 fn_80296214(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(f32 *)((char *)inner + 0x784);
}

void fn_80296220(int obj, f32 v)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(f32 *)((char *)inner + 0x784) = v;
}

int fn_8029622C(int obj)
{
    return (*(u16 *)((char *)obj + 0xb0) & 0x1000) == 0;
}

int fn_80296448(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return (*(u8 *)((char *)inner + 0x3f0) >> 5) & 1;
}

int fn_80296464(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(int *)((char *)inner + 0x360) & 1;
}
#pragma peephole reset
#pragma scheduling reset

typedef struct {
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 b10 : 1;
    u8 b08 : 1;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} ByteFlags;

extern u8 lbl_803DE459;
extern f32 lbl_803E7EA4;
extern f32 lbl_803E7ED4;
extern f32 lbl_803E7F08;
extern void *lbl_803DE44C;
extern u8 lbl_803DC66C;
extern void objSetAnimField48to0(int *obj);
extern s16 *objModelGetVecFn_800395d8(int obj, int idx);
extern f32 lbl_803E7EE0;
extern f32 lbl_803E7EF0;
extern int getCurSeqNo(void);
extern void setTimeStop(int x);
extern void cutsceneEnterExit(int a, int b);
extern int *gCameraInterface;
extern void fn_802AB5A4(int a, int b, int c);
extern f32 lbl_803E8060;
extern f32 lbl_803E7F4C;
extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);
extern void Obj_FreeObject(int obj);
extern int *gBaddieControlInterface;
extern int fn_802AC7DC(int a, int b, int c);
extern int lbl_80332EC0[];
extern f32 lbl_803E80EC;
extern void *lbl_80332ED4[];
extern u8 lbl_803DE42C;
extern void *lbl_803DE454;
extern f32 lbl_803E7F6C;
extern f32 lbl_803E7FD4;
extern f32 lbl_803E7FCC;
extern void Resource_Release(void *handle);
extern void showDeathMenu(void);

#pragma scheduling off
#pragma peephole off
int fn_80295BF0(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(u8 *)((char *)inner + 0x8c8) != 0x44;
}

int fn_80295C0C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return ((*(u8 *)((char *)inner + 0x3f0) >> 1) & 1) == 0;
}

int fn_80295C24(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(f32 *)((char *)inner + 0x87c) > lbl_803E7EA4;
}

int fn_80295C40(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(f32 *)((char *)inner + 0x838) > lbl_803E7ED4;
}

int fn_80295CBC(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)inner + 0x274) == 0x13;
}

void fn_802961FC(int a, u8 type)
{
    if (type > 2) {
        lbl_803DE459 = 0;
    }
}

int fn_8029630C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)inner + 0x274) != 0x26;
}

int fn_8029669C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)inner + 0x274) == 7;
}

int fn_802966B4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)inner + 0x274) == 6;
}

void fn_80296BBC(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(int *)((char *)inner + 0x360) &= ~2;
}

void fn_80296C6C(int obj, int flag)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ((ByteFlags *)((char *)inner + 0x3f3))->b02 = flag;
}

void fn_80297254(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ((ByteFlags *)((char *)inner + 0x3f2))->b20 = 1;
}

void fn_8029726C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ((ByteFlags *)((char *)inner + 0x3f2))->b40 = 1;
}

void fn_80297284(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ((ByteFlags *)((char *)inner + 0x3f2))->b80 = 1;
}
#pragma peephole reset
#pragma scheduling reset

extern int lbl_803DE424;

#pragma scheduling off
#pragma peephole off
int fn_802966CC(int obj)
{
    return *(int *)((char *)obj + 0xc8);
}

void fn_80296B70(int v)
{
    lbl_803DE424 = v;
}

f32 fn_802966F4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(f32 *)((char *)inner + 0x778);
}

int fn_802972A8(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(int *)((char *)inner + 0x7f0);
}

int EmissionController_IsLingering(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(u8 *)((char *)inner + 0x8c5);
}

uint playerGetStateFlag310(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(int *)((char *)inner + 0x310);
}

int fn_80296A14(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)*(int *)((char *)inner + 0x35c) + 4);
}

int fn_80296A8C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)*(int *)((char *)inner + 0x35c) + 6);
}

int fn_80296C4C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return (*(u8 *)((char *)inner + 0x3f3) >> 1) & 1;
}

int fn_80296C5C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return (*(u8 *)((char *)inner + 0x3f3) >> 2) & 1;
}

int fn_8029656C(int obj, f32 *out)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *out = *(f32 *)((char *)inner + 0x77c);
    return *(u8 *)((char *)inner + 0x8c4);
}

int fn_80296AD4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s8 *)((char *)*(int *)((char *)inner + 0x35c) + 1);
}

int fn_80296AE8(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s8 *)((char *)*(int *)((char *)inner + 0x35c));
}

int playerGetMoney(void *player)
{
    int inner = *(int *)((char *)player + 0xb8);
    return *(u8 *)((char *)*(int *)((char *)inner + 0x35c) + 8);
}

int playerIsDisguised(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return (*(u8 *)((char *)inner + 0x3f3) >> 3) & 1;
}

int objGetAnimStateFlags(int obj, int flag)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s8 *)((char *)*(int *)((char *)inner + 0x35c) + 2) & flag;
}

int objGetAnimState80A(void *obj)
{
    void *inner = *(void **)((char *)obj + 0xb8);
    if (inner != NULL) {
        return *(s16 *)((char *)inner + 0x80a);
    }
    return 0;
}

int lightfoot_getExtraSize(void)
{
    return 0x440;
}

int lightfoot_getObjectTypeId(void)
{
    return 0x14b;
}

void cameraGetPrevPos2(int obj, f32 *x, f32 *y, f32 *z)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *x = *(f32 *)((char *)inner + 0x24);
    *y = *(f32 *)((char *)inner + 0x28);
    *z = *(f32 *)((char *)inner + 0x2c);
}

void lightfoot_hitDetect(void)
{
}

void lightfoot_release(void)
{
}
#pragma peephole reset
#pragma scheduling reset

extern void playerInitFuncPtrs(int obj);
extern void fn_802AB38C(int a, int b, int c);
extern int lbl_80333250[];
extern int lbl_80333050[];
extern f32 lbl_803E7EDC;

#pragma scheduling off
#pragma peephole off
int fn_802966D4(int obj, int *out)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *out = *(int *)((char *)inner + 0x7f8);
    return *(int *)((char *)inner + 0x7f8) != 0;
}

int fn_80296C2C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s8 *)((char *)*(int *)((char *)inner + 0x35c)) > 0;
}

void fn_80298924(int obj)
{
    ObjHits_SyncObjectPositionIfDirty(obj);
}

void fn_802A00C0(int obj)
{
    ObjHits_SyncObjectPositionIfDirty(obj);
}

void fn_802A49A8(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(int *)((char *)inner + 0x400) = (int)lbl_80333250;
    *(int *)((char *)inner + 0x3f8) = (int)lbl_80333050;
}

void fn_802B6F48(int obj)
{
    playerInitFuncPtrs(obj);
}

int fn_802969F0(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (((ByteFlags *)((char *)inner + 0x3f1))->b01) {
        return *(u8 *)((char *)inner + 0x86c);
    }
    return -1;
}

void fn_802961D4(int obj, int v)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(s16 *)((char *)obj + 0) = v;
    *(s16 *)((char *)inner + 0x478) = v;
    *(s16 *)((char *)inner + 0x484) = v;
    *(int *)((char *)inner + 0x360) |= 0x800000;
}

void fn_80296B78(int obj, int p2)
{
    fn_802AB38C(obj, *(int *)((char *)obj + 0xb8), p2);
}

void fn_8029782C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(int *)((char *)inner + 0x360) |= 0x800000;
    ((ByteFlags *)((char *)inner + 0x3f6))->b20 = 0;
}

int objIsCurModelNotZero(void *obj)
{
    if (obj != NULL) {
        return *(s8 *)((char *)obj + 0xad) != 0;
    }
    return 0;
}

int playerHasSpell(int obj, int spell)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if ((u32)spell > 0xb) {
        return 0;
    }
    return *(u8 *)((char *)inner + 0x8c7) & (1 << spell);
}

int fn_80295C5C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    return *(s16 *)((char *)inner + 0x274) == 0x36 &&
           ((ByteFlags *)((char *)inner + 0x3f3))->b10;
}

int objFn_80296700(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0x8b3) != 0 && *(u8 *)((char *)inner + 0x8b4) != 0) {
        return 1;
    }
    return 0;
}

void fn_802961A4(int obj, int *out1, f32 *out2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *out1 = *(s16 *)((char *)obj + 0xa0);
    if (*(s16 *)((char *)inner + 0x274) == 0x26) {
        *out2 = *(f32 *)((char *)inner + 0x7d8);
    } else {
        *out2 = *(f32 *)((char *)inner + 0x7d4);
    }
}

void playerLock(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (p2 != 0) {
        *(int *)((char *)inner + 0x360) |= 0x200000;
    } else {
        *(int *)((char *)inner + 0x360) &= ~0x200000;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void GameBit_Set(int bit, int value);
extern void playerDie(int obj);
extern void Sfx_PlayFromObject(int obj, int id);
extern s16 lbl_80334A54[];
extern int lbl_803DB0DC[];
extern int lbl_803DB0D0[];
extern f32 lbl_803E7EE4;
extern f32 lbl_803E7EE8;
extern f32 lbl_803E7EEC;
extern void fn_802B8108(void);
extern void fn_802B7D28(void);
extern void fn_802B7BF0(void);
extern void fn_802B7B0C(void);
extern void fn_802B78A4(void);
extern void fn_802B74C4(void);
extern void fn_802B735C(void);
extern int fn_802B7298(int obj, int p2);

#pragma scheduling off
#pragma peephole off
void fn_80296A9C(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int deref = *(int *)((char *)inner + 0x35c);
    int v = *(s16 *)((char *)deref + 6) + p2;
    if (v < 0) {
        v = 0;
    } else if (v > 0x64) {
        v = 0x64;
    }
    *(s16 *)((char *)deref + 6) = (s16)v;
}

void fn_80296518(int obj, int flag, int set)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (set != 0) {
        *(s8 *)((char *)*(int *)((char *)inner + 0x35c) + 2) |= flag;
    } else {
        *(s8 *)((char *)*(int *)((char *)inner + 0x35c) + 2) &= ~flag;
    }
}

u8 fn_80296414(int obj, int p2, u8 *out)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *out = *(u8 *)((char *)inner + 0x682);
    return *(s16 *)((char *)inner + 0x274) == 0x1c &&
           *(u32 *)((char *)inner + 0x67c) == (u32)p2;
}

int fn_80295C88(int obj)
{
    f32 dist = lbl_803E7EDC;
    return ObjGroup_FindNearestObject(0x30, obj, &dist);
}

void fn_8029697C(int obj, s16 *out1, s16 *out2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *out1 = lbl_803E7EE4 * *(f32 *)((char *)inner + 0x7b8);
    if (*(void **)((char *)inner + 0x7f0) != NULL) {
        *out2 = lbl_803E7EE8 * *(f32 *)((char *)inner + 0x7bc);
    } else {
        *out2 = lbl_803E7EEC * *(f32 *)((char *)inner + 0x7bc);
    }
}

void playerAddHealth(int obj, int amount)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int deref = *(int *)((char *)inner + 0x35c);
    int h = *(s8 *)((char *)deref);
    h += amount;
    if (h < 0) {
        h = 0;
    } else if (h > *(s8 *)((char *)deref + 1)) {
        h = *(s8 *)((char *)deref + 1);
    }
    *(s8 *)((char *)deref) = (s8)h;
    if (*(s8 *)((char *)*(int *)((char *)inner + 0x35c)) <= 0) {
        playerDie(obj);
    }
}

void playerAddRemoveMagic(int obj, int amount)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int deref = *(int *)((char *)inner + 0x35c);
    int m = *(s16 *)((char *)deref + 4);
    m += amount;
    if (m < 0) {
        m = 0;
    } else if (m > *(s16 *)((char *)deref + 6)) {
        m = *(s16 *)((char *)deref + 6);
    }
    *(s16 *)((char *)deref + 4) = (s16)m;
    if (amount > 0) {
        Sfx_PlayFromObject(0, 0x21c);
    }
}

void fn_802994A4(int obj)
{
    *(s16 *)((char *)*(int *)((char *)obj + 0xb8) + 0x80a) = -1;
    ObjHits_SyncObjectPositionIfDirty(obj);
}

void lightfoot_initialise(void)
{
    lbl_803DB0DC[0] = (int)fn_802B8108;
    lbl_803DB0DC[1] = (int)fn_802B7D28;
    lbl_803DB0DC[2] = (int)fn_802B7BF0;
    lbl_803DB0DC[3] = (int)fn_802B7B0C;
    lbl_803DB0DC[4] = (int)fn_802B78A4;
    lbl_803DB0D0[0] = (int)fn_802B74C4;
    lbl_803DB0D0[1] = (int)fn_802B735C;
    lbl_803DB0D0[2] = (int)fn_802B7298;
}

int objFn_802962b4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ByteFlags *f = (ByteFlags *)((char *)inner + 0x3f0);
    s16 s;
    if (f->b04 || f->b08 || f->b10) {
        return 0;
    }
    s = *(s16 *)((char *)inner + 0x274);
    if (s == 1 || s == 2) {
        return 1;
    }
    return 0;
}

int fn_80296240(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ByteFlags *f = (ByteFlags *)((char *)inner + 0x3f0);
    s16 s;
    if (f->b04 || f->b08 || f->b20 || f->b10 ||
        ((ByteFlags *)((char *)inner + 0x3f3))->b08) {
        return 0;
    }
    s = *(s16 *)((char *)inner + 0x274);
    if (s == 1 || s == 2) {
        return 1;
    }
    return 0;
}

void fn_80296474(int obj, int spell, int set)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if ((u32)spell > 0xb) {
        return;
    }
    if (set != 0) {
        *(u8 *)((char *)inner + 0x8c7) |= (1 << spell);
    } else {
        *(u8 *)((char *)inner + 0x8c7) &= ~(1 << spell);
    }
    GameBit_Set(lbl_80334A54[spell], set);
}

void fn_802A4B4C(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    void *p = *(void **)((char *)inner + 0x7f8);
    if (p != NULL) {
        *(int *)((char *)p + 0xf8) = 1;
        *(int *)((char *)inner + 0x360) |= 0x800000;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern uint GameBit_Get(int bit);
extern void fn_802A514C(void);

#pragma scheduling off
#pragma peephole off
void fn_802985AC(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    ((ByteFlags *)((char *)inner + 0x3f4))->b20 = 0;
    *(f32 *)((char *)inner + 0x414) = lbl_803E7EA4;
    ((ByteFlags *)((char *)inner + 0x3f3))->b10 = 0;
    *(s16 *)((char *)inner + 0x80a) = -1;
    ObjHits_SyncObjectPositionIfDirty(obj);
}

int fn_8029F9D4(int p1, int state)
{
    if (GameBit_Get(0x2d0)) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return -1;
    }
    return 0;
}

int fn_80297748(int p1, int obj)
{
    if (*(s8 *)((char *)obj + 0x27a) != 0) {
        *(u8 *)((char *)obj + 0x357) = 0;
    }
    *(u8 *)((char *)obj + 0x357) += 1;
    if (*(s8 *)((char *)obj + 0x346) != 0 && *(s8 *)((char *)obj + 0x357) > 0x1e) {
        *(int *)((char *)obj + 0x308) = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

int fn_8029852C(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u8 v;
    ((ByteFlags *)((char *)inner + 0x3f6))->b20 = 1;
    v = *(u8 *)((char *)state + 0x34b);
    if (v == 3) {
        *(int *)((char *)state + 0x308) = (int)fn_8029782C;
        return 0x3c;
    }
    if (v == 4) {
        *(int *)((char *)state + 0x308) = (int)fn_8029782C;
        return 0x3e;
    }
    if (v == 1) {
        *(int *)((char *)state + 0x308) = (int)fn_8029782C;
        return 0x3b;
    }
    *(int *)((char *)state + 0x308) = (int)fn_8029782C;
    return 0x39;
}

int fn_802A2E8C(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 fz;
    *(int *)((char *)inner + 0x360) &= ~2;
    *(int *)((char *)inner + 0x360) |= 0x2000;
    *(int *)((char *)p2 + 4) |= 0x100000;
    fz = lbl_803E7EA4;
    *(f32 *)((char *)p2 + 0x280) = fz;
    *(f32 *)((char *)p2 + 0x284) = fz;
    *(int *)((char *)p2 + 0) |= 0x200000;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    return 0;
}

int fn_802977A8(int obj, int state)
{
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0xe, lbl_803E7EA4, 0);
        *(s8 *)((char *)state + 0x346) = 0;
    }
    *(f32 *)((char *)state + 0x2a0) = lbl_803E7F08;
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = 0;
        return 0x41;
    }
    return 0;
}

int fn_8029D454(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)state + 0x34d) = 3;
    if (*(s8 *)((char *)*(int *)((char *)inner + 0x35c)) > 0) {
        ObjAnim_SetCurrentMove(obj, 0xc8, lbl_803E7EA4, 0);
        *(int *)((char *)state + 0x308) = 0;
        return -0x21;
    }
    return 0;
}

int fn_8029B994(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u32 b;
    if ((*(int *)((char *)state + 0x31c) & 0x100) != 0) {
        b = (*(u8 *)((char *)inner + 0x3f4) >> 6) & 1;
        if (b != 0) {
            if (lbl_803DE44C != NULL && b != 0) {
                *(u8 *)((char *)inner + 0x8b4) = 4;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
            }
            *(int *)((char *)state + 0x308) = 0;
            return 0x32;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern int ObjAnim_SetCurrentMove(int obj, int moveId, f32 blend, int flag);
extern void ObjModel_SampleJointTransform(int model, int a, int b, f32 blend, f32 frame, void *out1, void *out2);
extern void fn_8014C540(int obj, void *a, void *b, void *c);
extern void fn_802AA2B0(int obj, int state, f32 a, f32 b);
extern void objHitDetectFn_80062e84(int obj, int a, int b);
extern void staffFn_80170380(int a, int b);
extern f32 PSVECMag(f32 *v);
extern void PSVECScale(f32 *dst, f32 *src, f32 s);
extern f32 fn_80293E80(f32 x);
extern f32 sin(f32 x);
extern f32 lbl_803E7F94;
extern f32 lbl_803E7F98;
extern f32 lbl_803DE460;
extern f32 lbl_803DE464;
extern int arrayIndexOf(void *arr, int count, int val);
extern void objRenderFuzz(int obj);
extern void objRenderFn_800413d4(int obj);
extern void fuzzRenderFn_800412dc(int obj);
extern void objSetMtxFn_800412d4(int a);
extern s16 lbl_803DC6C4;
extern int *gPartfxInterface;
extern f32 lbl_803E80C4;
extern f32 lbl_803DE478;
extern f32 lbl_803E80D8;
extern void setAButtonIcon(int idx);
extern void setBButtonIcon(int idx);
extern f32 lbl_803DE45C;
extern f32 lbl_803E7FA0;
extern f32 lbl_803E7FA4;
extern f32 lbl_803E7F5C;
extern f32 lbl_803E8150;
extern f32 lbl_803DAF88[];
extern s16 lbl_80332F2C[];
extern s16 lbl_80332F48[];
extern int *gPlayerInterface;
extern int *gObjectTriggerInterface;
extern f32 lbl_803E7F08;
extern f32 lbl_803E7FD8;
extern f32 lbl_803E801C;
extern f32 lbl_803E7F10;
extern f32 lbl_803E811C;
extern f32 lbl_803E80E4;
extern f32 lbl_803E7ED8;
extern void objMove(int obj, f32 x, f32 y, f32 z);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup();
extern int Obj_SetupObject(int setup, int a, int b, int c, int d);
extern u8 framesThisStep;
extern int lbl_803DE448;
extern int lbl_803DE450;
extern int lbl_803DE420;
extern int lbl_803DE47C;
extern int coordsToMapCell(f32 x, f32 z);
extern int randomGetRange(int lo, int hi);
extern void mm_free(void *ptr);
extern void fn_80026C88(int a);
extern void buttonDisable(int a, int b);
extern f32 lbl_803E8234;
extern f32 lbl_803DC740[];
extern s16 lbl_803DC73C[];
extern f32 lbl_803E81DC;
extern f32 lbl_803E81E0;
extern f32 lbl_803E81E4;
extern f32 lbl_803E81E8;
extern f32 lbl_803E81EC;
extern f32 lbl_803E81F0;
extern f32 lbl_803E81F4;
extern f32 lbl_803E81F8;
extern f32 lbl_803E81FC;
extern f32 lbl_803E8200;
extern f32 lbl_803E8204;
extern f32 lbl_803E8208;
extern f32 lbl_803E827C;
extern s16 lbl_803DC748;
extern f32 lbl_803E813C;
extern s8 padGetStickX(int channel);
extern s8 padGetStickY(int channel);
extern u16 getButtonsHeld(int channel);
extern u16 getButtonsJustPressed(int channel);
extern u16 getButtonsJustPressedIfNotBusy(int channel);
extern f32 lbl_803E7E98;
extern f32 timeDelta;
extern void fn_8011F34C(int a);
extern void fn_80295CF4(int obj, int a);
extern int getAngle(f32 a, f32 b);
extern f32 lbl_803E7F34;
extern void Music_Trigger(int a, int b);
extern f32 lbl_803E8238;
extern f32 lbl_803E823C;
extern f32 lbl_803DC690[];
extern int lbl_803DC688[];
extern int Obj_GetPlayerObject(void);
extern void CameraShake_Start(f32 a, f32 b, f32 c);
extern void doRumble(f32 a);
extern f32 lbl_803E81CC;
extern f32 lbl_803E81D0;
extern f32 lbl_803E81D4;
extern f32 lbl_803E81D8;
extern f32 lbl_803E7FE8;
extern f32 lbl_803E7EAC;
extern f32 lbl_803E8058;
extern f32 lbl_803E7E9C;
extern f32 lbl_803E8240;
extern f32 lbl_803E8278;
extern void objThrowFn_80182504(int a);
extern void objSaveFn_800ea774(int a);
extern f32 lbl_803E8280;
extern f32 lbl_803E7F44;
extern f32 lbl_803E7F48;
extern f32 lbl_803E7EF8;
extern int lbl_803DE434;
extern void fn_8018A20C(int a, int b);
extern void fn_80189F5C(int a, void *b, void *c);
extern f32 lbl_803E812C;
extern f32 lbl_803E7F28;
extern f32 lbl_803E7F2C;
extern int *gWaterfxInterface;
extern void Sfx_StopFromObject(int obj, int id);
extern int fn_8029B9FC(int obj, int state, f32 fv);
extern int fn_80299E44(int obj, int state, f32 fv);
extern f32 lbl_803E7F40;
extern u16 getButtons_80014dd8(int port);
extern f32 powfBitEstimate(f32 base, f32 exp);
extern f32 lbl_803E7E8C;
extern s16 lbl_803336BC[];
extern s16 lbl_80333714[];
extern f32 lbl_803E7F20;
extern f32 lbl_803E7F14;
extern f32 lbl_803E7F18;
extern f32 lbl_803E7F1C;
extern f32 lbl_803E7F24;
extern f32 lbl_803E7FC0;
extern f32 lbl_803E7F0C;
extern int audioPickSoundEffect_8006ed24(u8 id, int bank);
extern void characterDoEyeAnims(int obj, int q);
extern f32 lbl_803E820C;
extern f32 lbl_803E7EB4;
extern void playerShadowFn_80062a30(int obj);
extern int lbl_803DAFC8[];
extern int lbl_803DE4B8;
extern void fn_802B0EA4(int obj, int state, int sub);
extern s8 fn_802A74A4(int obj, int state, int sub, void *out, f32 fv, int n);
extern f32 sqrtf(f32 x);
extern f32 lbl_803E80E8;
extern f32 lbl_803E7EFC;
extern f32 lbl_803E8070;
extern f32 lbl_803E7F30;
extern void *getTrickyObject(void);
extern void trickyImpress(void *trickyObj);
extern int Obj_GetActiveModel(int obj);
extern int Obj_SetActiveModelIndex(int obj, int idx);
extern void *memcpy(void *dst, const void *src, u32 size);
extern int *lbl_803DCAB4;
extern f32 lbl_803E800C;
extern f32 lbl_803E8138;
extern f32 lbl_803E8050;
extern int Sfx_IsPlayingFromObject(int obj, u16 sfxId);

typedef struct {
    u8 pad[0x7ac];
    s16 moves[8];
    f32 blend[8];
    f32 angles[8];
} MoveTable;

typedef struct {
    u8 pad0[8];
    int a8[26];
    f32 a70[3];
    f32 a7c[6];
    f32 a94[7];
} EmitElem;

#pragma scheduling off
#pragma peephole off
int fn_8029DA60(int obj, int state)
{
    *(u8 *)((char *)state + 0x34d) = 3;
    *(f32 *)((char *)state + 0x2a0) = lbl_803E7FD8;
    *(f32 *)((char *)state + 0x280) = lbl_803E7EA4;
    (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, 2);
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

int fn_802A7160(int obj, int state)
{
    if (GameBit_Get(0x970)) {
        GameBit_Set(0x970, 0);
        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0x10, obj, -1);
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

void fn_8029BC08(int obj)
{
    *(int *)((char *)*(int *)((char *)obj + 0x54) + 0x48) = 0;
    if (*(s16 *)((char *)lbl_803DE44C + 0x44) == 0x2d) {
        objSetAnimField48to0((int *)lbl_803DE44C);
    }
    lbl_803DC66C = 1;
}

void fn_8029F67C(int obj)
{
    int m = *(int *)((char *)obj + 0x64);
    s16 *v;
    *(int *)((char *)m + 0x30) &= ~0x1000;
    *(s16 *)((char *)obj + 0x6) &= ~0x8;
    *(s16 *)((char *)obj + 0xa2) = -1;
    v = objModelGetVecFn_800395d8(obj, 9);
    if (v != NULL) {
        v[0] = 0;
        v[1] = 0;
        v[2] = 0;
    }
}

void fn_80296124(int obj, void *p2, void *p3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(int *)((char *)inner + 0x360) &= ~0x4000;
    if (p2 != NULL) {
        *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)p2 + 0);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)p2 + 4);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)p2 + 8);
        *(int *)((char *)inner + 0x360) |= 0x4000;
    }
    if (p3 != NULL) {
        s16 t = *(s16 *)((char *)p3 + 0);
        *(s16 *)((char *)obj + 0) = t;
        *(s16 *)((char *)inner + 0x478) = t;
        *(s16 *)((char *)inner + 0x484) = t;
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        *(s16 *)((char *)obj + 2) = *(s16 *)((char *)p3 + 2);
        *(s16 *)((char *)obj + 4) = *(s16 *)((char *)p3 + 4);
        *(int *)((char *)inner + 0x360) |= 0x4000;
    }
}

int fn_8029605C(int obj, f32 *p2, f32 *p3)
{
    void *inner = *(void **)((char *)obj + 0xb8);
    if (inner != NULL && getCurSeqNo() == 0) {
        if ((*(int *)((char *)inner + 0x360) & 0x400) != 0) {
            *p2 = *(f32 *)((char *)inner + 0x788);
            *p3 = *(f32 *)((char *)inner + 0x78c);
            return 1;
        }
        return 0;
    }
    return 0;
}

void fn_8029A420(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0x8c8) != 0x42 && getCurSeqNo() == 0) {
        (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
            0x42, 0, 1, 0, 0, 0x3c, 0xfe);
    }
    ((ByteFlags *)((char *)inner + 0x3f6))->b40 = 0;
    *(s16 *)((char *)inner + 0x80a) = -1;
}

void playerUpdateWhileTimeStopped(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 zero = lbl_803E7EA4;
    f32 v = *(f32 *)((char *)inner + 0x820);
    if (v > zero) {
        v -= lbl_803E7EE0;
        *(f32 *)((char *)inner + 0x820) = v;
        v = *(f32 *)((char *)inner + 0x820);
        if (v <= zero) {
            cutsceneEnterExit(0, 0);
            *(u8 *)((char *)inner + 0x8cf) = 1;
        } else if (lbl_803E7EF0 == v) {
            cutsceneEnterExit(1, 0);
            setTimeStop(0xfd);
        }
    }
}

void fn_8029DAE0(int obj, int *p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u8 c;
    *p2 &= ~0x4000;
    c = *(u8 *)((char *)inner + 0x8c8);
    if (c != 0x48 && c != 0x47 && getCurSeqNo() == 0) {
        (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
            0x42, 0, 1, 0, 0, 0x3c, 0xfe);
    }
    ObjHits_SyncObjectPositionIfDirty(obj);
}

void fn_80295B2C(int obj, f32 f1, f32 f2, f32 f3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(f32 *)((char *)obj + 0x8c) = f1;
    *(f32 *)((char *)obj + 0x80) = f1;
    *(f32 *)((char *)obj + 0x18) = f1;
    *(f32 *)((char *)obj + 0xc) = f1;
    *(f32 *)((char *)obj + 0x90) = f2;
    *(f32 *)((char *)obj + 0x84) = f2;
    *(f32 *)((char *)obj + 0x1c) = f2;
    *(f32 *)((char *)obj + 0x10) = f2;
    *(f32 *)((char *)obj + 0x94) = f3;
    *(f32 *)((char *)obj + 0x88) = f3;
    *(f32 *)((char *)obj + 0x20) = f3;
    *(f32 *)((char *)obj + 0x14) = f3;
    fn_802AB5A4(obj, inner, 7);
    (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 1);
    *(int *)((char *)inner + 0x304) = (int)fn_802A514C;
}

int fn_802A4F8C(int obj, int state, f32 fv)
{
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0x92, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E8060;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 3);
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

void playerAddMoney(int obj, int amount)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int cap;
    int total;
    if (GameBit_Get(0x91b)) {
        cap = 0xc8;
    } else if (GameBit_Get(0x91a)) {
        cap = 0x64;
    } else if (GameBit_Get(0x919)) {
        cap = 0x32;
    } else {
        cap = 0xa;
    }
    total = *(u8 *)((char *)*(int *)((char *)inner + 0x35c) + 8) + amount;
    if (amount > *(u8 *)((char *)inner + 0x3e8)) {
        *(u8 *)((char *)inner + 0x3e8) = (u8)amount;
    }
    if (total < 0) {
        total = 0;
    } else if (total > cap) {
        total = cap;
    }
    *(u8 *)((char *)*(int *)((char *)inner + 0x35c) + 8) = (u8)total;
    GameBit_Set(0x1be, total);
}

void fn_80296C84(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int deref = *(int *)((char *)inner + 0x35c);
    int v = *(s8 *)((char *)deref + 1);
    if (v < 0) {
        v = 0;
    } else if (v > *(s8 *)((char *)deref + 1)) {
        v = *(s8 *)((char *)deref + 1);
    }
    *(s8 *)((char *)*(int *)((char *)inner + 0x35c)) = (s8)v;
    Obj_SetModelColorFadeRecursive(obj, 0x168, 0xc8, 0, 0, 1);
    ((ByteFlags *)((char *)inner + 0x3f3))->b04 = 1;
    *(f32 *)((char *)inner + 0x79c) = lbl_803E7EA4;
    *(u8 *)((char *)inner + 0x8a2) = 0xff;
}

void fn_8029672C(int obj, int mode)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (mode == 0) {
        if (lbl_803DE44C == NULL) return;
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) return;
        *(u8 *)((char *)inner + 0x8b4) = 0;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
    } else if (mode == 1) {
        if (lbl_803DE44C == NULL) return;
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) return;
        *(u8 *)((char *)inner + 0x8b4) = 1;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
    } else {
        if (lbl_803DE44C == NULL) return;
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) return;
        *(u8 *)((char *)inner + 0x8b4) = 1;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
    }
}

void fn_802967E0(int obj, int mode)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (mode == 0) {
        if (lbl_803DE44C == NULL) return;
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) return;
        *(u8 *)((char *)inner + 0x8b4) = 2;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
    } else if (mode == 1) {
        if (lbl_803DE44C == NULL) return;
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) return;
        *(u8 *)((char *)inner + 0x8b4) = 4;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
    } else {
        if (lbl_803DE44C == NULL) return;
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) return;
        *(u8 *)((char *)inner + 0x8b4) = 4;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
    }
}

void lightfoot_free(int obj, int p2)
{
    int i;
    int count;
    int inner = *(int *)((char *)obj + 0xb8);
    ObjGroup_RemoveObject(obj, 3);
    count = *(u8 *)((char *)obj + 0xeb);
    for (i = 0; i < count; i++) {
        void *child = *(void **)((char *)obj + 0xc8);
        if (child != NULL) {
            ObjLink_DetachChild(obj, child);
            if (p2 == 0) {
                Obj_FreeObject((int)child);
            }
        }
    }
    (*(void (*)(int, int, int))(*(int *)(*gBaddieControlInterface + 0x40)))(obj, inner, 0x20);
}

int fn_8029B6BC(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r = fn_802AC7DC(obj, state, inner);
    if (r != 0) {
        return r;
    }
    if (*(s16 *)((char *)obj + 0xa0) != 0x449) {
        u8 c;
        ObjAnim_SetCurrentMove(obj, 0x449, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F4C;
        Sfx_PlayFromObject(obj, 0x40b);
        c = *(u8 *)((char *)inner + 0x8c8);
        if (c != 0x42 && c != 0x4c) {
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x42, 0, 1, 0, 0, 0x3c, 0xfe);
        }
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return -1;
    }
    return 0;
}

int fn_802B7298(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(void **)((char *)p2 + 0x2d0) != NULL) {
        if (*(u16 *)((char *)*(int *)((char *)inner + 0x40c) + 0x22) <
            *(u16 *)((char *)inner + 0x3fe)) {
            if (*(s8 *)((char *)p2 + 0x27b) != 0 || *(s8 *)((char *)p2 + 0x346) != 0 ||
                *(s16 *)((char *)p2 + 0x274) == 0) {
                (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, p2, 4);
            }
        } else if (*(s8 *)((char *)p2 + 0x27b) != 0 || *(s8 *)((char *)p2 + 0x346) != 0) {
            (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, p2, 0);
        }
    }
    return 0;
}

int fn_802A9B1C(int obj, int p2, int p3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u8 c = *(u8 *)((char *)inner + 0x8c8);
    int deref;
    int v;
    if (c == 0x48 || c == 0x47 || c == 0x44 ||
        *(void **)((char *)inner + 0x7f8) != NULL ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b20 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b04 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b08 ||
        ((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) {
        return 0;
    }
    deref = *(int *)((char *)inner + 0x35c);
    if (p3 == 0x2d) {
        if (*(s16 *)((char *)deref + 4) < 2) return 0;
    } else {
        if (*(s16 *)((char *)deref + 4) < 1) return 0;
    }
    v = *(s16 *)((char *)p2 + 0x274);
    if (v == 1 || v == 2 || v == 0x2a || v == 0x2c || (u16)(v - 0x2e) <= 1 || v == 0x2d) {
        return 1;
    }
    return 0;
}

void fn_8029FFD0(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    s16 v = *(s16 *)((char *)p2 + 0x274);
    if (v != 0x15 && v != 0x14 && v != 0x12 && v != 0x13 && v != 0xe && v != 0xf && v != 0x10) {
        u8 c = *(u8 *)((char *)inner + 0x8c8);
        if (c != 0x48 && c != 0x47 && c != 0x42 && getCurSeqNo() == 0) {
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x42, 0, 1, 0, 0, 0, 0xff);
            *(u8 *)((char *)inner + 0x8c8) = 0x42;
        }
        *(int *)((char *)inner + 0x360) |= 0x800000;
        ObjHits_SyncObjectPositionIfDirty(obj);
    }
    *(s16 *)((char *)obj + 0xa2) = -1;
}

int objAnimFn_80296328(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int v;
    if ((*(u16 *)((char *)obj + 0xb0) & 0x1000) != 0 &&
        ((ByteFlags *)((char *)inner + 0x3f2))->b80 == 0) {
        return 0;
    }
    if (((ByteFlags *)((char *)inner + 0x3f0))->b04 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b08 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b20 ||
        *(void **)((char *)inner + 0x7f8) != NULL ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b02) {
        return 0;
    }
    v = *(s16 *)((char *)inner + 0x274);
    if (v == 1 || v == 2 || v == 0x26) {
        return 1;
    }
    if (v == 0x18) {
        if (GameBit_Get(0x3e3)) {
            return 1;
        }
        if (*(s16 *)((char *)*(int *)((char *)inner + 0x7f0) + 0x46) == 0x416) {
            return 1;
        }
    }
    if (*(void **)((char *)inner + 0x2d0) != NULL) {
        return 1;
    }
    return 0;
}

void fn_802AD204(int p1, int obj)
{
    char *t = (char *)lbl_80332EC0;
    *(int *)((char *)obj + 0x3fc) = *(int *)((char *)obj + 0x3f8);
    if (((ByteFlags *)((char *)obj + 0x3f0))->b20) {
        if (((ByteFlags *)((char *)obj + 0x3f1))->b20) {
            *(int *)((char *)obj + 0x3f8) = (int)(t + 0x310);
            *(int *)((char *)obj + 0x400) = (int)(t + 0xd8);
        } else {
            *(int *)((char *)obj + 0x3f8) = (int)(t + 0x210);
            *(int *)((char *)obj + 0x400) = (int)(t + 0xd8);
        }
    } else if (*(void **)((char *)obj + 0x7f8) != NULL) {
        *(int *)((char *)obj + 0x3f8) = (int)(t + 0x250);
        *(int *)((char *)obj + 0x400) = (int)(t + 0x390);
    } else if (((ByteFlags *)((char *)obj + 0x3f1))->b20) {
        if (*(u8 *)((char *)obj + 0x8b3) != 0) {
            *(int *)((char *)obj + 0x3f8) = (int)(t + 0x290);
            *(int *)((char *)obj + 0x400) = (int)(t + 0x390);
        } else {
            *(int *)((char *)obj + 0x3f8) = (int)(t + 0x2d0);
            *(int *)((char *)obj + 0x400) = (int)(t + 0x390);
        }
    } else if (*(u8 *)((char *)obj + 0x8b3) != 0) {
        *(int *)((char *)obj + 0x3f8) = (int)(t + 0x1d0);
        *(int *)((char *)obj + 0x400) = (int)(t + 0x390);
    } else {
        *(int *)((char *)obj + 0x3f8) = (int)(t + 0x190);
        *(int *)((char *)obj + 0x400) = (int)(t + 0x390);
    }
}

#pragma dont_inline on
void fn_802AB5A4(int obj, int p2, int flags)
{
    u8 f = (u8)flags;
    char *q = (char *)p2 + 4;
    if (f & 1) {
        objFn_800e67ac(obj, q);
    }
    if (f & 2) {
        objFn_800e64f4(obj, q);
        *(f32 *)(q + 0x20) = *(f32 *)((char *)obj + 0x18);
        *(f32 *)(q + 0x24) = lbl_803E80EC + *(f32 *)((char *)obj + 0x1c);
        *(f32 *)(q + 0x28) = *(f32 *)((char *)obj + 0x20);
    }
    if (f & 4) {
        *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x10) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x14) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x18) = *(f32 *)((char *)obj + 0x14);
        *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x1c) = *(f32 *)((char *)obj + 0x18);
        *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x20) = *(f32 *)((char *)obj + 0x1c);
        *(f32 *)((char *)*(int *)((char *)obj + 0x54) + 0x24) = *(f32 *)((char *)obj + 0x20);
    }
}
#pragma dont_inline reset

int fn_802A5048(int obj, int state, f32 fv)
{
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0x8e, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E8060;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 3);
    if (*(s8 *)((char *)state + 0x346) != 0) {
        int i;
        void **p;
        lbl_803DE42C = 0;
        p = lbl_80332ED4;
        for (i = 0; i < 7; i++) {
            if (*p != NULL) {
                Obj_FreeObject((int)*p);
                *p = NULL;
            }
            p++;
        }
        if (lbl_803DE454 != NULL) {
            Resource_Release(lbl_803DE454);
            lbl_803DE454 = NULL;
        }
        showDeathMenu();
    }
    return 0;
}

int fn_8029D7F0(int obj, int state, f32 fv)
{
    *(u8 *)((char *)state + 0x34d) = 3;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0x44c, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7FD4;
    }
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x44c:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, 0x44d, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7FCC;
        }
        break;
    case 0x44d:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}

int fn_802A9A0C(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int threshold;
    if (GameBit_Get(0xc55)) {
        threshold = 0x14;
    } else {
        threshold = 0xa;
    }
    if (GameBit_Get(0x107) &&
        *(s16 *)((char *)*(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c) + 4) >= threshold &&
        *(u8 *)((char *)inner + 0x8c8) != 0x44 &&
        *(void **)((char *)inner + 0x7f8) == NULL &&
        !((ByteFlags *)((char *)inner + 0x3f0))->b20 &&
        !((ByteFlags *)((char *)inner + 0x3f0))->b04 &&
        !((ByteFlags *)((char *)inner + 0x3f0))->b08 &&
        ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
        s16 v = *(s16 *)((char *)p2 + 0x274);
        if (v == 1 || v == 2 || v == 0x25 || v == 0x24) {
            return 1;
        }
    }
    return 0;
}

int fn_802A9C0C(int obj, int p2, int p3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u8 c = *(u8 *)((char *)inner + 0x8c8);
    int deref;
    int v;
    if (c == 0x48 || c == 0x47 || c == 0x44 ||
        *(void **)((char *)inner + 0x7f8) != NULL ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b20 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b04 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b08 ||
        ((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0) {
        return 0;
    }
    deref = *(int *)((char *)inner + 0x35c);
    if (p3 == 0x2d) {
        if (*(s16 *)((char *)deref + 4) < 2) return 0;
    } else {
        if (*(s16 *)((char *)deref + 4) < 1) return 0;
    }
    v = *(s16 *)((char *)p2 + 0x274);
    if (v == 1 || v == 2 || (u16)(v - 0x24) <= 1 || (u16)(v - 0x2a) <= 2 ||
        (u16)(v - 0x2e) <= 1 || v == 0x2d) {
        return 1;
    }
    return 0;
}

void fn_8029C8C8(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(f32 *)((char *)p2 + 0x298) < lbl_803E7F6C) {
        s16 h = *(s16 *)((char *)obj + 0);
        *(s16 *)((char *)inner + 0x484) = h;
        *(s16 *)((char *)inner + 0x478) = h;
        *(int *)((char *)inner + 0x494) = h;
        *(f32 *)((char *)p2 + 0x298) = lbl_803E7EA4;
    } else {
        int t = *(int *)((char *)inner + 0x474);
        *(int *)((char *)inner + 0x494) = t;
        *(s16 *)((char *)inner + 0x484) = (s16)t;
        *(int *)((char *)inner + 0x48c) = 0;
        *(int *)((char *)inner + 0x488) = 0;
    }
    lbl_803DC66C = 1;
    if (*(s16 *)((char *)p2 + 0x274) != 0x24 && *(s16 *)((char *)p2 + 0x274) != 0x25 &&
        lbl_803DE42C != 0) {
        int i;
        void **p;
        *(s16 *)((char *)inner + 0x80a) = -1;
        lbl_803DE42C = 0;
        p = lbl_80332ED4;
        for (i = 0; i < 7; i++) {
            if (*p != NULL) {
                Obj_FreeObject((int)*p);
                *p = NULL;
            }
            p++;
        }
        if (lbl_803DE454 != NULL) {
            Resource_Release(lbl_803DE454);
            lbl_803DE454 = NULL;
        }
    }
}

void fn_802B1B28(int obj, f32 fv)
{
    f32 x, y, z;
    f32 v;

    v = *(f32 *)((char *)obj + 0x24);
    if (v < lbl_803E801C) {
        v = lbl_803E801C;
    } else if (v > lbl_803E7F10) {
        v = lbl_803E7F10;
    }
    *(f32 *)((char *)obj + 0x24) = v;

    v = *(f32 *)((char *)obj + 0x28);
    if (v < lbl_803E811C) {
        v = lbl_803E811C;
    } else if (v > lbl_803E80E4) {
        v = lbl_803E80E4;
    }
    *(f32 *)((char *)obj + 0x28) = v;

    v = *(f32 *)((char *)obj + 0x2c);
    if (v < lbl_803E801C) {
        v = lbl_803E801C;
    } else if (v > lbl_803E7F10) {
        v = lbl_803E7F10;
    }
    *(f32 *)((char *)obj + 0x2c) = v;

    y = *(f32 *)((char *)obj + 0x28) * fv;
    if (y > lbl_803E7ED8) {
        y = lbl_803E7ED8;
    }
    x = *(f32 *)((char *)obj + 0x24) * fv;
    z = *(f32 *)((char *)obj + 0x2c) * fv;
    objMove(obj, x, y, z);
}

void fn_802B85E4(int obj, int p2)
{
    int inner = *(int *)((char *)p2 + 0x40c);
    int child;
    int setup;

    if (*(s16 *)((char *)inner + 0x26) == *(s16 *)((char *)inner + 0x28)) return;
    if (*(u8 *)((char *)obj + 0x36) == 0) return;

    child = *(int *)((char *)obj + 0xc8);
    if (child != 0) {
        ObjLink_DetachChild(obj, child);
        Obj_FreeObject(child);
    }
    if (Obj_IsLoadingLocked()) {
        if (*(s16 *)((char *)inner + 0x28) > 0) {
            setup = Obj_AllocObjectSetup(0x20);
            setup = Obj_SetupObject(setup, 4, *(s8 *)((char *)obj + 0xac), -1,
                                    *(int *)((char *)obj + 0x30));
            ObjLink_AttachChild(obj, setup, 0);
            *(s16 *)((char *)inner + 0x26) = *(s16 *)((char *)inner + 0x28);
        }
    } else {
        *(s16 *)((char *)inner + 0x26) = 0;
    }
}

void fn_802B827C(int obj, int p2, int p3)
{
    int idx;

    if (*(u8 *)((char *)p3 + 0x2e) == 0) return;
    if ((*(u16 *)((char *)p2 + 0x400) & 2) == 0) return;

    idx = *(int *)((char *)obj + 0x4c);
    if (*(u32 *)((char *)idx + 0x14) == 0x46A51 && GameBit_Get(0xc49) == 0) {
        GameBit_Set(0xc49, 1);
    } else if (*(u32 *)((char *)idx + 0x14) == 0x46A55 && GameBit_Get(0xc4a) == 0) {
        GameBit_Set(0xc4a, 1);
    } else if (*(u32 *)((char *)idx + 0x14) == 0x49928 && GameBit_Get(0xc4b) == 0) {
        GameBit_Set(0xc4b, 1);
    }
    *(u8 *)((char *)p3 + 0x2e) = 0;
}

void fn_802A96D8(void)
{
    void **p;
    s8 i;
    int idx3;
    int obj;

    if (!Obj_IsLoadingLocked()) return;
    p = lbl_80332ED4;
    idx3 = 0;
    for (i = 0; i < 7; i++) {
        if (*p == NULL) {
            obj = Obj_AllocObjectSetup(0x24, 0x4ec);
            ObjPath_GetPointWorldPosition(lbl_803DE44C, 0, (char *)obj + 8,
                                          (char *)obj + 0xc, (char *)obj + 0x10, 0);
            *(u8 *)((char *)obj + 4) = 2;
            *(u8 *)((char *)obj + 5) = 1;
            *(u8 *)((char *)obj + 6) = 0xff;
            *(u8 *)((char *)obj + 7) = 0xff;
            *(s16 *)((char *)obj + 0x1a) = (s16)idx3;
            *(s16 *)((char *)obj + 0x1c) = 0;
            *p = (void *)Obj_SetupObject(obj, 5, -1, -1, 0);
        }
        p++;
        idx3 += 3;
    }
}

void fn_802B4DE0(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int off;
    int i;

    if (lbl_803DE448 != 0) {
        Obj_FreeObject(lbl_803DE448);
        ObjLink_DetachChild(obj, lbl_803DE448);
        lbl_803DE448 = 0;
    }
    if ((int)lbl_803DE44C != 0) {
        Obj_FreeObject((int)lbl_803DE44C);
        ObjLink_DetachChild(obj, lbl_803DE44C);
        lbl_803DE44C = NULL;
    }
    if (lbl_803DE450 != 0) {
        lbl_803DE450 = 0;
    }
    off = 0;
    for (i = 0; i < *(u8 *)((char *)inner + 0x8a8); i++) {
        int e = *(int *)(*(int *)((char *)inner + 0x3dc) + off + 0x64);
        if (e != 0) mm_free((void *)e);
        off += 0xb0;
    }
    ObjGroup_RemoveObject(obj, 0);
    ObjGroup_RemoveObject(obj, 0x25);
    fn_80026C88(lbl_803DE420);
}

void fn_802A13F4(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int cell;
    int t;
    int sfx;

    if (*(int *)((char *)p2 + 0x314) & 1) {
        cell = coordsToMapCell(*(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x14));
        if (cell == 0x12) {
            Sfx_PlayFromObject(obj, 0x211);
        } else {
            Sfx_PlayFromObject(obj, 0x10);
        }
    }
    if (lbl_803DE47C > 0) {
        t = lbl_803DE47C - framesThisStep;
        lbl_803DE47C = t;
        if (t < 0) lbl_803DE47C = 0;
    }
    if (*(int *)((char *)p2 + 0x314) & 0x80) {
        if (lbl_803DE47C == 0) {
            if (randomGetRange(1, 0x64) < 0x46) {
                if (*(s16 *)((char *)inner + 0x81a) == 0) {
                    sfx = 0x398;
                } else {
                    sfx = 0x25;
                }
                Sfx_PlayFromObject(obj, (u16)sfx);
                lbl_803DE47C = 0x3c;
            }
        }
    }
}

int fn_802BA6E0(int obj, int state)
{
    f32 k = lbl_803E8234;
    int idx;

    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    *(u32 *)((char *)state) |= 0x200000;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        idx = randomGetRange(0, 1);
        *(f32 *)((char *)state + 0x2a0) = lbl_803DC740[idx];
        ObjAnim_SetCurrentMove(obj, lbl_803DC73C[idx], lbl_803E8234, 0);
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        return -2;
    }
    if (*(u8 *)((char *)obj + 0xaf) & 1) {
        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
            randomGetRange(0, 2) + 6, obj, -1);
        buttonDisable(0, 0x100);
    }
    return 0;
}

int fn_802BABB4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);

    switch (*(u8 *)((char *)inner + 0xa8c)) {
    case 0:
        if (GameBit_Get(0xf3)) {
            *(u8 *)((char *)inner + 0xa8e) |= 0x20;
        }
        return 2;
    case 5:
        return 3;
    case 4:
        if (GameBit_Get(0x1db)) return 8;
        return 6;
    case 1:
        if (GameBit_Get(0x16f)) return 8;
        if (GameBit_Get(0x28)) return 7;
        if (GameBit_Get(0x27)) return 7;
        return 6;
    case 3:
        return 8;
    default:
        return 8;
    }
}

int fn_802A98FC(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    s16 sel = *(s16 *)((char *)p2 + 0x274);

    if (sel == 1 || sel == 2) {
        void *slot = *(void **)((char *)inner + 0x4b8);
        u8 af;
        u8 c;
        if (slot == NULL || *(s16 *)((char *)slot + 0x46) != 0x414 ||
            ((af = *(u8 *)((char *)slot + 0xaf)) & 4) == 0 || (af & 0x18) != 0) {
            return 0;
        }
        c = *(u8 *)((char *)inner + 0x8c8);
        if (*(void **)((char *)p2 + 0x2d0) != NULL ||
            c == 0x48 || c == 0x47 || c == 0x44 ||
            *(void **)((char *)inner + 0x7f8) != NULL ||
            ((ByteFlags *)((char *)inner + 0x3f0))->b20 ||
            ((ByteFlags *)((char *)inner + 0x3f0))->b04 ||
            ((ByteFlags *)((char *)inner + 0x3f0))->b08 ||
            ((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0 ||
            *(s16 *)((char *)*(int *)((char *)inner + 0x35c) + 4) < 0x14 ||
            !GameBit_Get(0x5bd)) {
            return 0;
        }
        return 1;
    }
    return 0;
}

void fn_802B84D0(int obj)
{
    switch (*(int *)((char *)*(int *)((char *)obj + 0x4c) + 0x14)) {
    case 0x34316:
        *(f32 *)((char *)obj + 0x18) = lbl_803E81DC;
        *(f32 *)((char *)obj + 0x1c) = lbl_803E81E0;
        *(f32 *)((char *)obj + 0x20) = lbl_803E81E4;
        *(s16 *)((char *)obj + 0) = 0x2565;
        break;
    case 0x33E3C:
        *(f32 *)((char *)obj + 0x18) = lbl_803E81E8;
        *(f32 *)((char *)obj + 0x1c) = lbl_803E81EC;
        *(f32 *)((char *)obj + 0x20) = lbl_803E81F0;
        *(s16 *)((char *)obj + 0) = 0x1c42;
        break;
    case 0x33E34:
        *(f32 *)((char *)obj + 0x18) = lbl_803E81F4;
        *(f32 *)((char *)obj + 0x1c) = lbl_803E81EC;
        *(f32 *)((char *)obj + 0x20) = lbl_803E81F8;
        *(s16 *)((char *)obj + 0) = 0x1d00;
        break;
    case 0x45C47:
        *(f32 *)((char *)obj + 0x18) = lbl_803E81FC;
        *(f32 *)((char *)obj + 0x1c) = lbl_803E81E0;
        *(f32 *)((char *)obj + 0x20) = lbl_803E8200;
        *(s16 *)((char *)obj + 0) = 0x32c1;
        break;
    case 0x460B6:
        *(f32 *)((char *)obj + 0x18) = lbl_803E8204;
        *(f32 *)((char *)obj + 0x1c) = lbl_803E81E0;
        *(f32 *)((char *)obj + 0x20) = lbl_803E8208;
        *(s16 *)((char *)obj + 0) = 0x119f;
        break;
    }
}

int fn_802A97D0(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    void *slot;
    u8 af;
    u8 c;
    s16 sel = *(s16 *)((char *)p2 + 0x274);

    if ((sel != 1 && sel != 2 && sel != 0x26) ||
        !GameBit_Get(0x957) ||
        (slot = *(void **)((char *)inner + 0x4b8)) == NULL ||
        *(s16 *)((char *)slot + 0x46) != 0x64f ||
        ((af = *(u8 *)((char *)slot + 0xaf)) & 4) == 0 ||
        (af & 0x18) != 0 ||
        *(void **)((char *)p2 + 0x2d0) != NULL ||
        (c = *(u8 *)((char *)inner + 0x8c8)) == 0x48 || c == 0x47 || c == 0x44 ||
        *(void **)((char *)inner + 0x7f8) != NULL ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b20 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b04 ||
        ((ByteFlags *)((char *)inner + 0x3f0))->b08 ||
        ((ByteFlags *)((char *)inner + 0x3f4))->b40 == 0 ||
        *(s16 *)((char *)*(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c) + 4) < 0xa) {
        return 0;
    }
    return 1;
}

int fn_802BA938(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 k = lbl_803E8234;
    s16 v;

    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    *(u32 *)((char *)state) |= 0x200000;
    *(f32 *)((char *)state + 0x2a0) = lbl_803E827C;

    if (*(s16 *)((char *)obj + 0xa0) != lbl_803DC748) {
        ObjAnim_SetCurrentMove(obj, lbl_803DC748, k, 0);
    }

    *(s16 *)((char *)inner + 0xa84) = randomGetRange(0x4b0, 0x960);
    v = *(s16 *)((char *)inner + 0xa84) - (int)fv;
    *(s16 *)((char *)inner + 0xa84) = v;
    if (v <= 0) {
        return -4;
    }
    if (*(u8 *)((char *)obj + 0xaf) & 1) {
        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
            randomGetRange(0, 2) + 6, obj, -1);
        buttonDisable(0, 0x100);
    }
    return 0;
}

#pragma dont_inline on
void fn_802B18BC(int obj, int state, f32 fv)
{
    f32 v;

    if ((*(u16 *)((char *)state + 0x6e0) & 0x100) && fn_802A9A0C(obj, state)) {
        ((ByteFlags *)((char *)state + 0x3f4))->b20 = 1;
        *(f32 *)((char *)state + 0x414) += fv;
        v = *(f32 *)((char *)state + 0x414);
        if (v < lbl_803E7EA4) {
            v = lbl_803E7EA4;
        } else if (v > lbl_803E813C) {
            v = lbl_803E813C;
        }
        *(f32 *)((char *)state + 0x414) = v;
    } else {
        ((ByteFlags *)((char *)state + 0x3f4))->b20 = 0;
        *(f32 *)((char *)state + 0x414) = lbl_803E7EA4;
    }

    *(f32 *)((char *)state + 0x410) -= fv;
    if (*(f32 *)((char *)state + 0x410) < lbl_803E7EA4) {
        *(f32 *)((char *)state + 0x410) = lbl_803E7EA4;
    }
    *(f32 *)((char *)state + 0x878) -= fv;
    if (*(f32 *)((char *)state + 0x878) < lbl_803E7EA4) {
        *(f32 *)((char *)state + 0x878) = lbl_803E7EA4;
    }
    *(f32 *)((char *)state + 0x87c) -= fv;
    if (*(f32 *)((char *)state + 0x87c) < lbl_803E7EA4) {
        *(f32 *)((char *)state + 0x87c) = lbl_803E7EA4;
    }
    *(f32 *)((char *)state + 0x880) -= fv;
    if (*(f32 *)((char *)state + 0x880) < lbl_803E7EA4) {
        *(f32 *)((char *)state + 0x880) = lbl_803E7EA4;
    }
}
#pragma dont_inline reset

void fn_802B19F8(int obj, int state, f32 fv)
{
    u8 c;

    *(int *)((char *)state + 0x6d0) = 0;
    *(int *)((char *)state + 0x6d4) = 0;
    *(u16 *)((char *)state + 0x6e0) = 0;
    *(u16 *)((char *)state + 0x6e2) = 0;
    *(u16 *)((char *)state + 0x6e4) = 0;
    if ((*(int *)((char *)state + 0x360) & 0x200000) == 0 &&
        *(s16 *)((char *)state + 0x81a) != -1 &&
        (c = *(u8 *)((char *)state + 0x8c8)) != 0x44 && c != 0x4e) {
        *(int *)((char *)state + 0x6d0) = padGetStickX(0);
        *(int *)((char *)state + 0x6d4) = padGetStickY(0);
        *(u16 *)((char *)state + 0x6e0) = getButtonsHeld(0);
        *(u16 *)((char *)state + 0x6e2) = getButtonsJustPressed(0);
        *(u16 *)((char *)state + 0x6e4) = getButtonsJustPressedIfNotBusy(0);
    }
    *(f32 *)((char *)state + 0x6dc) = (f32)*(int *)((char *)state + 0x6d0);
    *(f32 *)((char *)state + 0x6d8) = (f32)*(int *)((char *)state + 0x6d4);
    fn_802B18BC(obj, state, fv);
}

void fn_8029A4A8(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    s16 sel = *(s16 *)((char *)p2 + 0x274);
    void **p;
    int i;

    if (sel == 0x2a || sel == 0x2e || sel == 0x2f || sel == 0x2c) return;

    *(int *)((char *)inner + 0x360) |= 0x800000;
    *(s16 *)((char *)inner + 0x80a) = -1;
    *(int *)((char *)inner + 0x360) &= ~0x2000400;

    if (*(s16 *)((char *)p2 + 0x274) != 0x2b) {
        if (*(u8 *)((char *)inner + 0x8c8) != 0x42 && getCurSeqNo() == 0) {
            (*(void (*)(int, int, int, int, int, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x42, 0, 1, 0, 0, 0x3c, 0xfe);
        }
        ((ByteFlags *)((char *)inner + 0x3f6))->b40 = 0;
    }

    lbl_803DE42C = 0;
    p = lbl_80332ED4;
    for (i = 0; i < 7; i++) {
        if (*p != NULL) {
            Obj_FreeObject((int)*p);
            *p = NULL;
        }
        p++;
    }
    if (lbl_803DE454 != NULL) {
        Resource_Release(lbl_803DE454);
        lbl_803DE454 = NULL;
    }
}

int fn_802BA7EC(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 k = lbl_803E8234;
    int idx;

    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    *(u32 *)((char *)state) |= 0x200000;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        idx = randomGetRange(0, 1);
        *(f32 *)((char *)state + 0x2a0) = lbl_803DC740[idx];
        ObjAnim_SetCurrentMove(obj, lbl_803DC73C[idx], lbl_803E8234, 0);
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        return -1;
    }
    if (*(u8 *)((char *)obj + 0xaf) & 1) {
        if (*(u8 *)((char *)inner + 0xa8e) & 0x20) {
            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
                randomGetRange(0, 2) + 6, obj, -1);
        } else {
            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
                5, obj, -1);
        }
        buttonDisable(0, 0x100);
    }
    return 0;
}

void fn_802B07D8(int obj, int state)
{
    int setup;
    int b;

    if ((int)lbl_803DE44C == 0 && Obj_IsLoadingLocked()) {
        setup = Obj_AllocObjectSetup(0x18, 0x69);
        setup = Obj_SetupObject(setup, 4, -1, -1, *(int *)((char *)obj + 0x30));
        lbl_803DE44C = (void *)setup;
        ObjLink_AttachChild(obj, setup, 2);
    }
    if ((int)lbl_803DE44C != 0) {
        *(int *)((char *)lbl_803DE44C + 0x30) = *(int *)((char *)obj + 0x30);
    }

    *(f32 *)((char *)state + 0x7d4) -= lbl_803E7E98 * timeDelta;
    if (*(f32 *)((char *)state + 0x7d4) < lbl_803E7EA4) {
        *(f32 *)((char *)state + 0x7d4) = lbl_803E7EA4;
    }
    *(f32 *)((char *)state + 0x7d8) -= lbl_803E7E98 * timeDelta;
    if (*(f32 *)((char *)state + 0x7d8) < lbl_803E7EA4) {
        *(f32 *)((char *)state + 0x7d8) = lbl_803E7EA4;
    }

    fn_8011F34C((u8)(int)*(f32 *)((char *)state + 0x7d4));

    if (obj != 0) {
        b = (*(s8 *)((char *)obj + 0xad) != 0);
    } else {
        b = 0;
    }
    if (b == 0 && GameBit_Get(0x75)) {
        fn_80295CF4(obj, 0);
    }
}

int fn_802BAA54(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 k = lbl_803E8234;
    s16 v;

    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    *(u32 *)((char *)state) |= 0x200000;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E827C;
        if (*(s16 *)((char *)obj + 0xa0) != lbl_803DC748) {
            ObjAnim_SetCurrentMove(obj, lbl_803DC748, lbl_803E8234, 0);
        }
        *(s16 *)((char *)inner + 0xa84) = randomGetRange(0x4b0, 0x960);
    }

    v = *(s16 *)((char *)inner + 0xa84) - (int)fv;
    *(s16 *)((char *)inner + 0xa84) = v;
    if (v <= 0) {
        return -3;
    }
    if (*(u8 *)((char *)obj + 0xaf) & 1) {
        if (*(u8 *)((char *)inner + 0xa8e) & 0x20) {
            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
                randomGetRange(0, 2) + 6, obj, -1);
        } else {
            (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(
                5, obj, -1);
        }
        buttonDisable(0, 0x100);
    }
    return 0;
}

int fn_8029D900(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int hit;

    *(u8 *)((char *)state + 0x34d) = 3;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        if (ObjHits_GetPriorityHit(obj, &hit, 0, 0)) {
            *(s16 *)((char *)inner + 0x478) =
                (s16)getAngle(-*(f32 *)((char *)hit + 0x24), -*(f32 *)((char *)hit + 0x2c));
            *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        }
        ObjAnim_SetCurrentMove(obj, 0x407, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F34;
    }
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x407:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ObjAnim_SetCurrentMove(obj, 0x408, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = lbl_803E7FCC;
        }
        break;
    case 0x408:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
        break;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}

int fn_802957B4(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int sub;

    if (obj == 0) {
        return 0;
    }
    (*(void (*)(int, int, int))(*(int *)(*gCameraInterface + 0x24)))(0, 1, 0);
    (*(void (*)(int, int, int, int))(*(int *)(*gObjectTriggerInterface + 0x50)))(0x42, 4, 0, 0);

    sub = *(int *)((char *)inner + 0x7f0);
    if (sub == 0) {
        return 0;
    }
    (*(void (*)(int, int))(*(int *)(*(int *)((char *)sub + 0x68) + 0x3c)))(sub, 0);
    (*(void (*)(int, int))(*(int *)(*gCameraInterface + 0x28)))(obj, 0);
    *(s16 *)((char *)obj + 6) = *(s16 *)((char *)obj + 6) & ~8;
    *(int *)((char *)*(int *)((char *)obj + 0x64) + 0x30) &= ~0x1000;
    *(int *)((char *)inner + 0x7f0) = 0;
    *(s16 *)((char *)obj + 0xa2) = -1;
    (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 1);
    *(int *)((char *)inner + 0x304) = (int)fn_802A514C;
    Music_Trigger(0x1f, 0);
    Music_Trigger(0x97, 0);
    Music_Trigger(0xe6, 0);
    Music_Trigger(0xd5, 0);
    return 1;
}

int fn_802B978C(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int sub = *(int *)((char *)obj + 0x54);
    f32 k = lbl_803E8234;

    *(u32 *)((char *)state) |= 0x200000;
    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(u8 *)((char *)inner + 0xa8e) &= ~0x8;
        *(s16 *)((char *)sub + 0x60) |= 0x200;
        ObjAnim_SetCurrentMove(obj, 0x204, k, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E8238;
        Sfx_PlayFromObject(obj, 0x3b3);
    }
    if ((*(s16 *)((char *)sub + 0x60) & 0x200) && (*(s8 *)((char *)sub + 0xad) & 2)) {
        *(u8 *)((char *)inner + 0xa8e) |= 0x8;
    }
    if (*(u8 *)((char *)inner + 0xa8e) & 0x8) {
        *(u8 *)((char *)sub + 0x6e) = 0;
        *(u8 *)((char *)sub + 0x6f) = 0;
        *(s16 *)((char *)sub + 0x60) &= ~0x200;
    } else {
        *(u8 *)((char *)sub + 0x6e) = 0xb;
        *(u8 *)((char *)sub + 0x6f) = 1;
        *(s16 *)((char *)sub + 0x60) |= 0x200;
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E823C) {
        return 8;
    }
    return 0;
}

int fn_8029BC4C(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int idx;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        if (lbl_803DE459 == 0) {
            lbl_803DE459 = 1;
        } else if (lbl_803DE459 > 2) {
            lbl_803DE459 = 2;
        }
        idx = lbl_803DE459;
        *(f32 *)((char *)state + 0x2a0) = lbl_803DC690[idx - 1];
        ObjAnim_SetCurrentMove(obj, lbl_803DC688[idx - 1], lbl_803E7EA4, 0);
        lbl_803DE459 = 0;
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x70) = 0;
        if (*(void **)((char *)state + 0x2d0) != NULL) {
            *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
            return 0x25;
        }
        ((ByteFlags *)((char *)inner + 0x3f1))->b80 = 1;
        *(int *)((char *)inner + 0x360) |= 0x800000;
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    return 0;
}

#pragma dont_inline on
void fn_802B8360(int obj, int p2)
{
    if (*(int *)((char *)p2 + 0x314) & 4) {
        *(int *)((char *)p2 + 0x314) &= ~4;
        Sfx_PlayFromObject(obj, 0x12e);
    }
    if (*(int *)((char *)p2 + 0x314) & 2) {
        *(int *)((char *)p2 + 0x314) &= ~2;
        Sfx_PlayFromObject(obj, 0x12e);
    }
    if (*(int *)((char *)p2 + 0x314) & 1) {
        *(int *)((char *)p2 + 0x314) &= ~1;
        if (randomGetRange(0, 2) == 0) {
            Sfx_PlayFromObject(obj, 0x43c);
        }
    }
    if (*(int *)((char *)p2 + 0x314) & 0x80) {
        *(int *)((char *)p2 + 0x314) &= ~0x80;
        Sfx_PlayFromObject(obj, 0x130);
    }
    if (*(int *)((char *)p2 + 0x314) & 0x200) {
        *(int *)((char *)p2 + 0x314) &= ~0x200;
        Sfx_PlayFromObject(obj, 0x133);
    }
    if (*(int *)((char *)p2 + 0x314) & 0x40) {
        *(int *)((char *)p2 + 0x314) &= ~0x40;
        Sfx_PlayFromObject(obj, 0x135);
    }
    if (*(int *)((char *)p2 + 0x314) & 0x800) {
        *(int *)((char *)p2 + 0x314) &= ~0x800;
        ObjHits_RecordObjectHit(Obj_GetPlayerObject(), obj, 0x19, 2, 1);
        Sfx_PlayFromObject(obj, 0x136);
        CameraShake_Start(lbl_803E81CC, lbl_803E81D0, lbl_803E81D4);
        doRumble(lbl_803E81D8);
    }
}
#pragma dont_inline reset

int fn_8029E3F4(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 k;
    f32 a, b;
    u8 s1, s2;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(s16 *)((char *)state + 0x278) = 0x1c;
        *(int *)((char *)inner + 0x898) = 0;
    }
    k = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        s1 = 0;
        a = *(f32 *)((char *)inner + 0x654);
        if (a < lbl_803E7EA4) {
            s1 = 1;
            a = -a;
        }
        s2 = 0;
        b = *(f32 *)((char *)inner + 0x65c);
        if (b < lbl_803E7EA4) {
            s2 = 1;
            b = -b;
        }
        if (a > b) {
            if (s1) {
                *(u8 *)((char *)inner + 0x682) = 0;
            } else {
                *(u8 *)((char *)inner + 0x682) = 1;
            }
        } else {
            if (s2) {
                *(u8 *)((char *)inner + 0x682) = 2;
            } else {
                *(u8 *)((char *)inner + 0x682) = 3;
            }
        }
        ObjAnim_SetCurrentMove(obj, 0x57, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7FE8;
        Sfx_PlayFromObject(obj, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x2d3 : 0x2b));
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return -1;
    }
    return 0;
}

int fn_802A49C8(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int sub;
    f32 k;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        if (*(int *)((char *)inner + 0x7f8) != 0) {
            ObjHits_MarkObjectPositionDirty(*(int *)((char *)inner + 0x7f8));
        }
        ObjAnim_SetCurrentMove(obj, 0x443, lbl_803E7EAC, 0);
        *(s16 *)((char *)state + 0x278) = 1;
        *(int *)((char *)inner + 0x898) = (int)fn_802A514C;
    }
    k = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    *(f32 *)((char *)state + 0x2a0) = lbl_803E8058;

    if (*(int *)((char *)state + 0x314) & 1) {
        Sfx_PlayFromObject(obj, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x327 : 0x379));
    }

    sub = *(int *)((char *)inner + 0x7f8);
    if (sub == 0 && *(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    if (sub != 0 && *(f32 *)((char *)obj + 0x98) > lbl_803E7E9C) {
        *(u8 *)((char *)inner + 0x800) = 0;
        if (*(int *)((char *)inner + 0x7f8) != 0) {
            int s2 = *(int *)((char *)inner + 0x7f8);
            s16 id = *(s16 *)((char *)s2 + 0x46);
            if (id == 0x3cf || id == 0x662) {
                objThrowFn_80182504(s2);
            } else {
                objSaveFn_800ea774(s2);
            }
            *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 6) &= ~0x4000;
            *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
            *(int *)((char *)inner + 0x7f8) = 0;
        }
    }
    return 0;
}

int fn_802B9CC4(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int near;
    f32 sp = lbl_803E8240;
    s16 d;

    near = ObjGroup_FindNearestObject(0x13, obj, &sp);
    *(u32 *)((char *)state) |= 0x200000;

    if (*(s16 *)((char *)state + 0x334) < *(s16 *)((char *)inner + 0xa86) ||
        lbl_803E8234 == *(f32 *)((char *)state + 0x298)) {
        return 8;
    }

    if (*(s16 *)((char *)state + 0x336) < -0xaf) {
        *(s16 *)((char *)state + 0x336) = -*(s16 *)((char *)state + 0x336);
    }
    d = *(s16 *)((char *)state + 0x336);
    if (d > 0) {
        if (*(s16 *)((char *)obj + 0xa0) != 0x201) {
            ObjAnim_SetCurrentMove(obj, 0x201, lbl_803E8234, 0);
        }
    } else if (d <= 0) {
        if (*(s16 *)((char *)obj + 0xa0) != 0x200) {
            ObjAnim_SetCurrentMove(obj, 0x200, lbl_803E8234, 0);
        }
    }
    *(f32 *)((char *)state + 0x2a0) = lbl_803E8278;
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 8);

    if (*(int *)((char *)state + 0x31c) & 0x100) {
        if (near == 0 || (*(u8 *)((char *)near + 0xaf) & 4) == 0) {
            return 0xc;
        }
    }
    return 0;
}

int fn_802B9E38(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);

    *(u32 *)((char *)state) |= 0x200000;
    *(u8 *)((char *)obj + 0xaf) |= 0x8;

    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x206:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            if (*(f32 *)((char *)state + 0x2a0) > lbl_803E8234) {
                ObjAnim_SetCurrentMove(obj, 0x205, lbl_803E8234, 0);
                *(f32 *)((char *)state + 0x2a0) = lbl_803E827C;
            } else {
                return 8;
            }
        }
        if (*(s16 *)((char *)inner + 0xa88) != 0 &&
            *(f32 *)((char *)state + 0x2a0) > lbl_803E8234) {
            if (*(int *)((char *)state + 0x31c) != 0 ||
                lbl_803E8234 != *(f32 *)((char *)state + 0x290) ||
                lbl_803E8234 != *(f32 *)((char *)state + 0x28c)) {
                *(f32 *)((char *)state + 0x2a0) = -*(f32 *)((char *)state + 0x2a0);
            }
        }
        break;
    case 0x205:
        if (*(s16 *)((char *)inner + 0xa88) != 0) {
            if (*(int *)((char *)state + 0x31c) != 0 ||
                lbl_803E8234 != *(f32 *)((char *)state + 0x290) ||
                lbl_803E8234 != *(f32 *)((char *)state + 0x28c)) {
                ObjAnim_SetCurrentMove(obj, 0x207, lbl_803E8234, 0);
                *(f32 *)((char *)state + 0x2a0) = lbl_803E8280;
            }
        }
        break;
    case 0x207:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            return 8;
        }
        break;
    default:
        ObjAnim_SetCurrentMove(obj, 0x206, lbl_803E8234, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E8280;
        break;
    }
    return 0;
}

int fn_80298CCC(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 k;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjHits_MarkObjectPositionDirty(obj);
    }
    k = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x294) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x28) = k;
    *(f32 *)((char *)obj + 0x2c) = k;

    if (*(s16 *)((char *)obj + 0xa0) == 0xdd) {
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F44) {
            fn_8018A20C(lbl_803DE434, 0);
        }
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F48 &&
            (*(u8 *)((char *)state + 0x356) & 1) == 0) {
            Sfx_PlayFromObject(obj, 0x2c3);
            *(u8 *)((char *)state + 0x356) |= 1;
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)inner + 0x360) |= 0x800000;
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return 2;
        }
    } else {
        ObjAnim_SetCurrentMove(obj, 0xdd, k, 0);
        fn_80189F5C(lbl_803DE434, (char *)obj + 0xc, (char *)obj + 0x14);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
        *(u8 *)((char *)state + 0x356) = 0;
        *(s16 *)((char *)inner + 0x478) = *(s16 *)((char *)lbl_803DE434);
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        if ((int)lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
            *(u8 *)((char *)inner + 0x8b4) = 4;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
        }
    }
    return 0;
}

void fn_80295CF4(int obj, int a)
{
    int inner = *(int *)((char *)obj + 0xb8);

    if ((int)lbl_803DE44C == 0 || ((ByteFlags *)((char *)inner + 0x3f4))->b40 == a) {
        return;
    }
    if (a == 0) {
        *(s16 *)((char *)lbl_803DE44C + 6) |= 0x4000;
        if ((int)lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
            *(u8 *)((char *)inner + 0x8b4) = 1;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
        }
        GameBit_Set(0x96b, 1);
        GameBit_Set(0x961, 1);
        GameBit_Set(0x969, 1);
        GameBit_Set(0x964, 1);
        GameBit_Set(0x965, 1);
        GameBit_Set(0x986, 1);
        GameBit_Set(0x960, 1);
    } else {
        if (((ByteFlags *)((char *)inner + 0x3f4))->b40) {
            *(u8 *)((char *)inner + 0x8b4) = 4;
            ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
        }
        *(s16 *)((char *)lbl_803DE44C + 6) &= ~0x4000;
        GameBit_Set(0x96b, 0);
        GameBit_Set(0x961, 0);
        GameBit_Set(0x969, 0);
        GameBit_Set(0x964, 0);
        GameBit_Set(0x965, 0);
        GameBit_Set(0x986, 0);
        GameBit_Set(0x960, 0);
    }
    ((ByteFlags *)((char *)inner + 0x3f4))->b40 = a;
}

void fn_802AE83C(int obj, int inner)
{
    int sub;

    ((ByteFlags *)((char *)inner + 0x3f1))->b40 = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 0;
    *(u8 *)((char *)inner + 0x40d) = 0;
    ((ByteFlags *)((char *)inner + 0x3f0))->b20 = 1;
    ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
    *(f32 *)((char *)inner + 0x440) = lbl_803E7EA4;
    *(f32 *)((char *)inner + 0x43c) = lbl_803E7EA4;
    Sfx_StopFromObject(obj, (u16)(*(s16 *)((char *)inner + 0x81a) == 0 ? 0x2d0 : 0x26));

    if ((int)lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
        *(u8 *)((char *)inner + 0x8b4) = 1;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
    }
    *(u8 *)((char *)inner + 0x800) = 0;
    sub = *(int *)((char *)inner + 0x7f8);
    if (sub != 0) {
        s16 id = *(s16 *)((char *)sub + 0x46);
        if (id == 0x3cf || id == 0x662) {
            objThrowFn_80182504(sub);
        } else {
            objSaveFn_800ea774(sub);
        }
        *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 6) &= ~0x4000;
        *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
        *(int *)((char *)inner + 0x7f8) = 0;
    }
    if (*(f32 *)((char *)obj + 0x28) < lbl_803E812C) {
        Sfx_PlayFromObject(obj, 0x212);
        (*(void (*)(int, f32, f32, f32, f32))(*(int *)(*gWaterfxInterface + 0x10)))(
            obj, *(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x10),
            *(f32 *)((char *)obj + 0x14), lbl_803E7ED8);
    }
}

int fn_80298380(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0xfb, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F28;
        *(f32 *)((char *)state + 0x294) = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x284) = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x280) = lbl_803E7EA4;
        *(f32 *)((char *)obj + 0x24) = lbl_803E7EA4;
        *(f32 *)((char *)obj + 0x28) = lbl_803E7EA4;
        *(f32 *)((char *)obj + 0x2c) = lbl_803E7EA4;
    }

    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }

    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
    *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)obj);
    *(s16 *)((char *)inner + 0x478) = *(s16 *)((char *)obj);
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 2);

    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x25;
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F2C) {
        if (*(u8 *)((char *)state + 0x349) == 1) {
            r = fn_80299E44(obj, state, fv);
            if (r != 0) {
                return r;
            }
        } else {
            if ((int)lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                *(u8 *)((char *)inner + 0x8b4) = 0;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
            }
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return -1;
        }
    }
    return 0;
}

int fn_802A4B78(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int sub;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, 0x447, lbl_803E7EA4, 0);
        *(s16 *)((char *)state + 0x278) = 1;
        *(int *)((char *)inner + 0x898) = (int)fn_802A514C;
    }
    if ((*(int *)((char *)state + 0x314) & 1) &&
        (sub = *(int *)((char *)inner + 0x7f8)) != 0) {
        switch (*(s16 *)((char *)sub + 0x46)) {
        case 0x6d:
        case 0x754:
            Sfx_PlayFromObject(obj, 0x31f);
            break;
        case 0x1f4:
        case 0x1f5:
        case 0x1f6:
        case 0x1f7:
        case 0x1f8:
        case 0x1f9:
        case 0x519:
            Sfx_PlayFromObject(obj, 0x39b);
            break;
        default:
            Sfx_PlayFromObject(obj, 0x6d);
            break;
        }
    }
    *(f32 *)((char *)state + 0x280) = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x2a0) = lbl_803E7F40;

    sub = *(int *)((char *)inner + 0x7f8);
    if (sub == 0 && *(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)inner + 0x360) |= 0x800000;
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    if (sub != 0 && *(f32 *)((char *)obj + 0x98) > lbl_803E7F48) {
        *(u8 *)((char *)inner + 0x800) = 0;
        if (*(int *)((char *)inner + 0x7f8) != 0) {
            int s2 = *(int *)((char *)inner + 0x7f8);
            s16 id = *(s16 *)((char *)s2 + 0x46);
            if (id == 0x3cf || id == 0x662) {
                objThrowFn_80182504(s2);
            } else {
                objSaveFn_800ea774(s2);
            }
            *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 6) &= ~0x4000;
            *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
            *(int *)((char *)inner + 0x7f8) = 0;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int playerSetHeldObject(int obj, int held)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int sub;

    if (held != 0) {
        *(int *)((char *)inner + 0x7f8) = held;
        (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 5);
        *(int *)((char *)inner + 0x304) = (int)fn_802A4B4C;
    } else if (*(int *)((char *)inner + 0x7f8) != 0) {
        *(u8 *)((char *)inner + 0x800) = 0;
        sub = *(int *)((char *)inner + 0x7f8);
        if (sub != 0) {
            s16 id = *(s16 *)((char *)sub + 0x46);
            if (id == 0x3cf || id == 0x662) {
                objThrowFn_80182504(sub);
            } else {
                objSaveFn_800ea774(sub);
            }
            *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 6) &= ~0x4000;
            *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
            *(int *)((char *)inner + 0x7f8) = 0;
        }
        *(int *)((char *)inner + 0x360) |= 0x800000;
        (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 1);
        *(int *)((char *)inner + 0x304) = (int)fn_802A514C;
    }
    return *(int *)((char *)inner + 0x7f8) != 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80298184(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;
    f32 k;
    s16 hdr;

    *(int *)((char *)inner + 0x360) |= 0x800;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
        k = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = k;
        *(f32 *)((char *)state + 0x284) = k;
        *(f32 *)((char *)state + 0x280) = k;
        *(f32 *)((char *)obj + 0x24) = k;
        *(f32 *)((char *)obj + 0x28) = k;
        *(f32 *)((char *)obj + 0x2c) = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
    hdr = *(s16 *)obj;
    *(s16 *)((char *)inner + 0x484) = hdr;
    *(s16 *)((char *)inner + 0x478) = hdr;
    if ((getButtons_80014dd8(0) & 0x20) == 0) {
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x25;
    }
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ((ByteFlags *)((char *)inner + 0x3f6))->b10 = 0;
    }
    if (((ByteFlags *)((char *)inner + 0x3f6))->b10) {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7E8C;
        if (*(s16 *)((char *)obj + 0xa0) != 0x455) {
            doRumble(lbl_803E7ED8);
            ObjAnim_SetCurrentMove(obj, 0x455, lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x280) = -*(f32 *)((char *)inner + 0x88c);
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            ((ByteFlags *)((char *)inner + 0x3f6))->b10 = 0;
        }
    } else {
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7EF8;
        if (*(s16 *)((char *)obj + 0xa0) != 0x458 &&
            ObjAnim_GetCurrentEventCountdown((ObjAnimComponent *)obj) == 0) {
            ObjAnim_SetCurrentMove(obj, 0x458, *(f32 *)((char *)obj + 0x98), 0);
            ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 8);
        }
    }
    *(f32 *)((char *)state + 0x280) =
        *(f32 *)((char *)state + 0x280) *
        powfBitEstimate(*(f32 *)((char *)inner + 0x888), timeDelta);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int fn_80297AD0(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;
    f32 k;
    s16 hdr;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, lbl_803336BC[*(s16 *)((char *)lbl_80333714 + 0x422)],
                               lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F20;
        k = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = k;
        *(f32 *)((char *)state + 0x284) = k;
        *(f32 *)((char *)state + 0x280) = k;
        *(f32 *)((char *)obj + 0x24) = k;
        *(f32 *)((char *)obj + 0x28) = k;
        *(f32 *)((char *)obj + 0x2c) = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 0x10);
    hdr = *(s16 *)obj;
    *(s16 *)((char *)inner + 0x484) = hdr;
    *(s16 *)((char *)inner + 0x478) = hdr;
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    if ((*(u8 *)((char *)state + 0x356) & 1) == 0 &&
        *(f32 *)((char *)obj + 0x98) > lbl_803E7F14) {
        Sfx_PlayFromObject(obj, 0x1b);
        *(u8 *)((char *)state + 0x356) |= 1;
    }
    if ((*(u8 *)((char *)state + 0x356) & 2) == 0 &&
        *(f32 *)((char *)obj + 0x98) > lbl_803E7F18) {
        Sfx_PlayFromObject(obj, 0x2e);
        *(u8 *)((char *)state + 0x356) |= 2;
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x25;
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F1C) {
        if (*(u8 *)((char *)state + 0x349) != 1) {
            if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                *(u8 *)((char *)inner + 0x8b4) = 0;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
            }
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return -1;
        }
        r = fn_80299E44(obj, state, fv);
        if (r != 0) {
            return r;
        }
        return 0;
    }
    return 0;
}

int fn_80297D0C(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;
    f32 k;
    s16 hdr;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, lbl_803336BC[*(s16 *)((char *)lbl_80333714 + 0x632)],
                               lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F24;
        *(u8 *)((char *)state + 0x356) = 0;
        k = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = k;
        *(f32 *)((char *)state + 0x284) = k;
        *(f32 *)((char *)state + 0x280) = k;
        *(f32 *)((char *)obj + 0x24) = k;
        *(f32 *)((char *)obj + 0x28) = k;
        *(f32 *)((char *)obj + 0x2c) = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
    hdr = *(s16 *)obj;
    *(s16 *)((char *)inner + 0x484) = hdr;
    *(s16 *)((char *)inner + 0x478) = hdr;
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 2);
    if (*(int *)((char *)state + 0x314) & 0x200) {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, 0x3cd);
        *(u16 *)((char *)inner + 0x8d8) |= 4;
    }
    if ((*(u8 *)((char *)state + 0x356) & 1) == 0 &&
        *(f32 *)((char *)obj + 0x98) > lbl_803E7F14) {
        Sfx_PlayFromObject(obj, 0x2e);
        *(u8 *)((char *)state + 0x356) |= 1;
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x25;
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F1C) {
        if (*(u8 *)((char *)state + 0x349) != 1) {
            if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                *(u8 *)((char *)inner + 0x8b4) = 0;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
            }
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return -1;
        }
        r = fn_80299E44(obj, state, fv);
        if (r != 0) {
            return r;
        }
        return 0;
    }
    return 0;
}

int fn_80297F48(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;
    f32 k;
    s16 hdr;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, lbl_803336BC[*(s16 *)((char *)lbl_80333714 + 0x582)],
                               lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F24;
        *(u8 *)((char *)state + 0x356) = 0;
        k = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = k;
        *(f32 *)((char *)state + 0x284) = k;
        *(f32 *)((char *)state + 0x280) = k;
        *(f32 *)((char *)obj + 0x24) = k;
        *(f32 *)((char *)obj + 0x28) = k;
        *(f32 *)((char *)obj + 0x2c) = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 1);
    hdr = *(s16 *)obj;
    *(s16 *)((char *)inner + 0x484) = hdr;
    *(s16 *)((char *)inner + 0x478) = hdr;
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 2);
    if (*(int *)((char *)state + 0x314) & 0x200) {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, 0x3cd);
        *(u16 *)((char *)inner + 0x8d8) |= 4;
    }
    if ((*(u8 *)((char *)state + 0x356) & 1) == 0 &&
        *(f32 *)((char *)obj + 0x98) > lbl_803E7F14) {
        Sfx_PlayFromObject(obj, 0x2e);
        *(u8 *)((char *)state + 0x356) |= 1;
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x25;
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F1C) {
        if (*(u8 *)((char *)state + 0x349) != 1) {
            if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                *(u8 *)((char *)inner + 0x8b4) = 0;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
            }
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return -1;
        }
        r = fn_80299E44(obj, state, fv);
        if (r != 0) {
            return r;
        }
        return 0;
    }
    return 0;
}

int fn_8029D250(int obj, int state, f32 fv)
{
    MoveTable *mt = (MoveTable *)lbl_80332EC0;
    int inner = *(int *)((char *)obj + 0xb8);
    u32 flags;
    int idx;

    *(u8 *)((char *)state + 0x34d) = 3;
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        if (*(void **)((char *)state + 0x2d0) != NULL &&
            (*(u32 *)((char *)inner + 0x884) & 1)) {
            doRumble(lbl_803E7ED8);
            flags = *(u32 *)((char *)inner + 0x884);
            if (flags & 2) {
                idx = 3;
            } else if (flags & 4) {
                idx = 1;
            } else if (flags & 8) {
                idx = 2;
            } else {
                idx = 3;
            }
            ObjAnim_SetCurrentMove(obj, mt->moves[idx], mt->blend[idx], 0);
            *(f32 *)((char *)state + 0x2a0) = mt->angles[idx];
            *(f32 *)((char *)state + 0x280) = -*(f32 *)((char *)inner + 0x88c);
        } else {
            ObjAnim_SetCurrentMove(obj, mt->moves[*(u8 *)((char *)inner + 0x8a2)],
                                   lbl_803E7EA4, 0);
            *(f32 *)((char *)state + 0x2a0) = mt->angles[*(u8 *)((char *)inner + 0x8a2)];
        }
    }
    if (*(void **)((char *)state + 0x2d0) != NULL) {
        *(s16 *)((char *)inner + 0x478) = *(s16 *)((char *)inner + 0x478) +
            (int)((f32)*(int *)((char *)inner + 0x4a4) / lbl_803E7FC0);
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
    }
    *(f32 *)((char *)state + 0x280) =
        *(f32 *)((char *)state + 0x280) *
        powfBitEstimate(*(f32 *)((char *)inner + 0x888), fv);
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 2);
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_802A514C;
        return 2;
    }
    return 0;
}

int fn_80297854(int obj, int state, f32 fv)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r;
    f32 k;
    s16 hdr;

    if (*(s8 *)((char *)state + 0x27a) != 0) {
        ObjAnim_SetCurrentMove(obj, lbl_803336BC[*(s16 *)((char *)lbl_80333714 + 0x4d2)],
                               lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F0C;
        k = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = k;
        *(f32 *)((char *)state + 0x284) = k;
        *(f32 *)((char *)state + 0x280) = k;
        *(f32 *)((char *)obj + 0x24) = k;
        *(f32 *)((char *)obj + 0x28) = k;
        *(f32 *)((char *)obj + 0x2c) = k;
    }
    r = fn_8029B9FC(obj, state, fv);
    if (r != 0) {
        return r;
    }
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x30)))(obj, state, fv, 0x10);
    hdr = *(s16 *)obj;
    *(s16 *)((char *)inner + 0x484) = hdr;
    *(s16 *)((char *)inner + 0x478) = hdr;
    (*(void (*)(int, int, f32, int))(*(int *)(*gPlayerInterface + 0x20)))(obj, state, fv, 1);
    if (*(int *)((char *)state + 0x314) & 0x200) {
        doRumble(lbl_803E7F10);
        Sfx_PlayFromObject(obj, 0x3cd);
        *(u16 *)((char *)inner + 0x8d8) |= 4;
    }
    if ((*(u8 *)((char *)state + 0x356) & 1) == 0 &&
        *(f32 *)((char *)obj + 0x98) > lbl_803E7F14) {
        Sfx_PlayFromObject(obj, 0x1b);
        *(u8 *)((char *)state + 0x356) |= 1;
    }
    if ((*(u8 *)((char *)state + 0x356) & 2) == 0 &&
        *(f32 *)((char *)obj + 0x98) > lbl_803E7F18) {
        Sfx_PlayFromObject(obj, audioPickSoundEffect_8006ed24(*(u8 *)((char *)inner + 0x86c),
                                                              *(u8 *)((char *)inner + 0x8a5)));
        *(u8 *)((char *)state + 0x356) |= 2;
    }
    if (*(s8 *)((char *)state + 0x346) != 0) {
        *(int *)((char *)state + 0x308) = (int)fn_8029C8C8;
        return 0x25;
    }
    if (*(f32 *)((char *)obj + 0x98) > lbl_803E7F1C) {
        if (*(u8 *)((char *)state + 0x349) != 1) {
            if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
                *(u8 *)((char *)inner + 0x8b4) = 0;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
            }
            *(int *)((char *)state + 0x308) = (int)fn_802A514C;
            return -1;
        }
        r = fn_80299E44(obj, state, fv);
        if (r != 0) {
            return r;
        }
        return 0;
    }
    return 0;
}

void fn_802B86B8(int obj, int a, int b)
{
    int p = *(int *)((char *)a + 0x40c);
    int sub = *(int *)((char *)obj + 0x4c);
    int mode;
    int v;

    (*(void (*)(int, int, int, void *, void *, void *))(*(int *)(*gBaddieControlInterface + 0x14)))(
        obj, Obj_GetPlayerObject(), 0x10,
        (char *)p + 0x1e, (char *)p + 0x20, (char *)p + 0x22);
    *(f32 *)((char *)b + 0x2c0) = (f32)(u32)*(u16 *)((char *)p + 0x22);
    mode = *(int *)((char *)obj + 0xf8);
    if (mode == 2) {
        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0, obj, -1);
        *(int *)((char *)obj + 0xf8) = 1;
    } else if (mode == 3) {
        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(1, obj, -1);
        *(int *)((char *)obj + 0xf8) = 1;
    } else {
        characterDoEyeAnims(obj, a + 0x3ac);
        *(int *)((char *)b + 0x2d0) = Obj_GetPlayerObject();
        v = *(int *)((char *)sub + 0x14);
        if (v >= 0x49942 || v < 0x4993f) {
            (*(void (*)(int, int, f32, int))(*(int *)(*gBaddieControlInterface + 0x2c)))(
                obj, b, lbl_803E820C, 1);
        }
        *(int *)((char *)a + 0x3e0) = *(int *)((char *)obj + 0xc0);
        *(int *)((char *)obj + 0xc0) = 0;
        (*(void (*)(int, int, f32, f32, void *, void *))(*(int *)(*gPlayerInterface + 0x8)))(
            obj, b, timeDelta, timeDelta, lbl_803DB0DC, lbl_803DB0D0);
        *(int *)((char *)obj + 0xc0) = *(int *)((char *)a + 0x3e0);
        fn_802B8360(obj, a);
    }
}

void fn_802B4C18(int obj, int state, f32 fv)
{
    u8 buf[0x40];

    *(f32 *)((char *)state + 0x2a4) = lbl_803E7EB4;
    *(f32 *)((char *)state + 0x290) = *(f32 *)((char *)state + 0x6dc);
    *(f32 *)((char *)state + 0x28c) = *(f32 *)((char *)state + 0x6d8);
    *(int *)((char *)state + 0x31c) = *(u16 *)((char *)state + 0x6e2);
    *(int *)((char *)state + 0x318) = *(u16 *)((char *)state + 0x6e0);
    *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x6e) = 0;
    *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x6f) = 0;
    *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x6c) = 0;
    *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x6d) = 0;
    *(u8 *)((char *)state + 0x25f) = 1;
    *(u32 *)((char *)state + 0x4) &= ~0x8100000;
    playerShadowFn_80062a30(obj);
    *(u8 *)((char *)state + 0x8c5) = 0;
    *(int *)((char *)state + 0x360) &= ~0x2000;
    *(int *)state |= 0x1000000;
    fn_802B0EA4(obj, state, state);
    if (fn_802A74A4(obj, state, state, buf, fv, 0x60) == 8) {
        *(int *)((char *)state + 0x2d0) = 0;
        *(u8 *)((char *)state + 0x349) = 0;
        (*(void (*)(int))(*(int *)(*gCameraInterface + 0x48)))(0);
        if (lbl_803DE44C != 0 && ((ByteFlags *)((char *)state + 0x3f4))->b40) {
            *(u8 *)((char *)state + 0x8b4) = 1;
            ((ByteFlags *)((char *)state + 0x3f4))->b08 = 1;
        }
        (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 0xa);
        *(int *)((char *)state + 0x304) = 0;
    }
    (*(void (*)(int, int, f32, f32, int *, int *))(*(int *)(*gPlayerInterface + 0x8)))(
        obj, state, fv, fv, lbl_803DAFC8, &lbl_803DE4B8);
    *(int *)state &= ~0x1000000;
}

int fn_802AB1D0(int obj)
{
    int objs;
    int i;
    int count;
    int best;
    int cur;
    f32 dist;
    f32 bestDist;
    f32 scale;
    s16 yaw;
    void *held;

    if (*(u16 *)((char *)obj + 0xb0) & 0x1000) {
        return 0;
    }
    held = *(void **)((char *)*(int *)((char *)obj + 0xb8) + 0x2d0);
    if (held != NULL) {
        return (int)held;
    }
    best = 0;
    objs = (int)ObjGroup_GetObjects(8, &count);
    bestDist = lbl_803E7EA4;
    for (i = 0; i < count; i++) {
        cur = ((int *)objs)[i];
        if ((*(s16 *)((char *)cur + 0x44) == 0x1c || *(s16 *)((char *)cur + 0x44) == 0x2a) &&
            *(u8 *)((char *)cur + 0x36) == 0xff) {
            f32 dx = *(f32 *)((char *)cur + 0x18) - *(f32 *)((char *)obj + 0x18);
            f32 dy = *(f32 *)((char *)cur + 0x1c) - *(f32 *)((char *)obj + 0x1c);
            f32 dz = *(f32 *)((char *)cur + 0x20) - *(f32 *)((char *)obj + 0x20);
            dist = dx * dx + dy * dy + dz * dz;
            if (dist < lbl_803E80E8) {
                if (dist <= lbl_803E7EA4) {
                    scale = (f32)*(s8 *)((char *)*(int *)((char *)cur + 0x50) + 0x56);
                    if (scale <= lbl_803E7EA4) {
                        scale = lbl_803E7EE0;
                    }
                    dist = sqrtf(dist) / scale;
                }
                yaw = Obj_GetYawDeltaToObject(obj, cur, 0);
                if (yaw < 0x5555 && yaw > -0x5555) {
                    if (dist < bestDist || lbl_803E7EA4 == bestDist) {
                        bestDist = dist;
                        best = cur;
                    }
                }
            }
        }
    }
    return best;
}

int fn_802AE480(int obj, int inner, int state)
{
    f32 h;
    f32 lim;

    *(int *)((char *)inner + 0x360) |= 0x1000000;
    *(f32 *)((char *)state + 0x2a0) = lbl_803E7F20;
    h = *(f32 *)((char *)obj + 0x98);
    if (h > lbl_803E7EFC && h < lbl_803E7F44 &&
        *(f32 *)((char *)state + 0x294) >
            *(f32 *)((char *)*(int *)((char *)inner + 0x400) + 0x1c) - lbl_803E7E9C &&
        *(f32 *)((char *)state + 0x298) > lbl_803E7F2C &&
        *(int *)((char *)inner + 0x488) >= 0x96) {
        ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 1;
        ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
        *(u8 *)((char *)inner + 0x8a6) = *(u8 *)((char *)inner + 0x8a7);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E8070;
        ObjAnim_SetCurrentMove(obj, *(s16 *)((char *)*(int *)((char *)inner + 0x3f8) + 0x3a),
                               lbl_803E7EA4, 0);
        ObjAnim_SetCurrentEventStepFrames((ObjAnimComponent *)obj, 0x10);
        *(int *)((char *)inner + 0x858) = *(s16 *)((char *)inner + 0x484);
        *(f32 *)((char *)inner + 0x844) =
            (lbl_803E7F14 + (*(f32 *)((char *)*(int *)((char *)inner + 0x400) + 0x14) +
                             *(f32 *)((char *)state + 0x294))) / lbl_803E7F30;
        *(s16 *)((char *)inner + 0x478) = *(s16 *)((char *)inner + 0x484);
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x484) + 0x8000;
        *(f32 *)((char *)state + 0x294) = -*(f32 *)((char *)state + 0x294);
        *(f32 *)((char *)state + 0x280) = -*(f32 *)((char *)state + 0x280);
    }
    if (((ByteFlags *)((char *)inner + 0x3f0))->b80) {
        if (*(f32 *)((char *)state + 0x294) <=
                (lim = *(f32 *)((char *)*(int *)((char *)inner + 0x400) + 0x10)) &&
            *(f32 *)((char *)state + 0x280) <= lim) {
            *(int *)((char *)inner + 0x494) = *(s16 *)((char *)inner + 0x484);
            ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
            return 1;
        }
        *(f32 *)((char *)inner + 0x408) = lbl_803E7EA4;
        *(f32 *)((char *)inner + 0x438) = *(f32 *)((char *)inner + 0x830);
    }
    return 0;
}

void fn_80295E90(int obj, int mode)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int oldModel;
    int newModel;
    void *tricky;

    objModelGetVecFn_800395d8(obj, 0);
    objModelGetVecFn_800395d8(obj, 9);
    if (mode != 0) {
        fn_80295CF4(obj, 0);
        ((ByteFlags *)((char *)inner + 0x3f3))->b08 = 1;
        tricky = getTrickyObject();
        if (tricky != NULL) {
            trickyImpress(tricky);
        }
        GameBit_Set(0xc30, 1);
        Sfx_PlayFromObject(obj, 0x69);
        (*(void (*)(int, int, int, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))(obj, 0x801, 0, 0x50, 0);
        oldModel = Obj_GetActiveModel(obj);
        Obj_SetActiveModelIndex(obj, 2);
        newModel = Obj_GetActiveModel(obj);
        memcpy((void *)*(int *)((char *)newModel + 0x2c), (void *)*(int *)((char *)oldModel + 0x2c), 0x68);
        memcpy((void *)*(int *)((char *)newModel + 0x30), (void *)*(int *)((char *)oldModel + 0x30), 0x68);
        if (mode == 2) {
            ((ByteFlags *)((char *)inner + 0x3f4))->b80 = 1;
        }
    } else {
        fn_80295CF4(obj, 1);
        ((ByteFlags *)((char *)inner + 0x3f3))->b08 = 0;
        ((ByteFlags *)((char *)inner + 0x3f4))->b80 = 0;
        (*(void (*)(int, int, int, int, int))(*(int *)(*lbl_803DCAB4 + 0xc)))(obj, 0x801, 0, 0x50, 0);
        oldModel = Obj_GetActiveModel(obj);
        Obj_SetActiveModelIndex(obj, 1);
        newModel = Obj_GetActiveModel(obj);
        memcpy((void *)*(int *)((char *)newModel + 0x2c), (void *)*(int *)((char *)oldModel + 0x2c), 0x68);
        memcpy((void *)*(int *)((char *)newModel + 0x30), (void *)*(int *)((char *)oldModel + 0x30), 0x68);
        GameBit_Set(0xc30, 0);
        Sfx_PlayFromObject(obj, 0x69);
    }
}

int fn_802A14F8(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 k;
    f32 pos[2];

    *(int *)((char *)inner + 0x360) &= ~2;
    *(int *)((char *)inner + 0x360) |= 0x2000;
    *(int *)((char *)state + 0x4) |= 0x100000;
    k = lbl_803E7EA4;
    *(f32 *)((char *)state + 0x280) = k;
    *(f32 *)((char *)state + 0x284) = k;
    *(int *)state |= 0x200000;
    *(f32 *)((char *)obj + 0x24) = k;
    *(f32 *)((char *)obj + 0x2c) = k;
    *(int *)((char *)state + 0x4) |= 0x8000000;
    *(f32 *)((char *)obj + 0x28) = k;
    if (*(s8 *)((char *)state + 0x27a) != 0 && lbl_803DE44C != 0 &&
        ((ByteFlags *)((char *)inner + 0x3f4))->b40) {
        *(u8 *)((char *)inner + 0x8b4) = 1;
        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
    }
    if (*(s16 *)((char *)obj + 0xa0) == 0x41a) {
        if (*(s8 *)((char *)state + 0x346) != 0) {
            fn_802AB5A4(obj, inner + 4, 5);
            *(int *)((char *)state + 0x308) = (int)fn_8029FFD0;
            return -0x13;
        }
    } else {
        pos[0] = *(f32 *)((char *)inner + 0x54c);
        pos[1] = *(f32 *)((char *)inner + 0x550);
        if (*(u8 *)((char *)inner + 0x8c8) != 0x48 && *(u8 *)((char *)inner + 0x8c8) != 0x47) {
            (*(void (*)(int, int, int, int, void *, int, int))(*(int *)(*gCameraInterface + 0x1c)))(
                0x4b, 1, 1, 8, pos, 0, 0xff);
        }
        ObjAnim_SetCurrentMove(obj, 0x41a, lbl_803E7EA4, 1);
        *(s16 *)((char *)inner + 0x478) =
            getAngle(*(f32 *)((char *)inner + 0x56c), *(f32 *)((char *)inner + 0x574));
        *(s16 *)((char *)inner + 0x484) = *(s16 *)((char *)inner + 0x478);
        *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)inner + 0x58c);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)inner + 0x76c);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)inner + 0x594);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E800C;
    }
    fn_802AB5A4(obj, inner + 4, 5);
    return 0;
}

void fn_802972B4(int obj, int *flags, f32 *p5, f32 *p6, f32 *p7, s16 *p8)
{
    int inner = *(int *)((char *)obj + 0xb8);
    s8 idx;
    u8 mode;
    f32 zero;

    *flags = 0;
    zero = lbl_803E7EA4;
    *p5 = zero;
    *p6 = zero;
    *p7 = zero;
    if (*(s16 *)((char *)inner + 0x274) == 0x26) {
        *flags |= 1;
        idx = *(s8 *)((char *)inner + 0x8ce);
        if (idx != -1) {
            *flags |= ((EmitElem *)(*(int *)((char *)inner + 0x3dc) +
                                    *(u8 *)((char *)inner + 0x8a9) * 0xb0))->a8[idx];
            *p6 = ((EmitElem *)(*(int *)((char *)inner + 0x3dc) +
                                *(u8 *)((char *)inner + 0x8a9) * 0xb0))
                      ->a70[*(s8 *)((char *)inner + 0x8ce)];
            *p7 = ((EmitElem *)(*(int *)((char *)inner + 0x3dc) +
                                *(u8 *)((char *)inner + 0x8a9) * 0xb0))
                      ->a7c[*(s8 *)((char *)inner + 0x8ce)];
            *p5 = ((EmitElem *)(*(int *)((char *)inner + 0x3dc) +
                                *(u8 *)((char *)inner + 0x8a9) * 0xb0))
                      ->a94[*(s8 *)((char *)inner + 0x8ce)];
        }
        if (*(u8 *)(*(int *)((char *)inner + 0x3dc) +
                    *(u8 *)((char *)inner + 0x8a9) * 0xb0 + 0x88) & 2) {
            if (*(u8 *)((char *)inner + 0x8ab) < *(u8 *)((char *)inner + 0x8ac)) {
                *p6 = lbl_803E7EA4;
                *p7 = lbl_803E7EA4;
            }
        }
        if ((*(u8 *)(*(int *)((char *)inner + 0x3dc) +
                     *(u8 *)((char *)inner + 0x8a9) * 0xb0 + 0x88) & 1) &&
            *(f32 *)((char *)inner + 0x820) >= lbl_803E7EF0) {
            *flags |= 0x80;
        }
    }
    mode = *(u8 *)((char *)inner + 0x8c1);
    if (mode == 0) {
        *flags |= 0x100;
    } else if (mode == 1) {
        *flags |= 0x200;
    } else if (mode == 2) {
        *flags |= 0x400;
    }
    if (*(s16 *)((char *)inner + 0x274) == 0x2e || *(s16 *)((char *)inner + 0x274) == 0x2f) {
        *flags &= 0x7d;
        *flags |= 2;
    }
    *p8 = 0x78;
}

void fn_802B066C(int obj, int state)
{
    f32 v;
    f32 px;
    f32 py;
    f32 pz;

    if (*(u8 *)((char *)state + 0x86c) == 0x1a) {
        return;
    }
    if (((ByteFlags *)((char *)state + 0x3f0))->b08 == 0) {
        v = sqrtf(*(f32 *)((char *)obj + 0x2c) * *(f32 *)((char *)obj + 0x2c) +
                  *(f32 *)((char *)obj + 0x24) * *(f32 *)((char *)obj + 0x24) +
                  *(f32 *)((char *)obj + 0x28) * *(f32 *)((char *)obj + 0x28));
        *(f32 *)((char *)state + 0x7a4) = v;
        v = *(f32 *)((char *)state + 0x7a4);
        if (v < lbl_803E7EE0) {
            v = lbl_803E7EE0;
        } else if (v > lbl_803E8138) {
            v = lbl_803E8138;
        }
        *(f32 *)((char *)state + 0x7a4) = v;
    }
    *(f32 *)((char *)state + 0x79c) =
        *(f32 *)((char *)state + 0x79c) - timeDelta * *(f32 *)((char *)state + 0x7a4);
    if (*(f32 *)((char *)state + 0x79c) <= lbl_803E7EA4) {
        if (Sfx_IsPlayingFromObject(obj, 0x394)) {
            Sfx_StopFromObject(obj, 0x394);
            Sfx_PlayFromObject(obj, 0x395);
        }
        *(f32 *)((char *)state + 0x79c) = lbl_803E7EA4;
        return;
    }
    *(f32 *)((char *)state + 0x7a0) = *(f32 *)((char *)state + 0x7a0) - timeDelta;
    if (*(f32 *)((char *)state + 0x7a0) <= lbl_803E7EA4) {
        ObjPath_GetPointWorldPosition(obj, 0xb, &px, &py, &pz, 0);
        ObjHits_RecordPositionHit(px, py, pz, obj, 0, 0x1f, 1, -1);
        *(f32 *)((char *)state + 0x7a0) = lbl_803E8050;
    }
}

void fn_802AABE4(int obj)
{
    s16 *movp;
    f32 *outp;
    int model;
    short i;
    int inner = *(int *)((char *)obj + 0xb8);
    f32 out2[2];
    f32 out1[5];

    model = ((int *)*(int *)((char *)obj + 0x7c))[*(s8 *)((char *)obj + 0xad)];

    ObjAnim_SetCurrentMove(obj, *(s16 *)*(int *)((char *)inner + 0x3f8), lbl_803E7EA4, 0);
    ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EA4, *(f32 *)((char *)obj + 8), out1, out2);
    lbl_803DAF88[0] = out1[1];

    ObjAnim_SetCurrentMove(obj, lbl_80332F2C[0], lbl_803E7EA4, 0);
    ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EA4, *(f32 *)((char *)obj + 8), out1, out2);
    lbl_803DAF88[1] = out1[1];

    i = 12;
    movp = (s16 *)((char *)lbl_80332F48 + 0x22);
    outp = &lbl_803DAF88[i];
    for (; i <= 15; i++) {
        ObjAnim_SetCurrentMove(obj, *movp, lbl_803E7EA4, 0);
        ObjModel_SampleJointTransform(model, 0, 0, lbl_803E7EA4, *(f32 *)((char *)obj + 8), out1, out2);
        *outp = out1[1];
        movp++;
        outp++;
    }
    ObjAnim_WriteStateWord((ObjAnimComponent *)obj, 0, 0, 0);
}

void fn_802B4A9C(int obj, int sA, int sB)
{
    int *target = (int *)(*(int (*)(int))(*(int *)(*gCameraInterface + 0x3c)))(*gCameraInterface);
    u32 v = (*(u8 *)((char *)sA + 0x3f4) >> 6) & 1;

    if (v != 0) {
        if ((*(u32 *)((char *)sA + 0x360) & 0x10) != 0) {
            if (lbl_803DE44C != NULL && v != 0) {
                *(u8 *)((char *)sA + 0x8b4) = 2;
                ((ByteFlags *)((char *)sA + 0x3f4))->b08 = 0;
            }
            *(u8 *)((char *)sB + 0x349) = 1;
            if (target != NULL) {
                *(int **)((char *)sB + 0x2d0) = target;
            } else {
                f32 dist = lbl_803E8150;
                *(int *)((char *)sB + 0x2d0) = ObjGroup_FindNearestObject(3, obj, &dist);
            }
        } else {
            if (target != NULL) {
                if (*(int **)((char *)sB + 0x2d0) != target) {
                    *(u8 *)((char *)sB + 0x349) = 0;
                    if ((*(u8 *)((char *)*(int *)((char *)target + 0x78) + 4) & 0xf) == 1) {
                        if (lbl_803DE44C != NULL && ((*(u8 *)((char *)sA + 0x3f4) >> 6) & 1) != 0) {
                            *(u8 *)((char *)sA + 0x8b4) = 2;
                            ((ByteFlags *)((char *)sA + 0x3f4))->b08 = 0;
                        }
                        *(u8 *)((char *)sB + 0x349) = 1;
                    }
                }
                *(int **)((char *)sB + 0x2d0) = target;
            } else {
                *(int *)((char *)sB + 0x2d0) = 0;
                *(u8 *)((char *)sB + 0x349) = 0;
            }
        }
        if (*(int **)((char *)sB + 0x2d0) != NULL) {
            fn_8014C540(*(int *)((char *)sB + 0x2d0), (char *)sA + 0x884, (char *)sA + 0x888,
                        (char *)sA + 0x88c);
        } else {
            *(s16 *)((char *)sA + 0x80e) = -1;
        }
    }
}

int fn_8029A5E4(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r = fn_802AC7DC(obj, state, inner);
    if (r != 0) {
        return r;
    }
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    if (*(s8 *)((char *)state + 0x27a) != 0) {
        int p = *(int *)((char *)*(int *)((char *)obj + 0xb8) + 0x35c);
        int val = *(s16 *)((char *)p + 4);
        if (val < 0) {
            val = 0;
        } else {
            int hi = *(s16 *)((char *)p + 6);
            if (val > hi) {
                val = hi;
            }
        }
        *(s16 *)((char *)p + 4) = (s16)val;
        lbl_803DE45C = lbl_803E7F30;
    }
    if (lbl_803E7F30 == lbl_803DE45C || lbl_803E7FA0 == lbl_803DE45C ||
        lbl_803E7FA4 == lbl_803DE45C) {
        fn_802AA2B0(obj, state, *(f32 *)((char *)inner + 0x7bc),
                    (f32)randomGetRange(-0xc8, 0xc8) / lbl_803E7F5C);
    }
    lbl_803DE45C = lbl_803DE45C - lbl_803E7EE0;
    if (lbl_803DE45C < lbl_803E7EA4) {
        *(int *)((char *)state + 0x308) = (int)fn_8029A4A8;
        return 0x2d;
    }
    if (*(int **)((char *)state + 0x2d0) == NULL) {
        if ((*(u16 *)((char *)inner + 0x6e2) & 0x200) != 0 ||
            *(u8 *)((char *)inner + 0x8c8) != 0x52) {
            *(int *)((char *)state + 0x308) = (int)fn_8029A420;
            return 0x2c;
        }
    }
    return 0;
}

void fn_80296D20(int obj, void *arg)
{
    int state = *(int *)((char *)obj + 0xb8);
    int inner = *(int *)((char *)obj + 0xb8);
    short type;

    if (*(void **)((char *)obj + 0x30) == arg) {
        objHitDetectFn_80062e84(obj, 0, 1);
        type = *(s16 *)((char *)state + 0x274);
        if (type == 0xa || type == 0xc) {
            *(int *)((char *)state + 4) &= ~0x100000;
            fn_802AB5A4(obj, inner, 5);
            ((ByteFlags *)((char *)inner + 0x3f0))->b80 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b10 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b08 = 0;
            staffFn_80170380(lbl_803DE450, 2);
            ((ByteFlags *)((char *)inner + 0x3f0))->b02 = 0;
            *(int *)((char *)inner + 0x360) |= 0x800000;
            ObjHits_SyncObjectPositionIfDirty(obj);
            ((ByteFlags *)((char *)inner + 0x3f0))->b40 = 0;
            ((ByteFlags *)((char *)inner + 0x3f0))->b04 = 1;
            ((ByteFlags *)((char *)inner + 0x3f4))->b10 = 1;
            *(u8 *)((char *)inner + 0x800) = 0;
            if (*(void **)((char *)inner + 0x7f8) != NULL) {
                short id = *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 0x46);
                if (id == 0x3cf || id == 0x662) {
                    objThrowFn_80182504(*(int *)((char *)inner + 0x7f8));
                } else {
                    objSaveFn_800ea774(*(int *)((char *)inner + 0x7f8));
                }
                *(s16 *)((char *)*(int *)((char *)inner + 0x7f8) + 6) &= ~0x4000;
                *(int *)((char *)*(int *)((char *)inner + 0x7f8) + 0xf8) = 0;
                *(int *)((char *)inner + 0x7f8) = 0;
            }
            (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, state, 2);
            *(int *)((char *)state + 0x304) = (int)fn_802A514C;
        }
    }
}

void fn_802A81B8(int obj, int state, f32 *out)
{
    f32 mag;
    u32 flag = (*(u8 *)((char *)state + 0x3f1) >> 5) & 1;

    if (flag != 0 || *(int **)((char *)state + 0x2d0) != NULL) {
        out[0] = *(f32 *)((char *)obj + 0x24);
        out[1] = lbl_803E7EA4;
        out[2] = *(f32 *)((char *)obj + 0x2c);
        mag = PSVECMag(out);
        if (mag > lbl_803E7EA4) {
            PSVECScale(out, out, lbl_803E7EE0 / mag);
        } else {
            out[0] = -fn_80293E80(lbl_803E7F94 * (f32)*(s16 *)((char *)state + 0x478) /
                                  lbl_803E7F98);
            out[1] = lbl_803E7EA4;
            out[2] = -sin(lbl_803E7F94 * (f32)*(s16 *)((char *)state + 0x478) / lbl_803E7F98);
        }
    } else {
        out[0] = -fn_80293E80(lbl_803E7F94 * (f32)*(s16 *)((char *)state + 0x478) / lbl_803E7F98);
        out[1] = lbl_803E7EA4;
        out[2] = -sin(lbl_803E7F94 * (f32)*(s16 *)((char *)state + 0x478) / lbl_803E7F98);
    }
}

int fn_8029B7B0(int obj, int state)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int r = fn_802AC7DC(obj, state, inner);
    u32 b;
    if (r != 0) {
        return r;
    }
    {
        f32 z = lbl_803E7EA4;
        *(f32 *)((char *)state + 0x294) = z;
        *(f32 *)((char *)state + 0x284) = z;
        *(f32 *)((char *)state + 0x280) = z;
        *(f32 *)((char *)obj + 0x24) = z;
        *(f32 *)((char *)obj + 0x28) = z;
        *(f32 *)((char *)obj + 0x2c) = z;
    }
    setAButtonIcon(6);
    setBButtonIcon(0xa);
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x43d:
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)state + 0x308) = (int)fn_8029A4A8;
            return 0x2d;
        }
        break;
    case 0x448:
        if (*(f32 *)((char *)obj + 0x98) > lbl_803E7E9C) {
            if (*(u8 *)((char *)inner + 0x8b3) == 0) {
                Sfx_PlayFromObject(obj, 0x2c);
                if (lbl_803DE44C != NULL) {
                    b = (*(u8 *)((char *)inner + 0x3f4) >> 6) & 1;
                    if (b != 0) {
                        *(u8 *)((char *)inner + 0x8b4) = 2;
                        ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 0;
                    }
                }
            }
        }
        if (*(s8 *)((char *)state + 0x346) != 0) {
            *(int *)((char *)state + 0x308) = (int)fn_8029A4A8;
            return 0x2d;
        }
        break;
    default:
    {
        f32 z;
        ObjAnim_SetCurrentMove(obj, 0x43d, lbl_803E7EA4, 0);
        *(f32 *)((char *)state + 0x2a0) = lbl_803E7F4C;
        if (lbl_803DE44C != NULL) {
            b = (*(u8 *)((char *)inner + 0x3f4) >> 6) & 1;
            if (b != 0) {
                *(u8 *)((char *)inner + 0x8b4) = 4;
                ((ByteFlags *)((char *)inner + 0x3f4))->b08 = 1;
            }
        }
        z = lbl_803E7EA4;
        lbl_803DE460 = z;
        lbl_803DE464 = z;
        *(f32 *)((char *)inner + 0x7bc) = z;
        *(f32 *)((char *)inner + 0x7b8) = z;
        break;
    }
    }
    if ((*(u16 *)((char *)inner + 0x6e2) & 0x200) != 0 || *(u8 *)((char *)inner + 0x8c8) != 0x52) {
        buttonDisable(0, 0x200);
        *(int *)((char *)state + 0x308) = (int)fn_8029A420;
        return 0x2c;
    }
    return 0;
}

void fn_802B4ED8(int obj, int p2, int mode)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 sx, sy, sz;
    u32 v;
    u32 m;

    if ((s8)p2 != -1) {
        if ((*(u32 *)((char *)inner + 0x360) & 0x4001) != 0) {
            return;
        }
    }
    v = (*(u8 *)((char *)inner + 0x3f3) >> 3) & 1;
    if (v != 0) {
        return;
    }
    if ((u32)*(u8 *)((char *)obj + 0x36) < 2) {
        return;
    }
    if (*(void **)((char *)inner + 0x7f0) != NULL) {
        if ((*(u16 *)((char *)obj + 0xb0) & 0x1000) != 0 ||
            arrayIndexOf(&lbl_803DC6C4, 2, *(s16 *)((char *)inner + 0x274)) != -1) {
            int p = *(int *)((char *)inner + 0x7f0);
            (*(void (*)(int, f32))(*(int *)((char *)*(int *)*(int *)((char *)p + 0x68) + 0x50)))(
                p, *(f32 *)((char *)*(int *)((char *)obj + 0x50) + 4));
        }
    }
    if ((*(u32 *)((char *)inner + 0x360) & 0x8000000) != 0) {
        sx = *(f32 *)((char *)obj + 0xc);
        sy = *(f32 *)((char *)obj + 0x10);
        sz = *(f32 *)((char *)obj + 0x14);
        *(f32 *)((char *)obj + 0xc) = *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x20);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x24);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x28);
        *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x20) = sx;
        *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x24) = sy;
        *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x28) = sz;
    }
    *(f32 *)((char *)obj + 0x10) =
        *(f32 *)((char *)obj + 0x10) + *(f32 *)((char *)inner + 0x7c8);
    m = (u32)(mode & 0xff);
    if (m == 1) {
        objRenderFuzz(obj);
    } else if (m == 2) {
        objRenderFn_800413d4(obj);
    } else if (m == 4) {
        fuzzRenderFn_800412dc(obj);
    }
    objSetMtxFn_800412d4(0);
    *(f32 *)((char *)obj + 0x10) =
        *(f32 *)((char *)obj + 0x10) - *(f32 *)((char *)inner + 0x7c8);
    if ((*(u32 *)((char *)inner + 0x360) & 0x8000000) != 0) {
        *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x20) = *(f32 *)((char *)obj + 0xc);
        *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x24) = *(f32 *)((char *)obj + 0x10);
        *(f32 *)((char *)*(int *)((char *)obj + 0x64) + 0x28) = *(f32 *)((char *)obj + 0x14);
        *(f32 *)((char *)obj + 0xc) = sx;
        *(f32 *)((char *)obj + 0x10) = sy;
        *(f32 *)((char *)obj + 0x14) = sz;
    }
}

void fn_802AA8D0(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    struct {
        u8 pad[0xc];
        f32 x;
        f32 y;
        f32 z;
    } buf;
    f32 base = lbl_803E80C4;
    f32 dy;
    int i;

    dy = base - *(f32 *)((char *)inner + 0x7d0);
    buf.y = dy;
    if (lbl_803DE478 < lbl_803E80D8) {
        *(u8 *)((char *)inner + 0x8ca) = 0;
        return;
    }
    if (dy <= lbl_803E7EA4) {
        lbl_803DE478 = lbl_803DE478 - lbl_803E7F14 * timeDelta;
        return;
    }
    lbl_803DE478 = base;
    buf.y = dy + *(f32 *)((char *)obj + 0x10);
    for (i = 0; i < 10; i++) {
        buf.x = *(f32 *)((char *)obj + 0xc) + (f32)randomGetRange(-0x64, 0x64) / lbl_803E7ED8;
        buf.z = *(f32 *)((char *)obj + 0x14) + (f32)randomGetRange(-0x64, 0x64) / lbl_803E7ED8;
        (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
            obj, randomGetRange(0, 2) + 0x3f4, &buf, 1, -1, 0);
        (**(void (**)(int, int, void *, int, int, int))((char *)(*gPartfxInterface) + 0x8))(
            obj, randomGetRange(0, 2) + 0x3f7, &buf, 1, -1, 0);
    }
}
#pragma peephole reset
#pragma scheduling reset
