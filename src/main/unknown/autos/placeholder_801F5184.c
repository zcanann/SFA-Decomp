#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_801F5184.h"

extern undefined8 FUN_80006724();
extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_8000680c();
extern undefined8 FUN_80006824();
extern undefined4 FUN_80006920();
extern void* FUN_800069a8();
extern double FUN_80006a38();
extern undefined4 FUN_80006ba8();
extern undefined4 FUN_80017520();
extern undefined4 FUN_80017524();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern double FUN_80017708();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern int FUN_80017730();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017784();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_80017a78();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ad0();
extern uint FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_80017af8();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined8 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjHits_RecordObjectHit();
extern int ObjHits_GetPriorityHit();
extern int ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjPath_GetPointLocalPosition();
extern int FUN_80039520();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern undefined4 FUN_8005335c();
extern undefined4 FUN_8005336c();
extern undefined4 FUN_80053b3c();
extern undefined4 FUN_80053b70();
extern undefined4 FUN_80053bfc();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_8005b024();
extern undefined8 FUN_8005d17c();
extern undefined4 FUN_8005d3a0();
extern undefined4 FUN_8005d3a4();
extern undefined4 FUN_800632e8();
extern int FUN_800632f4();
extern uint FUN_8007f66c();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f6e4();
extern undefined4 FUN_8007f718();
extern int FUN_8007f764();
extern undefined4 FUN_80080f28();
extern byte FUN_80080f2c();
extern undefined4 FUN_80080f3c();
extern undefined4 FUN_800810e0();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_80081118();
extern undefined4 FUN_8008112c();
extern undefined4 FUN_8011e868();
extern ushort FUN_8016edb4();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern undefined8 FUN_8028683c();
extern int FUN_80286840();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294ccc();
extern void fn_8001CB3C(void *state);
extern int fn_8001CC9C(int obj, int red, int green, int blue, int alpha);
extern void Obj_FreeObject(int obj);
extern void storeZeroToFloatParam(void *timer);
extern void s16toFloat(void *timer, int duration);
extern int timerCountDown(void *timer);
extern void itemPickupDoParticleFx(int obj, f32 scale, int mode, int count);
extern void fn_801F4C04(void);
extern void fn_801F4C28(int obj, void *state);

extern undefined4 DAT_801f5cc4;
extern undefined4 DAT_802c2c68;
extern undefined4 DAT_802c2c6c;
extern undefined4 DAT_802c2c70;
extern undefined4 DAT_802c2c74;
extern undefined4 DAT_802c2c78;
extern undefined4 DAT_802c2c7c;
extern undefined4 DAT_802c2c80;
extern undefined4 DAT_802c2c84;
extern uint DAT_80329908;
extern undefined4 DAT_80329a10;
extern undefined4 DAT_80329a20;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcd90;
extern undefined4 DAT_803dcd9c;
extern undefined4 DAT_803dcdb0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd72c;
extern int *gExpgfxInterface;
extern s16 lbl_803DC128;
extern undefined4 DAT_803de928;
extern undefined4 DAT_803de92a;
extern undefined4 DAT_803de92c;
extern undefined4 DAT_803de92e;
extern undefined4 DAT_803de930;
extern undefined4 DAT_803de938;
extern f64 DOUBLE_803e6b68;
extern f64 DOUBLE_803e6ba0;
extern f64 DOUBLE_803e6bb0;
extern f64 DOUBLE_803e6c08;
extern f64 DOUBLE_803e6c40;
extern f64 DOUBLE_803e6cb8;
extern f64 DOUBLE_803e6cc0;
extern f64 DOUBLE_803e6d18;
extern f64 DOUBLE_803e6d58;
extern f64 DOUBLE_803e6d60;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803dcd98;
extern f32 FLOAT_803de920;
extern f32 FLOAT_803de924;
extern f32 FLOAT_803e6b40;
extern f32 FLOAT_803e6b44;
extern f32 FLOAT_803e6b48;
extern f32 FLOAT_803e6b4c;
extern f32 FLOAT_803e6b50;
extern f32 FLOAT_803e6b54;
extern f32 FLOAT_803e6b58;
extern f32 FLOAT_803e6b5c;
extern f32 FLOAT_803e6b60;
extern f32 FLOAT_803e6b70;
extern f32 FLOAT_803e6b74;
extern f32 FLOAT_803e6b78;
extern f32 FLOAT_803e6b7c;
extern f32 FLOAT_803e6b80;
extern f32 FLOAT_803e6b84;
extern f32 FLOAT_803e6b88;
extern f32 FLOAT_803e6b90;
extern f32 FLOAT_803e6b94;
extern f32 FLOAT_803e6b98;
extern f32 FLOAT_803e6bb8;
extern f32 FLOAT_803e6bbc;
extern f32 FLOAT_803e6bc0;
extern f32 FLOAT_803e6bc4;
extern f32 FLOAT_803e6bd4;
extern f32 FLOAT_803e6bd8;
extern f32 FLOAT_803e6bdc;
extern f32 FLOAT_803e6be0;
extern f32 FLOAT_803e6be4;
extern f32 FLOAT_803e6bec;
extern f32 FLOAT_803e6bf0;
extern f32 FLOAT_803e6bf8;
extern f32 FLOAT_803e6bfc;
extern f32 FLOAT_803e6c00;
extern f32 FLOAT_803e6c10;
extern f32 FLOAT_803e6c14;
extern f32 FLOAT_803e6c18;
extern f32 FLOAT_803e6c1c;
extern f32 FLOAT_803e6c20;
extern f32 FLOAT_803e6c24;
extern f32 FLOAT_803e6c30;
extern f32 FLOAT_803e6c34;
extern f32 FLOAT_803e6c38;
extern f32 FLOAT_803e6c48;
extern f32 FLOAT_803e6c4c;
extern f32 FLOAT_803e6c50;
extern f32 FLOAT_803e6c54;
extern f32 FLOAT_803e6c58;
extern f32 FLOAT_803e6c5c;
extern f32 FLOAT_803e6c60;
extern f32 FLOAT_803e6c64;
extern f32 FLOAT_803e6c68;
extern f32 FLOAT_803e6c6c;
extern f32 FLOAT_803e6c70;
extern f32 FLOAT_803e6c74;
extern f32 FLOAT_803e6c78;
extern f32 FLOAT_803e6c7c;
extern f32 FLOAT_803e6c80;
extern f32 FLOAT_803e6c84;
extern f32 FLOAT_803e6c88;
extern f32 FLOAT_803e6c8c;
extern f32 FLOAT_803e6c90;
extern f32 FLOAT_803e6c94;
extern f32 FLOAT_803e6c98;
extern f32 FLOAT_803e6c9c;
extern f32 FLOAT_803e6ca0;
extern f32 FLOAT_803e6ca4;
extern f32 FLOAT_803e6ca8;
extern f32 FLOAT_803e6cac;
extern f32 FLOAT_803e6cb0;
extern f32 FLOAT_803e6cc8;
extern f32 FLOAT_803e6ccc;
extern f32 FLOAT_803e6cd0;
extern f32 FLOAT_803e6cd4;
extern f32 FLOAT_803e6cd8;
extern f32 FLOAT_803e6cdc;
extern f32 FLOAT_803e6ce0;
extern f32 FLOAT_803e6ce4;
extern f32 FLOAT_803e6ce8;
extern f32 FLOAT_803e6cec;
extern f32 FLOAT_803e6cf0;
extern f32 FLOAT_803e6cf8;
extern f32 FLOAT_803e6d00;
extern f32 FLOAT_803e6d04;
extern f32 FLOAT_803e6d08;
extern f32 FLOAT_803e6d0c;
extern f32 FLOAT_803e6d10;
extern f32 FLOAT_803e6d20;
extern f32 FLOAT_803e6d24;
extern f32 FLOAT_803e6d28;
extern f32 FLOAT_803e6d2c;
extern f32 FLOAT_803e6d30;
extern f32 FLOAT_803e6d34;
extern f32 FLOAT_803e6d38;
extern f32 FLOAT_803e6d3c;
extern f32 FLOAT_803e6d40;
extern f32 FLOAT_803e6d44;
extern f32 FLOAT_803e6d48;
extern f32 FLOAT_803e6d50;
extern f32 FLOAT_803e6d68;
extern f32 FLOAT_803e6d6c;
extern f32 FLOAT_803e6d70;
extern f32 FLOAT_803e6d74;
extern f32 FLOAT_803e6d78;
extern f32 FLOAT_803e6d7c;
extern f32 FLOAT_803e6d80;

/*
 * --INFO--
 *
 * Function: FireFlyFn_801f4f88
 * EN v1.0 Address: 0x801F4F88
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F5194
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void *Obj_GetPlayerObject(void);
extern f32 mathFn_80010ee0(f32 *src, int b, f32 t);
extern int getAngle(f32 dx, f32 dy);
extern f32 Vec_xzDistance(f32 *a, f32 *b);
extern f32 getXZDistance(f32 *a, f32 *b);
extern void gameBitIncrement(int eventId);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int GameBit_Get(int eventId);
extern int GameBit_Set(int eventId, int val);
extern u32 randomGetRange(int min, int max);
extern void fn_801F4D54(int obj, int state);
extern int *gPartfxInterface;
extern int *gMapEventInterface;
extern int *gObjectTriggerInterface;
extern f32 timeDelta;
extern f32 lbl_803E5EA8;
extern f32 lbl_803E5EB4;
extern f64 lbl_803E5ED0;
extern f32 lbl_803E5ED8;
extern f32 lbl_803E5EDC;
extern f32 lbl_803E5EE0;
extern f32 lbl_803E5EE4;
extern f32 lbl_803E5EE8;
extern f32 lbl_803E5EEC;
extern f32 lbl_803E5EC4;
extern f32 lbl_803E5EF0;
extern f32 lbl_803E5EF8;
extern f32 lbl_803E5EFC;
extern f32 lbl_803E5F00;
extern void objRenderFn_80041018(int obj);
extern void unlockLevel(int mapId, int flags, int unlocked);
extern void loadMapAndParent(int mapId);
extern int mapGetDirIdx(int mapId);
extern void lockLevel(int mapDir, int locked);
extern void warpToMap(int mapId, int transition);
extern void skyFn_80088c94(int skyId, int enabled);
extern void setDrawCloudsAndLights(int enabled);
extern void getEnvfxAct(int obj, int target, int effectId, int flags);
extern void getEnvfxActImmediately(int obj, int target, int effectId, int flags);
extern void Rcp_SetSpiritVisionEnabled(int enabled);
extern void setAButtonIcon(int iconId);
extern int getSkyColorFn_80088e08(int skyId);
extern void fn_80296518(int obj, int arg, int enable);
extern void objRenderFn_8003b8f4(f32 scale);
extern f32 Vec_distance(void *a, void *b);
extern int ObjList_FindObjectById(int objectId);
extern int lbl_80328CC8[];
extern f32 lbl_803E5F10;


/*
 * --INFO--
 *
 * Function: FUN_801f4f8c
 * EN v1.0 Address: 0x801F4F8C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F51C0
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4f8c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4f90
 * EN v1.0 Address: 0x801F4F90
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801F523C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801f4f90(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined2 *param_9)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801f4f98
 * EN v1.0 Address: 0x801F4F98
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F5260
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4f98(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4f9c
 * EN v1.0 Address: 0x801F4F9C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F538C
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4f9c(undefined4 param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fa0
 * EN v1.0 Address: 0x801F4FA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F5504
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fa0(undefined4 param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fa4
 * EN v1.0 Address: 0x801F4FA4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F55C0
 * EN v1.1 Size: 1104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fa4(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fa8
 * EN v1.0 Address: 0x801F4FA8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F5A10
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fa8(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fac
 * EN v1.0 Address: 0x801F4FAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F5A60
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fac(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fb0
 * EN v1.0 Address: 0x801F4FB0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F5C34
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fb0(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fb4
 * EN v1.0 Address: 0x801F4FB4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801F5CC8
 * EN v1.1 Size: 1148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801f4fb4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,undefined *param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            int param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fbc
 * EN v1.0 Address: 0x801F4FBC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F6144
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fbc(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fc0
 * EN v1.0 Address: 0x801F4FC0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F6170
 * EN v1.1 Size: 2196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fc0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fc4
 * EN v1.0 Address: 0x801F4FC4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F6A04
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fc4(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fc8
 * EN v1.0 Address: 0x801F4FC8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F6B84
 * EN v1.1 Size: 516b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fc8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fcc
 * EN v1.0 Address: 0x801F4FCC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F6D88
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fcc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fd0
 * EN v1.0 Address: 0x801F4FD0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F708C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fd0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fd4
 * EN v1.0 Address: 0x801F4FD4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F70C0
 * EN v1.1 Size: 888b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fd4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fd8
 * EN v1.0 Address: 0x801F4FD8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F7438
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fd8(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fdc
 * EN v1.0 Address: 0x801F4FDC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F74DC
 * EN v1.1 Size: 1116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fdc(ushort *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fe0
 * EN v1.0 Address: 0x801F4FE0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F7938
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fe0(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fe4
 * EN v1.0 Address: 0x801F4FE4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F7978
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fe4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fe8
 * EN v1.0 Address: 0x801F4FE8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F7A0C
 * EN v1.1 Size: 1408b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fe8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4fec
 * EN v1.0 Address: 0x801F4FEC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F7F8C
 * EN v1.1 Size: 784b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4fec(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4ff0
 * EN v1.0 Address: 0x801F4FF0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F829C
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4ff0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4ff4
 * EN v1.0 Address: 0x801F4FF4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F8380
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4ff4(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4ff8
 * EN v1.0 Address: 0x801F4FF8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F83B4
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4ff8(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f4ffc
 * EN v1.0 Address: 0x801F4FFC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F84E8
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4ffc(int param_1,short *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5000
 * EN v1.0 Address: 0x801F5000
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F8640
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5000(ushort *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5004
 * EN v1.0 Address: 0x801F5004
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F8700
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5004(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5008
 * EN v1.0 Address: 0x801F5008
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F8724
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5008(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f500c
 * EN v1.0 Address: 0x801F500C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F87B4
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f500c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5010
 * EN v1.0 Address: 0x801F5010
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F88DC
 * EN v1.1 Size: 3860b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5010(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5014
 * EN v1.0 Address: 0x801F5014
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F97F0
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5014(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5018
 * EN v1.0 Address: 0x801F5018
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801F9A74
 * EN v1.1 Size: 804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801f5018(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801f5020
 * EN v1.0 Address: 0x801F5020
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F9D98
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5020(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5024
 * EN v1.0 Address: 0x801F5024
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F9DC4
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5024(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5028
 * EN v1.0 Address: 0x801F5028
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F9E3C
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5028(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f502c
 * EN v1.0 Address: 0x801F502C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F9F84
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f502c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5030
 * EN v1.0 Address: 0x801F5030
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801F9FD0
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5030(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5034
 * EN v1.0 Address: 0x801F5034
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FA270
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5034(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5038
 * EN v1.0 Address: 0x801F5038
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FA3D4
 * EN v1.1 Size: 1180b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5038(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f503c
 * EN v1.0 Address: 0x801F503C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FA870
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f503c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5040
 * EN v1.0 Address: 0x801F5040
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FA8A0
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5040(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5044
 * EN v1.0 Address: 0x801F5044
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FA92C
 * EN v1.1 Size: 876b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5044(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5048
 * EN v1.0 Address: 0x801F5048
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FAC98
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5048(uint param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f504c
 * EN v1.0 Address: 0x801F504C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FAD44
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f504c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5050
 * EN v1.0 Address: 0x801F5050
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FAD7C
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5050(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5054
 * EN v1.0 Address: 0x801F5054
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FAEB8
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5054(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5058
 * EN v1.0 Address: 0x801F5058
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FAEF0
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5058(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f505c
 * EN v1.0 Address: 0x801F505C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FB1F4
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f505c(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5060
 * EN v1.0 Address: 0x801F5060
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FB2B4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5060(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5064
 * EN v1.0 Address: 0x801F5064
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FB2EC
 * EN v1.1 Size: 848b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5064(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5068
 * EN v1.0 Address: 0x801F5068
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FB63C
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5068(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f506c
 * EN v1.0 Address: 0x801F506C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FB674
 * EN v1.1 Size: 512b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f506c(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801f5070
 * EN v1.0 Address: 0x801F5070
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801FB874
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f5070(uint param_1)
{
}

void fn_801F568C(void) {}

typedef struct WmSpiritPlaceState {
    f32 heightOffset;
    int unk_04;
    s16 unk_08;
    s16 unk_0A;
    s16 primaryGameBit;
    s16 secondaryGameBit;
    s16 setupParam;
    u8 flags12;
    u8 mapEventState;
    u8 transitionDelay;
    u8 flags15;
    u8 pad16[2];
} WmSpiritPlaceState;

typedef struct WmSeqPointState {
    f32 radius;
    s16 requiredGameBit;
    s16 gateGameBit;
    s16 triggerId;
    s16 unk0A;
    u8 command;
    u8 done;
    u8 mode;
    u8 skyWasOn;
} WmSeqPointState;

int fn_801F5690(int obj, int unused, int actor)
{
    WmSpiritPlaceState *state;
    int i;
    int mapId;
    u8 action;
    u8 fxPos[24];

    state = *(WmSpiritPlaceState **)(obj + 0xb8);
    if ((state->flags12 & 1) != 0) {
        (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 8))(obj, 0x7d8, NULL, 2, -1, 0);
        (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 8))(obj, 0x7d8, fxPos, 2, -1, 0);
    }

    *(u8 *)(actor + 0x56) = 0;
    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
    *(void **)(actor + 0xe8) = fn_801F568C;

    for (i = 0; i < *(u8 *)(actor + 0x8b); i++) {
        action = *(u8 *)(actor + i + 0x81);
        switch (action) {
            case 1:
                unlockLevel(0, 0, 1);
                break;
            case 3:
                mapId = *(int *)(*(int *)(obj + 0x4c) + 0x14);
                if (mapId == 0x47295 || mapId == 0x49781 || mapId == 0x4a1c0) {
                    warpToMap(0x7e, 0);
                }
                break;
            case 4:
                mapId = *(int *)(*(int *)(obj + 0x4c) + 0x14);
                if (mapId == 0x47295 || mapId == 0x49781 || mapId == 0x4a1c0 ||
                    mapId == 0x4a250 || mapId == 0x4a5e6) {
                    state->transitionDelay = 1;
                }
                break;
            case 5:
                state->flags12 = (u8)(state->flags12 | 1);
                break;
            case 6:
                state->flags12 = (u8)(state->flags12 & ~1);
                break;
            case 7:
                skyFn_80088c94(7, 0);
                setDrawCloudsAndLights(1);
                getEnvfxAct(obj, obj, 0x84, 0);
                getEnvfxAct(obj, obj, 0x8a, 0);
                getEnvfxActImmediately(0, 0, 0x217, 0);
                getEnvfxActImmediately(0, 0, 0x216, 0);
                break;
            case 8:
                Rcp_SetSpiritVisionEnabled(1);
                break;
            case 9:
                Rcp_SetSpiritVisionEnabled(0);
                break;
            case 2:
                mapId = *(int *)(*(int *)(obj + 0x4c) + 0x14);
                if (mapId == 0x2183) {
                    lockLevel(mapGetDirIdx(0x41), 0);
                    lockLevel(mapGetDirIdx(0xb), 1);
                    (*(void (**)(int))(*gMapEventInterface + 0x78))(1);
                } else if (mapId == 0x47295) {
                    loadMapAndParent(0x42);
                    lockLevel(mapGetDirIdx(0x42), 0);
                    lockLevel(mapGetDirIdx(0xb), 1);
                    (*(void (**)(int, int))(*gMapEventInterface + 0x44))(0x42, 3);
                    (*(void (**)(int, int))(*gMapEventInterface + 0x44))(7, 4);
                } else if (mapId == 0x49781) {
                    loadMapAndParent(0x42);
                    lockLevel(mapGetDirIdx(0x42), 0);
                    lockLevel(mapGetDirIdx(0xb), 1);
                    (*(void (**)(int, int))(*gMapEventInterface + 0x44))(0x42, 3);
                    (*(void (**)(int, int))(*gMapEventInterface + 0x44))(7, 5);
                } else if (mapId == 0x4a1c0) {
                    loadMapAndParent(0x42);
                    lockLevel(mapGetDirIdx(0x42), 0);
                    lockLevel(mapGetDirIdx(0xb), 1);
                    (*(void (**)(int, int))(*gMapEventInterface + 0x44))(0x42, 3);
                    (*(void (**)(int, int))(*gMapEventInterface + 0x44))(7, 7);
                }
                break;
        }
    }

    return 0;
}

int wmspiritplace_getExtraSize(void) { return 0x18; }
int wmspiritplace_getObjectTypeId(void) { return 0x0; }
void wmspiritplace_free(void) {}

#pragma peephole off
#pragma scheduling off
void wmspiritplace_render(undefined4 p1, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, s8 visible)
{
    if (visible != 0) {
    }
}
#pragma scheduling reset
#pragma peephole reset

void wmspiritplace_hitDetect(int obj)
{
    if (*(void **)(obj + 0x74) != NULL) {
        objRenderFn_80041018(obj);
    }
}

void wmspiritplace_update(int obj)
{
    WmSpiritPlaceState *state;
    int mapId;

    state = *(WmSpiritPlaceState **)(obj + 0xb8);
    if (state->transitionDelay == 0) {
        state->flags12 = (u8)(state->flags12 & ~1);
        mapId = *(int *)(*(int *)(obj + 0x4c) + 0x14);
        if (mapId == 0x47295) {
            if (state->mapEventState == 2) {
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
                }
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    if (GameBit_Get(state->secondaryGameBit) == 0 || GameBit_Get(0x29b) == 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
                    } else {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        GameBit_Set(state->secondaryGameBit, 0);
                        GameBit_Set(0xbfd, 0);
                    }
                } else {
                    if ((*(u8 *)(obj + 0xaf) & 0x10) != 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xef);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        state->flags15 = (u8)((state->flags15 & 0x7f) | 0x80);
                    }
                }
            } else {
                *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
            }
        } else if (mapId == 0x2183) {
            if (state->mapEventState == 1) {
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
                }
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
                } else {
                    if ((*(u8 *)(obj + 0xaf) & 0x10) != 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xef);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
                        GameBit_Set(state->secondaryGameBit, 1);
                        GameBit_Set(state->primaryGameBit, 0);
                    }
                }
            } else {
                *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
            }
        } else if (mapId == 0x49781) {
            if (state->mapEventState == 3) {
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
                }
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    if (GameBit_Get(state->secondaryGameBit) == 0 || GameBit_Get(0x8a2) == 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
                    } else {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        GameBit_Set(state->secondaryGameBit, 0);
                    }
                } else {
                    if ((*(u8 *)(obj + 0xaf) & 0x10) != 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xef);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        state->flags15 = (u8)((state->flags15 & 0x7f) | 0x80);
                    }
                }
            } else {
                *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
            }
        } else if (mapId == 0x4a1c0) {
            if (state->mapEventState == 4) {
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
                }
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    if (GameBit_Get(state->secondaryGameBit) == 0 || GameBit_Get(0xc71) == 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
                    } else {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        GameBit_Set(state->secondaryGameBit, 0);
                    }
                } else {
                    if ((*(u8 *)(obj + 0xaf) & 0x10) != 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xef);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        state->flags15 = (u8)((state->flags15 & 0x7f) | 0x80);
                    }
                }
            } else {
                *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
            }
        } else if (mapId == 0x4a250) {
            if (state->mapEventState == 5) {
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
                }
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    if (GameBit_Get(state->secondaryGameBit) == 0 || GameBit_Get(0xcb6) == 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
                    } else if (((state->flags15 >> 6) & 1) != 0) {
                        state->flags15 = (u8)(state->flags15 & 0xbf);
                        GameBit_Set(state->primaryGameBit, 0);
                        GameBit_Set(0xd1f, 1);
                        getEnvfxActImmediately(0, 0, 0x217, 0);
                        getEnvfxActImmediately(obj, obj, 0x216, 0);
                        getEnvfxActImmediately(obj, obj, 0x229, 0);
                        getEnvfxActImmediately(obj, obj, 0x22a, 0);
                        (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 4, 1);
                        (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 10, 0);
                        (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 0xb, 1);
                    }
                } else {
                    if ((*(u8 *)(obj + 0xaf) & 0x10) != 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xef);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        state->flags15 = (u8)((state->flags15 & 0x7f) | 0x80);
                        state->flags15 = (u8)((state->flags15 & 0xbf) | 0x40);
                    }
                }
            } else {
                *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
            }
        } else if (mapId == 0x4a5e6) {
            if (state->mapEventState == 6) {
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
                }
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    if (GameBit_Get(state->secondaryGameBit) == 0 || GameBit_Get(0xcb8) == 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
                    } else {
                        GameBit_Set(state->primaryGameBit, 0);
                        GameBit_Set(state->secondaryGameBit, 1);
                    }
                } else {
                    if ((*(u8 *)(obj + 0xaf) & 0x10) != 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xef);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
                        state->flags15 = (u8)((state->flags15 & 0x7f) | 0x80);
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                    }
                }
            } else {
                *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
            }
        }
        if ((s8)state->flags15 < 0) {
            *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
        }
    } else {
        state->transitionDelay--;
        if (state->transitionDelay == 0) {
            GameBit_Set(state->secondaryGameBit, 1);
        }
    }
}

void wmspiritplace_init(int obj, int setup)
{
    WmSpiritPlaceState *state;

    state = *(WmSpiritPlaceState **)(obj + 0xb8);
    *(void **)(obj + 0xbc) = fn_801F5690;
    *(s16 *)(obj + 0) = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(s16 *)(setup + 0x1a) << 8);
    state->heightOffset = ((f32)(*(s16 *)(setup + 0x1c)) / lbl_803E5EF8) / lbl_803E5EFC;
    state->unk_04 = 0;
    state->unk_08 = 0;
    state->unk_0A = 0;
    state->secondaryGameBit = *(s16 *)(setup + 0x1e);
    state->primaryGameBit = *(s16 *)(setup + 0x20);
    state->setupParam = (s16)*(s8 *)(setup + 0x19);
    state->flags15 = (u8)(state->flags15 & 0x7f);
    *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | 0x6000);
    state->mapEventState = (*(u8 (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac));

    if (*(int *)(*(int *)(obj + 0x4c) + 0x14) == 0x47295) {
        if (GameBit_Get(0x1fc) != 0 || GameBit_Get(0xeaf) != 0 || state->mapEventState > 2) {
            *(f32 *)(obj + 0xc) = *(f32 *)(obj + 0xc) - lbl_803E5F00;
        }
    } else if (*(int *)(*(int *)(obj + 0x4c) + 0x14) == 0x4a5e6 && state->mapEventState > 5) {
        *(f32 *)(obj + 0xc) = *(f32 *)(obj + 0xc) + lbl_803E5F00;
    }
}

void wmspiritplace_release(void) {}
void wmspiritplace_initialise(void) {}

void fn_801F654C(int obj)
{
    WmSeqPointState *state;
    int skyOn;

    state = *(WmSeqPointState **)(obj + 0xb8);
    if (state->triggerId == 0x21) {
        GameBit_Set(0xd1b, 1);
    } else if (state->triggerId == 1) {
        skyOn = getSkyColorFn_80088e08(0) & 0xff;
        if (state->skyWasOn != 0 && skyOn == 0) {
            getEnvfxActImmediately(0, 0, 0x22d, 0);
            getEnvfxActImmediately(obj, obj, 0x22c, 0);
            getEnvfxActImmediately(obj, obj, 0x229, 0);
            getEnvfxActImmediately(obj, obj, 0x22a, 0);
            (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 4, 1);
            (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 10, 0);
            (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 0xb, 0);
        } else if (state->skyWasOn == 0 && skyOn != 0) {
            getEnvfxActImmediately(0, 0, 0x217, 0);
            getEnvfxActImmediately(obj, obj, 0x216, 0);
            getEnvfxActImmediately(obj, obj, 0x84, 0);
            getEnvfxActImmediately(obj, obj, 0x8a, 0);
            (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 4, 0);
            (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 10, 1);
            (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 0xb, 1);
        }
    }
}

int fn_801F6750(int obj, int unused, int actor)
{
    WmSeqPointState *state;
    int player;
    int i;
    u8 action;

    state = *(WmSeqPointState **)(obj + 0xb8);
    player = (int)Obj_GetPlayerObject();
    *(u8 *)(actor + 0x56) = 0;
    *(void **)(actor + 0xe8) = fn_801F654C;

    for (i = 0; i < *(u8 *)(actor + 0x8b); i++) {
        action = *(u8 *)(actor + i + 0x81);
        if (state->triggerId == 0) {
            if (action != 0) {
                state->command = action;
                switch (action) {
                    case 1:
                        GameBit_Set(0x143, 1);
                        break;
                    case 2:
                        GameBit_Set(0x143, 0);
                        break;
                    case 4:
                        GameBit_Set(0x21d, 1);
                        fn_80296518(player, 8, 0);
                        GameBit_Set(0x277, 1);
                        break;
                    case 5:
                        GameBit_Set(0x21d, 1);
                        break;
                    default:
                        break;
                }
            }
        } else if (action == 0xb) {
            if ((getSkyColorFn_80088e08(0) & 0xff) != 0) {
                getEnvfxActImmediately(0, 0, 0x217, 0);
                getEnvfxActImmediately(obj, obj, 0x216, 0);
                getEnvfxActImmediately(obj, obj, 0x84, 0);
                getEnvfxActImmediately(obj, obj, 0x8a, 0);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 4, 0);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 10, 1);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 0xb, 1);
            }
        } else if (action == 0xa) {
            if ((getSkyColorFn_80088e08(0) & 0xff) == 0) {
                getEnvfxActImmediately(0, 0, 0x22d, 0);
                getEnvfxActImmediately(obj, obj, 0x22c, 0);
                getEnvfxActImmediately(obj, obj, 0x229, 0);
                getEnvfxActImmediately(obj, obj, 0x22a, 0);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 4, 1);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 10, 0);
                (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 0xb, 0);
            }
        }
        *(u8 *)(actor + i + 0x81) = 0;
    }

    return 0;
}

int wmseqpoint_getExtraSize(void) { return 0x10; }
int wmseqpoint_getObjectTypeId(void) { return 0x0; }
void wmseqpoint_free(void) {}

#pragma peephole off
void wmseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 isVisible;

    isVisible = visible;
    if (isVisible != 0) {
        objRenderFn_8003b8f4(lbl_803E5F10);
    }
}
#pragma peephole reset

void wmseqpoint_hitDetect(void) {}

void wmseqpoint_update(int obj)
{
    WmSeqPointState *state;
    int player;
    int target;
    int i;

    player = (int)Obj_GetPlayerObject();
    state = *(WmSeqPointState **)(obj + 0xb8);

    if (state->gateGameBit != -1) {
        if (state->done != 0) {
            if (GameBit_Get(state->gateGameBit) != 0) {
                return;
            }
            GameBit_Set(state->gateGameBit, 1);
            state->done = 1;
            return;
        }
        if (GameBit_Get(state->gateGameBit) != 0) {
            state->done = 1;
            return;
        }
    }

    if (state->done != 0) {
        return;
    }

    switch (state->mode) {
        case 0:
            if (Vec_distance((void *)(obj + 0x18), (void *)(player + 0x18)) < state->radius) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(state->triggerId, obj, -1);
                state->done = 1;
            }
            break;
        case 1:
            if (state->requiredGameBit != -1 && GameBit_Get(state->requiredGameBit) != 0) {
                if (state->triggerId == 0x22) {
                    for (i = 0; i < 5; i++) {
                        GameBit_Set(lbl_80328CC8[i * 2], 0);
                        target = ObjList_FindObjectById(lbl_80328CC8[i * 2 + 1]);
                        *(u8 *)(*(int *)(target + 0xb8) + 0xd) = 0;
                        if (*(s16 *)(target + 0xb4) != -1) {
                            (*(void (**)(int))(*gObjectTriggerInterface + 0x4c))(*(s16 *)(target + 0xb4));
                        }
                    }
                } else if (state->triggerId == 1) {
                    state->skyWasOn = (u8)getSkyColorFn_80088e08(0);
                }
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(state->triggerId, obj, -1);
                state->done = 1;
            }
            break;
        case 2:
            if (Vec_distance((void *)(obj + 0x18), (void *)(player + 0x18)) < state->radius &&
                state->requiredGameBit != -1 && GameBit_Get(state->requiredGameBit) != 0) {
                if (state->triggerId == 0x21) {
                    GameBit_Set(0xd1b, 0);
                    target = ObjList_FindObjectById(0x4aeb1);
                    *(u8 *)(*(int *)(target + 0xb8) + 0xd) = 0;
                    if (*(s16 *)(target + 0xb4) != -1) {
                        (*(void (**)(int))(*gObjectTriggerInterface + 0x4c))(*(s16 *)(target + 0xb4));
                    }
                }
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(state->triggerId, obj, -1);
                state->done = 1;
            }
            break;
        case 3:
            if (Vec_distance((void *)(obj + 0x18), (void *)(player + 0x18)) < state->radius &&
                state->requiredGameBit != -1 && GameBit_Get(state->requiredGameBit) == 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(state->triggerId, obj, -1);
                GameBit_Set(state->requiredGameBit, 1);
                state->done = 1;
            }
            break;
        case 4:
            if (state->requiredGameBit != -1 && GameBit_Get(state->requiredGameBit) == 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(state->triggerId, obj, -1);
                GameBit_Set(state->requiredGameBit, 1);
                state->done = 1;
            }
            break;
        case 5:
            if (state->requiredGameBit != -1 && GameBit_Get(state->requiredGameBit) != 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(state->triggerId, obj, -1);
            }
            break;
        default:
            break;
    }
}

void wmseqpoint_init(int obj, int setup)
{
    WmSeqPointState *state;

    state = *(WmSeqPointState **)(obj + 0xb8);
    *(void **)(obj + 0xbc) = fn_801F6750;
    *(s16 *)(obj + 0) = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
    state->radius = (f32)*(s16 *)(setup + 0x1a);
    state->triggerId = *(s16 *)(setup + 0x1c);
    state->done = 0;
    state->mode = *(u8 *)(setup + 0x19);
    state->requiredGameBit = *(s16 *)(setup + 0x1e);
    state->gateGameBit = *(s16 *)(setup + 0x20);
    state->command = 0;
    state->unk0A = 0;
}

void wmseqpoint_release(void) {}
void wmseqpoint_initialise(void) {}

int fn_801F6E8C(int p1, int p2, int actor)
{
    int ret;

    ret = 0;
    *(s16 *)(actor + 0x6e) = -1;
    *(u8 *)(actor + 0x56) = (u8)ret;
    return ret;
}

int wmsun_getExtraSize(void) { return 0x10; }
int wmsun_getObjectTypeId(void) { return 0x0; }
void wmsun_hitDetect(void) {}
void wmsun_release(void) {}
void wmsun_initialise(void) {}
int wmspiritset_getExtraSize(void) { return 0x2; }
int wmspiritset_getObjectTypeId(void) { return 0x0; }
void wmspiritset_free(void) {}
void wmspiritset_hitDetect(void) {}
void wmspiritset_update(void) {}
void wmspiritset_release(void) {}
void wmspiritset_initialise(void) {}
int wmplanets_getExtraSize(void) { return 0x1c; }
int wmplanets_getObjectTypeId(void) { return 0x0; }
void wmplanets_free(void) {}
void wmplanets_hitDetect(void) {}
void wmplanets_release(void) {}
void wmplanets_initialise(void) {}
int wmwallcrawler_getExtraSize(void) { return 0x29c; }
int wmwallcrawler_getObjectTypeId(void) { return 0x0; }
void wmwallcrawler_release(void) {}
void wmwallcrawler_initialise(void) {}
int wmnewcrystal_getExtraSize(void) { return 0x6c; }
int wmnewcrystal_getObjectTypeId(void) { return 0x0; }
void wmnewcrystal_free(void) {}
void wmnewcrystal_hitDetect(void) {}
void wmnewcrystal_update(void) {}
void wmnewcrystal_release(void) {}
void wmnewcrystal_initialise(void) {}
int vfplevelcontrol_getExtraSize(void) { return 0x1c; }
int vfplevelcontrol_getObjectTypeId(void) { return 0x0; }
void vfplevelcontrol_render(void) {}
void vfplevelcontrol_hitDetect(void) {}
void vfplevelcontrol_release(void) {}
int vfpobjcreator_getExtraSize(void) { return 0xa; }
int vfpobjcreator_getObjectTypeId(void) { return 0x0; }
void vfpobjcreator_free(void) {}
void vfpobjcreator_hitDetect(void) {}
void vfpobjcreator_release(void) {}
void vfpobjcreator_initialise(void) {}
int vfpminifire_getExtraSize(void) { return 0xc; }
int vfpminifire_getObjectTypeId(void) { return 0x0; }
void vfpminifire_hitDetect(void) {}
void vfpminifire_release(void) {}
void vfpminifire_initialise(void) {}
int dll_219_getExtraSize_ret_4(void) { return 0x4; }
int dll_219_getObjectTypeId(void) { return 0x0; }
void dll_219_render_nop(void) {}
void dll_219_hitDetect_nop(void) {}
void dll_219_release_nop(void) {}
void dll_219_initialise_nop(void) {}
int vfpstatueball_getExtraSize(void) { return 0xc; }
int vfpstatueball_getObjectTypeId(void) { return 0x0; }
void vfpstatueball_render(void) {}
void vfpstatueball_hitDetect(void) {}
void vfpstatueball_release(void) {}
void vfpstatueball_initialise(void) {}
int dll_21B_getExtraSize_ret_4(void) { return 0x4; }
int dll_21B_getObjectTypeId(void) { return 0x0; }
void dll_21B_render_nop(void) {}
void dll_21B_hitDetect_nop(void) {}
void dll_21B_release_nop(void) {}
void dll_21B_initialise_nop(void) {}
int fn_801FAFEC(void) { return 0x0; }
int vfpladders_getExtraSize(void) { return 0x8; }
int vfpladders_getObjectTypeId(void) { return 0x0; }
void vfpladders_render(void) {}
void vfpladders_hitDetect(void) {}
void vfpladders_release(void) {}
void vfpladders_initialise(void) {}
int vfplift_getExtraSize(void) { return 0x20; }
int vfplift_getObjectTypeId(void) { return 0x0; }
void vfplift_release(void) {}
void vfplift_initialise(void) {}
int vfpblock1_getExtraSize(void) { return 0x2; }
int vfpblock1_getObjectTypeId(void) { return 0x0; }
void vfpblock1_render(void) {}
void vfpblock1_hitDetect(void) {}

extern void mm_free(void *p);
extern void Music_Trigger(int id, int a);
extern void timeOfDayFn_80055000(void);
extern int lbl_803DC148;
extern f32 lbl_803E60F0;
extern f32 lbl_803E605C;
extern f32 lbl_803E5F94;

#pragma scheduling off
#pragma peephole off
void vfplevelcontrol_initialise(void) {
    lbl_803DC148 = 0x82;
}

int fn_801F7FF4(int obj) {
    *(u8 *)(*(int *)(obj + 0xb8) + 0x296) = 1;
    return 0;
}

int fn_801FB220(int obj) {
    *(u8 *)(*(int *)(obj + 0xb8) + 0x1c) |= 0x40;
    return 0;
}

void vfplift_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    objRenderFn_8003b8f4(lbl_803E60F0);
}

void wmnewcrystal_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    objRenderFn_8003b8f4(lbl_803E605C);
}

void wmwallcrawler_free(int obj) {
    ObjGroup_RemoveObject(obj, 3);
}

void dll_219_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}

void dll_219_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)init[0x18] << 8);
    *(s16 *)inner = *(s16 *)((char *)init + 0x1e);
    *(u16 *)((char *)obj + 0xb0) |= 0x6000;
}

void wmspiritset_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)init[0x18] << 8);
    if (*(s16 *)((char *)obj + 0x46) == 0x264) {
        *(f32 *)((char *)obj + 8) = lbl_803E5F94;
    }
    *(s16 *)inner = *(s16 *)((char *)init + 0x1e);
}

void wmsun_free(int obj) {
    int *inner = *(int **)(obj + 0xb8);
    if (*(void **)((char *)inner + 8) != NULL) {
        mm_free(*(void **)((char *)inner + 8));
    }
    *(int *)((char *)inner + 8) = 0;
}

void vfplevelcontrol_free(int obj) {
    timeOfDayFn_80055000();
    ObjGroup_RemoveObject(obj, 9);
    Music_Trigger(0xe1, 0);
}

void vfpladders_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)init[0x18] << 8);
    *(s16 *)((char *)inner + 2) = *(s16 *)((char *)init + 0x20);
    *(s16 *)inner = *(s16 *)((char *)init + 0x1e);
    *(u16 *)((char *)obj + 0xb0) |= 0x6000;
    *(void **)((char *)obj + 0xbc) = (void *)fn_801FAFEC;
}

void vfpobjcreator_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)init[0x1e] << 8);
    *(s16 *)inner = *(s16 *)((char *)init + 0x18);
    *(s16 *)((char *)inner + 2) = *(s16 *)((char *)init + 0x1c);
    *(s16 *)((char *)inner + 4) = *(s16 *)((char *)inner + 2);
    *(s16 *)((char *)inner + 6) = (s8)init[0x1f];
    *(s16 *)((char *)inner + 8) = init[0x20];
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_801FB434(int obj);
extern void fn_801FB23C(int obj);
extern void fn_801F943C(void);
extern void fn_80053ED0(int n);
extern void fn_80053EBC(int n);
extern void doNothing_8005D148(int a, int b);
extern void doNothing_8005D14C(int a, int b);
extern u8 framesThisStep;
extern f32 lbl_803E5F90;
extern f32 lbl_803E5F24;
extern f32 lbl_803E6088;
extern f32 lbl_803E5FB4;

#pragma scheduling off
#pragma peephole off
void vfplift_update(int obj) {
    int v;
    Obj_GetPlayerObject();
    v = *(s16 *)((char *)obj + 0x46);
    if (v == 0x3b7) {
        fn_801FB434(obj);
    } else if (v == 0x3bf) {
        fn_801FB23C(obj);
    } else if (v == 0x53f) {
        fn_801FB23C(obj);
    }
}

void vfplift_hitDetect(int obj) {
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(s16 *)((char *)inner + 0xc) != -1 && GameBit_Get(*(s16 *)((char *)inner + 0xc)) == 0) {
        *(u8 *)((char *)obj + 0xaf) |= 8;
    } else if ((*(u8 *)((char *)obj + 0xaf) & 8) != 0) {
        *(u8 *)((char *)obj + 0xaf) ^= 8;
    }
}

void wmspiritset_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    int *inner = *(int **)(p1 + 0xb8);
    s16 v = *(s16 *)inner;
    if ((v == -1 || GameBit_Get(v) != 0) && vis != 0) {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E5F90);
    }
}

void wmsun_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    int *inner = *(int **)(p1 + 0xb8);
    if (vis != 0 && *(u8 *)((char *)inner + 0xd) != 0) {
        doNothing_8005D148(p2, 0x10000);
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E5F24);
        doNothing_8005D14C(p2, 0x10000);
    }
}

void vfpminifire_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    if (vis != 0 && *(u8 *)(p1 + 0x36) != 0) {
        fn_80053ED0(8);
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6088);
        fn_80053EBC(8);
    }
}

void wmwallcrawler_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    int *inner = *(int **)(p1 + 0xb8);
    if ((*(u16 *)((char *)inner + 0x294) & 0x40) != 0 && (u8)*(u8 *)(p1 + 0x36) < 0xff) {
        if (*(u8 *)(p1 + 0x36) > 0xff - framesThisStep) {
            *(u8 *)(p1 + 0x36) = 0xff;
            *(u16 *)((char *)inner + 0x294) &= ~0x40;
        } else {
            *(u8 *)(p1 + 0x36) = *(u8 *)(p1 + 0x36) + framesThisStep;
        }
    }
    if (vis != 0 && *(s16 *)((char *)inner + 0x28c) == 0) {
        objRenderFn_8003b8f4(lbl_803E5FB4);
    }
}

void wmnewcrystal_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(void **)((char *)obj + 0xbc) = (void *)fn_801F943C;
    if ((u8)(*(int (*)(int))(*(int *)(*gMapEventInterface + 0x40)))((s8)*(u8 *)((char *)obj + 0xac)) > 1) {
        GameBit_Set(0xd27, 1);
        *(u8 *)((char *)inner + 0x68) = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void timeOfDayFn_80055038(void);
extern f32 lbl_803E60F8;
extern f32 lbl_803E5FA0;
extern f32 lbl_803E5F98;
extern f32 lbl_803E5F9C;

#pragma scheduling off
#pragma peephole off
void vfplevelcontrol_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    ObjGroup_AddObject(obj, 9);
    *(s16 *)((char *)inner + 2) = 0;
    *(s16 *)((char *)inner + 4) = 0;
    *(s16 *)((char *)inner + 6) = 0;
    *(s16 *)((char *)inner + 8) = 0;
    *(s16 *)((char *)inner + 0xa) = 0;
    *(s16 *)((char *)inner + 0xc) = 0;
    *(s16 *)((char *)inner + 0xe) = 1;
    if (*(s16 *)((char *)init + 0x1a) != 0 && *(s16 *)((char *)init + 0x1a) <= 2) {
        *(s16 *)((char *)inner + 0xe) = *(s16 *)((char *)init + 0x1a);
    }
    lbl_803DC148 = 0x82;
    (*(void (*)(int))(*(int *)(*gMapEventInterface + 0x40)))((s8)*(u8 *)((char *)obj + 0xac));
    *(s16 *)((char *)inner + 0xa) = 0;
    *(s16 *)((char *)inner + 0xc) = 0;
    *(u16 *)((char *)obj + 0xb0) |= 0x6000;
    timeOfDayFn_80055038();
    GameBit_Set(0xdcf, 1);
    unlockLevel(0, 0, 1);
    if (GameBit_Get(0xe1b) != 0) {
        *(u8 *)((char *)inner + 0x18) = 4;
    } else {
        GameBit_Set(0xe1a, 0);
        GameBit_Set(0xe19, 0);
        GameBit_Set(0xe17, 0);
        GameBit_Set(0xe18, 0);
    }
}

void vfplift_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(void **)((char *)obj + 0xbc) = (void *)fn_801FB220;
    *(s16 *)obj = (s16)((s8)init[0x18] << 8);
    *(s16 *)((char *)inner + 0xa) = 0;
    *(s16 *)((char *)inner + 0xc) = *(s16 *)((char *)init + 0x20);
    *(s16 *)((char *)inner + 0xe) = *(s16 *)((char *)init + 0x1e);
    *(f32 *)inner = (f32)(s32)*(s16 *)((char *)init + 0x1a);
    *(u8 *)((char *)inner + 0x1a) = *(s16 *)((char *)init + 0x1c);
    *(s16 *)((char *)inner + 0x12) = 0;
    *(s16 *)((char *)inner + 0x14) = 0;
    *(s16 *)((char *)inner + 0x16) = 0;
    *(s16 *)((char *)inner + 0x18) = 0;
    if (*(s16 *)((char *)obj + 0x46) == 0x3bf) {
        if (GameBit_Get(*(s16 *)((char *)inner + 0xe)) != 0) {
            *(s16 *)((char *)inner + 0xa) = 4;
            *(u8 *)((char *)inner + 0x1c) |= 0x80;
        } else {
            *(s16 *)((char *)inner + 0xa) = 3;
        }
    }
    if (*(s16 *)((char *)obj + 0x46) == 0x3b7 && GameBit_Get(0x4ee) != 0) {
        if (GameBit_Get(*(s16 *)((char *)inner + 0xe)) != 0) {
            *(s16 *)((char *)inner + 0xa) = 3;
        } else {
            *(s16 *)((char *)inner + 0xa) = 4;
            *(u8 *)((char *)inner + 0x1c) |= 0x80;
        }
    }
}

void wmplanets_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    f32 a = lbl_803E5FA0 * *(f32 *)((char *)*(int *)((char *)obj + 0x50) + 4);
    *(f32 *)((char *)obj + 8) = a * (lbl_803E5F98 + (f32)(s32)(s8)init[0x18]);
    if (*(s16 *)init != 0) {
        *(f32 *)((char *)inner + 0xc) = -(f32)(s32)((s8)init[0x19] << 4);
    } else {
        *(f32 *)((char *)inner + 0xc) = lbl_803E5F9C;
    }
    *(s16 *)inner = (s16)randomGetRange(0x64, 0xc8);
    *(s16 *)((char *)inner + 2) = (s16)randomGetRange(0xc8, 0x190);
    *(s16 *)((char *)inner + 4) = 0;
    *(s16 *)((char *)inner + 8) = (s16)randomGetRange(0, 0x960);
    *(f32 *)((char *)inner + 0x10) = *(f32 *)((char *)obj + 0xc);
    *(f32 *)((char *)inner + 0x14) = *(f32 *)((char *)obj + 0x10);
    *(f32 *)((char *)inner + 0x18) = *(f32 *)((char *)obj + 0x14);
    Obj_SetActiveModelIndex((int)obj, *(s16 *)((char *)init + 0x1a));
    *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)init + 0x10) + *(f32 *)((char *)inner + 0xc);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dll_21B_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}

void vfpblock1_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}

void vfpladders_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}

void vfplift_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}

void vfpminifire_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x18)))(obj);
}

void vfpstatueball_free(int obj) {
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x14)))(obj);
}

void wmplanets_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    if (vis != 0) {
        objRenderFn_8003b8f4(lbl_803E5F98);
    }
}

void dll_21B_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)((s8)init[0x18] << 8);
    *(s16 *)inner = *(s16 *)((char *)init + 0x1e);
    *(u16 *)((char *)obj + 0xb0) |= 0x6000;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void fn_801F9804(int obj) {
    int inner = *(int *)((char *)obj + 0xb8);
    s16 bits[4];
    s16 *p;
    int i;

    if (*(u8 *)(inner + 0x18) < 4) {
        bits[0] = GameBit_Get(0xe1a);
        bits[1] = GameBit_Get(0xe19);
        bits[2] = GameBit_Get(0xe17);
        bits[3] = GameBit_Get(0xe18);
        p = &bits[*(u8 *)(inner + 0x18)];
        for (i = *(u8 *)(inner + 0x18); i < 4; i++) {
            if (i == *(u8 *)(inner + 0x18)) {
                if (*p != 0) {
                    *(u8 *)(inner + 0x18) = *(u8 *)(inner + 0x18) + 1;
                    if (*(u8 *)(inner + 0x18) == 4) {
                        GameBit_Set(0xe1b, 1);
                    }
                }
            } else if (*p != 0) {
                *(u8 *)(inner + 0x18) = 0;
                GameBit_Set(0xe1a, 0);
                GameBit_Set(0xe19, 0);
                GameBit_Set(0xe17, 0);
                GameBit_Set(0xe18, 0);
                break;
            }
            p++;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E6090;
extern f32 lbl_803E60A4;
extern f32 lbl_803E609C;

#pragma scheduling off
#pragma peephole off
void vfpminifire_init(int *obj, u8 *init) {
    *(f32 *)((char *)obj + 0x28) = lbl_803E6090;
    *(f32 *)((char *)obj + 0x10) = lbl_803E60A4 + *(f32 *)((char *)init + 0xc);
    *(f32 *)((char *)obj + 8) = *(f32 *)((char *)obj + 8) * lbl_803E609C;
    (*(void (*)(int *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 0x38c, 0, 2, -1, 0);
    Sfx_PlayFromObject((int)obj, 0x103);
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
}

void vfpstatueball_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    *(s16 *)inner = *(s16 *)((char *)init + 0x1e);
    *(s16 *)((char *)inner + 2) = 0x19;
    *(u16 *)((char *)obj + 0xb0) |= 0x4000;
    if (*(s16 *)((char *)init + 0x1a) > 2) {
        *(s16 *)((char *)init + 0x1a) = 2;
    }
    if (*(s16 *)((char *)init + 0x1c) > 1) {
        *(f32 *)((char *)obj + 8) = *(f32 *)((char *)obj + 8) * (f32)(s32)*(s16 *)((char *)init + 0x1c);
    }
    Obj_SetActiveModelIndex((int)obj, *(s16 *)((char *)init + 0x1a));
    *(u8 *)((char *)inner + 5) = (u8)GameBit_Get(*(s16 *)inner);
}
#pragma peephole reset
#pragma scheduling reset
