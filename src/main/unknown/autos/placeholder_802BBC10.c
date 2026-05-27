#include "ghidra_import.h"
#include "main/objanim.h"
#include "main/unknown/autos/placeholder_802BBC10.h"

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

extern undefined8 FUN_80006824();
extern undefined8 FUN_80006920();
extern void* FUN_800069a8();
extern undefined4 FUN_800069bc();
extern int FUN_80006a64();
extern undefined8 FUN_80006a68();
extern undefined4 FUN_80006a6c();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_80006ba8();
extern char FUN_80006bc8();
extern char FUN_80006bd0();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_800176f4();
extern double FUN_80017708();
extern undefined4 FUN_8001771c();
extern int FUN_80017730();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017754();
extern uint FUN_80017758();
extern undefined4 FUN_8001776c();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017784();
extern undefined4 FUN_8001789c();
extern undefined4 FUN_800178a0();
extern undefined4 FUN_800178a4();
extern undefined4 FUN_800178ac();
extern undefined4 FUN_800178b0();
extern uint FUN_800178b4();
extern byte FUN_80017a20();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern int FUN_8002f6ac();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined objHitReact_update();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjHits_GetPriorityHit();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 ObjPath_GetPointWorldPositionArray();
extern undefined4 ObjPath_GetPointLocalPosition();
extern undefined4 ObjPath_GetPointModelMtx();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 objAnimFn_80038f38();
extern undefined4 FUN_80039468();
extern undefined4 FUN_8003964c();
extern undefined4 FUN_8003a1c4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b444();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8003b870();
extern undefined4 FUN_80053754();
extern undefined4 FUN_80053758();
extern int FUN_80056600();
extern undefined4 FUN_8006dca8();
extern undefined4 FUN_8007f6e4();
extern undefined4 FUN_8007f718();
extern undefined4 FUN_800e8630();
extern undefined4 FUN_801141dc();
extern undefined4 FUN_801141e8();
extern int FUN_80114340();
extern int FUN_801149b8();
extern undefined4 FUN_801149bc();
extern undefined4 FUN_80114b10();
extern undefined4 dll_2E_func03();
extern undefined4 FUN_801150ac();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_80135814();
extern undefined4 FUN_8020a498();
extern undefined4 FUN_8020a4a4();
extern undefined8 FUN_80286834();
extern undefined4 FUN_80286838();
extern undefined4 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294d60();
extern undefined4 FUN_80295098();
extern undefined4 FUN_802950a4();
extern undefined4 FUN_802950a8();
extern undefined4 FUN_80295140();
extern undefined4 FUN_80295148();
extern undefined4 FUN_80295150();
extern undefined4 FUN_80295158();
extern undefined4 FUN_80295160();
extern undefined4 FUN_80295168();
extern undefined4 FUN_80295170();
extern undefined4 FUN_80295174();
extern undefined4 FUN_8029517c();
extern undefined4 FUN_80295184();
extern undefined4 FUN_8029518c();
extern undefined4 FUN_80295194();
extern undefined4 FUN_802bb420();
extern undefined4 FUN_802bb998();
extern uint countLeadingZeros();

extern undefined4 DAT_802c3428;
extern undefined4 DAT_802c342c;
extern undefined4 DAT_802c3430;
extern undefined4 DAT_802c3434;
extern undefined4 DAT_802c3438;
extern undefined4 DAT_802c343c;
extern undefined4 DAT_802c3440;
extern undefined4 DAT_802c3444;
extern undefined4 DAT_802c3448;
extern undefined4 DAT_802c344c;
extern undefined4 DAT_802c3450;
extern undefined4 DAT_802c3454;
extern undefined4 DAT_802c3458;
extern undefined4 DAT_802c345c;
extern undefined4 DAT_802c3460;
extern undefined4 DAT_802c3464;
extern undefined4 DAT_802c3468;
extern undefined4 DAT_802c346c;
extern undefined4 DAT_802c3470;
extern undefined4 DAT_802c3474;
extern undefined4 DAT_802c3478;
extern undefined4 DAT_802c347c;
extern undefined4 DAT_802c3498;
extern undefined4 DAT_802c349c;
extern undefined4 DAT_802c34a0;
extern undefined4 DAT_802c34a4;
extern undefined4 DAT_802c34a8;
extern undefined4 DAT_802c34ac;
extern undefined4 DAT_802c34b0;
extern undefined4 DAT_802c34b4;
extern undefined4 DAT_802c34b8;
extern undefined4 DAT_802c34bc;
extern undefined4 DAT_802c34c0;
extern undefined4 DAT_802c34c4;
extern undefined4 DAT_802c34c8;
extern undefined DAT_80335cfc;
extern undefined DAT_80335d10;
extern undefined4 DAT_80335d24;
extern undefined4 DAT_80335d30;
extern undefined4 DAT_80335d60;
extern undefined4 DAT_80335d70;
extern undefined4 DAT_80335e08;
extern undefined4 DAT_80335e64;
extern undefined4 DAT_80335e94;
extern undefined4 DAT_80335ea4;
extern undefined4 DAT_80335ebc;
extern undefined4 DAT_80335edc;
extern undefined4 DAT_80335ee4;
extern undefined4 DAT_80335f00;
extern undefined4 DAT_80335f0c;
extern undefined4 DAT_80335f30;
extern undefined4 DAT_80335f70;
extern undefined4 DAT_80336014;
extern undefined4 DAT_803360b8;
extern undefined4 DAT_8033635c;
extern undefined4 DAT_80336368;
extern undefined4 DAT_80336374;
extern undefined4 DAT_80336380;
extern undefined4 DAT_8033638c;
extern undefined4 DAT_80336398;
extern ushort DAT_803363b0;
extern undefined4 DAT_803363b8;
extern undefined4 DAT_803363c4;
extern undefined4 DAT_803dbd90;
extern undefined4 DAT_803dbd94;
extern undefined4 DAT_803dbd98;
extern undefined4 DAT_803dbd9c;
extern undefined4 DAT_803dbda0;
extern undefined4 DAT_803dbda4;
extern undefined4 DAT_803dbda8;
extern undefined4 DAT_803dbdac;
extern undefined4 DAT_803dbdb0;
extern undefined4 DAT_803dbdb4;
extern undefined4 DAT_803dbdb8;
extern undefined4 DAT_803dbdbc;
extern undefined4 DAT_803dbdc0;
extern undefined4 DAT_803dbdd0;
extern undefined4 DAT_803dbe10;
extern undefined4 DAT_803dbe14;
extern undefined4 DAT_803dbe18;
extern undefined4 DAT_803dbe1c;
extern undefined4 DAT_803dbe20;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dd39c;
extern undefined4 DAT_803dd3b8;
extern undefined4 DAT_803dd3bc;
extern undefined4 DAT_803dd3c0;
extern undefined4 DAT_803dd3d8;
extern undefined4 DAT_803dd3dc;
extern undefined4 DAT_803dd3e0;
extern undefined4 DAT_803dd3e4;
extern undefined4 DAT_803dd3e8;
extern undefined4 DAT_803dd3ec;
extern undefined4 DAT_803dd3fc;
extern undefined4 DAT_803dd402;
extern undefined4 DAT_803dd404;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e0;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd71c;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803df144;
extern undefined4 DAT_803df148;
extern undefined4* DAT_803df150;
extern undefined4 DAT_803df154;
extern undefined4 DAT_803df158;
extern undefined4 DAT_803df15c;
extern undefined4 DAT_803df160;
extern undefined4 DAT_803e8ec8;
extern undefined4 DAT_803e8f70;
extern undefined4 DAT_803e9030;
extern undefined4 DAT_803e9034;
extern undefined4 DAT_803e9038;
extern f64 DOUBLE_803e8f08;
extern f64 DOUBLE_803e8f78;
extern f64 DOUBLE_803e9098;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803dd3d4;
extern f32 FLOAT_803dd3f4;
extern f32 FLOAT_803dd3f8;
extern f32 FLOAT_803e8ecc;
extern f32 FLOAT_803e8ed8;
extern f32 FLOAT_803e8ef0;
extern f32 FLOAT_803e8f3c;
extern f32 FLOAT_803e8f40;
extern f32 FLOAT_803e8f44;
extern f32 FLOAT_803e8f48;
extern f32 FLOAT_803e8f4c;
extern f32 FLOAT_803e8f50;
extern f32 FLOAT_803e8f58;
extern f32 FLOAT_803e8f5c;
extern f32 FLOAT_803e8f60;
extern f32 FLOAT_803e8f64;
extern f32 FLOAT_803e8f80;
extern f32 FLOAT_803e8f84;
extern f32 FLOAT_803e8f88;
extern f32 FLOAT_803e8f8c;
extern f32 FLOAT_803e8f90;
extern f32 FLOAT_803e8f94;
extern f32 FLOAT_803e8f98;
extern f32 FLOAT_803e8f9c;
extern f32 FLOAT_803e8fa0;
extern f32 FLOAT_803e8fa4;
extern f32 FLOAT_803e8fa8;
extern f32 FLOAT_803e8fac;
extern f32 FLOAT_803e8fb0;
extern f32 FLOAT_803e8fb4;
extern f32 FLOAT_803e8fb8;
extern f32 FLOAT_803e8fbc;
extern f32 FLOAT_803e8fc0;
extern f32 FLOAT_803e8fc4;
extern f32 FLOAT_803e8fc8;
extern f32 FLOAT_803e8fcc;
extern f32 FLOAT_803e8fd0;
extern f32 FLOAT_803e8fd4;
extern f32 FLOAT_803e8fd8;
extern f32 FLOAT_803e8fdc;
extern f32 FLOAT_803e8fe0;
extern f32 FLOAT_803e8fe4;
extern f32 FLOAT_803e8fe8;
extern f32 FLOAT_803e8fec;
extern f32 FLOAT_803e8ff0;
extern f32 FLOAT_803e8ff4;
extern f32 FLOAT_803e9004;
extern f32 FLOAT_803e9008;
extern f32 FLOAT_803e9010;
extern f32 FLOAT_803e9014;
extern f32 FLOAT_803e9018;
extern f32 FLOAT_803e901c;
extern f32 FLOAT_803e9020;
extern f32 FLOAT_803e9024;
extern f32 FLOAT_803e9028;
extern f32 FLOAT_803e902c;
extern f32 FLOAT_803e903c;
extern f32 FLOAT_803e9040;
extern f32 FLOAT_803e9044;
extern f32 FLOAT_803e9048;
extern f32 FLOAT_803e904c;
extern f32 FLOAT_803e9050;
extern f32 FLOAT_803e9054;
extern f32 FLOAT_803e9058;
extern f32 FLOAT_803e905c;
extern f32 FLOAT_803e9060;
extern f32 FLOAT_803e9064;
extern f32 FLOAT_803e9068;
extern f32 FLOAT_803e906c;
extern f32 FLOAT_803e9070;
extern f32 FLOAT_803e9074;
extern f32 FLOAT_803e9078;
extern f32 FLOAT_803e907c;
extern f32 FLOAT_803e9080;
extern f32 FLOAT_803e9084;
extern f32 FLOAT_803e9088;
extern f32 FLOAT_803e908c;
extern f32 FLOAT_803e9090;
extern f32 FLOAT_803e9094;
extern f32 FLOAT_803e90a0;
extern f32 FLOAT_803e90a4;
extern f32 FLOAT_803e90a8;
extern f32 FLOAT_803e90ac;
extern f32 FLOAT_803e90b0;
extern f32 FLOAT_803e90b4;
extern f32 FLOAT_803e90b8;
extern f32 FLOAT_803e90bc;
extern undefined4 _DAT_803df140;

/*
 * --INFO--
 *
 * Function: DIMSnowHorn1_update
 * EN v1.0 Address: 0x802BB720
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BBC14
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void DIMSnowHorn1_update(undefined4 param_1, undefined4 param_2, int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb724
 * EN v1.0 Address: 0x802BB724
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BBE80
 * EN v1.1 Size: 1484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb724(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb728
 * EN v1.0 Address: 0x802BB728
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BC44C
 * EN v1.1 Size: 716b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb728(undefined4 param_1,undefined4 param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb72c
 * EN v1.0 Address: 0x802BB72C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BC718
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb72c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb730
 * EN v1.0 Address: 0x802BB730
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BC760
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb730(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb734
 * EN v1.0 Address: 0x802BB734
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BC848
 * EN v1.1 Size: 196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802bb734(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb73c
 * EN v1.0 Address: 0x802BB73C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BC90C
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802bb73c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb744
 * EN v1.0 Address: 0x802BB744
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BC9EC
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802bb744(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb74c
 * EN v1.0 Address: 0x802BB74C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BCADC
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_802bb74c(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb754
 * EN v1.0 Address: 0x802BB754
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BCB60
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_802bb754(ushort *param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb75c
 * EN v1.0 Address: 0x802BB75C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BCC34
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb75c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb760
 * EN v1.0 Address: 0x802BB760
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BCC68
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb760(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb764
 * EN v1.0 Address: 0x802BB764
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BCDEC
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb764(undefined2 *param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb768
 * EN v1.0 Address: 0x802BB768
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BCEF8
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb768(int param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb76c
 * EN v1.0 Address: 0x802BB76C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BCF30
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb76c(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb770
 * EN v1.0 Address: 0x802BB770
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BCFA0
 * EN v1.1 Size: 480b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802bb770(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,
            int param_10,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb778
 * EN v1.0 Address: 0x802BB778
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BD180
 * EN v1.1 Size: 756b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb778(int param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb77c
 * EN v1.0 Address: 0x802BB77C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BD474
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_802bb77c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13
                ,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb784
 * EN v1.0 Address: 0x802BB784
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BD584
 * EN v1.1 Size: 2456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802bb784(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb78c
 * EN v1.0 Address: 0x802BB78C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BDF1C
 * EN v1.1 Size: 1084b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb78c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb790
 * EN v1.0 Address: 0x802BB790
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BE358
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802bb790(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,undefined4 param_10
            ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb798
 * EN v1.0 Address: 0x802BB798
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BE4A4
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb798(double param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb79c
 * EN v1.0 Address: 0x802BB79C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BE5C4
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb79c(int param_1,float *param_2,int *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7a0
 * EN v1.0 Address: 0x802BB7A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BE600
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb7a0(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7a4
 * EN v1.0 Address: 0x802BB7A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BE790
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb7a4(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7a8
 * EN v1.0 Address: 0x802BB7A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BE820
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb7a8(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7ac
 * EN v1.0 Address: 0x802BB7AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BE8EC
 * EN v1.1 Size: 1388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb7ac(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7b0
 * EN v1.0 Address: 0x802BB7B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BEE58
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb7b0(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7b4
 * EN v1.0 Address: 0x802BB7B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BF088
 * EN v1.1 Size: 988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb7b4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7b8
 * EN v1.0 Address: 0x802BB7B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BF464
 * EN v1.1 Size: 804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb7b8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7bc
 * EN v1.0 Address: 0x802BB7BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BF788
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb7bc(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7c0
 * EN v1.0 Address: 0x802BB7C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BF7BC
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb7c0(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7c4
 * EN v1.0 Address: 0x802BB7C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BF838
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb7c4(undefined4 param_1,int param_2,char param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7c8
 * EN v1.0 Address: 0x802BB7C8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BFA34
 * EN v1.1 Size: 532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb7c8(undefined4 param_1,undefined4 param_2,int *param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7cc
 * EN v1.0 Address: 0x802BB7CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BFC48
 * EN v1.1 Size: 644b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb7cc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7d0
 * EN v1.0 Address: 0x802BB7D0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802BFECC
 * EN v1.1 Size: 472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802bb7d0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,ushort *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7d8
 * EN v1.0 Address: 0x802BB7D8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802C00A4
 * EN v1.1 Size: 3100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb7d8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,double param_5
                 ,double param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7dc
 * EN v1.0 Address: 0x802BB7DC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802C0CC0
 * EN v1.1 Size: 736b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802bb7dc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,ushort *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7e4
 * EN v1.0 Address: 0x802BB7E4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802C0FA0
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802bb7e4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7ec
 * EN v1.0 Address: 0x802BB7EC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802C10E8
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802bb7ec(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7f4
 * EN v1.0 Address: 0x802BB7F4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802C11CC
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_802bb7f4(undefined2 *param_1,uint *param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb7fc
 * EN v1.0 Address: 0x802BB7FC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802C12F4
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_802bb7fc(int param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb804
 * EN v1.0 Address: 0x802BB804
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x802C136C
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_802bb804(int param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802bb80c
 * EN v1.0 Address: 0x802BB80C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802C1434
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb80c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb810
 * EN v1.0 Address: 0x802BB810
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802C148C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb810(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb814
 * EN v1.0 Address: 0x802BB814
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802C1528
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb814(ushort *param_1,float *param_2,float *param_3,float *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb818
 * EN v1.0 Address: 0x802BB818
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802C1610
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb818(undefined4 param_1,float *param_2,undefined4 *param_3,float *param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb81c
 * EN v1.0 Address: 0x802BB81C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802C1684
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb81c(int param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb820
 * EN v1.0 Address: 0x802BB820
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802C16E8
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb820(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb824
 * EN v1.0 Address: 0x802BB824
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802C17B0
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb824(short *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb828
 * EN v1.0 Address: 0x802BB828
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802C192C
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb828(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9,int param_10)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb82c
 * EN v1.0 Address: 0x802BB82C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802C1B34
 * EN v1.1 Size: 688b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb82c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802bb830
 * EN v1.0 Address: 0x802BB830
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802C1DE4
 * EN v1.1 Size: 520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb830(undefined2 *param_1,int param_2)
{
}

/* Pattern wrappers. */
int fn_802BC0D0(void) { return 0x0; }
int fn_802BCCFC(void) { return 0x0; }
void DR_EarthWarrior_func21(void) {}
int DR_EarthWarrior_func20(void) { return 0x0; }
int DR_EarthWarrior_func16(void) { return 0x0; }
int DR_EarthWarrior_render2(void) { return 0x0; }
int DR_EarthWarrior_setScale(void) { return 0x0; }
int DR_EarthWarrior_getExtraSize(void) { return 0x14fc; }
int DR_EarthWarrior_getObjectTypeId(void) { return 0x43; }
int fn_802BF728(void) { return 0x0; }
void DR_CloudRunner_func21(void) {}
int DR_CloudRunner_func20(void) { return 0x0; }
int DR_CloudRunner_func16(void) { return 0x0; }
int DR_CloudRunner_render2(void) { return 0x0; }
int DR_CloudRunner_setScale(void) { return 0x0; }
int DR_CloudRunner_getExtraSize(void) { return 0xbc8; }
int DR_CloudRunner_getObjectTypeId(void) { return 0x43; }
void DR_CloudRunner_release(void) {}

extern int GameBit_Get(int id);
extern f32 lbl_803E82D0;
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);

int dim2prisonmammoth_getExtraSize(void) { return 0x604; }
int dim2prisonmammoth_getObjectTypeId(void) { return 0; }
void dim2prisonmammoth_free(void) {}

void dim2prisonmammoth_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E82D0);
    }
}

void dim2prisonmammoth_hitDetect(void) {}

#pragma scheduling off
#pragma peephole off
int fn_802BC36C(int* obj) {
    int* sub = *(int**)((char*)obj + 76);
    switch ((s8)*(s8*)((char*)sub + 25)) {
        case 0:
            if ((u32)GameBit_Get(548) != 0) return 3;
            return 2;
        case 1:
            if ((u32)GameBit_Get(707) != 0) return 3;
            return 3;
        default:
            return 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E83E8;
extern f32 lbl_803E83A4;
extern void fn_8003B950(int mtx);

#pragma scheduling off
#pragma peephole off
void dim2prisonmammoth_release(void) {}

f32 DR_CloudRunner_func19(int obj, f32 *out)
{
    *out = lbl_803E83E8;
    return lbl_803E83A4;
}

void DR_CloudRunner_func18(int obj, f32 *a, int *b)
{
    *a = lbl_803E83A4;
    *b = 0;
}

void DR_EarthWarrior_func15(int obj, f32 *x, f32 *y, f32 *z)
{
    *x = *(f32 *)((char *)obj + 0xc);
    *y = *(f32 *)((char *)obj + 0x10);
    *z = *(f32 *)((char *)obj + 0x14);
}

int fn_802BDBCC(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(u16 *)((char *)inner + 0x14e4) |= 0x20;
    return 2;
}

int DR_CloudRunner_func11(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0xbb8) != 0) {
        return 1;
    }
    return 2;
}

void DR_EarthWarrior_modelMtxFn(int obj, f32 *x, f32 *y, f32 *z)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *x = *(f32 *)((char *)inner + 0x1438);
    *y = *(f32 *)((char *)inner + 0x143c);
    *z = *(f32 *)((char *)inner + 0x1440);
}

void DR_CloudRunner_func22(int obj)
{
    fn_8003B950(ObjPath_GetPointModelMtx(obj, 2));
}
#pragma peephole reset
#pragma scheduling reset

extern void playerTailFn_80026b3c(int *p1, int p2, int p3, void *p4);
extern void Resource_Release(int handle);
extern u8 framesThisStep;
extern void *lbl_803DE4D0;

#pragma scheduling off
#pragma peephole off
int DR_CloudRunner_func14(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0xbb7) != 0) {
        return 2;
    }
    return 1;
}

int DR_EarthWarrior_func11(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0x14eb) != 0) {
        return 1;
    }
    return 2;
}

int DR_EarthWarrior_func14(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0x14ea) != 0) {
        return 2;
    }
    return 1;
}

void DR_CloudRunner_modelMtxFn(int obj, int a, int b, int c)
{
    ObjPath_GetPointWorldPosition(obj, 2, a, b, c, 0);
}

void DR_EarthWarrior_func18(int obj, f32 *a, int *b)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *a = (f32)(s32)*(s16 *)((char *)inner + 0x102c);
    *b = *(s16 *)((char *)inner + 0x102e);
}

int fn_802BF730(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    u8 v;
    if (*(s16 *)((char *)inner + 0xbb0) == 0) {
        v = *(u8 *)((char *)obj + 0x36);
        *(u8 *)((char *)obj + 0x36) = v - framesThisStep;
    }
    return 0;
}

void fn_802BC788(int a, int b)
{
    playerTailFn_80026b3c((int *)b, *(int *)b, *(int *)(*(int *)((char *)a + 0xb8) + 0x14f8), 0);
}

void DR_EarthWarrior_release(void)
{
    if (lbl_803DE4D0 != NULL) {
        Resource_Release((int)lbl_803DE4D0);
        lbl_803DE4D0 = NULL;
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int GameBit_Set(int id, int value);
extern int *gGameUIInterface;
extern int lbl_803DB1C0[];
extern void *lbl_803DE4E0;
extern int fn_802C0B84(int obj);
extern int fn_802C0A5C(int obj, int p2);
extern int fn_802C0978(int obj, int p2);
extern int fn_802C0830(int obj, int p2);
extern void fn_802C0550();
extern void fn_802BF934();
extern void fn_802BF75C();

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_free(int obj)
{
    GameBit_Set(0x7aa, *(s16 *)((char *)*(int *)((char *)obj + 0xb8) + 0xbb0));
    ObjGroup_RemoveObject(obj, 0xa);
    ObjGroup_RemoveObject(obj, 0x26);
    (*(void (*)(void))(*(int *)(*gGameUIInterface + 0x60)))();
}

void DR_CloudRunner_initialise(void)
{
    ((void **)lbl_803DB1C0)[0] = (void *)fn_802C0B84;
    ((void **)lbl_803DB1C0)[1] = (void *)fn_802C0A5C;
    ((void **)lbl_803DB1C0)[2] = (void *)fn_802C0978;
    ((void **)lbl_803DB1C0)[3] = (void *)fn_802C0830;
    ((void **)lbl_803DB1C0)[4] = (void *)fn_802C0550;
    ((void **)lbl_803DB1C0)[5] = (void *)fn_802BF934;
    ((void **)lbl_803DB1C0)[6] = (void *)fn_802BF75C;
    ((void **)lbl_803DB1C0)[7] = (void *)fn_802BF730;
    lbl_803DE4E0 = (void *)fn_802BF728;
}
#pragma peephole reset
#pragma scheduling reset

extern int Resource_Acquire(int id, int kind);
extern int lbl_803DB160[];
extern int lbl_803DB1B0[];
extern void *lbl_803DE4C8;
extern void *lbl_803DE4D4;
extern int fn_802BC27C(int obj, int p2);
extern int fn_802BC19C(int obj, int p2);
extern int fn_802BC0D8(int obj, int p2);
extern void fn_802BD7AC();
extern void fn_802BCE14();
extern void fn_802BCD04();

#pragma scheduling off
#pragma peephole off
void dim2prisonmammoth_initialise(void)
{
    ((void **)lbl_803DB160)[0] = (void *)fn_802BC36C;
    ((void **)lbl_803DB160)[1] = (void *)fn_802BC27C;
    ((void **)lbl_803DB160)[2] = (void *)fn_802BC19C;
    ((void **)lbl_803DB160)[3] = (void *)fn_802BC0D8;
    lbl_803DE4C8 = (void *)fn_802BC0D0;
}

extern f32 lbl_803E82C0;
extern f32 lbl_803E82C4;
extern f32 lbl_803E82C8;
extern f32 lbl_803E82CC;
extern f32 lbl_803DC758;
extern s16 lbl_803DC754;
extern int randomGetRange(int lo, int hi);
extern int ObjAnim_SetCurrentMove(int obj, int moveId, f32 blend, int flag);
extern int RandomTimer_UpdateRangeTrigger(int p, f32 a, f32 b);
extern int *gObjectTriggerInterface;
extern void buttonDisable(int a, int b);
extern void Sfx_PlayFromObject(int obj, int id);

#pragma scheduling off
#pragma peephole off
int fn_802BC0D8(int obj, int p2)
{
    f32 fz = lbl_803E82C0;
    *(f32 *)((char *)p2 + 0x294) = fz;
    *(f32 *)((char *)p2 + 0x284) = fz;
    *(f32 *)((char *)p2 + 0x280) = fz;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x28) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    *(int *)((char *)p2 + 0) |= 0x200000;
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        int k = randomGetRange(0, 1);
        *(f32 *)((char *)p2 + 0x2a0) = (&lbl_803DC758)[k];
        ObjAnim_SetCurrentMove(obj, (&lbl_803DC754)[k], lbl_803E82C0, 0);
    }
    if (*(s8 *)((char *)p2 + 0x346) != 0) {
        return -1;
    }
    return 0;
}

int fn_802BC19C(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 fz = lbl_803E82C0;
    *(f32 *)((char *)p2 + 0x294) = fz;
    *(f32 *)((char *)p2 + 0x284) = fz;
    *(f32 *)((char *)p2 + 0x280) = fz;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x28) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    *(int *)((char *)p2 + 0) |= 0x200000;
    *(f32 *)((char *)p2 + 0x2a0) = lbl_803E82C4;
    if (*(s16 *)((char *)obj + 0xa0) != 0) {
        ObjAnim_SetCurrentMove(obj, 0, fz, 0);
    }
    *(s16 *)((char *)inner + 0x38c) = randomGetRange(0x4b0, 0x960);
    *(u8 *)((char *)obj + 0xaf) &= ~8;
    if (*(u8 *)((char *)obj + 0xaf) & 1) {
        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0, obj, -1);
        buttonDisable(0, 0x100);
    }
    return 0;
}

int fn_802BC27C(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 fz = lbl_803E82C0;
    *(f32 *)((char *)p2 + 0x294) = fz;
    *(f32 *)((char *)p2 + 0x284) = fz;
    *(f32 *)((char *)p2 + 0x280) = fz;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x28) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    *(int *)((char *)p2 + 0) |= 0x200000;
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E82C4;
        if (*(s16 *)((char *)obj + 0xa0) != 5) {
            ObjAnim_SetCurrentMove(obj, 5, fz, 0);
        }
        *(s16 *)((char *)inner + 0x38c) = randomGetRange(0x4b0, 0x960);
    }
    if (*(u8 *)((char *)obj + 0xaf) & 1) {
        GameBit_Set(0x223, 1);
        buttonDisable(0, 0x100);
    }
    if (RandomTimer_UpdateRangeTrigger(inner + 0x600, lbl_803E82C8, lbl_803E82CC)) {
        Sfx_PlayFromObject(obj, 0x43a);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E83F4;
extern f32 lbl_803E83F8;
extern f32 lbl_803E83BC;
extern f32 lbl_803E8408;
extern f32 lbl_803E840C;
extern s16 lbl_803DC79A;
extern f32 Vec_distance(int a, int b);
extern void *Obj_GetPlayerObject(void);
extern void fn_802BF0C8(int obj, int p2, int mode);

#pragma scheduling off
#pragma peephole off
int fn_802C0978(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(int *)((char *)p2 + 0) |= 0x200000;
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        f32 fz = lbl_803E83A4;
        *(f32 *)((char *)p2 + 0x294) = fz;
        *(f32 *)((char *)p2 + 0x284) = fz;
        *(f32 *)((char *)p2 + 0x280) = fz;
        *(f32 *)((char *)obj + 0x24) = fz;
        *(f32 *)((char *)obj + 0x28) = fz;
        *(f32 *)((char *)obj + 0x2c) = fz;
        *(s16 *)((char *)p2 + 0x338) = 0;
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E83F4;
        *(f32 *)((char *)p2 + 0x2b8) = lbl_803E83F8;
        if (*(s16 *)((char *)obj + 0xa0) != 0) {
            ObjAnim_SetCurrentMove(obj, 0, fz, 0);
        }
        if (((ByteFlags *)((char *)inner + 0xbc0))->b20) {
            ((ByteFlags *)((char *)inner + 0xbc0))->b20 = 0;
            *(u8 *)((char *)p2 + 0x25f) = 0;
        }
    }
    if (*(f32 *)((char *)p2 + 0x298) < lbl_803E83BC) {
        *(s16 *)((char *)p2 + 0x334) = 0;
        *(s16 *)((char *)p2 + 0x336) = 0;
        *(f32 *)((char *)p2 + 0x298) = lbl_803E83A4;
    }
    return 0;
}

int fn_802C0A5C(int obj, int p2)
{
    int q = *(int *)((char *)obj + 0x4c);
    int inner;
    *(int *)((char *)p2 + 0) |= 0x200000;
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        f32 fz;
        ObjHits_DisableObject(obj);
        *(u8 *)((char *)p2 + 0x25f) = 0;
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E8408;
        fz = lbl_803E83A4;
        *(f32 *)((char *)p2 + 0x294) = fz;
        *(f32 *)((char *)p2 + 0x284) = fz;
        *(f32 *)((char *)p2 + 0x280) = fz;
        *(f32 *)((char *)obj + 0x24) = fz;
        *(f32 *)((char *)obj + 0x28) = fz;
        *(f32 *)((char *)obj + 0x2c) = fz;
        return 0;
    }
    inner = *(int *)((char *)obj + 0xb8);
    Vec_distance(obj + 0x18, (int)Obj_GetPlayerObject() + 0x18);
    if (RandomTimer_UpdateRangeTrigger(inner + 0xb54, lbl_803E83F8, lbl_803E840C)) {
        Sfx_PlayFromObject(obj, 0x464);
    }
    if (GameBit_Get(*(s16 *)((char *)q + 0x1e))) {
        *(int *)((char *)obj + 0xf4) = 0;
        ObjHits_EnableObject(obj);
        ObjHits_SyncObjectPositionIfDirty(obj);
        ((ByteFlags *)((char *)inner + 0xbc0))->b10 = *(s16 *)((char *)inner + 0xbb0) > 0;
        *(s16 *)((char *)obj + 0) = lbl_803DC79A;
        return 3;
    }
    return 0;
}

int fn_802C0830(int obj, int p2)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(s8 *)((char *)p2 + 0x27a) != 0) {
        ((ByteFlags *)((char *)inner + 0xbc0))->b10 = 0;
        *(f32 *)((char *)obj + 0x28) = lbl_803E83A4;
        if (((ByteFlags *)((char *)inner + 0xbc0))->b20) {
            ((ByteFlags *)((char *)inner + 0xbc0))->b20 = 0;
            fn_802BF0C8(obj, p2, ((ByteFlags *)((char *)inner + 0xbc0))->b20);
        }
    }
    switch (*(s16 *)((char *)obj + 0xa0)) {
    case 0x203:
        if (*(s16 *)((char *)inner + 0xbb0) != 0) {
            ObjAnim_SetCurrentMove(obj, 0x20c, lbl_803E83A4, 0);
            *(f32 *)((char *)p2 + 0x2a0) = lbl_803E8408;
        }
        break;
    case 0x20c:
        if (*(s8 *)((char *)p2 + 0x346) != 0) {
            *(u8 *)((char *)inner + 0xad5) &= ~2;
            return 3;
        }
        break;
    default: {
        f32 fz;
        ObjAnim_SetCurrentMove(obj, 0x203, lbl_803E83A4, 0);
        *(u8 *)((char *)inner + 0xad5) |= 2;
        fz = lbl_803E83A4;
        *(f32 *)((char *)p2 + 0x294) = fz;
        *(f32 *)((char *)p2 + 0x284) = fz;
        *(f32 *)((char *)p2 + 0x280) = fz;
        *(f32 *)((char *)obj + 0x24) = fz;
        *(f32 *)((char *)obj + 0x28) = fz;
        *(f32 *)((char *)obj + 0x2c) = fz;
        *(f32 *)((char *)p2 + 0x2a0) = lbl_803E8408;
        break;
    }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

void DR_EarthWarrior_initialise(void)
{
    ((void **)lbl_803DB1B0)[0] = (void *)fn_802BDBCC;
    ((void **)lbl_803DB1B0)[1] = (void *)fn_802BD7AC;
    ((void **)lbl_803DB1B0)[2] = (void *)fn_802BCE14;
    ((void **)lbl_803DB1B0)[3] = (void *)fn_802BCD04;
    lbl_803DE4D4 = (void *)fn_802BCCFC;
    if (lbl_803DE4D0 == NULL) {
        lbl_803DE4D0 = (void *)Resource_Acquire(0x5a, 1);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void dll_2E_func06();
extern f32 lbl_803E8338;
extern f32 lbl_803E83A8;
extern f32 lbl_803E8360;
extern f32 lbl_803E8354;
extern f32 lbl_803E8364;
extern f32 lbl_803E8304;

#pragma scheduling off
#pragma peephole off
f32 DR_EarthWarrior_func19(int obj, f32 *out)
{
    int inner = *(int *)((char *)obj + 0xb8);
    f32 v = lbl_803E8360 * *(f32 *)((char *)inner + 0x294) + lbl_803E8354;
    if (v < lbl_803E8354) {
        v = lbl_803E8354;
    } else if (v > lbl_803E8364) {
        v = lbl_803E8364;
    }
    *out = -v;
    return lbl_803E8304;
}

void DR_EarthWarrior_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    int inner = *(int *)((char *)p1 + 0xb8);
    if (vis == -1) {
        objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E8338);
        ObjPath_GetPointWorldPosition(p1, 0xb, (char *)inner + 0x1438, (char *)inner + 0x143c, (char *)inner + 0x1440, 0);
        ObjPath_GetPointWorldPositionArray(p1, 3, 4, (char *)inner + 0xb18);
    } else if (vis != 0) {
        objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E8338);
        ObjPath_GetPointWorldPosition(p1, 0xb, (char *)inner + 0x1438, (char *)inner + 0x143c, (char *)inner + 0x1440, 0);
        ObjPath_GetPointWorldPositionArray(p1, 3, 4, (char *)inner + 0xb18);
        dll_2E_func06(p1, (char *)inner + 0x3ec, 0);
    }
}

void DR_CloudRunner_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    int inner = *(int *)((char *)p1 + 0xb8);
    if (*(int *)((char *)p1 + 0xf4) == 0) {
        if (vis == -1) {
            objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E83A8);
            ObjPath_GetPointWorldPosition(p1, 3, (char *)inner + 0xae8, (char *)inner + 0xaec, (char *)inner + 0xaf0, 0);
        }
        if (*(u8 *)((char *)inner + 0xbb2) != 2 && vis != 0) {
            objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E83A8);
            dll_2E_func06(p1, (char *)inner + 0x4c4, 0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_80026C88(int p);
extern int Obj_FreeObject(int obj);

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_free(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(void **)((char *)inner + 0x14f8) != NULL) {
        fn_80026C88(*(int *)((char *)inner + 0x14f8));
    }
    ObjGroup_RemoveObject(obj, 0xa);
    if (((ByteFlags *)((char *)inner + 0x14ec))->b02) {
        (*(void (*)(void))(*(int *)(*gGameUIInterface + 0x60)))();
    }
    if (*(void **)((char *)inner + 0xb54) != NULL) {
        ObjLink_DetachChild(obj, *(int *)((char *)inner + 0xb54));
        Obj_FreeObject(*(int *)((char *)inner + 0xb54));
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int objAudioFn_800393f8(int obj, void *audio, int soundId, int volume, int p5, int p6);
extern void textureFree(int handle);
extern f32 lbl_803E82E8;
extern int lbl_8033527C[];
extern void *lbl_803DE4C0;

#pragma scheduling off
#pragma peephole off
void DR_EarthWarrior_func23(int obj, int mode)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (mode == 1) {
        *(s16 *)((char *)inner + 0x14e2) += 4;
        objAudioFn_800393f8(obj, (char *)inner + 0x3bc, 0x291, 0x1000, -1, 1);
        *(f32 *)((char *)inner + 0x1444) = lbl_803E82E8;
        *(f32 *)((char *)lbl_8033527C + 0x24) = *(f32 *)((char *)inner + 0x1444);
    }
}

void DIMSnowHorn1_release(void)
{
    void **p = &lbl_803DE4C0;
    void *v = *p;
    if (v != NULL) {
        textureFree((int)v);
    }
    *p = NULL;
}

int fn_802C0B84(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    if (*(u8 *)((char *)inner + 0xbb4) == 0) {
        return 2;
    }
    ObjHits_EnableObject(obj);
    ObjHits_SyncObjectPositionIfDirty(obj);
    ((ByteFlags *)((char *)inner + 0xbc0))->b10 = *(s16 *)((char *)inner + 0xbb0) > 0;
    return 3;
}
#pragma peephole reset
#pragma scheduling reset

extern int *gObjectTriggerInterface;

#pragma scheduling off
#pragma peephole off
void DR_CloudRunner_func17(int obj, int param)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)inner + 0xbb2) = (u8)param;
    if (param == 1) {
        s16 t;
        *(u8 *)((char *)inner + 0x464) = 0;
        t = *(s16 *)((char *)obj + 0xb4);
        if (t != -1) {
            (*(void (*)(int))(*(int *)(*gObjectTriggerInterface + 0x4c)))(t);
        }
    } else {
        *(u8 *)((char *)inner + 0x464) = 1;
    }
    if (param == 2) {
        GameBit_Set(0xed7, 1);
    } else {
        GameBit_Set(0xed7, 0);
    }
}

void DR_EarthWarrior_func17(int obj, int param)
{
    int inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)inner + 0x14e6) = (u8)param;
    if (param == 0) {
        GameBit_Set(0x7bc, 0);
        GameBit_Set(0x7d4, 1);
        *(u8 *)((char *)inner + 0x9fd) &= ~1;
        ((ByteFlags *)((char *)inner + 0x14ec))->b02 = 0;
        (*(void (*)(void))(*(int *)(*gGameUIInterface + 0x60)))();
    } else {
        int inner2 = *(int *)((char *)obj + 0xb8);
        int p = *(int *)((char *)obj + 0x4c);
        ((ByteFlags *)((char *)inner2 + 0x14ec))->b02 = 1;
        (*(void (*)(int, int))(*(int *)(*gGameUIInterface + 0x58)))(*(s16 *)((char *)p + 0x1a), 0x5cf);
        (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x5c)))(*(s16 *)((char *)inner2 + 0x14e2));
        GameBit_Set(0x7bc, 1);
        GameBit_Set(0x7d4, 0);
    }
}

extern int *gRomCurveInterface;
extern f32 lbl_803E8410;

int fn_802C0BFC(int obj, int p2, int p3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int local = 1;
    int i;
    *(u8 *)((char *)obj + 0xaf) |= 8;
    for (i = 0; i < *(u8 *)((char *)p3 + 0x8b); i++) {
        int idx = i + 0x81;
        if ((int)*(u8 *)((char *)p3 + idx) == 1) {
            (*(void (*)(int, int, f32, int *, int))(*(int *)(*gRomCurveInterface + 0x8c)))(inner + 0x35c, obj, lbl_803E8410, &local, 0xf);
        }
    }
    ((ByteFlags *)((char *)inner + 0xbc1))->b80 = 1;
    return 0;
}

extern int *gPlayerInterface;
int fn_802BC3F0(int obj, int p2, int p3);

void dim2prisonmammoth_init(int obj, int p2)
{
    int inner;
    *(s16 *)((char *)obj + 0) = (s16)((s8)*(s8 *)((char *)p2 + 0x18) << 8);
    *(int *)((char *)obj + 0xbc) = (int)fn_802BC3F0;
    inner = *(int *)((char *)obj + 0xb8);
    if (*(void **)((char *)obj + 0x64) != NULL) {
        *(int *)((char *)*(int *)((char *)obj + 0x64) + 0x30) |= 0xa10;
        *(int *)((char *)*(int *)((char *)obj + 0x64) + 0x30) |= 0x8020;
    }
    (*(void (*)(int, int, int, int))(*(int *)(*gPlayerInterface + 0x4)))(obj, inner, 4, 1);
    *(u8 *)((char *)inner + 0x25f) = 0;
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
}

extern void setMatrixFromObjectPos(f32 *out, void *vec);
extern void Matrix_TransformPoint(f32 *mtx, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
extern f32 lbl_803E82C0;

int fn_802BC3F0(int obj, int p2, int p3)
{
    struct {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 matrix[16];
    int inner;
    int p;

    *(u8 *)((char *)p3 + 0x56) = 0;
    *(s16 *)((char *)p3 + 0x6e) = *(s16 *)((char *)p3 + 0x70);
    inner = *(int *)((char *)obj + 0xb8);
    (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 2);

    v.mat[1] = *(f32 *)((char *)obj + 0xc);
    v.mat[2] = *(f32 *)((char *)obj + 0x10);
    v.mat[3] = *(f32 *)((char *)obj + 0x14);
    v.angles[0] = *(s16 *)((char *)obj + 0);
    v.angles[1] = *(s16 *)((char *)obj + 2);
    v.angles[2] = *(s16 *)((char *)obj + 4);
    v.mat[0] = *(f32 *)((char *)obj + 8);
    setMatrixFromObjectPos(matrix, v.angles);

    p = *(int *)((char *)obj + 0x64);
    Matrix_TransformPoint(matrix, lbl_803E82C0, lbl_803E82C0, lbl_803E82C0,
                          (f32 *)((char *)p + 0x20), (f32 *)((char *)p + 0x24), (f32 *)((char *)p + 0x28));
    return 0;
}

extern void *Obj_GetPlayerObject(void);
extern f32 lbl_803DC78C;
extern f32 lbl_803DC790;

void DR_CloudRunner_func15(int obj, f32 *a, f32 *b, f32 *c)
{
    struct {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 matrix[16];
    void *src = Obj_GetPlayerObject();
    if (src == NULL) {
        src = (void *)obj;
    }
    v.mat[1] = *(f32 *)((char *)src + 0xc);
    v.mat[2] = *(f32 *)((char *)src + 0x10);
    v.mat[3] = *(f32 *)((char *)src + 0x14);
    v.angles[0] = *(s16 *)((char *)src + 0);
    v.angles[1] = *(s16 *)((char *)src + 2);
    v.angles[2] = *(s16 *)((char *)src + 4);
    v.mat[0] = lbl_803E83A8;
    setMatrixFromObjectPos(matrix, v.angles);
    Matrix_TransformPoint(matrix, lbl_803E83A4, lbl_803DC78C, lbl_803DC790, a, b, c);
}

extern void mtx44_mult(void *lhs, void *rhs, void *out);
extern f32 lbl_803DB170[];

void DR_EarthWarrior_func22(int obj, f32 scale)
{
    struct {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 lp0, lp1, lp2;
    int mtx = (int)ObjPath_GetPointModelMtx(obj, 2);
    ObjPath_GetPointLocalPosition(obj, 2, &lp0, &lp1, &lp2);
    v.mat[1] = lp0;
    v.mat[2] = lp1;
    v.mat[3] = lp2;
    v.angles[0] = 0;
    v.angles[1] = 0;
    v.angles[2] = 0;
    v.mat[0] = scale / *(f32 *)((char *)*(int *)((char *)obj + 0x50) + 0x4);
    setMatrixFromObjectPos(lbl_803DB170, v.angles);
    mtx44_mult(lbl_803DB170, (void *)mtx, lbl_803DB170);
    fn_8003B950((int)lbl_803DB170);
}

extern void fn_802BABB4();
extern void fn_802BAA54();
extern void fn_802BA938();
extern void fn_802BA7EC();
extern void fn_802BA6E0();
extern void fn_802BA3EC();
extern void fn_802BA1D4();
extern void fn_802B9FC0();
extern void fn_802B9E38();
extern void fn_802B9CC4();
extern void fn_802B98F0();
extern void fn_802B978C();
extern void fn_802B9784();
extern int lbl_803DB130[];
extern void *lbl_803DE4C4;
extern s16 lbl_803DC730;
extern int textureLoad(int id, int p2);

void DIMSnowHorn1_initialise(void)
{
    s16 *src = &lbl_803DC730;
    void **dst = &lbl_803DE4C0;
    ((void **)lbl_803DB130)[0] = (void *)fn_802BABB4;
    ((void **)lbl_803DB130)[1] = (void *)fn_802BAA54;
    ((void **)lbl_803DB130)[2] = (void *)fn_802BA938;
    ((void **)lbl_803DB130)[3] = (void *)fn_802BA7EC;
    ((void **)lbl_803DB130)[4] = (void *)fn_802BA6E0;
    ((void **)lbl_803DB130)[5] = (void *)fn_802BA3EC;
    ((void **)lbl_803DB130)[6] = (void *)fn_802BA1D4;
    ((void **)lbl_803DB130)[7] = (void *)fn_802B9FC0;
    ((void **)lbl_803DB130)[8] = (void *)fn_802B9E38;
    ((void **)lbl_803DB130)[9] = (void *)fn_802B9CC4;
    ((void **)lbl_803DB130)[10] = (void *)fn_802B98F0;
    ((void **)lbl_803DB130)[11] = (void *)fn_802B978C;
    lbl_803DE4C4 = (void *)fn_802B9784;
    *dst = (void *)textureLoad(*src, 0);
}

typedef struct {
    f32 f0;
    f32 f4;
    f32 f8;
    s16 hc;
    u8 pad_e[2];
    f32 f10;
    f32 f14;
    f32 f18;
    s16 h1c;
    u16 h1e;
    u16 h20;
    u8 pad_22[2];
} SnowHornEntry;

extern u8 lbl_80335030[];
extern void ddh_cc_initinterrupts();
extern int lbl_803E8230;
extern int lbl_803DC734;
extern f32 lbl_803E82B8;
extern int *gPathControlInterface;
extern void dll_2E_func05(int obj, int q, int a, int b, int c);

void DIMSnowHorn1_init(int obj, int p2, int p3)
{
    u8 *base = lbl_80335030;
    int stk = lbl_803E8230;
    int inner;
    int q;
    s8 idx;
    *(s16 *)((char *)obj + 0) = (s16)((s8)*(s8 *)((char *)p2 + 0x18) << 8);
    *(int *)((char *)obj + 0xbc) = (int)ddh_cc_initinterrupts;
    ObjGroup_AddObject(obj, 0xa);
    inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)inner + 0xa8c) = *(u8 *)((char *)p2 + 0x19);
    *(s16 *)((char *)inner + 0xa86) = 5;
    *(s16 *)((char *)inner + 0xa88) = 0x3e8;
    if (*(void **)((char *)obj + 0x64) != NULL) {
        *(int *)((char *)*(int *)((char *)obj + 0x64) + 0x30) |= 0xa10;
    }
    if (*(void **)((char *)obj + 0x54) != NULL) {
        *(s16 *)((char *)*(int *)((char *)obj + 0x54) + 0xb2) = 9;
    }
    (*(void (*)(int, int, int, int))(*(int *)(*gPlayerInterface + 0x4)))(obj, inner, 0xc, 1);
    *(f32 *)((char *)inner + 0x2a4) = lbl_803E82B8;
    q = inner + 0x4;
    *(u8 *)((char *)q + 0x25b) = 0;
    switch (*(u8 *)((char *)inner + 0xa8c)) {
    case 1:
    case 3:
    case 4:
        (*(void (*)(int, int, int, int))(*(int *)(*gPathControlInterface + 0x4)))(q, 3, 0x200020, 1);
        (*(void (*)(int, int, int, int, int))(*(int *)(*gPathControlInterface + 0x8)))(q, 2, (int)(base + 0xe0), (int)&lbl_803DC734, 8);
        (*(void (*)(int, int, int, int, int *))(*(int *)(*gPathControlInterface + 0xc)))(q, 4, (int)(base + 0xa0), (int)(base + 0xd0), &stk);
        (*(void (*)(int, int))(*(int *)(*gPathControlInterface + 0x20)))(obj, q);
        break;
    case 2:
        break;
    }
    dll_2E_func05(obj, inner + 0x35c, -0x2000, 0x2aaa, 3);
    *(u8 *)((char *)inner + 0x96d) |= 8;
    if (p3 == 0) {
        idx = -1;
        switch (*(u8 *)((char *)inner + 0xa8c)) {
        case 1:
            if (GameBit_Get(0x16f)) {
                idx = 0;
            }
            break;
        case 3:
            idx = 1;
            break;
        case 4:
            if (GameBit_Get(0x1db)) {
                idx = 2;
            }
            break;
        }
        if (idx >= 0) {
            SnowHornEntry *e = &((SnowHornEntry *)base)[idx];
            if (GameBit_Get(e->h1e)) {
                *(f32 *)((char *)obj + 0xc) = e->f10;
                *(f32 *)((char *)obj + 0x10) = e->f14;
                *(f32 *)((char *)obj + 0x14) = e->f18;
                *(s16 *)((char *)obj + 0) = e->h1c;
            } else {
                *(f32 *)((char *)obj + 0xc) = e->f0;
                *(f32 *)((char *)obj + 0x10) = e->f4;
                *(f32 *)((char *)obj + 0x14) = e->f8;
                *(s16 *)((char *)obj + 0) = e->hc;
            }
            if (GameBit_Get(e->h20)) {
                *(s16 *)((char *)obj + 0) += 0x8000;
            }
        }
    }
}

extern int dll_2E_func07(int obj, int p3, void *q, int a, int b);
extern int *gPathControlInterface;

int fn_802BDBE8(int obj, int p2, int p3)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int i;
    f32 fz;
    *(u8 *)((char *)obj + 0xaf) |= 8;
    if (dll_2E_func07(obj, p3, (void *)(inner + 0x3ec), 0, 0) != 0) {
        return 1;
    }
    for (i = 0; i < *(u8 *)((char *)p3 + 0x8b); i++) {
        int idx = i + 0x81;
        int v = *(u8 *)((char *)p3 + idx);
        switch (v) {
        case 0xa:
            break;
        case 0xe:
        case 0xf:
            *(u8 *)((char *)inner + 0x9fd) |= 1;
            *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x62) &= ~0x20;
            break;
        case 0x10:
            *(u8 *)((char *)inner + 0x9fd) &= ~1;
            *(u8 *)((char *)*(int *)((char *)obj + 0x54) + 0x62) |= 0x20;
            break;
        }
    }
    *(int *)((char *)inner + 0xeb8) |= 0x800000;
    (*(void (*)(int, int))(*(int *)(*gPathControlInterface + 0x20)))(obj, inner + 0x4);
    fz = lbl_803E8304;
    *(f32 *)((char *)inner + 0x294) = fz;
    *(f32 *)((char *)inner + 0x284) = fz;
    *(f32 *)((char *)inner + 0x280) = fz;
    *(f32 *)((char *)obj + 0x24) = fz;
    *(f32 *)((char *)obj + 0x28) = fz;
    *(f32 *)((char *)obj + 0x2c) = fz;
    return 0;
}

extern int dll_2E_func0A(int a, void *out);
extern void dll_2E_func05(int obj, int q, int a, int b, int c);
extern void dll_2E_func08(int q, int a, int b);
extern f32 lbl_803E8414;
extern f32 lbl_803E8424;
void fn_802BF0C8(int obj, int inner, int bit);

void DR_CloudRunner_init(int obj, int p2)
{
    struct {
        s16 angles[4];
        f32 mat[4];
    } stk;
    int inner;
    int r;
    *(s16 *)((char *)obj + 0) = (s16)((s8)*(s8 *)((char *)p2 + 0x18) << 8);
    *(int *)((char *)obj + 0xbc) = (int)fn_802C0BFC;
    ObjGroup_AddObject(obj, 0xa);
    inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)inner + 0xbb4) = *(u8 *)((char *)p2 + 0x19);
    *(s16 *)((char *)inner + 0xbae) = 5;
    *(s16 *)((char *)inner + 0xbb0) = *(s16 *)((char *)p2 + 0x1a);
    *(s8 *)((char *)inner + 0xbc4) = -1;
    *(f32 *)((char *)inner + 0xb50) = (f32)*(s16 *)((char *)p2 + 0x1c) / lbl_803E8414;
    if (*(void **)((char *)obj + 0x64) != NULL) {
        *(int *)((char *)*(int *)((char *)obj + 0x64) + 0x30) |= 0xa10;
    }
    r = GameBit_Get(0x7a9);
    if (r != 0) {
        dll_2E_func0A(r + 0x13, &stk);
        *(f32 *)((char *)obj + 0xc) = stk.mat[1];
        *(f32 *)((char *)obj + 0x10) = stk.mat[2];
        *(f32 *)((char *)obj + 0x14) = stk.mat[3];
        *(s16 *)((char *)obj + 0) = stk.angles[0];
    }
    (*(void (*)(int, int, int, int))(*(int *)(*gPlayerInterface + 0x4)))(obj, inner, 8, 1);
    *(f32 *)((char *)inner + 0x2a4) = lbl_803E8424;
    fn_802BF0C8(obj, inner, ((ByteFlags *)((char *)inner + 0xbc0))->b20);
    dll_2E_func05(obj, inner + 0x4c4, -0x11c7, 0x1555, 1);
    dll_2E_func08(inner + 0x4c4, 0x12c, 0x78);
    ObjGroup_AddObject(obj, 0x26);
    ((ByteFlags *)((char *)inner + 0xbc0))->b01 = 0;
}

extern u8 lbl_803DC750;
extern u8 lbl_803351A8[];
extern f32 timeDelta;
extern void fn_8003A168(int obj, int q);
extern void characterDoEyeAnims(int obj, int q);
extern void saveGame_saveObjectPos(int obj);

void dim2prisonmammoth_update(int obj)
{
    struct {
        s16 angles[4];
        f32 mat[4];
    } v;
    f32 matrix[16];
    int inner = *(int *)((char *)obj + 0xb8);
    int p;
    *(u8 *)((char *)obj + 0xaf) &= ~8;
    if (((&lbl_803DC750)[*(s16 *)((char *)inner + 0x274)] & 8) == 0) {
        *(u8 *)((char *)inner + 0x5fc) = objHitReact_update(obj, lbl_803351A8, 1, *(u8 *)((char *)inner + 0x5fc), (void *)(inner + 0x390));
        if (*(u8 *)((char *)inner + 0x5fc) != 0) {
            fn_8003A168(obj, inner + 0x35c);
            characterDoEyeAnims(obj, inner + 0x35c);
            return;
        }
    }
    characterDoEyeAnims(obj, inner + 0x35c);
    v.mat[1] = *(f32 *)((char *)obj + 0xc);
    v.mat[2] = *(f32 *)((char *)obj + 0x10);
    v.mat[3] = *(f32 *)((char *)obj + 0x14);
    v.angles[0] = *(s16 *)((char *)obj + 0);
    v.angles[1] = *(s16 *)((char *)obj + 2);
    v.angles[2] = *(s16 *)((char *)obj + 4);
    v.mat[0] = *(f32 *)((char *)obj + 8);
    setMatrixFromObjectPos(matrix, v.angles);
    p = *(int *)((char *)obj + 0x64);
    Matrix_TransformPoint(matrix, lbl_803E82C0, lbl_803E82C0, lbl_803E82C0,
                          (f32 *)((char *)p + 0x20), (f32 *)((char *)p + 0x24), (f32 *)((char *)p + 0x28));
    *(u8 *)((char *)inner + 0x354) = 0;
    *(int *)((char *)inner + 0) &= ~0x8000;
    *(f32 *)((char *)inner + 0x290) = lbl_803E82C0;
    *(f32 *)((char *)inner + 0x28c) = lbl_803E82C0;
    *(int *)((char *)inner + 0x31c) = 0;
    *(int *)((char *)inner + 0x318) = 0;
    *(s16 *)((char *)inner + 0x330) = 0;
    *(int *)((char *)inner + 0) |= 0x400000;
    (*(void (*)(int, int, f32, f32, int, void *))(*(int *)(*gPlayerInterface + 0x8)))(obj, inner, timeDelta, timeDelta, (int)lbl_803DB160, &lbl_803DE4C8);
    saveGame_saveObjectPos(obj);
}

extern u8 lbl_803356F0[];
extern int lbl_803E83A0;
extern int lbl_803DC770;
extern int lbl_803DC774;
extern int lbl_803DC778;
extern int lbl_803DC77C;
extern int lbl_803DC780;
extern int lbl_803DC784;

void fn_802BF0C8(int obj, int p2, int mode)
{
    u8 *base = lbl_803356F0;
    int stk = lbl_803E83A0;
    int q = p2 + 0x4;
    u32 m;
    *(u8 *)((char *)q + 0x25b) = 1;
    m = (u8)mode;
    if (m == 1) {
        (*(void (*)(int, int, int, int))(*(int *)(*gPathControlInterface + 0x4)))(q, 0, 0x42087, 0);
        (*(void (*)(int, int, int, int, int))(*(int *)(*gPathControlInterface + 0x8)))(q, 1, (int)(base + 0x18), (int)&lbl_803DC774, 8);
        (*(void (*)(int, int, int, int, int *))(*(int *)(*gPathControlInterface + 0xc)))(q, 1, (int)(base + 0xc), (int)&lbl_803DC770, &stk);
    } else if (m == 2) {
        (*(void (*)(int, int, int, int))(*(int *)(*gPathControlInterface + 0x4)))(q, 3, 0x42087, 0);
        (*(void (*)(int, int, int, int, int))(*(int *)(*gPathControlInterface + 0x8)))(q, 2, (int)(base + 0x30), (int)&lbl_803DC77C, 8);
        (*(void (*)(int, int, int, int, int *))(*(int *)(*gPathControlInterface + 0xc)))(q, 1, (int)(base + 0x24), (int)&lbl_803DC778, &stk);
    } else if (m == 0) {
        (*(void (*)(int, int, int, int))(*(int *)(*gPathControlInterface + 0x4)))(q, 3, 0x42087, 0);
        (*(void (*)(int, int, int, int, int))(*(int *)(*gPathControlInterface + 0x8)))(q, 2, (int)(base + 0x48), (int)&lbl_803DC784, 8);
        (*(void (*)(int, int, int, int, int *))(*(int *)(*gPathControlInterface + 0xc)))(q, 1, (int)(base + 0x3c), (int)&lbl_803DC780, &stk);
    }
    (*(void (*)(int, int))(*(int *)(*gPathControlInterface + 0x20)))(obj, q);
}

extern void *Camera_GetCurrentViewSlot(void);
extern int padGetStickX(int p);
extern int padGetStickY(int p);
extern int getButtonsJustPressed(int p);
extern int getButtonsHeld(int p);
extern void fn_80222358(int obj, int q, f32 a, f32 b, f32 c, int d);
extern int lbl_803DE4D8;
extern f32 lbl_803E83B4;
void fn_802BF4D8(int obj);

void fn_802C11BC(int obj, int p2, f32 f)
{
    int inner;
    int flag;
    int slot;
    if (p2 != -1) {
        flag = (((framesThisStep - 1) - p2) == 0);
    } else {
        flag = 1;
    }
    slot = (int)Camera_GetCurrentViewSlot();
    inner = *(int *)((char *)obj + 0xb8);
    *(u8 *)((char *)inner + 0x354) = 0;
    *(int *)((char *)inner + 0) &= ~0x8000;
    *(int *)((char *)inner + 0) |= 0x200000;
    if (*(u8 *)((char *)inner + 0xbb2) == 2) {
        *(f32 *)((char *)inner + 0x290) = (f32)(s8)padGetStickX(0);
        *(f32 *)((char *)inner + 0x28c) = (f32)(s8)padGetStickY(0);
        *(int *)((char *)inner + 0x31c) = getButtonsJustPressed(0);
        *(int *)((char *)inner + 0x318) = getButtonsHeld(0);
        *(s16 *)((char *)inner + 0x330) = *(s16 *)slot;
        if (((ByteFlags *)((char *)inner + 0xbc0))->b01 != 0) {
            fn_80222358(obj, inner + 0x35c, *(f32 *)((char *)inner + 0xb50), lbl_803E83B4, lbl_803E8414, 1);
        }
    } else {
        f32 v = lbl_803E83A4;
        *(f32 *)((char *)inner + 0x290) = v;
        *(f32 *)((char *)inner + 0x28c) = v;
        *(int *)((char *)inner + 0x31c) = 0;
        *(int *)((char *)inner + 0x318) = 0;
        *(s16 *)((char *)inner + 0x330) = 0;
    }
    *(int *)((char *)inner + 0) |= 0x400000;
    if (flag != 0) {
        *(int *)((char *)inner + 0) &= ~0x400000;
    }
    (*(void (*)(int, int, f32, f32, int, void *))(*(int *)(*gPlayerInterface + 0x8)))(obj, inner, f, timeDelta, (int)lbl_803DB1C0, &lbl_803DE4E0);
    if ((*(int *)((char *)inner + 0x314) & 1) != 0) {
        fn_802BF4D8(obj);
    }
    if (((ByteFlags *)((char *)inner + 0xbc0))->b02 != 0) {
        (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x5c)))(*(s16 *)((char *)inner + 0xbb0) - lbl_803DE4D8);
    }
}

extern void fn_802B0EA4(int obj, int q, int inner);
extern void fn_802B1BF8(int obj, int q, int inner, f32 t);
extern void fn_802B1B28(int obj, f32 t);

#pragma scheduling off
#pragma peephole off
void fn_802BE6E8(int obj)
{
    int inner = *(int *)((char *)obj + 0xb8);
    int q;
    int slot;
    Obj_GetPlayerObject();
    q = inner + 0xb58;
    slot = (int)Camera_GetCurrentViewSlot();
    *(u8 *)((char *)inner + 0x354) = 0;
    *(int *)((char *)inner + 0) &= ~0x8000;
    if (*(u8 *)((char *)inner + 0x14e6) == 2) {
        *(f32 *)((char *)inner + 0x290) = (f32)(s8)padGetStickX(0);
        *(f32 *)((char *)inner + 0x28c) = (f32)(s8)padGetStickY(0);
        *(int *)((char *)inner + 0x31c) = getButtonsJustPressed(0);
        *(int *)((char *)inner + 0x318) = getButtonsHeld(0);
        *(s16 *)((char *)inner + 0x330) = *(s16 *)slot;
    } else {
        f32 v = lbl_803E8304;
        *(f32 *)((char *)inner + 0x290) = v;
        *(f32 *)((char *)inner + 0x28c) = v;
        *(int *)((char *)inner + 0x31c) = 0;
        *(int *)((char *)inner + 0x318) = 0;
        *(s16 *)((char *)inner + 0x330) = 0;
    }
    *(int *)((char *)inner + 0) |= 0x1000000;
    fn_802B0EA4(obj, q, inner);
    (*(void (*)(int, int, f32, f32, int, void *))(*(int *)(*gPlayerInterface + 0x8)))(obj, inner, timeDelta, timeDelta, (int)lbl_803DB1B0, &lbl_803DE4D4);
    *(s16 *)((char *)obj + 0x2) = (s16)(*(s16 *)((char *)obj + 0x2) + (*(s16 *)((char *)inner + 0x19c) >> 2));
    *(s16 *)((char *)obj + 0x4) = (s16)(*(s16 *)((char *)obj + 0x4) + (*(s16 *)((char *)inner + 0x19e) >> 2));
    if (((ByteFlags *)((char *)inner + 0x14ec))->b02) {
        (*(void (*)(int))(*(int *)(*gGameUIInterface + 0x5c)))(*(s16 *)((char *)inner + 0x14e2));
    }
    fn_802B1BF8(obj, q, inner, timeDelta);
    fn_802B1B28(obj, timeDelta);
    (*(void (*)(int, int, f32))(*(int *)(*gPathControlInterface + 0x10)))(obj, inner + 0x4, timeDelta);
    (*(void (*)(int, int))(*(int *)(*gPathControlInterface + 0x14)))(obj, inner + 0x4);
    (*(void (*)(int, int, f32))(*(int *)(*gPathControlInterface + 0x18)))(obj, inner + 0x4, timeDelta);
    *(s16 *)((char *)obj + 0) = *(s16 *)((char *)q + 0x478);
}
#pragma peephole reset
#pragma scheduling reset

extern void fn_80137948(const char *fmt, ...);
extern char sOnCloudFormat[];
extern void buttonDisable(int a, int b);
extern void fn_8003B500(int obj, int q, f32 f);
extern int *gMapEventInterface;
extern f32 lbl_803E8418;
extern f32 lbl_803E841C;
extern f32 lbl_803E8420;

#pragma peephole off
void DR_CloudRunner_update(int obj)
{
    int inner;
    Obj_GetPlayerObject();
    inner = *(int *)((char *)obj + 0xb8);
    *(s16 *)((char *)inner + 0xbae) = 5;
    fn_80137948(sOnCloudFormat, GameBit_Get(0xed7));
    *(u8 *)((char *)obj + 0xaf) &= ~8;
    if (*(u8 *)((char *)inner + 0xbb2) == 2) {
        *(u8 *)((char *)obj + 0xaf) |= 8;
        fn_802C11BC(obj, -1, timeDelta);
        *(int *)((char *)*(int *)((char *)obj + 0x50) + 0x44) |= 0x200000;
    } else {
        *(u8 *)((char *)inner + 0x25f) = 0;
        fn_802C11BC(obj, -1, timeDelta);
        *(int *)((char *)*(int *)((char *)obj + 0x50) + 0x44) &= ~0x200000;
    }
    if (*(s8 *)((char *)inner + 0xbc3) != 0) {
        s8 v = *(s8 *)((char *)inner + 0xbc3) - framesThisStep;
        *(s8 *)((char *)inner + 0xbc3) = v;
        if (v < 0) {
            *(s8 *)((char *)inner + 0xbc3) = 0;
        }
    }
    if (*(u8 *)((char *)inner + 0xbb2) == 2) {
        ObjHits_MarkObjectPositionDirty(obj);
        *(u8 *)((char *)inner + 0xad5) |= 1;
    } else {
        *(u8 *)((char *)inner + 0xad5) &= ~1;
    }
    dll_2E_func03(obj, inner + 0x4c4);
    objAnimFn_80038f38(obj, inner + 0x494);
    fn_8003B500(obj, inner + 0x464, lbl_803E83A4);
    characterDoEyeAnims(obj, inner + 0x464);
    if (*(u8 *)((char *)obj + 0xaf) & 1) {
        if (*(u8 *)((char *)inner + 0xbb2) == 0) {
            if (((ByteFlags *)((char *)inner + 0xbc0))->b10) {
                f32 vec[3];
                buttonDisable(0, 0x100);
                if ((*(int (*)(void))(*(int *)(*gMapEventInterface + 0x30)))() == 0) {
                    vec[0] = lbl_803E8418;
                    vec[1] = lbl_803E841C;
                    vec[2] = lbl_803E8420;
                    (*(void (*)(f32 *, int, int, int))(*(int *)(*gMapEventInterface + 0x24)))(vec, 0, 0, 0);
                }
                (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(4, obj, -1);
                *(int *)((char *)inner + 0xb04) = 0;
                *(u8 *)((char *)inner + 0xbb6) |= 4;
                *(u8 *)((char *)inner + 0xad5) |= 1;
                (*(void (*)(int, int, int))(*(int *)(*gPlayerInterface + 0x14)))(obj, inner, 4);
            } else {
                buttonDisable(0, 0x100);
                {
                    s8 t = *(s8 *)((char *)inner + 0xbc4);
                    if (t != -1) {
                        (*(void (*)(int, int, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(t, obj, -1);
                    }
                }
            }
        }
    }
}
#pragma peephole reset

extern u8 Obj_IsLoadingLocked(int obj);
extern void Sfx_PlayFromObject(int obj, int id);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int s, int b, int c, int d, int e);
extern void mathFn_80021ac8(void *a, void *b);
extern void voxmaps_worldToGrid(void *src, void *grid);
extern int voxmaps_traceLine(void *a, void *b, void *c, int d, int e);
extern void voxmaps_gridToWorld(void *grid, void *out);
extern f32 sqrtf(f32 x);
extern int *gPartfxInterface;
extern f32 lbl_803E83AC;
extern f32 lbl_803E83B0;

void fn_802BF4D8(int obj)
{
    f32 tr[2];
    f32 gB[2];
    f32 gC[2];
    f32 pos[3];
    f32 diff[3];
    f32 dir[3];
    struct {
        s16 angles[4];
        f32 mat[4];
    } s1;
    int inner = *(int *)((char *)obj + 0xb8);
    void *newObj;
    int setup;
    f32 dist;
    if (Obj_IsLoadingLocked(obj) == 0) {
        return;
    }
    Sfx_PlayFromObject(obj, 0x11e);
    setup = Obj_AllocObjectSetup(0x24, 0x42a);
    *(u8 *)((char *)setup + 6) = 0xff;
    *(u8 *)((char *)setup + 7) = 0xff;
    *(u8 *)((char *)setup + 4) = 2;
    *(u8 *)((char *)setup + 5) = 1;
    *(f32 *)((char *)setup + 8) = *(f32 *)((char *)inner + 0xae8);
    *(f32 *)((char *)setup + 0xc) = *(f32 *)((char *)inner + 0xaec);
    *(f32 *)((char *)setup + 0x10) = *(f32 *)((char *)inner + 0xaf0);
    newObj = (void *)Obj_SetupObject(setup, 5, -1, -1, 0);
    if (newObj == NULL) {
        return;
    }
    s1.mat[1] = lbl_803E83A4;
    s1.mat[2] = lbl_803E83A4;
    s1.mat[3] = lbl_803E83A4;
    s1.mat[0] = lbl_803E83A8;
    s1.angles[0] = *(s16 *)((char *)obj + 0);
    s1.angles[1] = (s16)((*(s16 *)((char *)obj + 2) - 0x190) >> 1);
    s1.angles[2] = 0;
    dir[0] = lbl_803E83A4;
    dir[1] = lbl_803E83A4;
    dir[2] = lbl_803E83AC;
    mathFn_80021ac8(s1.angles, dir);
    *(f32 *)((char *)newObj + 0x24) = dir[0];
    *(f32 *)((char *)newObj + 0x28) = dir[1];
    *(f32 *)((char *)newObj + 0x2c) = dir[2];
    pos[0] = lbl_803E83B0 * *(f32 *)((char *)newObj + 0x24);
    pos[1] = lbl_803E83B0 * *(f32 *)((char *)newObj + 0x28);
    pos[2] = lbl_803E83B0 * *(f32 *)((char *)newObj + 0x2c);
    pos[0] = *(f32 *)((char *)newObj + 0xc) + pos[0];
    pos[1] = *(f32 *)((char *)newObj + 0x10) + pos[1];
    pos[2] = *(f32 *)((char *)newObj + 0x14) + pos[2];
    voxmaps_worldToGrid((void *)(obj + 0x18), gC);
    voxmaps_worldToGrid(pos, gB);
    if (voxmaps_traceLine(gC, gB, tr, 0, 0) == 0) {
        voxmaps_gridToWorld(pos, tr);
        diff[0] = pos[0] - *(f32 *)((char *)newObj + 0xc);
        diff[1] = pos[1] - *(f32 *)((char *)newObj + 0x10);
        diff[2] = pos[2] - *(f32 *)((char *)newObj + 0x14);
        dist = sqrtf(diff[2] * diff[2] + (diff[0] * diff[0] + diff[1] * diff[1]));
    } else {
        dist = lbl_803E83B4;
    }
    *(int *)((char *)newObj + 0xf4) = (int)dist;
    *(int *)((char *)newObj + 0xf8) = obj;
    *(s16 *)((char *)newObj + 0x4) = 0;
    *(s16 *)((char *)newObj + 0x2) = 0;
    *(s16 *)((char *)newObj + 0) = 0;
    (*(void (*)(int, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))((int)newObj, 0x66, 0, 2, -1, 0);
}

extern f32 lbl_803E82EC;
extern f32 GXInit_ClearColor;
extern f32 GXInit_BlackColor;
extern f32 GXInit_WhiteColor;
extern f32 lbl_803E82FC;
extern f32 lbl_803E8300;
extern f32 lbl_803E8308;
extern f32 lbl_803E830C;

int fn_802BC830(int obj, int p2, int p3)
{
    *(int *)((char *)p2 + 0x360) |= 0x1000000;
    *(f32 *)((char *)p3 + 0x2a0) = lbl_803E82EC;
    if (*(f32 *)((char *)obj + 0x98) > GXInit_ClearColor &&
        *(f32 *)((char *)obj + 0x98) < GXInit_BlackColor &&
        *(f32 *)((char *)p3 + 0x294) > *(f32 *)((char *)*(int *)((char *)p2 + 0x400) + 0x1c) - GXInit_WhiteColor &&
        *(f32 *)((char *)p3 + 0x298) > lbl_803E82FC &&
        *(int *)((char *)p2 + 0x488) >= 0x96) {
        ((ByteFlags *)((char *)p2 + 0x3f0))->b40 = 1;
        ((ByteFlags *)((char *)p2 + 0x3f0))->b80 = 0;
        *(u8 *)((char *)p2 + 0x8a6) = *(u8 *)((char *)p2 + 0x8a7);
        *(f32 *)((char *)p3 + 0x2a0) = lbl_803E8300;
        ObjAnim_SetCurrentMove(obj, *(s16 *)((char *)*(int *)((char *)p2 + 0x3f8) + 0x3a), lbl_803E8304, 0);
        ObjAnim_SetCurrentEventStepFrames((struct ObjAnimComponent *)obj, 0x10);
        *(int *)((char *)p2 + 0x858) = *(s16 *)((char *)p2 + 0x484);
        *(f32 *)((char *)p2 + 0x844) = (lbl_803E8308 + (*(f32 *)((char *)*(int *)((char *)p2 + 0x400) + 0x14) + *(f32 *)((char *)p3 + 0x294))) / lbl_803E830C;
        *(s16 *)((char *)p2 + 0x478) = *(s16 *)((char *)p2 + 0x484);
        *(s16 *)((char *)p2 + 0x484) += 0x8000;
        *(f32 *)((char *)p3 + 0x294) = -*(f32 *)((char *)p3 + 0x294);
        *(f32 *)((char *)p3 + 0x280) = -*(f32 *)((char *)p3 + 0x280);
    }
    if (((ByteFlags *)((char *)p2 + 0x3f0))->b80 != 0) {
        f32 lim = *(f32 *)((char *)*(int *)((char *)p2 + 0x400) + 0x10);
        if (*(f32 *)((char *)p3 + 0x294) <= lim && *(f32 *)((char *)p3 + 0x280) <= lim) {
            *(int *)((char *)p2 + 0x494) = *(s16 *)((char *)p2 + 0x484);
            ((ByteFlags *)((char *)p2 + 0x3f0))->b40 = 0;
            ((ByteFlags *)((char *)p2 + 0x3f0))->b80 = 0;
            return 1;
        }
        *(f32 *)((char *)p2 + 0x408) = lbl_803E8304;
        *(f32 *)((char *)p2 + 0x438) = *(f32 *)((char *)p2 + 0x830);
        *(u16 *)((char *)p2 + 0x8d8) |= 8;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
