#include "ghidra_import.h"
#include "main/objanim.h"
#include "main/unknown/autos/placeholder_802BBC10.h"

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
extern uint FUN_80017760();
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
extern undefined4 FUN_800339b4();
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
extern undefined4 FUN_80038730();
extern undefined4 FUN_800387ac();
extern undefined4 FUN_8003882c();
extern undefined4 FUN_800388b4();
extern undefined4 FUN_80038f38();
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
extern undefined4 FUN_80115094();
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
 * Function: FUN_802bb720
 * EN v1.0 Address: 0x802BB720
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802BBC14
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802bb720(undefined4 param_1,undefined4 param_2,int param_3)
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
