#include "ghidra_import.h"
#include "main/dll/baddie/wispBaddie.h"

extern undefined4 FUN_80006954();
extern undefined4 FUN_80006984();
extern undefined4 FUN_80006988();
extern undefined4 FUN_800069d4();
extern undefined4 FUN_80006a00();
extern undefined8 FUN_80006c64();
extern undefined8 FUN_80006c74();
extern undefined8 FUN_80006c78();
extern undefined8 FUN_80006c84();
extern void* FUN_80006c9c();
extern undefined8 FUN_80017484();
extern undefined8 FUN_80017488();
extern int FUN_800174a0();
extern double FUN_800174a8();
extern undefined4 FUN_800174d4();
extern uint FUN_80017690();
extern uint FUN_80017760();
extern int FUN_80017a54();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_8003b878();
extern undefined4 FUN_8005398c();
extern undefined4 FUN_800709dc();
extern double FUN_800e9e74();
extern uint FUN_800ea9ac();
extern undefined4 FUN_8011e454();
extern undefined4 FUN_8011e458();
extern undefined8 FUN_8011e45c();
extern undefined4 FUN_8011e460();
extern undefined4 FUN_8011e464();
extern undefined8 FUN_80121c4c();
extern undefined8 FUN_80128260();
extern undefined4 FUN_8012845c();
extern undefined4 FUN_801287ac();
extern undefined4 FUN_80129a98();
extern undefined4 FUN_80129d10();
extern undefined4 FUN_8025da88();
extern undefined4 FUN_80286834();
extern undefined4 FUN_8028683c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286888();
extern undefined8 FUN_8028fde8();
extern undefined4 FUN_80294964();
extern undefined4 FUN_802949e8();
extern undefined4 SUB84();

extern undefined4 DAT_802c7b54;
extern undefined4 DAT_802c8e0a;
extern undefined4 DAT_8031bc84;
extern undefined4 DAT_8031bc86;
extern undefined4 DAT_8031c468;
extern undefined4 DAT_8031c640;
extern undefined DAT_8031c7e0;
extern undefined4 DAT_8031c940;
extern undefined4 DAT_8031c980;
extern undefined4 DAT_8031c9e0;
extern undefined4 DAT_803a9610;
extern undefined4 DAT_803a966c;
extern undefined4 DAT_803a96c8;
extern undefined4 DAT_803a96cc;
extern undefined4 DAT_803a96d0;
extern undefined4 DAT_803a9744;
extern undefined4 DAT_803a9760;
extern undefined4 DAT_803a9780;
extern undefined4 DAT_803a9fc4;
extern undefined4 DAT_803a9fd0;
extern undefined4 DAT_803a9fe0;
extern undefined4 DAT_803dc6f2;
extern undefined4 DAT_803dc738;
extern undefined4 DAT_803dc73c;
extern undefined4 DAT_803dc7c0;
extern undefined4 DAT_803dc7d0;
extern undefined4 DAT_803dc7d8;
extern undefined4 DAT_803dc7e0;
extern undefined4 DAT_803dc7e8;
extern undefined4 DAT_803dc7f0;
extern undefined4 DAT_803dc7f8;
extern undefined4 DAT_803dc800;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de3b4;
extern undefined4 DAT_803de3d0;
extern undefined4 DAT_803de3d2;
extern undefined4 DAT_803de3d4;
extern undefined4 DAT_803de3d6;
extern undefined4 DAT_803de3d8;
extern undefined4 DAT_803de3dc;
extern undefined4 DAT_803de400;
extern undefined4 DAT_803de424;
extern undefined4 DAT_803de444;
extern undefined4 DAT_803de448;
extern undefined4 DAT_803de456;
extern undefined4 DAT_803de458;
extern undefined4* DAT_803de4a4;
extern undefined4 DAT_803de4e0;
extern undefined4 DAT_803de560;
extern undefined4 DAT_803e2a84;
extern f64 DOUBLE_803e2af8;
extern f64 DOUBLE_803e2b08;
extern f64 DOUBLE_803e2be0;
extern f64 DOUBLE_803e2cf0;
extern f64 DOUBLE_803e2cf8;
extern f64 DOUBLE_803e2d00;
extern f64 DOUBLE_803e2d08;
extern f64 DOUBLE_803e2d28;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc69c;
extern f32 FLOAT_803dc6a0;
extern f32 FLOAT_803dc6a4;
extern f32 FLOAT_803dc6b4;
extern f32 FLOAT_803dc6b8;
extern f32 FLOAT_803dc6bc;
extern f32 FLOAT_803dc6f4;
extern f32 FLOAT_803de3c8;
extern f32 FLOAT_803de3cc;
extern f32 FLOAT_803de3e0;
extern f32 FLOAT_803de43c;
extern f32 FLOAT_803de47c;
extern f32 FLOAT_803de4d0;
extern f32 FLOAT_803e2abc;
extern f32 FLOAT_803e2ae4;
extern f32 FLOAT_803e2ae8;
extern f32 FLOAT_803e2b00;
extern f32 FLOAT_803e2b40;
extern f32 FLOAT_803e2b4c;
extern f32 FLOAT_803e2bb0;
extern f32 FLOAT_803e2bb4;
extern f32 FLOAT_803e2c2c;
extern f32 FLOAT_803e2c98;
extern f32 FLOAT_803e2ca0;
extern f32 FLOAT_803e2d10;
extern f32 FLOAT_803e2d14;
extern f32 FLOAT_803e2d18;
extern f32 FLOAT_803e2d1c;
extern f32 FLOAT_803e2d20;
extern f32 FLOAT_803e2d30;
extern f32 FLOAT_803e2d34;
extern f32 FLOAT_803e2d38;
extern f32 FLOAT_803e2d3c;
extern f32 FLOAT_803e2d40;
extern f32 FLOAT_803e2d44;
extern int iRam803de4e4;

/*
 * --INFO--
 *
 * Function: FUN_801262cc
 * EN v1.0 Address: 0x801262CC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801265B0
 * EN v1.1 Size: 4652b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801262cc(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801262d0
 * EN v1.0 Address: 0x801262D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801277DC
 * EN v1.1 Size: 2692b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801262d0(void)
{
}
