#include "ghidra_import.h"
#include "main/dll/CAM/dll_59.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_80006a1c();
extern undefined4 FUN_80006a38();
extern int FUN_80017730();
extern undefined4 FUN_80017830();
extern undefined4 camcontrol_getTargetPosition();
extern undefined8 camcontrol_buildPathPoints();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();

extern undefined4* DAT_803dd6d0;
extern undefined4* gCamcontrolPathState;
extern f64 DOUBLE_803e23d0;
extern f32 lbl_803E23C0;
extern f32 lbl_803E23C4;
extern f32 lbl_803E23D8;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E8;
extern f32 lbl_803E23EC;
extern f32 lbl_803E23F0;
extern f32 lbl_803E23F4;
extern f32 lbl_803E23F8;

/*
 * --INFO--
 *
 * Function: FUN_8010747c
 * EN v1.0 Address: 0x8010747C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80107718
 * EN v1.1 Size: 1640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8010747c(undefined4 param_1,undefined4 param_2,short *param_3)
{
}


/* Trivial 4b 0-arg blr leaves. */
void fn_80107AE4(void) {}
void fn_80107AE8(void) {}

/* fn_X(lbl); lbl = 0; */
extern u32 lbl_803DD540;
extern void fn_80023800(u32);
#pragma scheduling off
void fn_80107B20(void) { fn_80023800(lbl_803DD540); lbl_803DD540 = 0; }
#pragma scheduling reset
