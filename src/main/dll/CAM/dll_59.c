#include "ghidra_import.h"
#include "main/dll/CAM/dll_59.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006824();
extern undefined4 Obj_TransformWorldPointToLocal();
extern undefined4 FUN_80006a1c();
extern undefined4 FUN_80006a38();
extern int getAngle();
extern undefined4 FUN_80017830();
extern undefined4 camcontrol_getTargetPosition();
extern undefined8 camcontrol_buildPathPoints();
extern int Camera_GetCurrentViewSlot();
extern undefined4 FUN_8028688c();
extern double sqrtf();
extern undefined4 fn_80293E80();
extern undefined4 sin();

extern undefined4* lbl_803DCA50;
extern undefined4* lbl_803DD538;
extern f32* lbl_803DD540;
extern f64 lbl_803E1750;
extern f32 lbl_803E1740;
extern f32 lbl_803E1744;
extern f32 lbl_803E1758;
extern f32 lbl_803E175C;
extern f32 lbl_803E1768;
extern f32 lbl_803E176C;
extern f32 lbl_803E1770;
extern f32 lbl_803E1774;
extern f32 lbl_803E1778;

/*
 * --INFO--
 *
 * Function: CameraModeStaffAnim_init
 * EN v1.0 Address: 0x8010747C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80107718
 * EN v1.1 Size: 1640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void CameraModeStaffAnim_init(undefined4 param_1,undefined4 param_2,short *param_3)
{
}

void CameraModeBike_func06(f32 *param_1)
{
  lbl_803DD540[7] = param_1[0];
  lbl_803DD540[9] = param_1[1];
  lbl_803DD540[0xb] = param_1[2];
  lbl_803DD540[0xc] = param_1[3];
}


/* Trivial 4b 0-arg blr leaves. */
void CameraModeStaffAnim_release(void) {}
void CameraModeStaffAnim_initialise(void) {}

/* fn_X(lbl); lbl = 0; */
extern void mm_free(void *);
#pragma scheduling off
#pragma peephole off
void CameraModeBike_free(void) { mm_free(lbl_803DD540); lbl_803DD540 = 0; }
#pragma peephole reset
#pragma scheduling reset
