#include "ghidra_import.h"
#include "main/dll/dll_B4.h"

extern u8 *Obj_AllocObjectSetup(int size, int type);
extern u8 *Obj_SetupObject(u8 *obj, int a, int b, int c, int d);
extern u8 *Obj_GetActiveModel(u8 *obj);
extern void ObjModel_SetRenderCallback(u8 *model, void *cb);
extern void lockIconTexCb(void);
extern void aButtonIconTexCb(void);
extern void colorFn_8001efe0(int a, int b, int c, int d);
extern u8 *objCreateLight(int a, int b);
extern void modelLightStruct_setField50(u8 *p, int a);
extern void modelFn_8001db3c(u8 *p, int a);
extern void objSetEventName(u8 *p, int a);
extern void modelStruct2_setVectors(u8 *p, f32 a, f32 b, f32 c);
extern void modelLightStruct_setColorsA8AC(u8 *p, int a, int b, int c, int d);

extern u8 *lbl_803DD4BC;
extern u8 *lbl_803DD4C4;
extern f32 lbl_803E162C;
extern f32 lbl_803E1630;
extern f32 lbl_803E1640;

#pragma scheduling off

/*
 * --INFO--
 *
 * Function: lockIconInit
 * EN v1.0 Address: 0x80100FA0
 * EN v1.0 Size: 276b
 */
void lockIconInit(void)
{
  if (lbl_803DD4BC == NULL) {
    lbl_803DD4BC = Obj_SetupObject(Obj_AllocObjectSetup(0x18, 0x1FE), 4, -1, -1, 0);
    ObjModel_SetRenderCallback(Obj_GetActiveModel(lbl_803DD4BC), lockIconTexCb);
    lbl_803DD4BC[0xAD] = 1;
    ObjModel_SetRenderCallback(Obj_GetActiveModel(lbl_803DD4BC), aButtonIconTexCb);
    lbl_803DD4BC[0xAD] = 2;
    ObjModel_SetRenderCallback(Obj_GetActiveModel(lbl_803DD4BC), aButtonIconTexCb);
    colorFn_8001efe0(1, 0x32, 0x3C, 0x28);
    lbl_803DD4C4 = objCreateLight(0, 1);
    if (lbl_803DD4C4 != NULL) {
      modelLightStruct_setField50(lbl_803DD4C4, 4);
      modelFn_8001db3c(lbl_803DD4C4, 1);
      objSetEventName(lbl_803DD4C4, 1);
      modelStruct2_setVectors(lbl_803DD4C4, lbl_803E162C, lbl_803E1630, lbl_803E1640);
      modelLightStruct_setColorsA8AC(lbl_803DD4C4, 0xB4, 0xC8, 0xFF, 0xFF);
    }
  }
}
