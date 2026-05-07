#include "ghidra_import.h"
#include "main/dll/dll_B4.h"

extern u8 *Obj_AllocObjectSetup(int size, int type);
extern u8 *Obj_SetupObject(u8 *obj, int a, int b, int c, int d);
extern u8 *Obj_GetActiveModel(u8 *obj);
extern void ObjModel_SetRenderCallback(u8 *model, void *cb);
extern void fn_80100DCC(void);
extern void fn_80100C90(void);
extern void fn_8001EFE0(int a, int b, int c, int d);
extern u8 *fn_8001F4C8(int a, int b);
extern void fn_8001DB2C(u8 *p, int a);
extern void fn_8001DB3C(u8 *p, int a);
extern void fn_8001DB34(u8 *p, int a);
extern void fn_8001DC90(u8 *p, f32 a, f32 b, f32 c);
extern void fn_8001DAF0(u8 *p, int a, int b, int c, int d);

extern u8 *lbl_803DD4BC;
extern u8 *lbl_803DD4C4;
extern f32 lbl_803E162C;
extern f32 lbl_803E1630;
extern f32 lbl_803E1640;

#pragma scheduling off

/*
 * --INFO--
 *
 * Function: fn_80100FA0
 * EN v1.0 Address: 0x80100FA0
 * EN v1.0 Size: 276b
 */
void fn_80100FA0(void)
{
  if (lbl_803DD4BC == NULL) {
    lbl_803DD4BC = Obj_SetupObject(Obj_AllocObjectSetup(0x18, 0x1FE), 4, -1, -1, 0);
    ObjModel_SetRenderCallback(Obj_GetActiveModel(lbl_803DD4BC), fn_80100DCC);
    lbl_803DD4BC[0xAD] = 1;
    ObjModel_SetRenderCallback(Obj_GetActiveModel(lbl_803DD4BC), fn_80100C90);
    lbl_803DD4BC[0xAD] = 2;
    ObjModel_SetRenderCallback(Obj_GetActiveModel(lbl_803DD4BC), fn_80100C90);
    fn_8001EFE0(1, 0x32, 0x3C, 0x28);
    lbl_803DD4C4 = fn_8001F4C8(0, 1);
    if (lbl_803DD4C4 != NULL) {
      fn_8001DB2C(lbl_803DD4C4, 4);
      fn_8001DB3C(lbl_803DD4C4, 1);
      fn_8001DB34(lbl_803DD4C4, 1);
      fn_8001DC90(lbl_803DD4C4, lbl_803E162C, lbl_803E1630, lbl_803E1640);
      fn_8001DAF0(lbl_803DD4C4, 0xB4, 0xC8, 0xFF, 0xFF);
    }
  }
}
