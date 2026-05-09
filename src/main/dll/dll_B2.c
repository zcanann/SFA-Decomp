#include "ghidra_import.h"
#include "main/dll/dll_B2.h"

extern u8 *pCamera;

extern void* ObjModel_GetRenderOp(void *model, undefined4 idx);
extern void* textureIdxToPtr(int idx);
extern void fn_800528F0(void);
extern void fn_800528BC(void);
extern void fn_80051D5C(void *tex, undefined4 a, undefined4 b, u8 *color);
extern void GXSetBlendMode(int type, int src, int dst, int op);
extern void gxSetZMode_(u32 a, int b, u32 c);
extern void gxSetPeControl_ZCompLoc_(u32 a);
extern void GXSetAlphaCompare(int comp0, u8 ref0, int op, int comp1, u8 ref1);
extern void GXSetCullMode(int mode);

/*
 * --INFO--
 *
 * Function: aButtonIconTexCb
 * EN v1.0 Address: 0x80100C90
 * EN v1.0 Size: 316b
 */
#pragma peephole off
#pragma scheduling off

int aButtonIconTexCb(u8 *this_, void **objPtr, undefined4 arg3)
{
  u8 *renderOp;
  u8 color[4];

  renderOp = (u8 *)ObjModel_GetRenderOp(*objPtr, arg3);
  fn_800528F0();
  if (renderOp[0x29] == 1) {
    if ((pCamera[0x141] & 0x20) == 0) {
      color[3] = 0;
    } else {
      color[3] = this_[0x36];
    }
  } else {
    color[3] = this_[0x36];
  }
  if (pCamera[0x138] == 8) {
    color[3] = 0;
  }
  fn_80051D5C(textureIdxToPtr(*(int *)(renderOp + 0x24)), 0, 0, color);
  fn_800528BC();
  if (color[3] < 0xff) {
    GXSetBlendMode(1, 4, 5, 5);
    gxSetZMode_(1, 3, 0);
  } else {
    GXSetBlendMode(0, 1, 0, 5);
    gxSetZMode_(1, 3, 1);
  }
  gxSetPeControl_ZCompLoc_(1);
  GXSetAlphaCompare(7, 0, 0, 7, 0);
  GXSetCullMode(2);
  return 1;
}
