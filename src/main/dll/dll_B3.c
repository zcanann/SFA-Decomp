#include "ghidra_import.h"
#include "main/dll/dll_B3.h"

extern u8 *ObjModel_GetRenderOp(int model, int idx);
extern void fn_800528F0(void);
extern void fn_800528BC(void);
extern void *textureIdxToPtr(int idx);
extern void fn_80051D5C(void *tex, void *arg2, int arg3, void *color);
extern void GXSetBlendMode(int mode, int srcFactor, int dstFactor, int op);
extern void gxSetZMode_(u32 enable, int func, u32 update);
extern void gxSetPeControl_ZCompLoc_(u32 ctrl);
extern void GXSetAlphaCompare(int compA, int refA, int op, int compB, int refB);
extern void GXSetCullMode(int mode);

extern u8 *pCamera;
extern f32 lbl_803E1630;
extern f32 lbl_803E1634;
extern f32 lbl_803E1638;
extern f32 lbl_803E163C;

/*
 * --INFO--
 *
 * Function: fn_80100DCC
 * EN v1.0 Address: 0x80100DCC
 * EN v1.0 Size: 468b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int fn_80100DCC(u8 *param_1, int *param_2, int param_3)
{
  u8 *renderOp;
  u8 tier;
  u8 colorBuf[4];
  f32 dist;
  int alphaVal;

  renderOp = ObjModel_GetRenderOp(*param_2, param_3);
  dist = *(f32 *)(pCamera + 0x134);
  if (dist <= lbl_803E1630) {
    tier = 4;
  } else if (dist <= lbl_803E1634) {
    tier = 3;
  } else if (dist <= lbl_803E1638) {
    tier = 2;
  } else if (dist <= lbl_803E163C) {
    tier = 1;
  } else {
    tier = 0;
  }
  fn_800528F0();
  if (renderOp[0x29] <= tier) {
    colorBuf[0] = 0;
    colorBuf[1] = 0;
    colorBuf[2] = 0;
    alphaVal = ((param_1[0x36] + 1) * 0x60) >> 8;
    colorBuf[3] = alphaVal;
    fn_80051D5C(textureIdxToPtr(*(int *)(renderOp + 0x24)), 0, 0, colorBuf);
  } else {
    colorBuf[0] = 0xff;
    colorBuf[1] = 0xff;
    colorBuf[2] = 0xff;
    colorBuf[3] = param_1[0x36];
    fn_80051D5C(textureIdxToPtr(*(int *)(renderOp + 0x24)), 0, 0, colorBuf);
  }
  fn_800528BC();
  if (param_1[0x36] < 0xff || renderOp[0x29] <= tier) {
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
#pragma peephole reset
#pragma scheduling reset
