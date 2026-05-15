#include "ghidra_import.h"
#include "main/dll/DF/DFwhirlpool.h"

typedef struct DFropenodeExtra {
  int linkedObj;
  f32 minX;
  f32 maxX;
  f32 minZ;
  f32 maxZ;
  f32 minY;
  s16 angle;
  u8 pad1A[2];
  f32 planeNormalX;
  f32 planeNormalY;
  f32 planeNormalZ;
  f32 planeDistance;
  void *rope;
} DFropenodeExtra;

typedef struct DFRope {
  f32 *nodes;
  f32 *links;
  u8 count;
} DFRope;

extern int GameBit_Get(int eventId);
extern void Sfx_PlayFromObject(int obj, int soundId);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int soundId);
extern void Camera_LoadModelViewMatrix(f32 scale, f32 unused, int param_3, int obj, int param_5,
                                       int param_6);
extern void textureSetupFn_800799c0(void);
extern void textRenderSetupFn_800795e8(void);
extern void textRenderSetupFn_80079804(void);
extern void fn_800898C8(int param_1, u8 *blue, u8 *green, u8 *red);
extern void gxBlendFn_80078b4c(void);
extern void fn_80078740(void);
extern void selectTexture(void *texture, int param_2);
extern void fn_8005D118(undefined4 *objAndParam, u8 blue, u8 green, u8 red, int alpha);
extern void fn_801C0BF8(void *templateData, int angle, void *startNode, void *endNode, void *out);
extern void fn_8005CF8C(void *matrix, void *displayList, int count);
extern int randomGetRange(int min, int max);

extern u8 framesThisStep;
extern void *lbl_803DBF48;
extern undefined4 DAT_80325e00;
extern undefined4 DAT_80325e60;
extern undefined4 lbl_802C2358;
extern f32 lbl_803E4DF8;
extern f32 lbl_803E4DFC;
extern f32 lbl_803E4E18;

/*
 * --INFO--
 *
 * Function: dfropenode_render
 * EN v1.0 Address: 0x801C1F5C
 * EN v1.0 Size: 792b
 * EN v1.1 Address: 0x801C21A4
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void dfropenode_render(int obj, int param_2, int param_3)
{
  DFropenodeExtra *extra;
  DFRope *rope;
  int objDef;
  int alpha;
  int oldAlpha;
  int node;
  s16 segment;
  u8 red;
  u8 green;
  u8 blue;
  undefined4 objAndParam;
  u8 colorBytes[4];
  u8 matrix[0x88];
  f32 originalScale;

  objAndParam = (undefined4)param_2;
  extra = *(DFropenodeExtra **)(obj + 0xb8);
  objDef = *(int *)(obj + 0x4c);
  if ((*(s16 *)(objDef + 0x1c) == 0) || (GameBit_Get(*(s16 *)(objDef + 0x1c)) == 0)) {
    if (*(u8 *)(obj + 0x36) == 0) {
      Sfx_PlayFromObject(obj, 0x475);
    }
    if (*(u8 *)(obj + 0x36) < 0x46) {
      *(u8 *)(obj + 0x36) += framesThisStep;
    } else {
      *(u8 *)(obj + 0x36) = 0x46;
    }
  } else {
    oldAlpha = *(u8 *)(obj + 0x36);
    if (oldAlpha == 0x46) {
      Sfx_PlayFromObject(obj, 0x476);
    }
    alpha = oldAlpha - framesThisStep;
    if (alpha < 1) {
      *(u8 *)(obj + 0x36) = 0;
      return;
    }
    *(u8 *)(obj + 0x36) = (u8)alpha;
  }

  if (((*(u8 *)(objDef + 0x18) & 1) != 0) && (extra->linkedObj != 0) && (extra->rope != NULL)) {
    originalScale = *(f32 *)(obj + 8);
    *(f32 *)(obj + 8) = lbl_803E4DF8;
    Camera_LoadModelViewMatrix(lbl_803E4E18, lbl_803E4DFC, 0, obj, param_3, 0);
    *(f32 *)(obj + 8) = originalScale;
    textureSetupFn_800799c0();
    textRenderSetupFn_800795e8();
    textRenderSetupFn_80079804();
    if (*(u8 *)(objDef + 0x1b) == 1) {
      red = 0xff;
      green = 0xff;
      blue = 0xff;
    } else {
      *(u8 *)(obj + 0x36) = 0xff;
      fn_800898C8(0, &blue, &green, &red);
      green = (u8)((u32)green * 200 >> 8);
      red = (u8)((u32)red * 0xaa >> 8);
    }
    if (*(u8 *)(obj + 0x36) < 0x47) {
      gxBlendFn_80078b4c();
      alpha = ((u32)*(u8 *)(obj + 0x36) * 2) >> 1;
    } else {
      fn_80078740();
      alpha = 0xff;
    }
    selectTexture((&lbl_803DBF48)[*(u8 *)(objDef + 0x1b)], 0);
    fn_8005D118(&objAndParam, blue, green, red, alpha);
    rope = (DFRope *)extra->rope;
    node = (int)rope->nodes;
    for (segment = 0; segment < (int)(rope->count - 1); segment++) {
      fn_801C0BF8(&DAT_80325e00, extra->angle, (void *)node, (void *)(node + 0x34), matrix);
      fn_8005CF8C(matrix, &lbl_802C2358, 6);
      node += 0x34;
    }
    if (*(u8 *)(objDef + 0x1b) == 1) {
      Sfx_KeepAliveLoopedObjectSound(obj, 0x480);
      gxBlendFn_80078b4c();
      alpha = *(u8 *)(obj + 0x36) + (s8)randomGetRange(0, *(u8 *)(obj + 0x36));
      fn_8005D118(&objAndParam, blue, green, red, alpha);
      node = (int)rope->nodes;
      for (segment = 0; segment < (int)(rope->count - 1); segment++) {
        fn_801C0BF8(&DAT_80325e60, extra->angle, (void *)node, (void *)(node + 0x34), matrix);
        fn_8005CF8C(matrix, &lbl_802C2358, 6);
        node += 0x34;
      }
    }
  }
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dfropenode_hitDetect
 * EN v1.0 Address: 0x801C2274
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C245C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfropenode_hitDetect(void)
{
}
