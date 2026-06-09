#include "main/dll/DF/DFcradle.h"
#include "main/game_object.h"
#include "main/dll/DF/DFwhirlpool.h"
#include "main/dll/DF/dfropenode.h"

typedef struct DFWhirlpoolRenderState {
  undefined4 objAndParam;
  u8 red;
  u8 green;
  u8 blue;
} DFWhirlpoolRenderState;

extern u32 GameBit_Get(int eventId);
extern void Sfx_PlayFromObject(int obj, int soundId);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int soundId);
extern void Camera_LoadModelViewMatrix(int param_1, int param_2, int obj, f32 scale, f32 unused,
                                       int param_6);
extern void textureSetupFn_800799c0(void);
extern void textRenderSetupFn_800795e8(void);
extern void textRenderSetupFn_80079804(void);
extern void getAmbientColor(int param_1, u8 *blue, u8 *green, u8 *red);
extern void gxBlendFn_80078b4c(void);
extern void fn_80078740(void);
extern void selectTexture(void *texture, int param_2);
extern void setTextColor(undefined4 *objAndParam, u8 blue, u8 green, u8 red, int alpha);
extern void drawFn_8005cf8c(void *matrix, void *displayList, int count);
extern int randomGetRange(int min, int max);

extern u8 framesThisStep;
extern void *lbl_803DBF48;
extern u8 lbl_80325E00[];
extern u8 lbl_80325E60[];
extern u8 lbl_802C2358[];
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
void dfropenode_render(int obj, int param_2, int param_3)
{
  ObjAnimComponent *objAnim;
  DFropenodeExtra *extra;
  int objDef;
  int eventId;
  int fadeAlpha;
  u32 oldAlpha;
  DFRopeNode *node;
  s16 segment;
  DFWhirlpoolRenderState renderState;
  s16 matrix[0x30];
  f32 originalScale;

  renderState.objAndParam = (undefined4)param_2;
  objAnim = &((GameObject *)obj)->anim;
  extra = ((GameObject *)obj)->extra;
  objDef = *(int *)&objAnim->placementData;
  eventId = *(s16 *)(objDef + 0x1c);
  if ((eventId != 0) && (GameBit_Get(eventId) != 0)) {
    oldAlpha = objAnim->alpha;
    if (oldAlpha == 0x46) {
      Sfx_PlayFromObject(obj, 0x476);
    }
    fadeAlpha = oldAlpha - framesThisStep;
    if (fadeAlpha <= 0) {
      objAnim->alpha = 0;
      return;
    }
    objAnim->alpha = (u8)fadeAlpha;
  } else {
    if (objAnim->alpha == 0) {
      Sfx_PlayFromObject(obj, 0x475);
    }
    if (objAnim->alpha < 0x46) {
      objAnim->alpha += framesThisStep;
    } else {
      objAnim->alpha = 0x46;
    }
  }

  if (((*(u8 *)(objDef + 0x18) & 1) != 0) && (*(void **)&extra->linkedObj != NULL) &&
      (extra->rope != NULL)) {
    originalScale = ((GameObject *)obj)->anim.rootMotionScale;
    ((GameObject *)obj)->anim.rootMotionScale = lbl_803E4DF8;
    Camera_LoadModelViewMatrix(0, param_3, obj, lbl_803E4E18, lbl_803E4DFC, 0);
    ((GameObject *)obj)->anim.rootMotionScale = originalScale;
    textureSetupFn_800799c0();
    textRenderSetupFn_800795e8();
    textRenderSetupFn_80079804();
    if (*(u8 *)(objDef + 0x1b) == 1) {
      renderState.red = 0xff;
      renderState.green = 0xff;
      renderState.blue = 0xff;
    } else {
      objAnim->alpha = 0xff;
      getAmbientColor(0, &renderState.blue, &renderState.green, &renderState.red);
      renderState.green = (u8)(renderState.green * 200 >> 8);
      renderState.red = (u8)(renderState.red * 0xaa >> 8);
    }
    {
      int alpha;

      if (objAnim->alpha > 0x46) {
        fn_80078740();
        alpha = 0xff;
      } else {
        gxBlendFn_80078b4c();
        alpha = (objAnim->alpha + objAnim->alpha) >> 1;
      }
      selectTexture((&lbl_803DBF48)[*(u8 *)(objDef + 0x1b)], 0);
      setTextColor(&renderState.objAndParam, renderState.blue, renderState.green, renderState.red,
                  (u8)alpha);
    }
    node = extra->rope->nodes;
    for (segment = 0; segment < (int)(extra->rope->count - 1); segment++) {
      node++;
      fn_801C0BF8(lbl_80325E00, extra->angle, (node - 1)->pos, node->pos, matrix);
      drawFn_8005cf8c(matrix, lbl_802C2358, 6);
    }
    if (*(u8 *)(objDef + 0x1b) == 1) {
      Sfx_KeepAliveLoopedObjectSound(obj, 0x480);
      gxBlendFn_80078b4c();
      {
        int alpha;

        alpha = (u8)(objAnim->alpha + randomGetRange(0, objAnim->alpha));
        setTextColor(&renderState.objAndParam, renderState.blue, renderState.green,
                    renderState.red, alpha);
      }
      node = extra->rope->nodes;
      for (segment = 0; segment < (int)(extra->rope->count - 1); segment++) {
        node++;
        fn_801C0BF8(lbl_80325E60, extra->angle, (node - 1)->pos, node->pos, matrix);
        drawFn_8005cf8c(matrix, lbl_802C2358, 6);
      }
    }
  }
}

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
