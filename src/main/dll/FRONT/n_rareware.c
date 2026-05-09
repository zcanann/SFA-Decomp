#include "ghidra_import.h"
#include "main/dll/FRONT/n_rareware.h"

extern void *OSGetArenaHi(void);
extern void GXInitTexObj(void *obj, void *image, u16 width, u16 height, u8 format, u8 wrapS,
                         u8 wrapT, u8 mipmap);
extern void GXInitTexObjLOD(void *obj, u8 minFilt, u8 magFilt, f32 minLod, f32 maxLod,
                            f32 lodBias, u8 biasClamp, u8 doEdgeLOD, u8 maxAniso);
extern void GXInitTexObjUserData(void *obj, void *userData);
extern uint GXGetTexObjFmt(void *obj);
extern uint GXGetTexObjWidth(void *obj);
extern uint GXGetTexObjHeight(void *obj);
extern uint GXGetTexBufferSize(uint width, uint height, uint format, u8 mipmap, u8 maxLod);

extern void hudDrawColored(int texture, int x, int y, uint *color, uint scale, int flags);
extern void drawTexture(double x, double y, int texture, uint alpha, uint flags);
extern void gameTextSetColor(u8 red, u8 green, u8 blue, u8 alpha);
extern undefined4 gameTextGetStr(int id);
extern void gameTextShowStr(undefined4 text, int font, int x, int y);
extern void mapUnload(int mapId, int flags);
extern void fn_80041E30(void);
extern void loadMapAndParent(int param_1);
extern void fn_80041E24(void);
extern void fn_80088C0C(void);
extern void fn_8011D9B0(void);
extern void lockIconInit(void);
extern void warpToMap(int mapId, int param_2);
extern void loadUiDll(int dllNo);

extern int lbl_803A4438[];
extern u8 lbl_803DC950;
extern u8 lbl_803DC968;
extern u8 lbl_803DD5E8;
extern uint lbl_803DD5EC;
extern s8 lbl_803DD5F0;
extern f32 lbl_803DD5F4;
extern int lbl_803DD5F8;
extern u8 lbl_803DD5FC;
extern f32 lbl_803DD600;
extern f32 lbl_803DD604;
extern u8 lbl_803DD608;
extern u8 lbl_803DD609;
extern f64 lbl_803E1CE8;
extern f32 lbl_803E1CF0;
extern f32 lbl_803E1CF4;
extern f32 lbl_803E1CF8;
extern f32 lbl_803E1D00;
extern f32 lbl_803E1D08;
extern f32 lbl_803E1D0C;

/*
 * --INFO--
 *
 * Function: runLoadingScreens
 * EN v1.0 Address: 0x801159E4
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x80115C80
 * EN v1.1 Size: 880b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void runLoadingScreens(void)
{
  int alpha;
  int textureSlot;
  uint color;
  union { u32 word; u8 bytes[4]; } colorBuf;

  if (lbl_803DD5EC < 0xf0) {
    if (lbl_803DD5EC < 0x1e) {
      alpha = (int)((lbl_803E1CF4 * (f32)lbl_803DD5EC) / lbl_803E1CF8);
    } else if (lbl_803DD5EC < 0xd2) {
      alpha = 0xff;
    } else {
      alpha = (int)((lbl_803E1CF4 * (f32)(0xf0 - lbl_803DD5EC)) / lbl_803E1CF8);
    }

    textureSlot = lbl_803A4438[0];
    if (lbl_803DC968 != 0) {
      colorBuf.bytes[0] = 0;
      colorBuf.bytes[1] = 0x46;
      colorBuf.bytes[2] = 0xff;
    } else {
      colorBuf.bytes[0] = 0xdc;
      colorBuf.bytes[1] = 0;
      colorBuf.bytes[2] = 0;
    }
    colorBuf.bytes[3] = alpha;
    color = colorBuf.word;
    hudDrawColored(textureSlot,0x85,0xaa,&color,0x100,0);
  } else if (lbl_803DD5EC < 0x1e0) {
    if (lbl_803DD5EC < 0x10e) {
      alpha = (int)((lbl_803E1CF4 * (f32)(lbl_803DD5EC - 0xf0)) / lbl_803E1CF8);
    } else if (lbl_803DD5EC < 0x1c2) {
      alpha = 0xff;
    } else {
      alpha = (int)((lbl_803E1CF4 * (f32)(0x1e0 - lbl_803DD5EC)) / lbl_803E1CF8);
    }
    drawTexture((double)(f32)(uint)((int)(0x280 - (uint)*(u16 *)(lbl_803A4438[1] + 0xa)) >> 1),
                (double)(f32)(uint)((int)(0x1e0 - (uint)*(u16 *)(lbl_803A4438[1] + 0xc)) >> 1),
                lbl_803A4438[1],alpha,0x119);
  } else if (lbl_803DD5EC < 600) {
    if (lbl_803DD5EC < 0x1fe) {
      alpha = (int)((lbl_803E1CF4 * (f32)(lbl_803DD5EC - 0x1e0)) / lbl_803E1CF8);
    } else if (lbl_803DD5EC < 0x23a) {
      alpha = 0xff;
    } else {
      alpha = (int)((lbl_803E1CF4 * (f32)(600 - lbl_803DD5EC)) / lbl_803E1CF8);
    }
    drawTexture((double)(f32)(uint)((int)(0x280 - (uint)*(u16 *)(lbl_803A4438[2] + 0xa)) >> 1),
                (double)(f32)(uint)((int)(0x1e0 - (uint)*(u16 *)(lbl_803A4438[2] + 0xc)) >> 1),
                lbl_803A4438[2],alpha,0x119);
  }

  if (lbl_803DC950 == 0) {
    lbl_803DD5EC++;
  } else {
    lbl_803DD5E8 = 1;
  }

  if ((lbl_803DD5E8 != 0) && (lbl_803DD5EC > 600) && (lbl_803DC950 == 0)) {
    gameTextSetColor(0xff,0xff,0xff,0xff);
    gameTextShowStr(gameTextGetStr(0x565),0,0x118,300);
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: initLoadingScreenTextures
 * EN v1.0 Address: 0x80115D54
 * EN v1.0 Size: 280b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void initLoadingScreenTextures(void)
{
  int *textureSlot;
  int textureHeader;
  void *texObj;
  int arenaHi;
  int i;

  arenaHi = (int)OSGetArenaHi() - 0x40000;
  textureSlot = lbl_803A4438;
  for (i = 0; i < 3; i++) {
    *textureSlot = arenaHi;
    textureHeader = *textureSlot;
    *(int *)(textureHeader + 0x40) = 0;
    *(u8 *)(textureHeader + 0x48) = 0;
    texObj = (void *)(textureHeader + 0x20);
    GXInitTexObj(texObj,(void *)(textureHeader + 0x60),*(u16 *)(textureHeader + 0xa),
                 *(u16 *)(textureHeader + 0xc),*(u8 *)(textureHeader + 0x16),
                 *(u8 *)(textureHeader + 0x17),*(u8 *)(textureHeader + 0x18),0);
    GXInitTexObjLOD(texObj,*(u8 *)(textureHeader + 0x19),*(u8 *)(textureHeader + 0x1a),
                    lbl_803E1CF0,lbl_803E1CF0,lbl_803E1CF0,0,0,0);
    GXInitTexObjUserData(texObj,(void *)textureHeader);
    *(uint *)(textureHeader + 0x44) =
        GXGetTexBufferSize(GXGetTexObjWidth(texObj),GXGetTexObjHeight(texObj),
                           GXGetTexObjFmt(texObj),0,0);
    arenaHi += *(int *)(*textureSlot + 0x44) + 0x60;
    textureSlot++;
  }
  lbl_803DD5EC = 0;
  lbl_803DD5E8 = 0;
}
#pragma peephole reset
#pragma scheduling reset

/* Trivial 4b 0-arg blr leaves. */
void TitleScreenInit_render(void) {}
void TitleScreenInit_frameEnd(void) {}

/*
 * --INFO--
 *
 * Function: TitleScreenInit_frameStart
 * EN v1.0 Address: 0x80115E74
 * EN v1.0 Size: 72b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int TitleScreenInit_frameStart(void)
{
  if (lbl_803DD5F0 != 0) {
    lbl_803DD5F0 = 0;
    lbl_803DD5F4 = lbl_803E1D00;
    loadUiDll(4);
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

void TitleScreenInit_release(void) {}

/*
 * --INFO--
 *
 * Function: TitleScreenInit_initialise
 * EN v1.0 Address: 0x80115EC0
 * EN v1.0 Size: 96b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void TitleScreenInit_initialise(void)
{
  lbl_803DD5F0 = 1;
  lbl_803DD5F4 = lbl_803E1D00;
  mapUnload(0x3d,0x10000000);
  fn_80041E30();
  loadMapAndParent(0x3f);
  fn_80041E24();
  fn_80088C0C();
  fn_8011D9B0();
  lockIconInit();
  warpToMap(0x12,0);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: n_rareware_render
 * EN v1.0 Address: 0x80115F20
 * EN v1.0 Size: 152b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void n_rareware_render(void)
{
  int frame;

  if (((s8)lbl_803DD608 != 0) && ((s8)lbl_803DD609 <= 10)) {
    return;
  }

  frame = lbl_803DD5F8;
  if ((frame > 40) && ((s8)lbl_803DD5FC == 0)) {
    lbl_803DD5FC = 1;
    lbl_803DD604 = lbl_803E1D08;
  }
  if ((frame > 50) && ((s8)lbl_803DD5FC == 1)) {
    lbl_803DD5FC = 2;
  }
  if ((frame > 285) && ((s8)lbl_803DD5FC == 2)) {
    lbl_803DD5FC = 3;
    lbl_803DD600 = lbl_803E1D0C;
  }
}
#pragma peephole reset
#pragma scheduling reset

void n_rareware_frameEnd(void) {}
