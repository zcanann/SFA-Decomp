#include "ghidra_import.h"
#include "main/dll/dll_36.h"

extern f32 timeDelta;

extern void gameTextSetDrawFunc(void *callback);
extern void titleScreenPositionElements(f32 x, f32 y);
extern void fn_80135814(int p1, int p2);
extern void gameTextBoxFn_80134d40(int p1, int p2, int p3);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern void gameTextShowStr(void *str, int id, int x, int y);
extern void *gameTextGetStr(int id);
extern f32 fn_80293E80(f32 x);
extern void nameEntryTextDrawFunc(void);
extern void titleScreenTextDrawFunc(void);
extern void titleScreenShowCopyright(u8 arg);

extern u16 lbl_803DD6D8;
extern u32 lbl_803DD6DC;
extern f32 lbl_803DD6E0;
extern int lbl_803DD6E4;
extern u8 lbl_803DD6F0;
extern u8 lbl_803DD6F4;
extern u16 lbl_8031A880[];
extern int lbl_803A8690[];

extern f32 lbl_803E1D80;
extern f32 lbl_803E1D84;
extern f32 lbl_803E1D88;
extern f32 lbl_803E1D8C;
extern f32 lbl_803E1D90;
extern f32 lbl_803E1D94;
extern f32 lbl_803E1D98;
extern f32 lbl_803E1D9C;

/*
 * --INFO--
 *
 * Function: EnterSaveNameScreen_render
 * EN v1.0 Address: 0x8011B5D4
 * EN v1.0 Size: 656b
 * EN v1.1 Address: 0x8011B698
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void EnterSaveNameScreen_render(void)
{
  u8 buf[2];
  int i;

  buf[1] = 0;
  gameTextSetDrawFunc(nameEntryTextDrawFunc);
  titleScreenPositionElements(lbl_803E1D80, lbl_803E1D84);
  fn_80135814((int)(lbl_803DD6E0 + (f32)lbl_803DD6DC - lbl_803E1D88), 0);
  gameTextBoxFn_80134d40(0xff, 1, 1);
  gameTextSetColor(0xc0, 0xc0, 0xc0, 0xff);
  gameTextShow(0x3ae);
  gameTextSetColor(0xff, 0xff, 0xff, 0xff);
  gameTextSetDrawFunc(titleScreenTextDrawFunc);
  gameTextShow(0xed);

  for (i = 0; i < lbl_803DD6F4; i++) {
    buf[0] = (&lbl_803DD6F0)[i];
    gameTextShowStr(buf, i + 0x2a, 0, 0);
  }

  lbl_803DD6D8 = (int)((f32)lbl_803DD6D8 + timeDelta);

  gameTextSetColor(
      (int)(fn_80293E80(lbl_803E1D94 * (f32)lbl_803DD6D8) * lbl_803E1D90 + lbl_803E1D8C),
      (int)(fn_80293E80(lbl_803E1D98 * (f32)lbl_803DD6D8) * lbl_803E1D90 + lbl_803E1D8C),
      (int)(fn_80293E80(lbl_803E1D9C * (f32)lbl_803DD6D8) * lbl_803E1D90 + lbl_803E1D8C),
      0xff);

  i = lbl_803DD6E4;
  gameTextShowStr(gameTextGetStr(lbl_8031A880[i]), 0x56,
                  (int)((f32)(lbl_803A8690[i] + 0x8a) - lbl_803DD6E0), 0);

  gameTextSetDrawFunc(NULL);
  titleScreenShowCopyright(0);
}
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void EnterSaveNameScreen_frameEnd(void) {}
