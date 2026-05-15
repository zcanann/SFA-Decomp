#include "ghidra_import.h"
#include "main/dll/DIM/DIMbossspit.h"

extern f32 timeDelta;
extern u8 lbl_803DDB94;
extern f32 lbl_803DDB98;
extern f32 lbl_803DDB9C;
extern f32 lbl_803DDBA0;
extern f32 lbl_803DDBA4;
extern u8 lbl_803DDBA8[8];
extern u8 lbl_803DDBB0[8];
extern u8 *lbl_803DCAB8;
extern u8 *lbl_803DCA8C;
extern f32 lbl_803E4C90;
extern f32 lbl_803E4C9C;
extern f32 lbl_803E4CB4;
extern f32 lbl_803E4CB8;
extern f32 lbl_803E4CBC;
extern f32 lbl_803E4CC0;

extern void GameBit_Set(int bit, int value);
extern void Sfx_PlayFromObject(u8 *obj, int sfxId);
extern void doRumble(f32 val);
extern void fn_801BDF7C(u8 *arg1, u8 *arg4);

#pragma peephole off
#pragma scheduling off

/*
 * --INFO--
 *
 * Function: fn_801BE19C
 * EN v1.0 Address: 0x801BE19C
 * EN v1.0 Size: 688b
 */
void fn_801BE19C(u8 *arg1, u8 *unused2, u8 *arg3, u8 *arg4)
{
  f32 timer;
  u8 *vt;

  timer = lbl_803E4C90;

  *(s16 *)((u8 *)*(int *)(arg1 + 0x54) + 0x60) =
      (s16)(*(s16 *)((u8 *)*(int *)(arg1 + 0x54) + 0x60) | 1);

  arg4[0x25F] = 1;

  (*(void (**)(u8 *, u8 *, double, int))(*(int *)lbl_803DCAB8 + 0x2C))(
      arg1, arg4, (double)timer, 1);

  vt = (u8 *)*(int *)lbl_803DCAB8;
  ((void (*)(u8 *, u8 *, u8 *, s16, u8 *, int, int, int))*(void **)(vt + 0x54))(
      arg1, arg4, arg3 + 0x35C, *(s16 *)(arg3 + 0x3F4), arg3 + 0x405, 0, 0, 0);

  if (lbl_803E4C90 != lbl_803DDBA4) {
    lbl_803DDBA4 = lbl_803DDBA4 - timeDelta;
    timer = lbl_803DDBA4 * lbl_803E4CB4;
    if (lbl_803DDBA4 <= lbl_803E4CB8) {
      lbl_803DDBA4 = lbl_803E4C90;
      arg4[0x349] = 0;
      *(s16 *)((u8 *)*(int *)(arg1 + 0x54) + 0x60) =
          (s16)(*(s16 *)((u8 *)*(int *)(arg1 + 0x54) + 0x60) & ~1);
      arg1[0xAF] = (u8)(arg1[0xAF] | 0x8);
      GameBit_Set(0x20E, 0);
      if ((s8)lbl_803DDB94 >= 7) {
        GameBit_Set(0x311, 1);
      } else {
        GameBit_Set(0x268, 1);
      }
    }
  } else {
    timer = timer + lbl_803E4CBC;
  }

  if (lbl_803DDBA0 >= lbl_803DDB9C) {
    Sfx_PlayFromObject(arg1, 0x189);
    if (timer > lbl_803E4CBC) timer = lbl_803E4CBC;
    if (timer < lbl_803E4C9C) timer = lbl_803E4C9C;
    lbl_803DDB9C = lbl_803DDB9C + timer;
    doRumble(lbl_803E4CC0);
  }

  lbl_803DDBA0 = lbl_803DDBA0 + timeDelta;
  fn_801BDF7C(arg1, arg4);

  if (lbl_803E4C90 != lbl_803DDB98) {
    lbl_803DDB98 = lbl_803DDB98 - timeDelta;
    if (lbl_803DDB98 <= lbl_803E4C90) {
      lbl_803DDB98 = lbl_803E4C90;
      arg4[0x349] = 0;
      *(s16 *)((u8 *)*(int *)(arg1 + 0x54) + 0x60) =
          (s16)(*(s16 *)((u8 *)*(int *)(arg1 + 0x54) + 0x60) & ~1);
      arg1[0xAF] = (u8)(arg1[0xAF] | 0x8);
      GameBit_Set(0x20E, 0);
      if ((s8)lbl_803DDB94 == 3) {
        GameBit_Set(0x268, 1);
      } else {
        GameBit_Set(0x311, 1);
      }
    }
  }

  *(u32 *)(arg3 + 0x3E0) = *(u32 *)(arg1 + 0xC0);
  *(u32 *)(arg1 + 0xC0) = 0;

  (*(void (**)(double, double, u8 *, u8 *, u8 *, u8 *))(*(int *)lbl_803DCA8C + 0x8))(
      (double)timeDelta, (double)timeDelta, arg1, arg4, lbl_803DDBB0, lbl_803DDBA8);

  *(u32 *)(arg1 + 0xC0) = *(u32 *)(arg3 + 0x3E0);
}

#pragma peephole reset
#pragma scheduling reset
