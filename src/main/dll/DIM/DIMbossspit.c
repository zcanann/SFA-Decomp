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

#define DIMBOSSSPIT_MODEL_ACTIVE_FLAG 0x1
#define DIMBOSSSPIT_OBJECT_DISABLED_FLAG 0x8

#define DIMBOSSSPIT_EFFECT_ACTIVE_OFFSET 0x25f
#define DIMBOSSSPIT_ANIM_FINISHED_OFFSET 0x349
#define DIMBOSSSPIT_ANIM_POINTS_OFFSET 0x35c
#define DIMBOSSSPIT_ANIM_FRAME_OFFSET 0x3f4
#define DIMBOSSSPIT_ANIM_FLAGS_OFFSET 0x405
#define DIMBOSSSPIT_SAVED_OBJ_FIELD_C0_OFFSET 0x3e0

#define DIMBOSSSPIT_GAMEBIT_ACTIVE 0x20e
#define DIMBOSSSPIT_GAMEBIT_ROUTE_LOW 0x268
#define DIMBOSSSPIT_GAMEBIT_ROUTE_HIGH 0x311

#define DIMBOSSSPIT_ROUTE_HIGH_THRESHOLD 7
#define DIMBOSSSPIT_ROUTE_SPLIT_THRESHOLD 3
#define DIMBOSSSPIT_RUMBLE_SFX 0x189

#pragma peephole off
#pragma scheduling off

/*
 * --INFO--
 *
 * Function: fn_801BE19C
 * EN v1.0 Address: 0x801BE19C
 * EN v1.0 Size: 688b
 */
void fn_801BE19C(u8 *obj, u8 *unused2, u8 *state, u8 *updateState)
{
  f32 timer;
  u8 *vt;

  timer = lbl_803E4C90;

  *(s16 *)((u8 *)*(int *)(obj + 0x54) + 0x60) =
      (s16)(*(s16 *)((u8 *)*(int *)(obj + 0x54) + 0x60) | DIMBOSSSPIT_MODEL_ACTIVE_FLAG);

  updateState[DIMBOSSSPIT_EFFECT_ACTIVE_OFFSET] = 1;

  (*(void (**)(u8 *, u8 *, double, int))(*(int *)lbl_803DCAB8 + 0x2C))(
      obj, updateState, (double)timer, 1);

  vt = (u8 *)*(int *)lbl_803DCAB8;
  ((void (*)(u8 *, u8 *, u8 *, s16, u8 *, int, int, int))*(void **)(vt + 0x54))(
      obj, updateState, state + DIMBOSSSPIT_ANIM_POINTS_OFFSET,
      *(s16 *)(state + DIMBOSSSPIT_ANIM_FRAME_OFFSET),
      state + DIMBOSSSPIT_ANIM_FLAGS_OFFSET, 0, 0, 0);

  if (lbl_803E4C90 != lbl_803DDBA4) {
    lbl_803DDBA4 = lbl_803DDBA4 - timeDelta;
    timer = lbl_803DDBA4 * lbl_803E4CB4;
    if (lbl_803DDBA4 <= lbl_803E4CB8) {
      lbl_803DDBA4 = lbl_803E4C90;
      updateState[DIMBOSSSPIT_ANIM_FINISHED_OFFSET] = 0;
      *(s16 *)((u8 *)*(int *)(obj + 0x54) + 0x60) =
          (s16)(*(s16 *)((u8 *)*(int *)(obj + 0x54) + 0x60) & ~DIMBOSSSPIT_MODEL_ACTIVE_FLAG);
      obj[0xAF] = (u8)(obj[0xAF] | DIMBOSSSPIT_OBJECT_DISABLED_FLAG);
      GameBit_Set(DIMBOSSSPIT_GAMEBIT_ACTIVE, 0);
      if ((s8)lbl_803DDB94 >= DIMBOSSSPIT_ROUTE_HIGH_THRESHOLD) {
        GameBit_Set(DIMBOSSSPIT_GAMEBIT_ROUTE_HIGH, 1);
      } else {
        GameBit_Set(DIMBOSSSPIT_GAMEBIT_ROUTE_LOW, 1);
      }
    }
  } else {
    timer = timer + lbl_803E4CBC;
  }

  if (lbl_803DDBA0 >= lbl_803DDB9C) {
    Sfx_PlayFromObject(obj, DIMBOSSSPIT_RUMBLE_SFX);
    if (timer > lbl_803E4CBC) timer = lbl_803E4CBC;
    if (timer < lbl_803E4C9C) timer = lbl_803E4C9C;
    lbl_803DDB9C = lbl_803DDB9C + timer;
    doRumble(lbl_803E4CC0);
  }

  lbl_803DDBA0 = lbl_803DDBA0 + timeDelta;
  fn_801BDF7C(obj, updateState);

  if (lbl_803E4C90 != lbl_803DDB98) {
    lbl_803DDB98 = lbl_803DDB98 - timeDelta;
    if (lbl_803DDB98 <= lbl_803E4C90) {
      lbl_803DDB98 = lbl_803E4C90;
      updateState[DIMBOSSSPIT_ANIM_FINISHED_OFFSET] = 0;
      *(s16 *)((u8 *)*(int *)(obj + 0x54) + 0x60) =
          (s16)(*(s16 *)((u8 *)*(int *)(obj + 0x54) + 0x60) & ~DIMBOSSSPIT_MODEL_ACTIVE_FLAG);
      obj[0xAF] = (u8)(obj[0xAF] | DIMBOSSSPIT_OBJECT_DISABLED_FLAG);
      GameBit_Set(DIMBOSSSPIT_GAMEBIT_ACTIVE, 0);
      if ((s8)lbl_803DDB94 == DIMBOSSSPIT_ROUTE_SPLIT_THRESHOLD) {
        GameBit_Set(DIMBOSSSPIT_GAMEBIT_ROUTE_LOW, 1);
      } else {
        GameBit_Set(DIMBOSSSPIT_GAMEBIT_ROUTE_HIGH, 1);
      }
    }
  }

  *(u32 *)(state + DIMBOSSSPIT_SAVED_OBJ_FIELD_C0_OFFSET) = *(u32 *)(obj + 0xC0);
  *(u32 *)(obj + 0xC0) = 0;

  (*(void (**)(u8 *, u8 *, double, double, u8 *, u8 *))(*(int *)lbl_803DCA8C + 0x8))(
      obj, updateState, (double)timeDelta, (double)timeDelta, lbl_803DDBB0, lbl_803DDBA8);

  *(u32 *)(obj + 0xC0) = *(u32 *)(state + DIMBOSSSPIT_SAVED_OBJ_FIELD_C0_OFFSET);
}

#pragma peephole reset
#pragma scheduling reset
