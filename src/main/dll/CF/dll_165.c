#include "ghidra_import.h"
#include "main/dll/CF/dll_165.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId,int value);
extern void ObjHits_DisableObject(int obj);
extern void ObjGroup_AddObject(int obj, int group);
extern void ObjHitbox_SetSphereRadius(int obj, int radius);
extern void ObjAnim_SetMoveProgress(int obj, f32 progress);
extern f32 fn_80293E80(f32 angle);
extern f32 sin(f32 angle);

extern int *gGameUIInterface;
extern f32 lbl_803E3BBC;
extern f32 lbl_803E3BF4;
extern f32 lbl_803E3BF8;
extern f32 lbl_803E3C08;
extern f32 lbl_803E3C0C;
extern f32 lbl_803E3C10;
extern f32 lbl_803E3C14;
extern f32 lbl_803E3C18;

/*
 * --INFO--
 *
 * Function: staffactivated_init
 * EN v1.0 Address: 0x8018A53C
 * EN v1.0 Size: 684b
 * EN v1.1 Address: 0x8018A7DC
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void staffactivated_init(int obj, int setup)
{
  int sizeIndex;
  u8 setupType;
  u8 modelVariant;
  f32 scale;
  u8 *state;
  f32 angle;
  f32 offset;
  u32 bit;

  state = *(u8 **)(obj + 0xb8);
  ObjGroup_AddObject(obj, 0x41);
  *(s16 *)obj = (s16)((s32)*(u8 *)(setup + 0x18) << 8);

  sizeIndex = *(u8 *)(setup + 0x1d);
  if (sizeIndex > 2) {
    sizeIndex = 2;
  }

  setupType = *(u8 *)(setup + 0x1c);
  if (setupType == 2) {
    switch (sizeIndex) {
    case 0:
      modelVariant = 0;
      scale = lbl_803E3C0C;
      break;
    case 2:
      modelVariant = 2;
      scale = lbl_803E3C08;
      break;
    default:
      modelVariant = 1;
      scale = lbl_803E3BBC;
      break;
    }
  } else {
    scale = lbl_803E3BBC;
  }

  if (*(int *)(obj + 0x54) != 0) {
    ObjHitbox_SetSphereRadius(obj, (int)((f32)*(s16 *)(*(int *)(obj + 0x54) + 0x5a) * scale));
  }

  *(f32 *)(obj + 8) = *(f32 *)(*(int *)(obj + 0x50) + 4) * scale;
  if (*(f32 *)(obj + 8) < lbl_803E3C10) {
    *(f32 *)(obj + 8) = lbl_803E3C10;
  }

  switch (setupType) {
  case 2:
    *(u8 *)(obj + 0xe4) = modelVariant;
    angle = (lbl_803E3BF4 * (f32)*(s16 *)obj) / lbl_803E3BF8;
    offset = lbl_803E3C14 * *(f32 *)(obj + 8) * (lbl_803E3C18 * fn_80293E80(angle));
    *(f32 *)state = *(f32 *)(obj + 0xc) - offset;
    angle = (lbl_803E3BF4 * (f32)*(s16 *)obj) / lbl_803E3BF8;
    offset = lbl_803E3C14 * *(f32 *)(obj + 8) * (lbl_803E3C18 * sin(angle));
    *(f32 *)(state + 4) = *(f32 *)(obj + 0x14) - offset;
    break;
  case 3:
    angle = (lbl_803E3BF4 * (f32)*(s16 *)obj) / lbl_803E3BF8;
    offset = lbl_803E3C14 * *(f32 *)(obj + 8) * (lbl_803E3C18 * fn_80293E80(angle));
    *(f32 *)state = offset + *(f32 *)(obj + 0xc);
    angle = (lbl_803E3BF4 * (f32)*(s16 *)obj) / lbl_803E3BF8;
    offset = lbl_803E3C14 * *(f32 *)(obj + 8) * (lbl_803E3C18 * sin(angle));
    *(f32 *)(state + 4) = offset + *(f32 *)(obj + 0x14);
    break;
  default:
    *(f32 *)state = *(f32 *)(obj + 0xc);
    *(f32 *)(state + 4) = *(f32 *)(obj + 0x14);
    break;
  }

  if (*(s16 *)(setup + 0x22) > 0) {
    bit = (u8)GameBit_Get(*(s16 *)(setup + 0x22));
    state[0x1d] = (state[0x1d] & 0x7f) | ((bit & 1) << 7);
  } else {
    state[0x1d] = (state[0x1d] & 0x7f) | 0x80;
  }
  state[0x1d] = state[0x1d] & 0xef;

  if (*(s16 *)(setup + 0x24) > 0) {
    bit = (u8)GameBit_Get(*(s16 *)(setup + 0x24));
    state[0x1d] = (state[0x1d] & 0xbf) | ((bit & 1) << 6);
    if (((state[0x1d] >> 6) & 1) != 0) {
      if (setupType == 4) {
        state[0x1d] = state[0x1d] & 0xbf;
      } else if (setupType == 3) {
        ObjAnim_SetMoveProgress(obj, lbl_803E3BBC);
      }
    }
  }
}

/*
 * --INFO--
 *
 * Function: treasurechest_SeqFn
 * EN v1.0 Address: 0x8018A8BC
 * EN v1.0 Size: 248b
 */
#pragma scheduling off
#pragma peephole off
int treasurechest_SeqFn(int obj, int unused, u8 *events)
{
  int i;
  int setup;
  u8 *state;
  u8 eventId;

  setup = *(int *)(obj + 0x4c);
  state = *(u8 **)(obj + 0xb8);
  i = 0;
  while (i < events[0x8b]) {
    eventId = events[i + 0x81];
    switch (eventId) {
    case 1:
      if (*(s16 *)(setup + 0x1c) != 0) {
        (*(void (*)(int, int, int, int))(*(int *)(*gGameUIInterface + 0x38)))(
            *(s16 *)(setup + 0x1c), 0xc8, 0x8c, 0);
      }
      break;
    case 2:
      state[0] = (state[0] & 0xdf) | 0x20;
      break;
    case 3:
      state[0] = state[0] & 0xdf;
      break;
    case 4:
      *(s16 *)(obj + 6) = *(s16 *)(obj + 6) | 0x4000;
      ObjHits_DisableObject(obj);
      break;
    }
    i++;
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: treasurechest_getExtraSize
 * EN v1.0 Address: 0x8018A9B4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018ABD4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int treasurechest_getExtraSize(void)
{
  return 1;
}

/*
 * --INFO--
 *
 * Function: treasurechest_getObjectTypeId
 * EN v1.0 Address: 0x8018A9BC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018ABDC
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int treasurechest_getObjectTypeId(void)
{
  return 0;
}

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3C20;
extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
void treasurechest_render(void) { objRenderFn_8003b8f4(lbl_803E3C20); }
#pragma peephole reset
#pragma scheduling reset

extern u32 lbl_803DDAE0;
extern void Resource_Release(u32);
#pragma scheduling off
#pragma peephole off
void treasurechest_free(void) { Resource_Release(lbl_803DDAE0); }
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E3C24;
extern void hitDetectFn_80097070(int obj, int a, int b, int c, int d, f32 radius);
#pragma scheduling off
#pragma peephole off
void treasurechest_hitDetect(int obj)
{
  u8 *state;
  int setup;

  setup = *(int *)(obj + 0x4c);
  state = *(u8 **)(obj + 0xb8);
  if (((u32)state[0] >> 5 & 1) != 0) {
    f32 radius = lbl_803E3C24;
    hitDetectFn_80097070(obj, 2, (u8)(*(u8 *)(setup + 0x19) + 6), 4, 0, radius);
  }
}
#pragma peephole reset
#pragma scheduling reset
