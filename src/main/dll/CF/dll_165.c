#include "main/dll/CF/dll_165.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/resource.h"

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId,int value);
extern void ObjHits_DisableObject(int obj);
extern void ObjGroup_AddObject(int obj, int group);
extern void ObjHitbox_SetSphereRadius(int obj, int radius);
extern f32 mathSinf(f32 angle);
extern f32 mathCosf(f32 angle);

extern int *gGameUIInterface;
extern f32 lbl_803E3BBC;
extern f32 lbl_803E3BF4;
extern f32 lbl_803E3BF8;
extern f32 lbl_803E3C08;
extern f32 lbl_803E3C0C;
extern f32 lbl_803E3C10;
extern f32 lbl_803E3C14;
extern f32 lbl_803E3C18;
extern f64 lbl_803E3BD0;

typedef struct {
    u8 b7 : 1;
    u8 b6 : 1;
    u8 b5 : 1;
    u8 b4 : 1;
    u8 rest : 4;
} StaffFlags;

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
#pragma scheduling off
#pragma peephole off
void staffactivated_init(int obj, int setup)
{
  u8 *state;
  int sizeIndex;
  int modelVariant;
  f32 scale;
  StaffFlags *flags;

  state = ((GameObject *)obj)->extra;
  ObjGroup_AddObject(obj, 0x41);
  *(s16 *)obj = (s16)((s32)*(u8 *)(setup + 0x18) << 8);

  sizeIndex = *(u8 *)(setup + 0x1d);
  if (sizeIndex > 2) {
    sizeIndex = 2;
  }

  if (*(u8 *)(setup + 0x1c) == 2) {
    switch (sizeIndex) {
    case 2:
      modelVariant = 2;
      scale = lbl_803E3C08;
      break;
    default:
      modelVariant = 1;
      scale = lbl_803E3BBC;
      break;
    case 0:
      modelVariant = 0;
      scale = lbl_803E3C0C;
      break;
    }
  } else {
    scale = lbl_803E3BBC;
  }

  if (((GameObject *)obj)->anim.hitReactState != NULL) {
    ObjHitbox_SetSphereRadius(obj, (int)((f32)*(s16 *)(*(int *)&((GameObject *)obj)->anim.hitReactState + 0x5a) * scale));
  }

  ((GameObject *)obj)->anim.rootMotionScale = *(f32 *)(*(int *)&((GameObject *)obj)->anim.modelInstance + 4) * scale;
  if (((GameObject *)obj)->anim.rootMotionScale < lbl_803E3C10) {
    ((GameObject *)obj)->anim.rootMotionScale = lbl_803E3C10;
  }

  switch (*(u8 *)(setup + 0x1c)) {
  case 2:
    ((GameObject *)obj)->unkE4 = modelVariant;
    *(f32 *)state = -(lbl_803E3C14 *
                      (((GameObject *)obj)->anim.rootMotionScale *
                       (lbl_803E3C18 *
                        mathSinf((lbl_803E3BF4 * (f32)*(s16 *)obj) / lbl_803E3BF8))) -
                     ((GameObject *)obj)->anim.localPosX);
    *(f32 *)(state + 4) = -(lbl_803E3C14 *
                            (((GameObject *)obj)->anim.rootMotionScale *
                             (lbl_803E3C18 *
                              mathCosf((lbl_803E3BF4 * (f32)*(s16 *)obj) / lbl_803E3BF8))) -
                           ((GameObject *)obj)->anim.localPosZ);
    break;
  case 3:
    *(f32 *)state = lbl_803E3C14 *
                    (((GameObject *)obj)->anim.rootMotionScale *
                     (lbl_803E3C18 *
                      mathSinf((lbl_803E3BF4 * (f32)*(s16 *)obj) / lbl_803E3BF8))) +
                    ((GameObject *)obj)->anim.localPosX;
    *(f32 *)(state + 4) = lbl_803E3C14 *
                          (((GameObject *)obj)->anim.rootMotionScale *
                           (lbl_803E3C18 *
                            mathCosf((lbl_803E3BF4 * (f32)*(s16 *)obj) / lbl_803E3BF8))) +
                          ((GameObject *)obj)->anim.localPosZ;
    break;
  default:
    *(f32 *)state = ((GameObject *)obj)->anim.localPosX;
    *(f32 *)(state + 4) = ((GameObject *)obj)->anim.localPosZ;
    break;
  }

  flags = (StaffFlags *)(state + 0x1d);
  if (*(s16 *)(setup + 0x22) > 0) {
    flags->b7 = (u8)GameBit_Get(*(s16 *)(setup + 0x22));
  } else {
    flags->b7 = 1;
  }
  flags->b4 = 0;

  if (*(s16 *)(setup + 0x24) > 0) {
    if ((flags->b6 = (u8)GameBit_Get(*(s16 *)(setup + 0x24))) != 0) {
      switch (*(u8 *)(setup + 0x1c)) {
      case 3:
        ObjAnim_SetMoveProgress(lbl_803E3BBC, (ObjAnimComponent *)obj);
        break;
      case 4:
        flags->b6 = 0;
        break;
      case 2:
        break;
      case 6:
        break;
      }
    }
  }
}
#pragma peephole reset
#pragma scheduling reset

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

  setup = *(int *)&((GameObject *)obj)->anim.placementData;
  state = ((GameObject *)obj)->extra;
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
      ((StaffFlags *)state)->b5 = 1;
      break;
    case 3:
      ((StaffFlags *)state)->b5 = 0;
      break;
    case 4:
      ((GameObject *)obj)->anim.flags = ((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN;
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

extern void *lbl_803DDAE0;
#pragma scheduling off
#pragma peephole off
void treasurechest_free(void) { Resource_Release(lbl_803DDAE0); }
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E3C24;
extern void hitDetectFn_80097070(f32 radius, int obj, int a, int b, int c, int d);
#pragma scheduling off
#pragma peephole off
void treasurechest_hitDetect(int obj)
{
  u8 *state;
  int setup;

  setup = *(int *)&((GameObject *)obj)->anim.placementData;
  state = ((GameObject *)obj)->extra;
  if (((u32)state[0] >> 5 & 1) != 0) {
    hitDetectFn_80097070(lbl_803E3C24, obj, 2, (u8)(*(u8 *)(setup + 0x19) + 6), 4, 0);
  }
}
#pragma peephole reset
#pragma scheduling reset
