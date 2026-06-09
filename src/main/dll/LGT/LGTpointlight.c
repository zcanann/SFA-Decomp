#include "main/dll/LGT/LGTpointlight.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"


#pragma peephole off
#pragma scheduling off
extern void *objCreateLight(void *obj, int);
extern void modelLightStruct_setLightKind(void *, int);
extern void modelLightStruct_setPosition(f32, f32, f32);
extern void modelLightStruct_setDiffuseColor(void *, u8, u8, u8, int);
extern void modelLightStruct_setSpecularColor(void *, u8, u8, u8, int);
extern void modelLightStruct_setDistanceAttenuation(void *, f32, f32);
extern void modelLightStruct_setEnabled(void *, int, f32);
extern void modelLightStruct_startColorFade(void *, int, int);
extern void modelLightStruct_setDiffuseTargetColor(void *, int, int, int, int);
extern void lightSetField4D(void *, int);
extern void modelLightStruct_setupGlow(void *, int, u8, u8, u8, int, f32);
extern void modelLightStruct_setGlowProjectionRadius(void *, f32);

extern u8 lbl_802C2488[];
extern f32 lbl_803E5E08;
extern f32 lbl_803E5E0C;
extern f32 lbl_803E5E10;
extern f32 lbl_803E5E20;
extern f32 lbl_803E5E24;
extern f32 lbl_803E5E28;
extern f32 lbl_803E5E2C;
extern f32 lbl_803E5E30;
extern f32 lbl_803E5E34;
extern f32 lbl_803E5E38;
extern f32 lbl_803E5E3C;
extern f32 lbl_803E5E40;

typedef struct LightColorTable {
    u8 c[45];
} LightColorTable;

/*
 * --INFO--
 *
 * Function: lightsource_init
 * EN v1.0 Address: 0x801F37CC
 * EN v1.0 Size: 1112b
 */
void lightsource_init(GameObject *obj, LightSourceSetup *setup)
{
  LightSourceState *state;
  LightColorTable colors;
  int flags;
  int range;
  int colorBase;

  state = obj->extra;
  colors = *(LightColorTable *)lbl_802C2488;
  obj->anim.rotY = (s16)(((int)setup->yaw & 0x3fU) << 10);
  range = setup->range;
  if (range > 0) {
    obj->anim.rootMotionScale = (f32)range / lbl_803E5E20;
  }
  else {
    obj->anim.rootMotionScale = lbl_803E5E24;
  }

  state->mode = setup->mode;
  state->gameBit = setup->gameBit;
  state->fxType = 1;
  if (setup->flags & 0x20) {
    state->fxArg = 0;
  }
  else {
    state->fxArg = 3;
  }
  if (setup->options & 1) {
    state->sparks = 1;
  }
  else {
    state->sparks = 0;
  }

  switch (state->mode) {
  case 0:
    state->lit = 1;
    flags = setup->flags;
    if (flags & 4) {
      state->fxType = 4;
    }
    else if (flags & 8) {
      state->fxType = 8;
    }
    else if (flags & 0x10) {
      state->fxType = 6;
    }
    else if (flags & 1) {
      state->fxArg = 6;
    }
    break;
  }

  if (setup->flags & 0x40) {
    if (state->light == NULL) {
      state->light = objCreateLight(obj, 1);
      if (state->light != NULL) {
        modelLightStruct_setLightKind(state->light, 2);
      }
    }
    if (state->light != NULL) {
      if (obj->anim.seqId == 0x705 || obj->anim.seqId == 0x712) {
        modelLightStruct_setPosition(lbl_803E5E0C, lbl_803E5E0C, lbl_803E5E0C);
      }
      else {
        modelLightStruct_setPosition(lbl_803E5E0C, lbl_803E5E28, lbl_803E5E0C);
      }

      colorBase = state->fxType * 3;
      modelLightStruct_setDiffuseColor(state->light, colors.c[colorBase], colors.c[colorBase + 1], colors.c[colorBase + 2], 0xff);
      colorBase = state->fxType * 3;
      modelLightStruct_setSpecularColor(state->light, colors.c[colorBase], colors.c[colorBase + 1], colors.c[colorBase + 2], 0xff);
      modelLightStruct_setDistanceAttenuation(state->light, lbl_803E5E2C, lbl_803E5E30);
      modelLightStruct_setEnabled(state->light, 1, lbl_803E5E0C);
      modelLightStruct_startColorFade(state->light, 1, 3);

      colorBase = state->fxType * 3;
      modelLightStruct_setDiffuseTargetColor(state->light, (int)(lbl_803E5E34 * (f32)(u32)colors.c[colorBase]),
                      (int)(lbl_803E5E34 * (f32)(u32)colors.c[colorBase + 1]),
                      (int)(lbl_803E5E34 * (f32)(u32)colors.c[colorBase + 2]), 0xff);
      lightSetField4D(state->light, 1);

      if (setup->flags & 0x80) {
        if (obj->anim.seqId == 0x705 || obj->anim.seqId == 0x712) {
          colorBase = state->fxType * 3;
          modelLightStruct_setupGlow(state->light, 0, colors.c[colorBase], colors.c[colorBase + 1], colors.c[colorBase + 2],
                      0x8c, lbl_803E5E38 * (lbl_803E5E3C * obj->anim.rootMotionScale));
        }
        else {
          colorBase = state->fxType * 3;
          modelLightStruct_setupGlow(state->light, 0, colors.c[colorBase], colors.c[colorBase + 1], colors.c[colorBase + 2],
                      0x8c, lbl_803E5E3C * obj->anim.rootMotionScale);
        }
        modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E5E40);
      }
    }
  }
  else {
    state->light = NULL;
  }

  if (setup->flags & 2) {
    state->fxType = 0;
  }
  obj->objectFlags |= 0x2000;
  state->fxTimer = lbl_803E5E10;
  state->sparkTimer = lbl_803E5E08;
}

/* Trivial 4b 0-arg blr leaves. */
void lightsource_release(void) {}
void lightsource_initialise(void) {}
void wmworm_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int wmworm_getExtraSize(void) { return 0x1c; }
int wmworm_getObjectTypeId(void) { return 0x0; }

void wmworm_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void wmworm_free(int obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}
