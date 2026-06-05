#include "ghidra_import.h"
#include "main/dll/LGT/LGTpointlight.h"


#pragma peephole off
#pragma scheduling off
extern int objCreateLight(void *obj, int);
extern void modelLightStruct_setField50(int, int);
extern void lightVecFn_8001dd88(f32, f32, f32);
extern void modelLightStruct_setColorsA8AC(int, u8, u8, u8, int);
extern void modelLightStruct_setColors100104(int, u8, u8, u8, int);
extern void lightDistAttenFn_8001dc38(int, f32, f32);
extern void lightFn_8001db6c(int, int, f32);
extern void lightFn_8001d620(int, int, int);
extern void lightSetFieldB0(int, int, int, int, int);
extern void lightSetField4D(int, int);
extern void modelLightStruct_setupGlow(int, int, u8, u8, u8, int, f32);
extern void modelLightStruct_setGlowProjectionRadius(int, f32);

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
void lightsource_init(s16 *obj, int mapData)
{
  int *state;
  LightColorTable colors;
  int flags;
  int type;
  int range;
  int colorBase;

  state = *(int **)((u8 *)obj + 0xb8);
  colors = *(LightColorTable *)lbl_802C2488;
  *obj = (short)(((int)*(s8 *)(mapData + 0x18) & 0x3fU) << 10);
  range = *(s16 *)(mapData + 0x1a);
  if (range > 0) {
    *(f32 *)(obj + 4) = (f32)range / lbl_803E5E20;
  }
  else {
    *(f32 *)(obj + 4) = lbl_803E5E24;
  }

  *(u8 *)((int)state + 0x14) = *(u8 *)(mapData + 0x19);
  state[4] = (int)*(s16 *)(mapData + 0x1e);
  *(u8 *)((int)state + 0x15) = 1;
  if (*(s16 *)(mapData + 0x1c) & 0x20) {
    *(u8 *)((int)state + 0x16) = 0;
  }
  else {
    *(u8 *)((int)state + 0x16) = 3;
  }
  if (*(u8 *)(mapData + 0x22) & 1) {
    *(u8 *)((int)state + 0x19) = 1;
  }
  else {
    *(u8 *)((int)state + 0x19) = 0;
  }

  switch (*(u8 *)((int)state + 0x14)) {
  case 0:
    *(u8 *)((int)state + 0x17) = 1;
    flags = *(s16 *)(mapData + 0x1c);
    if (flags & 4) {
      *(u8 *)((int)state + 0x15) = 4;
    }
    else if (flags & 8) {
      *(u8 *)((int)state + 0x15) = 8;
    }
    else if (flags & 0x10) {
      *(u8 *)((int)state + 0x15) = 6;
    }
    else if (flags & 1) {
      *(u8 *)((int)state + 0x16) = 6;
    }
    break;
  }

  if (*(s16 *)(mapData + 0x1c) & 0x40) {
    if (*(void **)state == NULL) {
      *state = objCreateLight(obj, 1);
      if (*(void **)state != NULL) {
        modelLightStruct_setField50(*state, 2);
      }
    }
    if (*(void **)state != NULL) {
      type = *(s16 *)((u8 *)obj + 0x46);
      if (type == 0x705 || type == 0x712) {
        lightVecFn_8001dd88(lbl_803E5E0C, lbl_803E5E0C, lbl_803E5E0C);
      }
      else {
        lightVecFn_8001dd88(lbl_803E5E0C, lbl_803E5E28, lbl_803E5E0C);
      }

      colorBase = *(u8 *)((int)state + 0x15) * 3;
      modelLightStruct_setColorsA8AC(*state, colors.c[colorBase], colors.c[colorBase + 1], colors.c[colorBase + 2], 0xff);
      colorBase = *(u8 *)((int)state + 0x15) * 3;
      modelLightStruct_setColors100104(*state, colors.c[colorBase], colors.c[colorBase + 1], colors.c[colorBase + 2], 0xff);
      lightDistAttenFn_8001dc38(*state, lbl_803E5E2C, lbl_803E5E30);
      lightFn_8001db6c(*state, 1, lbl_803E5E0C);
      lightFn_8001d620(*state, 1, 3);

      colorBase = *(u8 *)((int)state + 0x15) * 3;
      lightSetFieldB0(*state, (int)(lbl_803E5E34 * (f32)(u32)colors.c[colorBase]),
                      (int)(lbl_803E5E34 * (f32)(u32)colors.c[colorBase + 1]),
                      (int)(lbl_803E5E34 * (f32)(u32)colors.c[colorBase + 2]), 0xff);
      lightSetField4D(*state, 1);

      if (*(s16 *)(mapData + 0x1c) & 0x80) {
        type = *(s16 *)((u8 *)obj + 0x46);
        if (type == 0x705 || type == 0x712) {
          colorBase = *(u8 *)((int)state + 0x15) * 3;
          modelLightStruct_setupGlow(*state, 0, colors.c[colorBase], colors.c[colorBase + 1], colors.c[colorBase + 2],
                      0x8c, lbl_803E5E38 * (lbl_803E5E3C * *(f32 *)(obj + 4)));
        }
        else {
          colorBase = *(u8 *)((int)state + 0x15) * 3;
          modelLightStruct_setupGlow(*state, 0, colors.c[colorBase], colors.c[colorBase + 1], colors.c[colorBase + 2],
                      0x8c, lbl_803E5E3C * *(f32 *)(obj + 4));
        }
        modelLightStruct_setGlowProjectionRadius(*state, lbl_803E5E40);
      }
    }
  }
  else {
    *state = 0;
  }

  if (*(s16 *)(mapData + 0x1c) & 2) {
    *(u8 *)((int)state + 0x15) = 0;
  }
  *(u16 *)((u8 *)obj + 0xb0) |= 0x2000;
  *(f32 *)(state + 1) = lbl_803E5E10;
  *(f32 *)(state + 2) = lbl_803E5E08;
}

/* Trivial 4b 0-arg blr leaves. */
void lightsource_release(void) {}
void lightsource_initialise(void) {}
void wmworm_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int wmworm_getExtraSize(void) { return 0x1c; }
int wmworm_getObjectTypeId(void) { return 0x0; }

#pragma peephole off
void wmworm_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }
#pragma peephole reset

extern int *gExpgfxInterface;
void wmworm_free(int obj) {
    ((void (*)(int))((void**)*gExpgfxInterface)[6])(obj);
}
