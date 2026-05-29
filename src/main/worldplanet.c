#include "ghidra_import.h"
#include "main/worldplanet.h"

extern void objRenderFn_8003b8f4(double scale);
extern void setShowWorldMapHud(int enabled);

extern f32 lbl_803E6618;
extern u32 GameBit_Get(int id);
extern int GameBit_Set(int id, int value);
extern void unlockLevel(int a, int b, int c);
extern int *gMapEventInterface;
extern int lbl_8032A1B4[5];
extern u8 lbl_803DC1B8[8];
extern u8 lbl_803DC1C0[8];
extern int lbl_803DC1F0;
extern int lbl_803DDD04;
extern u8 lbl_803DDD08;
extern s16 lbl_803DDD0A;
extern int lbl_803DDD28;
extern f32 lbl_803DDD2C;
extern f32 lbl_803E65F8;
extern u16 getNextTaskHintText(void);
extern void setDrawLights(int mode);
extern void audioStopByMask(int mask);
extern void Music_Trigger(int track, int arg2);
extern void mapUnload(int mapId, int flags);
extern int getCurMapLayer(void);
extern void envFxActFn_800887f8(int arg);
extern int *gScreenTransitionInterface;
extern int padGetStickX(int controller);
extern int padGetStickY(int controller);
extern int getLoadedFileFlags(int file);

int worldplanet_getExtraSize(void)
{
  return sizeof(WorldPlanetState);
}

int worldplanet_getObjectTypeId(void)
{
  return 0;
}

#pragma peephole off
#pragma scheduling off
#pragma peephole off
void worldplanet_free(void)
{
  setShowWorldMapHud(0);
  return;
}

void worldplanet_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                        undefined4 param_4,undefined4 param_5,char visible)
{
  int draw;

  draw = visible;
  if (draw != 0) {
    objRenderFn_8003b8f4((double)lbl_803E6618);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset
#pragma peephole reset

void worldplanet_hitDetect(void)
{
  return;
}

void worldplanet_release(void) {}

void worldplanet_initialise(void) {}

#pragma scheduling off
#pragma peephole off
void worldplanet_init(int obj) {
    int inner;
    int mask;
    int i;
    int flag;
    int layer;
    int j;

    inner = *(int *)(obj + 0xb8);
    lbl_803DDD04 = 0;
    GameBit_Set(0xa63, 1);
    mask = 0;
    for (i = 0; i < 5; i++) {
        if (GameBit_Get(lbl_8032A1B4[i]) != 0) {
            flag = 1;
            if (lbl_803DC1B8[i] != 0) {
                if (getNextTaskHintText() > 0xad) {
                    flag = 0;
                }
            }
            if ((u8)flag != 0) {
                mask |= 1 << i;
            }
        }
    }
    *(u8 *)(inner + 0x11) = (u8)mask;
    if (lbl_803DC1F0 != -1) {
        *(s8 *)(inner + 0x10) = (s8)lbl_803DC1F0;
    } else {
        for (j = 0; j < 5; j++) {
            if (GameBit_Get(lbl_8032A1B4[lbl_803DC1C0[j]]) != 0) {
                *(s8 *)(inner + 0x10) = (s8)lbl_803DC1C0[j];
                break;
            }
        }
    }
    lbl_803DDD08 = 0;
    setDrawLights(0);
    audioStopByMask(0xf);
    Music_Trigger(0x8f, 1);
    lbl_803DDD2C = lbl_803E65F8;
    setShowWorldMapHud(1);
    lbl_803DDD28 = -1;
    unlockLevel(0, 0, 1);
    mapUnload(0x2d, 0x10000000);
    layer = getCurMapLayer();
    (*(void (*)(int, int, int, int))(*(int *)(*gMapEventInterface + 0x1c)))(obj + 0xc, 0, 0, layer);
    (*(void (*)(int, int))(*(int *)(*gScreenTransitionInterface + 0xc)))(0x1e, 1);
    lbl_803DDD0A = 0xa;
    GameBit_Set(lbl_8032A1B4[2], 1);
    *(s16 *)(inner + 0x6) = 0x78;
    envFxActFn_800887f8(0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void worldplanet_readMapInput(int obj, u8 *outX, u8 *outY) {
    s8 *inner = *(s8 **)(obj + 0xb8);
    int stickX;
    int stickY;
    int resX;
    int resY;

    stickX = padGetStickX(0);
    stickY = padGetStickY(0);
    resX = 0;
    resY = 0;
    if (getLoadedFileFlags(0) == 0) {
        if ((s8)stickX < -0x23 && inner[0xa] >= -0x23) {
            resX = -1;
            inner[0xc] = 0;
        }
        if ((s8)stickX > 0x23 && inner[0xa] <= 0x23) {
            resX = 1;
            inner[0xc] = 0;
        }
        if ((s8)stickY < -0x23 && inner[0xb] >= -0x23) {
            resY = -1;
            inner[0xd] = 0;
        }
        if ((s8)stickY > 0x23 && inner[0xb] <= 0x23) {
            resY = 1;
            inner[0xd] = 0;
        }
        inner[0xb] = stickY;
        if (inner[0xb] < -0x23) {
            inner[0xd]++;
        } else if (inner[0xb] > 0x23) {
            inner[0xd]++;
        } else {
            inner[0xd] = 0;
        }
        if (inner[0xd] > 0x32) {
            inner[0xb] = 0;
            inner[0xd] = 0;
        }
        inner[0xa] = stickX;
        if (inner[0xa] < -0x23) {
            inner[0xc]++;
        } else if (inner[0xa] > 0x23) {
            inner[0xc]++;
        } else {
            inner[0xc] = 0;
        }
        if (inner[0xc] > 0x32) {
            inner[0xa] = 0;
            inner[0xc] = 0;
        }
        *outX = resX;
        *outY = resY;
    } else {
        *outX = 0;
        *outY = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset
