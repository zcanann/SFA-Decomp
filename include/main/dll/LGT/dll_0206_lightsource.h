#ifndef MAIN_DLL_LGT_LGTPOINTLIGHT_H_
#define MAIN_DLL_LGT_LGTPOINTLIGHT_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct LightSourceSetup {
    ObjPlacement base;
    s8 yaw;
    u8 mode;
    s16 range;
    s16 flags;
    s16 gameBit;
    u8 pad20[2];
    u8 options;
} LightSourceSetup;

typedef struct LightSourceState {
    void *light;
    f32 fxTimer;
    f32 sparkTimer;
    f32 sparkSpawnTimer;
    int gameBit;
    u8 mode;
    u8 fxType;
    u8 fxArg;
    u8 lit;
    u8 litPrev;
    u8 sparks;
    u8 loopFlags;
    u8 pad1B;
} LightSourceState;

typedef enum LightSourceMode {
    LIGHTSOURCE_MODE_STATIC = 0,      /* always lit; no hit interaction */
    LIGHTSOURCE_MODE_INTERACTIVE = 1, /* toggled lit/unlit by priority hits */
} LightSourceMode;

#define LIGHTSOURCE_FLAG_FX_ARG_6 0x01
#define LIGHTSOURCE_FLAG_DISABLE_FX_TYPE 0x02
#define LIGHTSOURCE_FLAG_FX_TYPE_4 0x04
#define LIGHTSOURCE_FLAG_FX_TYPE_8 0x08
#define LIGHTSOURCE_FLAG_FX_TYPE_6 0x10
#define LIGHTSOURCE_FLAG_FX_ARG_ZERO 0x20
#define LIGHTSOURCE_FLAG_CREATE_LIGHT 0x40
#define LIGHTSOURCE_FLAG_CREATE_GLOW 0x80
#define LIGHTSOURCE_OPTION_SPARKS 0x01

STATIC_ASSERT(offsetof(LightSourceSetup, yaw) == 0x18);
STATIC_ASSERT(offsetof(LightSourceSetup, mode) == 0x19);
STATIC_ASSERT(offsetof(LightSourceSetup, range) == 0x1a);
STATIC_ASSERT(offsetof(LightSourceSetup, flags) == 0x1c);
STATIC_ASSERT(offsetof(LightSourceSetup, gameBit) == 0x1e);
STATIC_ASSERT(offsetof(LightSourceSetup, options) == 0x22);
STATIC_ASSERT(sizeof(LightSourceState) == 0x1c);
STATIC_ASSERT(offsetof(LightSourceState, fxTimer) == 0x04);
STATIC_ASSERT(offsetof(LightSourceState, sparkTimer) == 0x08);
STATIC_ASSERT(offsetof(LightSourceState, gameBit) == 0x10);
STATIC_ASSERT(offsetof(LightSourceState, mode) == 0x14);
STATIC_ASSERT(offsetof(LightSourceState, fxType) == 0x15);
STATIC_ASSERT(offsetof(LightSourceState, fxArg) == 0x16);
STATIC_ASSERT(offsetof(LightSourceState, lit) == 0x17);
STATIC_ASSERT(offsetof(LightSourceState, sparks) == 0x19);
STATIC_ASSERT(offsetof(LightSourceState, loopFlags) == 0x1a);

void lightsource_init(GameObject *obj, LightSourceSetup *setup);

#endif /* MAIN_DLL_LGT_LGTPOINTLIGHT_H_ */
