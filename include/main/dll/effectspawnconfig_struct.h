#ifndef MAIN_DLL_EFFECTSPAWNCONFIG_STRUCT_H_
#define MAIN_DLL_EFFECTSPAWNCONFIG_STRUCT_H_

#include "global.h"

typedef struct EffectSpawnConfig {
    union {
        void* attachedSource;
        s16* model;
    };
    union {
        s32 quadVertex3Pad06;
        int unk04;
    };
    union {
        s32 lifetimeFrames;
        u32 count;
    };
    union {
        struct {
            s16 sourceVecX;
            s16 sourceVecY;
            s16 sourceVecZ;
            s16 sourceVecPad;
        };
        struct {
            s16 rot0;
            s16 rot1;
            s16 rot2;
            s16 pad06;
        };
    };
    union {
        f32 sourcePosX;
        f32 srcW;
    };
    union {
        f32 sourcePosY;
        f32 srcX;
    };
    union {
        f32 sourcePosZ;
        f32 srcY;
    };
    union {
        f32 sourcePosW;
        f32 srcZ;
    };
    union {
        struct {
            union {
                f32 velocityX;
                f32 velX;
            };
            union {
                f32 velocityY;
                f32 velY;
            };
            union {
                f32 velocityZ;
                f32 velZ;
            };
        };
        f32 velocity[3];
    };
    union {
        struct {
            union {
                f32 startPosX;
                f32 posX;
            };
            union {
                f32 startPosY;
                f32 posY;
            };
            union {
                f32 startPosZ;
                f32 posZ;
            };
        };
        f32 startPos[3];
    };
    f32 scale;
    union {
        s16 textureSetupFlags;
        s16 unk40;
    };
    union {
        s16 textureId;
        s16 kind;
    };
    union {
        u32 behaviorFlags;
        u32 flagsA;
    };
    union {
        u32 renderFlags;
        u32 flagsB;
    };
    union {
        u32 overrideColor0;
        u32 colA;
    };
    union {
        u32 overrideColor1;
        u32 colB;
    };
    union {
        u32 overrideColor2;
        u32 colC;
    };
    union {
        u16 colorWord0;
        u16 colD;
    };
    union {
        u16 colorWord1;
        u16 colE;
    };
    union {
        u16 colorWord2;
        u16 colF;
    };
    union {
        u8 effectTypeByte;
        u8 effectIdByte;
        u8 idByte;
    };
    union {
        u8 pad5F;
        u8 pad5f[1];
    };
    union {
        u8 initialAlpha;
        u8 alpha;
    };
    union {
        u8 linkGroup;
        u8 unk61;
    };
    union {
        u8 attachedSourceLinkGroup;
        u8 modelIdByte;
        u8 srcFlag;
    };
} EffectSpawnConfig;

STATIC_ASSERT(sizeof(EffectSpawnConfig) == 0x64);
STATIC_ASSERT(offsetof(EffectSpawnConfig, attachedSource) == 0x00);
STATIC_ASSERT(offsetof(EffectSpawnConfig, lifetimeFrames) == 0x08);
STATIC_ASSERT(offsetof(EffectSpawnConfig, sourceVecX) == 0x0C);
STATIC_ASSERT(offsetof(EffectSpawnConfig, sourcePosX) == 0x14);
STATIC_ASSERT(offsetof(EffectSpawnConfig, velocityX) == 0x24);
STATIC_ASSERT(offsetof(EffectSpawnConfig, startPosX) == 0x30);
STATIC_ASSERT(offsetof(EffectSpawnConfig, textureId) == 0x42);
STATIC_ASSERT(offsetof(EffectSpawnConfig, behaviorFlags) == 0x44);
STATIC_ASSERT(offsetof(EffectSpawnConfig, colorWord0) == 0x58);
STATIC_ASSERT(offsetof(EffectSpawnConfig, effectTypeByte) == 0x5E);
STATIC_ASSERT(offsetof(EffectSpawnConfig, initialAlpha) == 0x60);
STATIC_ASSERT(offsetof(EffectSpawnConfig, linkGroup) == 0x61);
STATIC_ASSERT(offsetof(EffectSpawnConfig, attachedSourceLinkGroup) == 0x62);

#endif /* MAIN_DLL_EFFECTSPAWNCONFIG_STRUCT_H_ */
