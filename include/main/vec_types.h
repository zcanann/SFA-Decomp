#ifndef MAIN_VEC_TYPES_H
#define MAIN_VEC_TYPES_H

#include "global.h"
#include "dolphin/mtx/vec_types.h"

typedef Vec Vec3f;

typedef struct Vec3s
{
    s16 x;
    s16 y;
    s16 z;
} Vec3s;

/* Shared rotation, scale and translation packet. Particle handlers also use
 * the rotation halfwords as effect-specific parameters. */
typedef struct MatrixTransform {
    union {
        u16 unsignedArgs[4];
        struct {
            s16 unk0;
            s16 unk2;
            s16 unk4;
            s16 effectParam;
        };
        struct {
            s16 rotX;
            s16 rotY;
            s16 rotZ;
            s16 pad06;
        };
        struct {
            s16 arg0;
            s16 arg1;
            s16 arg2;
            s16 arg3;
        };
        struct {
            s16 yaw; /* Effects 0xCA/0xCB rotate debris velocity by this heading. */
            s16 unused02;
            s16 variant;
            s16 unused06;
        } dig;
    };
    f32 scale;
    union {
        struct {
            f32 posX;
            f32 posY;
            f32 posZ;
        };
        Vec3f pos;
        f32 position[3];
        struct {
            f32 x;
            f32 y;
            f32 z;
        };
    };
} MatrixTransform;

STATIC_ASSERT(sizeof(MatrixTransform) == 0x18);
STATIC_ASSERT(offsetof(MatrixTransform, unsignedArgs) == 0x00);
STATIC_ASSERT(offsetof(MatrixTransform, dig.yaw) == 0x00);
STATIC_ASSERT(offsetof(MatrixTransform, dig.variant) == 0x04);
STATIC_ASSERT(offsetof(MatrixTransform, effectParam) == 0x06);
STATIC_ASSERT(offsetof(MatrixTransform, posY) == 0x10);
STATIC_ASSERT(offsetof(MatrixTransform, posZ) == 0x14);
STATIC_ASSERT(offsetof(MatrixTransform, scale) == 0x08);
STATIC_ASSERT(offsetof(MatrixTransform, x) == 0x0C);

#endif /* MAIN_VEC_TYPES_H */
