#ifndef MAIN_NEWSHADOWS_INTERNAL_H_
#define MAIN_NEWSHADOWS_INTERNAL_H_

#include "global.h"
#include "main/game_object.h"
#include "main/texture.h"

typedef struct NewShadowEntry
{
    u8 pad00[0x10];
    u8 isActive;
    u8 state;
    u8 pad12[0x2];
} NewShadowEntry;

typedef struct
{
    int id;
    f32 dist;
    int flags;
} ShadowSortEntry;

typedef struct
{
    GameObject* obj;
    f32 scale;
    u8 flags;
} NewShadowCaster;

typedef struct
{
    u16 packedXY;
} NewShadowVectorTexel;

typedef struct
{
    f32 x;
    f32 y;
} NewShadowVector2;

#define NEW_SHADOW_MAX_QUEUED_CASTERS 300
#define NEW_SHADOW_MAX_CASTERS 100
#define NEW_SHADOW_MAX_CAST_TEXTURES 8
#define NEW_SHADOW_FRAME_COUNT 3

typedef struct
{
    f32 modelMtx[12];
    f32 texMtx[12];
    Texture* texture;
    u8 alpha;
    u8 dirIndex;
    u8 pad66[2];
} NewShadowCastSlot;

typedef struct
{
    NewShadowEntry entries[0x21];
    Texture* frameTextures[NEW_SHADOW_FRAME_COUNT];
    u8 pad2A0[0x360 - 0x2A0];
    NewShadowCaster casters[NEW_SHADOW_MAX_QUEUED_CASTERS];
    NewShadowCastSlot castSlots[NEW_SHADOW_MAX_CASTERS];
    Texture* castTextures[NEW_SHADOW_MAX_CAST_TEXTURES];
} NewShadowData;

#define NEW_SHADOW_ENTRY_CAPACITY 0x25

#endif /* MAIN_NEWSHADOWS_INTERNAL_H_ */
