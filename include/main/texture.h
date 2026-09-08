#ifndef MAIN_TEXTURE_H_
#define MAIN_TEXTURE_H_

#include "global.h"
#include "dolphin/gx/GXStruct.h"

#define TEXTURE_ANIM_SELECT_NEXT  0x40
#define TEXTURE_ANIM_RANDOM_START 0x20000
#define TEXTURE_ANIM_PING_PONG    0x40000
#define TEXTURE_ANIM_REVERSE      0x80000

/*
 * Texture - the in-memory texture record managed by texture.c
 * (LoadedTextureEntry.texture points at one; textureLoad/textureFree
 * hand them out engine-wide). Field evidence (texture.c):
 *  - width/height/refCount @0xA/0xC/0xE: GXInitTexObj dims; refCount
 *    decremented on release, <=1 makes a cached texture evictable
 *  - wrapS/wrapT @0x17/0x18, minFilter/magFilter @0x19/0x1A,
 *    minLod/maxLod @0x1C/0x1D: textureInitSecondaryGXTexObj's GXInitTexObj /
 *    GXInitTexObjLOD argument loads (mipmap = maxLod > minLod)
 *  - tmemAddr @0x40 + preloaded @0x48: GXLoadTexObjPreLoaded path,
 *    TMEM region released through tmemAddr when preloaded is set
 *  - cached @0x49: nonzero blocks mm_free on release and instead arms
 *    evictTimer @0x4B (10-frame countdown)
 *  - imageOffset @0x50: image data lives at (u8 *)tex + 0x60 +
 *    imageOffset (read as *(int *) for indexing and *(void **) for
 *    null tests - keep the null-test width via launder)
 * Record is variable-length (image data follows the 0x60 header) -
 * sizeof(Texture) is the header size, not the complete allocation size.
 */
typedef struct Texture {
    struct Texture* nextAnimationFrame;
    u8 unk04[0x06];
    u16 width;
    u16 height;
    u16 refCount;
    u16 animationFrameCountFixed; /* Head: frame count in 8.8; non-head/allocated textures use 1. */
    u8 unk12[2];
    union {
        u16 animationFrameStep; /* 8.8 increment per frame. */
        u16 expgfxLinkGroup;
    };
    u8 format;
    u8 wrapS;
    u8 wrapT;
    u8 minFilter;
    u8 magFilter;
    u8 unk1B;
    u8 minLod;
    u8 maxLod;
    u8 unk1E[2];
    GXTexObj gxTexObj;
    u32* tmemAddr;
    u32 dataSize;
    u8 preloaded;
    u8 cached;
    u8 unk4A;
    u8 evictTimer;
    u32 loadedSize;
    s32 imageOffset;
    u8 unk54[0xC];
} Texture;

STATIC_ASSERT(offsetof(Texture, nextAnimationFrame) == 0x00);
STATIC_ASSERT(offsetof(Texture, width) == 0xA);
STATIC_ASSERT(offsetof(Texture, animationFrameCountFixed) == 0x10);
STATIC_ASSERT(offsetof(Texture, animationFrameStep) == 0x14);
STATIC_ASSERT(offsetof(Texture, minLod) == 0x1C);
STATIC_ASSERT(offsetof(Texture, maxLod) == 0x1D);
STATIC_ASSERT(offsetof(Texture, gxTexObj) == 0x20);
STATIC_ASSERT(offsetof(Texture, tmemAddr) == 0x40);
STATIC_ASSERT(offsetof(Texture, dataSize) == 0x44);
STATIC_ASSERT(offsetof(Texture, preloaded) == 0x48);
STATIC_ASSERT(offsetof(Texture, loadedSize) == 0x4C);
STATIC_ASSERT(offsetof(Texture, imageOffset) == 0x50);
STATIC_ASSERT(sizeof(Texture) == 0x60);

static inline GXTexObj* textureGetGXTexObj(Texture* texture) {
    return &texture->gxTexObj;
}

static inline void* textureGetImageData(Texture* texture) {
    return (u8*)texture + sizeof(Texture);
}

static inline GXTexRegion* textureGetGXTexRegion(Texture* texture) {
    return (GXTexRegion*)texture->tmemAddr;
}

void* textureLoadAsset(int asset);
void textureFree(Texture* texture);
void selectTextureWithSecondary(Texture* texture, int mapId);
void selectTexture(Texture* texture, int mapId);

void textureUpdateAnimationFrame(const Texture* texture, u32* animationFlags, s32* frameFixed);
void textureSetAnimationFrameStep(Texture* texture, u16 frameStep);
Texture* textureGetAnimationFrame(Texture* texture, int frameFixed);
void textureSelectAnimationFramePair(void* context, Texture* texture, Texture* forcedTexture, int flags,
                                     int packedFrame, int unused0, int unused1);

#endif
