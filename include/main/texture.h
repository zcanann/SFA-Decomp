#ifndef MAIN_TEXTURE_H_
#define MAIN_TEXTURE_H_

#include "global.h"

/*
 * Texture - the in-memory texture record managed by rcp_dolphin.c
 * (LoadedTextureEntry.texture points at one; textureLoad/textureFree
 * hand them out engine-wide). Field evidence (rcp_dolphin.c):
 *  - width/height/refCount @0xA/0xC/0xE: GXInitTexObj dims; refCount
 *    decremented on release, <=1 makes a cached texture evictable
 *  - wrapS/wrapT @0x17/0x18, minFilter/magFilter @0x19/0x1A,
 *    minLod/maxLod @0x1C/0x1D: fn_80053C40's GXInitTexObj /
 *    GXInitTexObjLOD argument loads (mipmap = maxLod > minLod)
 *  - tmemAddr @0x40 + preloaded @0x48: GXLoadTexObjPreLoaded path,
 *    TMEM region released through tmemAddr when preloaded is set
 *  - cached @0x49: nonzero blocks mm_free on release and instead arms
 *    evictTimer @0x4B (10-frame countdown)
 *  - imageOffset @0x50: image data lives at (u8 *)tex + 0x60 +
 *    imageOffset (read as *(int *) for indexing and *(void **) for
 *    null tests - keep the null-test width via launder)
 * Record is variable-length (image data follows the 0x60 header) -
 * do not take sizeof or index arrays of it.
 */
typedef struct Texture {
    u8 unk00[0xA];
    u16 width;
    u16 height;
    u16 refCount;
    u8 unk10[6];
    u8 unk16;
    u8 wrapS;
    u8 wrapT;
    u8 minFilter;
    u8 magFilter;
    u8 unk1B;
    u8 minLod;
    u8 maxLod;
    u8 unk1E[0x22];
    u32 *tmemAddr;
    u8 unk44[4];
    u8 preloaded;
    u8 cached;
    u8 unk4A;
    u8 evictTimer;
    u8 unk4C[4];
    s32 imageOffset;
    u8 unk54[0xC];
} Texture;

STATIC_ASSERT(offsetof(Texture, width) == 0xA);
STATIC_ASSERT(offsetof(Texture, preloaded) == 0x48);
STATIC_ASSERT(offsetof(Texture, imageOffset) == 0x50);
STATIC_ASSERT(sizeof(Texture) == 0x60);

void *textureLoadAsset(int asset);
void textureFree(u8 *tex);


/* extern-cleanup: consolidated prototypes */
void titlescreen_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void titlescreen_release(void);
void titlescreen_initialise(void);


/* extern-cleanup: consolidated prototypes (true-def sigs) */
void titlescreen_free(u8* obj);
void titlescreen_update(u8* obj);
void titlescreen_init(u8* obj, u8* p);

#endif
