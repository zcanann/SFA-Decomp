#include "dolphin/os/OSReport.h"
#include "main/frame_timing.h"
#include "track/intersect_depth_state_api.h"
#include "main/asset_load.h"
#include "main/map_load.h"
#include "main/shader_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/warpvec.h"
#include "main/zlb.h"
#include "main/dll/cloudaction_interface.h"
#include "main/texture.h"
#include "game/objects/object.h"
#include "main/gameloop_api.h"
#include "sys/objects/lifecycle.h"
#include "main/mapEvent.h"
#include "main/model_light.h"
#include "main/model.h"
#include "main/map_romlist_page.h"
#include "main/map_block.h"
#include "main/shader_init_api.h"
#include "main/newclouds.h"
#include "main/rcp_dolphin.h"
#include "main/rcp_dolphin_api.h"
#include "main/rcp_dolphin_render_api.h"
#include "main/camera.h"
#include "main/loaded_file_flags.h"
#include "main/pi_dolphin.h"
#include "main/screen_transition.h"
#include "main/sky_api.h"
#include "main/sky_interface.h"
#include "main/mm.h"
#include "main/dll/tricky_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/savegame_env_api.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSInterrupt.h"
#include "dolphin/mtx.h"
#include "dolphin/gx/GXDispList.h"
#include "dolphin/gx/GXFrameBuffer.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXGet.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXManage.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXTransform.h"
#include "main/dll/modgfx.h"
#include "main/newshadows.h"
#include "main/pi_dolphin_texture_api.h"
#include "main/gx_scissor_api.h"
#include "string.h"

typedef struct LoadedTextureEntry {
    int key;
    u8* texture;
    u8 flag;
    u8 padding[3];
    u32 size;
} LoadedTextureEntry;

#define LOADED_TEXTURE_CAPACITY 0x2BC

STATIC_ASSERT(sizeof(LoadedTextureEntry) == 0x10);

LoadedTextureEntry* gLoadedTextures;
u16* gRcpTexIdRemap;
int gLoadedTextureCount;
int* gRcpTexHeaderBuffer;
u32 lbl_803DCDB4;
u32 lbl_803DCDB0;
u8 gRcpTexAllocFailed;
u32 gRcpRenderFlags;

int gRcpTexBankCount[3];
int* gRcpTexBankTable[3];

u32 gRcpTexAllocTag = 6;
char sDebugIntLineFormat[] = "%d\n";

void* textureAlloc(u16 w, u16 h, int fmt, u8 mip, u8 maxLod, u8 wrapS, u8 wrapT, u8 minFilter, u8 magFilter);
void textureInitGXTexObj(Texture* texture);

void* textureIdxToPtr(int idx) {
    int i;
    if ((u32)idx & 0x80000000) {
        return (void*)idx;
    }
    i = idx - 1;
    if (i < 0 || i >= gLoadedTextureCount) {
        return NULL;
    }
    return gLoadedTextures[i].texture;
}

extern char sRcpTexRestructStrings[];

void texRestructRefs(int mode) {
    u8* na;
    int i;
    char* strs;
    int done;
    int pass;
    u8* tex;
    u32 size;
    int d;

    strs = (char*)(int)sRcpTexRestructStrings;
    done = 0;
    pass = 0;
    mmSetTextureAllocationState(2);
    OSReport(strs + 0x1164);
    printHeapStats(1);
    OSReport(strs + 0x1194);
    mmSetForceHeaps1and2Only(1);
    for (i = 0; i < gLoadedTextureCount; i++) {
        tex = gLoadedTextures[i].texture;
        if (tex != NULL && gLoadedTextures[i].flag != 0 && ((Texture*)tex)->cached == 0 &&
            (int)gLoadedTextures[i].size != -1 && mmGetRegionForPtr(tex) == 0 && *(void**)tex == NULL) {
            size = gLoadedTextures[i].size;
            na = (u8*)mmAlloc(size, 0xa0a0a0a0, 0);
            if (na == NULL) {
                OSReport(strs + 0x11b4, tex, getHeapItemSize(tex));
            } else if (na != NULL) {
                OSReport(strs + 0x11f4, tex, na, getHeapItemSize(tex));
                done = 0;
                memcpy(na, tex, size);
                DCStoreRange(na, size);
                textureInitGXTexObj((Texture*)na);
                d = mmSetFreeDelay(0);
                mm_free(gLoadedTextures[i].texture);
                mmSetFreeDelay(d);
                gLoadedTextures[i].texture = na;
            }
        }
    }
    mmSetForceHeaps1and2Only(-1);
    OSReport(strs + 0x1238);
    printHeapStats(1);
    defragMemory(2);
    while (done == 0 && pass < 4) {
        done = 1;
        for (i = 0; i < gLoadedTextureCount; i++) {
            tex = gLoadedTextures[i].texture;
            if (tex != NULL && gLoadedTextures[i].flag != 0 && ((Texture*)tex)->cached == 0 &&
                (int)gLoadedTextures[i].size != -1) {
                if (mmGetRegionForPtr(tex) == 0 && *(void**)tex == NULL) {
                    size = gLoadedTextures[i].size;
                    na = (u8*)mmAlloc(size, 0xa0a0a0a0, 0);
                    if (na == NULL) {
                        OSReport(strs + 0x125c, tex, getHeapItemSize(tex));
                    } else if (mmGetRegionForPtr(na) != 0) {
                        OSReport(strs + 0x129c, tex, na, getHeapItemSize(tex));
                        d = mmSetFreeDelay(0);
                        mm_free(na);
                        mmSetFreeDelay(d);
                    } else if (na < tex) {
                        OSReport(strs + 0x12d8, tex, na, getHeapItemSize(tex));
                        d = mmSetFreeDelay(0);
                        mm_free(na);
                        mmSetFreeDelay(d);
                    } else if (na != NULL) {
                        OSReport(strs + 0x1320, tex, na, getHeapItemSize(tex));
                        done = 0;
                        memcpy(na, tex, size);
                        DCStoreRange(na, size);
                        textureInitGXTexObj((Texture*)na);
                        d = mmSetFreeDelay(0);
                        mm_free(gLoadedTextures[i].texture);
                        mmSetFreeDelay(d);
                        gLoadedTextures[i].texture = na;
                    }
                } else if (mode == 0) {
                    if (mmGetRegionForPtr(tex) == 1 || mmGetRegionForPtr(tex) == 2) {
                        if (*(void**)tex == NULL && getHeapItemSize(tex) >= 0x3000) {
                            size = gLoadedTextures[i].size;
                            na = (u8*)mmAlloc(size, 0xa0a0a0a0, 0);
                            if (na == NULL) {
                                OSReport(strs + 0x125c, tex, getHeapItemSize(tex));
                            } else if (mmGetRegionForPtr(na) != 0) {
                                OSReport(strs + 0x1368, tex, na, getHeapItemSize(tex));
                                d = mmSetFreeDelay(0);
                                mm_free(na);
                                mmSetFreeDelay(d);
                            } else if (na != NULL) {
                                OSReport(strs + 0x13c8, tex, na, getHeapItemSize(tex));
                                done = 0;
                                memcpy(na, tex, size);
                                DCStoreRange(na, size);
                                textureInitGXTexObj((Texture*)na);
                                d = mmSetFreeDelay(0);
                                mm_free(gLoadedTextures[i].texture);
                                mmSetFreeDelay(d);
                                gLoadedTextures[i].texture = na;
                            }
                        }
                    }
                }
            }
        }
        printHeapStats(1);
        pass++;
    }
    OSReport(strs + 0x1420, pass);
    mmSetTextureAllocationState(0);
}

void textureInitSecondaryGXTexObj(Texture* tex, GXTexObj* obj) {
    u8 mipmap;
    if ((int)tex->maxLod - (int)tex->minLod > 0) {
        mipmap = 1;
    } else {
        mipmap = 0;
    }
    GXInitTexObj(obj, (u8*)tex + tex->imageOffset + sizeof(Texture), tex->width, tex->height, GX_TF_I4, tex->wrapS,
                 tex->wrapT, mipmap);
    if (mipmap != 0) {
        GXInitTexObjLOD(obj, tex->minFilter, tex->magFilter, (f32)(u32)tex->minLod, (f32)(s32)tex->maxLod, -2.0f, 0, 0,
                        0);
    } else {
        GXInitTexObjLOD(obj, ((Texture*)tex)->minFilter, ((Texture*)tex)->magFilter, 0.0f, 0.0f, 0.0f, 0, 0, 0);
    }
}

void textureInitGXTexObj(Texture* texture) {
    GXBool hasMipmaps = FALSE;
    GXTexObj* gxTexObj;
    u16 width;
    u16 height;
    GXTexFmt format;
    texture->tmemAddr = NULL;
    texture->preloaded = hasMipmaps;
    gxTexObj = textureGetGXTexObj(texture);
    if (texture->maxLod - texture->minLod > 0) {
        hasMipmaps = 1;
    }
    GXInitTexObj(gxTexObj, textureGetImageData(texture), texture->width, texture->height, texture->format,
                 texture->wrapS, texture->wrapT, hasMipmaps);
    if (hasMipmaps != 0) {
        GXInitTexObjLOD(gxTexObj, texture->minFilter, texture->magFilter, (f32)(u32)texture->minLod,
                        (f32)(s32)texture->maxLod, -2.0f, 0, 0, 0);
    } else {
        GXInitTexObjLOD(gxTexObj, texture->minFilter, texture->magFilter, 0.0f, 0.0f, 0.0f, 0, 0, 0);
    }
    GXInitTexObjUserData(gxTexObj, texture);
    format = GXGetTexObjFmt(gxTexObj);
    width = GXGetTexObjWidth(gxTexObj);
    height = GXGetTexObjHeight(gxTexObj);
    texture->dataSize = GXGetTexBufferSize(width, height, format, 0, 0);
}

void Rcp_ClearRenderFlags(u32 bits) {
    gRcpRenderFlags &= ~(u64)bits;
}

void Rcp_SetRenderFlags(u32 bits) {
    gRcpRenderFlags |= bits;
}

void* getLoadedTexture(int key) {
    LoadedTextureEntry* base;
    int i;

    i = 0;
    base = gLoadedTextures;
    for (; i < gLoadedTextureCount; i++) {
        if (key == base[i].key) {
            return base[i].texture;
        }
    }
    return NULL;
}

void textureUpdateAnimationFrame(const Texture* texture, u32* animationFlags, s32* frameFixed) {
    u32 reverse, pingPong, randomStart;
    u32 flags;
    int roll;
    int reflected;

    flags = *animationFlags;
    reverse = flags & TEXTURE_ANIM_REVERSE;
    pingPong = flags & TEXTURE_ANIM_PING_PONG;
    randomStart = flags & TEXTURE_ANIM_RANDOM_START;
    if (randomStart != 0) {
        if (pingPong == 0) {
            roll = randomGetRange(0, 0x3e8);
            if (roll > 0x3d9) {
                *animationFlags &= ~TEXTURE_ANIM_REVERSE;
                *animationFlags |= TEXTURE_ANIM_PING_PONG;
            }
        } else if (reverse == 0) {
            *frameFixed += texture->animationFrameStep * framesThisStep;
            if (*frameFixed >= texture->animationFrameCountFixed) {
                *frameFixed = texture->animationFrameCountFixed * 2 - 1 - *frameFixed;
                if (*frameFixed < 0) {
                    *frameFixed = 0;
                    *animationFlags &= ~(TEXTURE_ANIM_REVERSE | TEXTURE_ANIM_PING_PONG);
                } else {
                    *animationFlags |= TEXTURE_ANIM_REVERSE;
                }
            }
        } else {
            *frameFixed -= texture->animationFrameStep * framesThisStep;
            if (*frameFixed < 0) {
                *frameFixed = 0;
                *animationFlags &= ~(TEXTURE_ANIM_REVERSE | TEXTURE_ANIM_PING_PONG);
            }
        }
    } else if (pingPong != 0) {
        if (reverse == 0) {
            *frameFixed += texture->animationFrameStep * framesThisStep;
        } else {
            *frameFixed -= texture->animationFrameStep * framesThisStep;
        }
        do {
            reflected = 0;
            if (*frameFixed < 0) {
                *frameFixed = -*frameFixed;
                *animationFlags &= ~TEXTURE_ANIM_REVERSE;
                reflected = 1;
            }
            if (*frameFixed >= texture->animationFrameCountFixed) {
                *frameFixed = texture->animationFrameCountFixed * 2 - 1 - *frameFixed;
                *animationFlags |= TEXTURE_ANIM_REVERSE;
                reflected = 1;
            }
        } while (reflected != 0);
    } else if (reverse == 0) {
        *frameFixed += texture->animationFrameStep * framesThisStep;
        while (*frameFixed >= texture->animationFrameCountFixed) {
            *frameFixed -= texture->animationFrameCountFixed;
        }
    } else {
        *frameFixed -= texture->animationFrameStep * framesThisStep;
        while (*frameFixed < 0) {
            *frameFixed += texture->animationFrameCountFixed;
        }
    }
}

void textureSetAnimationFrameStep(Texture* texture, u16 frameStep) {
    texture->animationFrameStep = frameStep;
}

void textureSelectAnimationFramePair(void* context, Texture* texture, Texture* forcedTexture, int flags, int packedFrame,
                                     int unused0, int unused1) {
    int i;
    int idx, count;
    Texture* node;
    Texture* current;
    Texture* result;
    Texture* walk;
    u16 animationFrameCountFixed;

    if (texture == NULL) {
        return;
    }
    idx = packedFrame >> 16;
    animationFrameCountFixed = texture->animationFrameCountFixed;
    if (animationFrameCountFixed != 0) {
        count = animationFrameCountFixed >> 8;
    } else {
        count = 0;
    }
    current = texture;
    result = texture;
    if (count > 1 && idx < count) {
        node = texture;
        for (i = 0; i < idx && node != NULL; i++) {
            node = node->nextAnimationFrame;
        }
        if (node != NULL) {
            current = node;
        }
        if (flags & TEXTURE_ANIM_SELECT_NEXT) {
            if (flags & TEXTURE_ANIM_REVERSE) {
                idx--;
                if (idx < 0) {
                    if (flags & TEXTURE_ANIM_PING_PONG) {
                        idx += 2;
                    } else {
                        idx = 0;
                    }
                }
            } else {
                idx++;
                if (idx >= count) {
                    if (flags & TEXTURE_ANIM_PING_PONG) {
                        idx -= 2;
                    } else {
                        idx = count - 1;
                    }
                }
            }
            walk = texture;
            for (i = 0; i < idx && walk != NULL; i++) {
                walk = walk->nextAnimationFrame;
            }
            if (walk != NULL) {
                result = walk;
            }
        } else {
            result = current;
        }
    }
    if (forcedTexture != NULL) {
        result = forcedTexture;
    }
    selectTexture(current, 0);
    selectTexture(result, 1);
}

void Rcp_ResetRenderState(void) {
    gRcpRenderFlags = 0;
    lbl_803DCDB4 = 0;
    lbl_803DCDB0 = 0;
}

void textureFree(Texture* tex) {
    Texture* iter;
    Texture* next;
    if ((u8*)tex == gLoadedTextures[0].texture) {
        return;
    }
    if (tex == NULL) {
        ((Texture*)tex)->evictTimer = 10;
        return;
    }
    if (((Texture*)tex)->refCount == 0) {
        ((Texture*)tex)->evictTimer = 10;
        return;
    }
    if (((Texture*)tex)->cached != 0 && ((Texture*)tex)->refCount <= 1) {
        ((Texture*)tex)->evictTimer = 10;
    }
    (((Texture*)tex)->refCount)--;
    if (((Texture*)tex)->refCount != 0) {
        return;
    }
    {
        int i;
        for (i = 0; i < gLoadedTextureCount; i++) {
            if (gLoadedTextures[i].texture == (u8*)tex) {
                iter = tex->nextAnimationFrame;
                while (iter != NULL) {
                    if ((u32)iter < 0x80000000 || (u32)iter > 0x81800000) {
                        iter = NULL;
                    }
                    if ((u32)iter < 0x80000000 || (u32)iter >= 0xa0000000) {
                        iter = NULL;
                        continue;
                    }
                    if (iter == NULL) {
                        continue;
                    }
                    next = iter->nextAnimationFrame;
                    if (iter->preloaded != 0) {
                        newshadows_releaseTextureEntry((void*)iter->tmemAddr);
                    }
                    if (iter->cached == 0) {
                        mm_free(iter);
                    }
                    iter = next;
                }
                if (((Texture*)tex)->preloaded != 0) {
                    newshadows_releaseTextureEntry((void*)((Texture*)tex)->tmemAddr);
                }
                if (((Texture*)tex)->cached == 0) {
                    mm_free(tex);
                }
                gLoadedTextures[i].key = -1;
                gLoadedTextures[i].texture = NULL;
                return;
            }
        }
    }
}
static inline void loadTextureBank(int bank, int fileId) {
    int* p;
    int n = 0;

    p = getCurrentDataFile(fileId);
    gRcpTexBankTable[bank] = p;
    if (gRcpTexBankTable == NULL) {
        return;
    }
    while (p[0] != -1) {
        p++;
        n++;
    }
    gRcpTexBankCount[bank] = n - 1;
}

void* textureLoad(int texId, u8 useHandle) {
    int fileId;
    int bank;
    int bankIndex;
    u32 size;
    Texture* buf;
    Texture* firstTex;
    Texture* prevTex;
    int slot;
    Texture* walk;
    u32 bankWord;
    int bankWordSaved;
    BOOL interruptState;
    int origTexId;
    int frameCountFixed;
    u16 remapped;
    int dataByteOffset;
    int frameCount;
    int frameIndex;
    int storedSize;
    int n;
    int decompressedSize;
    int compressedSize;
    BOOL interruptsDisabled;
    int bankWordHeld;

    interruptState = TRUE;
    interruptsDisabled = FALSE;
    if (texId < 0) {
        n = -texId;
        if (n & 0x8000) {
            slot = n & 0x7fff;
            if (slot == 0x82e) {
                OSReport(sDebugIntLineFormat, slot);
            }
        }
    }
    for (n = 0; n < gLoadedTextureCount; n++) {
        if (texId == gLoadedTextures[n].key) {
            buf = (Texture*)gLoadedTextures[n].texture;
            buf->refCount += 1;
            if (useHandle != 0 && gLoadedTextures[n].flag != 0) {
                return (void*)(n + 1);
            }
            return buf;
        }
    }
    if (getLoadedFileFlags(0) != 0) {
        interruptState = OSDisableInterrupts();
        interruptsDisabled = TRUE;
    }
    origTexId = texId;
    if (texId < 0) {
        texId = -texId;
    } else if (texId >= 0xbb8 && (remapped = gRcpTexIdRemap[texId]) != 0) {
        texId = remapped + 1;
    } else {
        texId = gRcpTexIdRemap[texId];
    }
    bankIndex = texId & 0xffff;
    if (texId & 0x8000) {
        bank = 1;
        fileId = 0x20;
        bankIndex &= 0x7fff;
    } else if (origTexId >= 0xbb8) {
        bank = 2;
        fileId = 0x4f;
    } else {
        bank = 0;
        fileId = 0x23;
    }
    if (bankIndex >= gRcpTexBankCount[bank] || bankIndex < 0) {
        bankIndex = 0;
    }
    loadTextureBank(0, MLDF_FILEID_TEX0_TAB_A);
    loadTextureBank(1, MLDF_FILEID_TEX1_TAB_A);
    bankWord = gRcpTexBankTable[bank][bankIndex];
    frameCount = (bankWord >> TEX_TAB_FRAME_COUNT_SHIFT) & TEX_TAB_FRAME_COUNT_MASK;
    bankWordSaved = bankWord;
    if (frameCount == 1) {
        if (bank == 0) {
            tex0GetFrame(bankWord, bankIndex, &decompressedSize, &compressedSize, frameCount, 0,
                         TEXTURE_FRAME_QUERY_HEADER);
        } else if (bank == 2) {
            texPreGetFrame(bankWord, bankIndex, &decompressedSize, &compressedSize, frameCount, 0,
                           TEXTURE_FRAME_QUERY_HEADER);
        } else {
            tex1GetFrame(bankWord, bankIndex, &decompressedSize, &compressedSize, frameCount, 0,
                         TEXTURE_FRAME_QUERY_HEADER);
        }
        gRcpTexHeaderBuffer[0] = 0;
        gRcpTexHeaderBuffer[1] = decompressedSize;
        if (compressedSize == -1) {
            gRcpTexHeaderBuffer[2] = decompressedSize;
        } else {
            gRcpTexHeaderBuffer[2] = compressedSize;
        }
    } else if (bank == 0) {
        tex0GetFrame(bankWord, bankIndex, &decompressedSize, &compressedSize, frameCount, gRcpTexHeaderBuffer,
                     TEXTURE_FRAME_QUERY_OFFSETS);
    } else if (bank == 2) {
        texPreGetFrame(bankWord, bankIndex, &decompressedSize, &compressedSize, frameCount, gRcpTexHeaderBuffer,
                       TEXTURE_FRAME_QUERY_OFFSETS);
    } else {
        tex1GetFrame(bankWord, bankIndex, &decompressedSize, &compressedSize, frameCount, gRcpTexHeaderBuffer,
                     TEXTURE_FRAME_QUERY_OFFSETS);
    }
    firstTex = NULL;
    prevTex = NULL;
    frameIndex = 0;
    bankWordHeld = bankWordSaved;
    frameCountFixed = frameCount << 8;
    dataByteOffset = (bankWordSaved & 0xffffff) << 1;
    for (; frameIndex < frameCount; frameIndex++) {
        if (frameCount > 1) {
            if (bank == 0) {
                tex0GetFrame(bankWordHeld, bankIndex, &decompressedSize, &compressedSize, frameIndex,
                             gRcpTexHeaderBuffer, TEXTURE_FRAME_QUERY_INDEXED_HEADER);
            } else if (bank == 2) {
                texPreGetFrame(bankWordHeld, bankIndex, &decompressedSize, &compressedSize, frameIndex,
                               gRcpTexHeaderBuffer, TEXTURE_FRAME_QUERY_INDEXED_HEADER);
            } else {
                tex1GetFrame(bankWordHeld, bankIndex, &decompressedSize, &compressedSize, frameIndex,
                             gRcpTexHeaderBuffer, TEXTURE_FRAME_QUERY_INDEXED_HEADER);
            }
        }
        size = decompressedSize;
        if (compressedSize == -1) {
            storedSize = decompressedSize;
        } else {
            storedSize = compressedSize;
            mmSetTextureAllocationState(1);
            buf = mmAlloc(size, gRcpTexAllocTag, 0);
            mmSetTextureAllocationState(0);
            if (buf == NULL) {
                gRcpTexAllocFailed = 1;
                if (getLoadedFileFlags(0) != 0 && interruptsDisabled == TRUE) {
                    OSRestoreInterrupts(interruptState);
                } else if (interruptsDisabled == TRUE) {
                    OSRestoreInterrupts(interruptState);
                }
                if (useHandle != 0) {
                    return (void*)1;
                }
                return gLoadedTextures[0].texture;
            }
        }
        if (compressedSize != -1 && buf == NULL) {
            if (frameIndex == 0) {
                gRcpTexAllocFailed = 1;
                if (getLoadedFileFlags(0) != 0 && interruptsDisabled == TRUE) {
                    OSRestoreInterrupts(interruptState);
                } else if (interruptsDisabled == TRUE) {
                    OSRestoreInterrupts(interruptState);
                }
                if (useHandle != 0) {
                    return (void*)1;
                }
                return gLoadedTextures[0].texture;
            } else {
                firstTex->animationFrameCountFixed = frameCountFixed;
                frameIndex = frameCount;
                continue;
            }
        }
        if (compressedSize == -1) {
            buf = loadAndDecompressDataFile(fileId, 0, dataByteOffset + gRcpTexHeaderBuffer[frameIndex], storedSize, 0,
                                            bankIndex, 0);
            buf->cached = 1;
            if (useHandle != 0) {
                useHandle = 0;
            }
            buf->refCount = 1;
        } else {
            loadAndDecompressDataFile(fileId, buf, dataByteOffset + gRcpTexHeaderBuffer[frameIndex], storedSize, 0,
                                      bankIndex, 0);
        }
        if (compressedSize != -1) {
            DCStoreRange(buf, size);
        }
        buf->nextAnimationFrame = NULL;
        if (prevTex != NULL) {
            prevTex->nextAnimationFrame = buf;
        }
        prevTex = buf;
        if (frameIndex == 0) {
            firstTex = buf;
            buf->animationFrameCountFixed = frameCountFixed;
        } else {
            buf->animationFrameCountFixed = 1;
        }
    }
    walk = firstTex;
    firstTex->loadedSize = size;
    for (slot = 0; slot < gLoadedTextureCount; slot++) {
        if (gLoadedTextures[slot].key == -1) {
            break;
        }
    }
    if (slot == gLoadedTextureCount) {
        gLoadedTextureCount += 1;
    }
    gLoadedTextures[slot].key = origTexId;
    gLoadedTextures[slot].texture = (u8*)firstTex;
    gLoadedTextures[slot].flag = useHandle;
    gLoadedTextures[slot].size = getHeapItemSize(gLoadedTextures[slot].texture);
    if (gLoadedTextureCount > LOADED_TEXTURE_CAPACITY) {
        if (getLoadedFileFlags(0) != 0 && interruptsDisabled == TRUE) {
            OSRestoreInterrupts(interruptState);
        } else if (interruptsDisabled == TRUE) {
            OSRestoreInterrupts(interruptState);
        }
        if (useHandle != 0) {
            return (void*)1;
        }
        return gLoadedTextures[0].texture;
    }
    while (walk != NULL) {
        textureInitGXTexObj(walk);
        walk = walk->nextAnimationFrame;
    }
    if (getLoadedFileFlags(0) != 0 && interruptsDisabled == TRUE) {
        OSRestoreInterrupts(interruptState);
    } else if (interruptsDisabled == TRUE) {
        OSRestoreInterrupts(interruptState);
    }
    if (useHandle != 0) {
        return (void*)(slot + 1);
    }
    return firstTex;
}

Texture* textureGetAnimationFrame(Texture* texture, int frameFixed) {
    int limit = texture->animationFrameCountFixed;
    int i;
    if (frameFixed >= limit) {
        frameFixed = limit - 1;
    }
    frameFixed >>= 8;
    for (i = 0; i < frameFixed; i++) {
        texture = texture->nextAnimationFrame;
    }
    return texture;
}
void* textureAlloc(u16 w, u16 h, int fmt, u8 mip, u8 maxLod, u8 wrapS, u8 wrapT, u8 minFilter, u8 magFilter) {
    Texture* obj;
    u32 size = GXGetTexBufferSize(w, h, fmt, mip, maxLod) + (u32)sizeof(Texture);
    obj = mmAlloc(size, 6, 0);
    if (obj == NULL) {
        return NULL;
    }
    memset(obj, 0, sizeof(Texture) + 4);
    obj->format = fmt;
    obj->width = w;
    obj->height = h;
    obj->animationFrameCountFixed = 1;
    obj->refCount = 0;
    obj->wrapS = wrapS;
    obj->wrapT = wrapT;
    obj->minFilter = minFilter;
    obj->magFilter = magFilter;
    obj->imageOffset = 0;
    textureInitGXTexObj(obj);
    return obj;
}

void* textureLoadAsset(int asset) {
    void* out = NULL;
    if (getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED) {
        return NULL;
    }
    loadTextureFile(&out, asset);
    return out;
}

void loadTextureFiles(void) {
    int* bankEntry;
    int** bankTable;
    int* bankCount;
    int count;

    gLoadedTextures = mmAlloc(LOADED_TEXTURE_CAPACITY * sizeof(LoadedTextureEntry), 6, 0);
    gLoadedTextureCount = 0;
    loadTextureBank(0, MLDF_FILEID_TEX0_TAB_A);
    loadTextureBank(1, MLDF_FILEID_TEX1_TAB_A);
    count = 0;
    bankEntry = getCurrentDataFile(MLDF_FILEID_TEXPRE_TAB);
    gRcpTexBankTable[2] = bankEntry;
    while (bankEntry[0] != -1) {
        bankEntry++;
        count++;
    }
    gRcpTexBankCount[2] = count - 1;
    loadAssetFileById(&gRcpTexIdRemap, MLDF_FILEID_TEXTABLE_BIN);
    bankTable = gRcpTexBankTable;
    bankCount = gRcpTexBankCount;
    for (count = 0; count < 2; count++) {
        int entryCount = 0;
        bankEntry = bankTable[0];
        while (bankEntry[0] != -1) {
            bankEntry++;
            entryCount++;
        }
        bankCount[0] = entryCount - 1;
        bankTable++;
        bankCount++;
    }
    gRcpTexHeaderBuffer = mmAlloc(0x120, 6, 0);
    textureLoad(0, 0);
}

char sRcpTexRestructStrings[] = {
    0xFC, 0x12, 0x16, 0x03, 0xFF, 0xFF, 0xFF, 0xF8, 0xFC, 0x12, 0x16, 0x03, 0xFF, 0xFF, 0xFF, 0xF8,
};

u32 lbl_8030D068[32] = {0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038,
                        0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8,
                        0xef182c00, 0xcb024000, 0xef182c00, 0xc8112008, 0xef182c00, 0xc8112230, 0xef182c00, 0xc8112038,
                        0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8104a50, 0xef182c00, 0xc81049d8};
u32 lbl_8030D0E8[32] = {0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038,
                        0xef182c00, 0x00104340, 0xef182c00, 0x00104340, 0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50,
                        0xef182c00, 0xcb024000, 0xef182c00, 0xc8112008, 0xef182c00, 0xc8112230, 0xef182c00, 0xc8112038,
                        0xef182c00, 0xc8104340, 0xef182c00, 0xc8104340, 0xef182c00, 0xc8104b50, 0xef182c00, 0xc8104b50};
u32 lbl_8030D168[4] = {0xfc41ffff, 0xfffff638, 0xfc41ffff, 0xfffff638};
u32 lbl_8030D178[32] = {0xef180c00, 0x03024000, 0xef180c00, 0x00112008, 0xef180c00, 0x00112230, 0xef180c00, 0x00112038,
                        0xef180c00, 0x00104240, 0xef180c00, 0x001041c8, 0xef180c00, 0x00104a50, 0xef180c00, 0x001049d8,
                        0xef180c00, 0xcb024000, 0xef180c00, 0xc8112008, 0xef180c00, 0xc8112230, 0xef180c00, 0xc8112038,
                        0xef180c00, 0xc8104240, 0xef180c00, 0xc81041c8, 0xef180c00, 0xc8104a50, 0xef180c00, 0xc81049d8};
u32 lbl_8030D1F8[4] = {0xfc121803, 0xff0fffff, 0xfc121803, 0xff0fffff};
u32 lbl_8030D208[32] = {0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8,
                        0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8,
                        0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8,
                        0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8};
u32 lbl_8030D288[4] = {0xfc41c683, 0xff8fffff, 0xfc41c683, 0xff8fffff};
u32 lbl_8030D298[32] = {0xef080c00, 0x0c184240, 0xef080c00, 0x005461c8, 0xef080c00, 0x00546a70, 0xef080c00, 0x005469f8,
                        0xef080c00, 0x00504240, 0xef080c00, 0x005041c8, 0xef080c00, 0x00504a50, 0xef080c00, 0x005049d8,
                        0xef080c00, 0x0c184240, 0xef080c00, 0x005461c8, 0xef080c00, 0x00546a70, 0xef080c00, 0x005469f8,
                        0xef080c00, 0x00504240, 0xef080c00, 0x005041c8, 0xef080c00, 0x00504a50, 0xef080c00, 0x005049d8};
u32 lbl_8030D318[4] = {0xfc12160b, 0xfffffff8, 0xfc12160b, 0xfffffff8};
u32 lbl_8030D328[16] = {0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038,
                        0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8};
u32 lbl_8030D368[4] = {0xfc45ffff, 0xfffff638, 0xfc45ffff, 0xfffff638};
u32 lbl_8030D378[16] = {0xef180c00, 0x03024000, 0xef180c00, 0x00112008, 0xef180c00, 0x00112230, 0xef180c00, 0x00112038,
                        0xef180c00, 0x00104240, 0xef180c00, 0x001041c8, 0xef180c00, 0x00104a50, 0xef180c00, 0x001049d8};
u32 lbl_8030D3B8[4] = {0xfc12166b, 0xf0fffe38, 0xfc12166b, 0xf0fffe38};
u32 lbl_8030D3C8[16] = {0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038,
                        0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8};
u32 lbl_8030D408[4] = {0xfc35ffff, 0x4ffc7638, 0xfc35ffff, 0x4ffc7638};
u32 lbl_8030D418[16] = {0xef180c00, 0x03024000, 0xef180c00, 0x00112008, 0xef180c00, 0x00112230, 0xef180c00, 0x00112038,
                        0xef180c00, 0x00104240, 0xef180c00, 0x001041c8, 0xef180c00, 0x00104a50, 0xef180c00, 0x001049d8};
u32 lbl_8030D458[4] = {0xfc26a04d, 0x11409249, 0xfc26a004, 0x1f0c93ff};
u32 lbl_8030D468[32] = {0xef192c00, 0x03024000, 0xef192c00, 0x00112008, 0xef192c00, 0x00112230, 0xef192c00, 0x00112038,
                        0xef192c00, 0x00104240, 0xef192c00, 0x001041c8, 0xef192c00, 0x00104a50, 0xef192c00, 0x001049d8,
                        0xef192c00, 0xcb024000, 0xef192c00, 0xc8112008, 0xef192c00, 0xc8112230, 0xef192c00, 0xc8112038,
                        0xef192c00, 0xc8104240, 0xef192c00, 0xc81041c8, 0xef192c00, 0xc8104a50, 0xef192c00, 0xc81049d8};
u32 lbl_8030D4E8[4] = {0xfc22aa04, 0x1f0c93ff, 0xfc22aa04, 0x1f0c93ff};
u32 lbl_8030D4F8[32] = {0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038,
                        0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8,
                        0xef182c00, 0xcb024000, 0xef182c00, 0xc8112008, 0xef182c00, 0xc8112230, 0xef182c00, 0xc8112038,
                        0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8104a50, 0xef182c00, 0xc81049d8};
u32 lbl_8030D578[4] = {0xfc22aa04, 0x1f1093ff, 0xfc22aa04, 0x1f1093ff};
u32 lbl_8030D588[4] = {0xfc25a804, 0x1f0c93ff, 0xfc25a804, 0x1f0c93ff};
u32 lbl_8030D598[4] = {0xfc25a803, 0x1f0c93ff, 0xfc25a803, 0x1f0c93ff};
u32 lbl_8030D5A8[4] = {0xfc119623, 0xff2fffff, 0xfc1196ac, 0xf0fffe38};
u32 lbl_8030D5B8[4] = {0xfc367ea0, 0x5f0ef3ff, 0xfc367ea0, 0x5f0ef3ff};
u32 lbl_8030D5C8[32] = {0xef082c00, 0x00504240, 0xef082c00, 0x005041c8, 0xef082c00, 0x00553078, 0xef082c00, 0x005045d8,
                        0xef082c00, 0x00504240, 0xef082c00, 0x005041c8, 0xef082c00, 0x00553078, 0xef082c00, 0x005045d8,
                        0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8113078, 0xef182c00, 0xc81045d8,
                        0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc81045f8, 0xef182c00, 0xc81045d8};
u32 lbl_8030D648[32] = {0xef080c00, 0x00504240, 0xef080c00, 0x005041c8, 0xef080c00, 0x00553078, 0xef080c00, 0x005045d8,
                        0xef080c00, 0x00504240, 0xef080c00, 0x005041c8, 0xef080c00, 0x00553078, 0xef080c00, 0x005045d8,
                        0xef180c00, 0xc8104240, 0xef180c00, 0xc81041c8, 0xef180c00, 0xc8113078, 0xef180c00, 0xc81045d8,
                        0xef180c00, 0xc8104240, 0xef180c00, 0xc81041c8, 0xef180c00, 0xc81045f8, 0xef180c00, 0xc81045d8};
u32 lbl_8030D6C8[32] = {0xef082c80, 0x00504240, 0xef082c80, 0x005041c8, 0xef082c80, 0x00553078, 0xef082c80, 0x00504b50,
                        0xef082c80, 0x00504240, 0xef082c80, 0x005041c8, 0xef082c80, 0x00553078, 0xef082c80, 0x00504b50,
                        0xef182c80, 0xc8104240, 0xef182c80, 0xc81041c8, 0xef182c80, 0xc8113078, 0xef182c80, 0xc8104b50,
                        0xef182c80, 0xc8104240, 0xef182c80, 0xc81041c8, 0xef182c80, 0xc81045f8, 0xef182c80, 0xc8104b50};
u32 lbl_8030D748[4] = {0xfc22aa04, 0x1f0c93ff, 0xfc22aa04, 0x1f0c93ff};
u32 lbl_8030D758[32] = {0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00113078, 0xef182c00, 0x001045d8,
                        0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x001045f8, 0xef182c00, 0x001045d8,
                        0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8113078, 0xef182c00, 0xc81045d8,
                        0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc81045f8, 0xef182c00, 0xc81045d8};
u32 lbl_8030D7D8[32] = {0xef180c00, 0x00104240, 0xef180c00, 0x001041c8, 0xef180c00, 0x00113078, 0xef180c00, 0x001045d8,
                        0xef180c00, 0x00104240, 0xef180c00, 0x001041c8, 0xef180c00, 0x001045f8, 0xef180c00, 0x001045d8,
                        0xef180c00, 0xc8104240, 0xef180c00, 0xc81041c8, 0xef180c00, 0xc8113078, 0xef180c00, 0xc81045d8,
                        0xef180c00, 0xc8104240, 0xef180c00, 0xc81041c8, 0xef180c00, 0xc81045f8, 0xef180c00, 0xc81045d8};
u32 lbl_8030D858[4] = {0xfc121603, 0xfffffff8, 0xfc121603, 0xfffffff8};
u32 lbl_8030D868[32] = {0xef182c00, 0x00112e10, 0xef182c00, 0x00112d18, 0xef182c00, 0x00112e10, 0xef182c00, 0x00112d18,
                        0xef182c00, 0x00104e50, 0xef182c00, 0x00104dd8, 0xef182c00, 0x00104e50, 0xef182c00, 0x00104dd8,
                        0xef182c00, 0xc8112e10, 0xef182c00, 0xc8112d18, 0xef182c00, 0xc8112e10, 0xef182c00, 0xc8112d18,
                        0xef182c00, 0xc8104e50, 0xef182c00, 0xc8104dd8, 0xef182c00, 0xc8104e50, 0xef182c00, 0xc8104dd8};
u32 lbl_8030D8E8[4] = {0xfc121603, 0xfffffff8, 0xfc121603, 0xfffffff8};
u32 lbl_8030D8F8[32] = {0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00111338, 0xef182c00, 0x00111038,
                        0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00111338, 0xef182c00, 0x00111038,
                        0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8111338, 0xef182c00, 0xc8111038,
                        0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8111338, 0xef182c00, 0xc8111038};
u32 lbl_8030D978[16] = {0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8113078, 0xef182c00, 0xc8105858,
                        0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8113078, 0xef182c00, 0xc8105858};
u32 lbl_8030D9B8[4] = {0xfc121803, 0xff0fffff, 0xfc121803, 0xff0fffff};
u32 lbl_8030D9C8[32] = {0xef182c00, 0x00104e50, 0xef182c00, 0x00104dd8, 0xef182c00, 0x00104e50, 0xef182c00, 0x00104dd8,
                        0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50,
                        0xef182c00, 0x00104e50, 0xef182c00, 0x00104dd8, 0xef182c00, 0x00104e50, 0xef182c00, 0x00104dd8,
                        0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50};
u32 lbl_8030DA48[4] = {0xfc26a004, 0x1f1093ff, 0xfc26a004, 0x1f1093ff};
u32 lbl_8030DA58[32] = {0xef192c00, 0x00104e50, 0xef192c00, 0x00104dd8, 0xef192c00, 0x00104e50, 0xef192c00, 0x00104dd8,
                        0xef192c00, 0x00104a50, 0xef192c00, 0x001049d8, 0xef192c00, 0x00104a50, 0xef192c00, 0x001049d8,
                        0xef192c00, 0x00104e50, 0xef192c00, 0x00104dd8, 0xef192c00, 0x00104e50, 0xef192c00, 0x00104dd8,
                        0xef192c00, 0x00104a50, 0xef192c00, 0x001049d8, 0xef192c00, 0x00104a50, 0xef192c00, 0x001049d8};
u32 lbl_8030DAD8[4] = {0xfc121603, 0xff0fffff, 0xfc121603, 0xff0fffff};
u32 lbl_8030DAE8[32] = {0xef182c00, 0x03024000, 0xef182c00, 0x00112248, 0xef182c00, 0x00112230, 0xef182c00, 0x00112278,
                        0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8,
                        0xef182c00, 0xcb024000, 0xef182c00, 0xc8112248, 0xef182c00, 0xc8112230, 0xef182c00, 0xc8112278,
                        0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8104a50, 0xef182c00, 0xc81049d8};
u32 lbl_8030DB68[4] = {0xfc26a004, 0x1f0c93ff, 0xfc26a004, 0x1f0c93ff};
u32 lbl_8030DB78[32] = {0xef192c00, 0x03024000, 0xef192c00, 0x00112248, 0xef192c00, 0x00112230, 0xef192c00, 0x00112278,
                        0xef192c00, 0x00104240, 0xef192c00, 0x001041c8, 0xef192c00, 0x00104a50, 0xef192c00, 0x001049d8,
                        0xef192c00, 0xcb024000, 0xef192c00, 0xc8112248, 0xef192c00, 0xc8112230, 0xef192c00, 0xc8112278,
                        0xef192c00, 0xc8104240, 0xef192c00, 0xc81041c8, 0xef192c00, 0xc8104a50, 0xef192c00, 0xc81049d8};
u32 lbl_8030DBF8[4] = {0xfc55fe04, 0x1ffcfdfe, 0xfc55fe04, 0x1ffcfdfe};
u32 lbl_8030DC08[32] = {0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038,
                        0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8,
                        0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038,
                        0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8};

u32 lbl_8030DC88[208] = {(u32)sRcpTexRestructStrings, (u32)lbl_8030D068, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D1F8,           (u32)lbl_8030D208, 0x00000007, 0x00000004,
                         (u32)lbl_8030D318,           (u32)lbl_8030D328, 0x00000007, 0x00000000,
                         (u32)lbl_8030D3B8,           (u32)lbl_8030D3C8, 0x00000007, 0x00000000,
                         (u32)lbl_8030D4E8,           (u32)lbl_8030D4F8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D578,           (u32)lbl_8030D4F8, 0x00000007, 0x00000004,
                         (u32)lbl_8030D588,           (u32)lbl_8030D4F8, 0x00000007, 0x00000000,
                         (u32)lbl_8030D598,           (u32)lbl_8030D4F8, 0x00000007, 0x00000000,
                         (u32)lbl_8030D858,           (u32)lbl_8030D868, 0x0000000f, 0x00000002,
                         (u32)lbl_8030D858,           (u32)lbl_8030D868, 0x0000000f, 0x00000002,
                         (u32)lbl_8030D858,           (u32)lbl_8030D868, 0x0000000f, 0x00000002,
                         (u32)lbl_8030D858,           (u32)lbl_8030D868, 0x0000000f, 0x00000002,
                         (u32)lbl_8030D4E8,           (u32)lbl_8030D868, 0x0000000f, 0x00000002,
                         (u32)lbl_8030D578,           (u32)lbl_8030D868, 0x0000000f, 0x00000006,
                         (u32)lbl_8030D588,           (u32)lbl_8030D868, 0x0000000f, 0x00000002,
                         (u32)lbl_8030D598,           (u32)lbl_8030D868, 0x0000000f, 0x00000002,
                         (u32)lbl_8030D8E8,           (u32)lbl_8030D8F8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D8E8,           (u32)lbl_8030D8F8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D8E8,           (u32)lbl_8030D8F8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D8E8,           (u32)lbl_8030D8F8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D4E8,           (u32)lbl_8030D978, 0x00000007, 0x00000000,
                         (u32)lbl_8030D578,           (u32)lbl_8030D978, 0x00000007, 0x00000004,
                         (u32)lbl_8030D588,           (u32)lbl_8030D978, 0x00000007, 0x00000000,
                         (u32)lbl_8030D598,           (u32)lbl_8030D978, 0x00000007, 0x00000000,
                         (u32)lbl_8030DAD8,           (u32)lbl_8030DAE8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D1F8,           (u32)lbl_8030DAE8, 0x0000000f, 0x00000004,
                         (u32)lbl_8030D318,           (u32)lbl_8030DAE8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D3B8,           (u32)lbl_8030DAE8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D4E8,           (u32)lbl_8030DAE8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D578,           (u32)lbl_8030DAE8, 0x0000000f, 0x00000004,
                         (u32)lbl_8030D588,           (u32)lbl_8030DAE8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D598,           (u32)lbl_8030DAE8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D458,           (u32)lbl_8030D468, 0x0000000f, 0x00000000,
                         (u32)lbl_8030DB68,           (u32)lbl_8030DB78, 0x00000007, 0x00000000,
                         (u32)lbl_8030D9B8,           (u32)lbl_8030D9C8, 0x00000007, 0x00000002,
                         (u32)lbl_8030DA48,           (u32)lbl_8030DA58, 0x00000007, 0x00000002,
                         (u32)lbl_8030DBF8,           (u32)lbl_8030DC08, 0x0000000b, 0x00000000,
                         (u32)sRcpTexRestructStrings, (u32)lbl_8030D0E8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D168,           (u32)lbl_8030D178, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D288,           (u32)lbl_8030D298, 0x00000007, 0x00000004,
                         (u32)lbl_8030D368,           (u32)lbl_8030D378, 0x00000007, 0x00000000,
                         (u32)lbl_8030D408,           (u32)lbl_8030D418, 0x00000007, 0x00000000,
                         (u32)lbl_8030D168,           (u32)lbl_8030D178, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D288,           (u32)lbl_8030D298, 0x00000007, 0x00000004,
                         (u32)lbl_8030D368,           (u32)lbl_8030D378, 0x00000007, 0x00000000,
                         (u32)lbl_8030D408,           (u32)lbl_8030D418, 0x00000007, 0x00000000,
                         (u32)lbl_8030D5A8,           (u32)lbl_8030D5C8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D748,           (u32)lbl_8030D758, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D5A8,           (u32)lbl_8030D648, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D748,           (u32)lbl_8030D7D8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D5B8,           (u32)lbl_8030D5C8, 0x0000000f, 0x00000000,
                         (u32)lbl_8030D5B8,           (u32)lbl_8030D6C8, 0x0000000f, 0x00000000};

u32 lbl_8030DFC8[112] = {
    0xf5101000, 0x00014050, 0xf2000000, 0x0007c07c, 0xf5100900, 0x01010441, 0xf2000000, 0x0103c03c, 0xf5100540,
    0x0200c832, 0xf2000000, 0x0201c01c, 0xf5100350, 0x03008c23, 0xf2000000, 0x0300c00c, 0xf5101000, 0x00080050,
    0xf2000000, 0x0007c07c, 0xf5100900, 0x01080441, 0xf2000000, 0x0103c03c, 0xf5100540, 0x02080832, 0xf2000000,
    0x0201c01c, 0xf5100350, 0x03080c23, 0xf2000000, 0x0300c00c, 0xf5101000, 0x00014200, 0xf2000000, 0x0007c07c,
    0xf5100900, 0x01010601, 0xf2000000, 0x0103c03c, 0xf5100540, 0x0200ca02, 0xf2000000, 0x0201c01c, 0xf5100350,
    0x03008e03, 0xf2000000, 0x0300c00c, 0xf5100400, 0x00018050, 0xf2000000, 0x0007c07c, 0xf5100280, 0x01414441,
    0xf2000000, 0x0103c03c, 0xf51002a0, 0x02810832, 0xf2000000, 0x0201c01c, 0xf51002a8, 0x03c0cc23, 0xf2000000,
    0x0300c00c, 0xf5100400, 0x00080050, 0xf2000000, 0x0007c07c, 0xf5100280, 0x01480441, 0xf2000000, 0x0103c03c,
    0xf51002a0, 0x02880832, 0xf2000000, 0x0201c01c, 0xf51002a8, 0x03c80c23, 0xf2000000, 0x0300c00c, 0xf5100400,
    0x00018200, 0xf2000000, 0x0007c07c, 0xf5100280, 0x01414601, 0xf2000000, 0x0103c03c, 0xf51002a0, 0x02810a02,
    0xf2000000, 0x0201c01c, 0xf51002a8, 0x03c0ce03, 0xf2000000, 0x0300c00c, 0xf5180800, 0x00010040, 0xf5180440,
    0x0100c431, 0xf5180250, 0x02008822, 0xf5180254, 0x03008822, 0xf2000000, 0x0003c03c, 0xf2000000, 0x0001c01c,
    0xf2000000, 0x0000c00c, 0xf2000000, 0x0000c00c};

char sTexRestructAllocFailedMessage[] = "Failed to allocate memory->forcing texture free\n";
char sTexRestructRunningBanner[] = "^^^^^^^^^^^^^^^^  Restruct textures Running\n";
char sTexRestructReRegionBanner[] = "^^^^^^^^^^^^^^^^  REREGION \n";
char sTexRestructReRegionNoSpaceFormat[] = "texRestructRefs  No Space to ReRegion from 0x%x size %d!!!!\n";
char sTexRestructReRegionOptimalFormat[] = "texRestructRefs   Optimal ReRegion from 0x%x to 0x%x size %d!!!!\n";
char sTexRestructAfterReRegionBanner[] = "^^^^^^^^^^^^^^^^  AFTER REREGION \n";
char sTexRestructNoSpaceFormat[] = "texRestructRefs  No Space to Restructure from 0x%x size %d!!!!\n";
char sTexRestructWrongRegionFormat[] = "texRestructRefs Wrong region from 0x%x to 0x%x size %d!!!!\n";
char sTexRestructSubOptimalFormat[] = "texRestructRefs   SubOptimal Restructure from 0x%x to 0x%x size %d!!!!\n";
char sTexRestructOptimalFormat[] = "texRestructRefs   Optimal Restructure from 0x%x to 0x%x size %d!!!!\n";
char sTexRestructReRegionedStuckFormat[] =
    "texRestructRefs ReRegioned alloc can't get back into region 0 from 0x%x to 0x%x size %d!!!!\n";
char sTexRestructReRegionedOptimalFormat[] =
    "texRestructRefs   ReRegioned alloc Optimal Restructure from 0x%x to 0x%x size %d!!!!\n";
char sTexRestructFinishedFormat[] = "^^^^^^^^^^^^^^^^  Restruct textures Finished passes %d\n";
