#include <dolphin/gx.h>
#include <dolphin/os.h>
#include <string.h>

#include "dolphin/gx/__gx.h"

extern GXData* gx;

typedef struct __GXTexObjInt_struct {
    u32 mode0;
    u32 mode1;
    u32 image0;
    u32 image3;
    void* userData;
    GXTexFmt fmt;
    u32 tlutName;
    u16 loadCnt;
    u8 loadFmt;
    u8 flags;
} __GXTexObjInt;

typedef struct __GXTexRegionInt_struct {
    u32 image1;
    u32 image2;
    u16 sizeEven;
    u16 sizeOdd;
    u8 is32bMipmap;
    u8 isCached;
} __GXTexRegionInt;

typedef struct __GXTlutObjInt_struct {
    u32 tlut;
    u32 loadTlut0;
    u16 numEntries;
} __GXTlutObjInt;

typedef struct __GXTlutRegionInt_struct {
    u32 loadTlut1;
    __GXTlutObjInt tlutObj;
} __GXTlutRegionInt;

typedef struct GXDataCallbacksView {
    u8 _pad[0x410];
    GXTexRegionCallback texRegionCallback;
    GXTlutRegionCallback tlutRegionCallback;
} GXDataCallbacksView;

u8 GXTexMode0Ids[8] = {0x80, 0x81, 0x82, 0x83, 0xA0, 0xA1, 0xA2, 0xA3};
u8 GXTexMode1Ids[8] = {0x84, 0x85, 0x86, 0x87, 0xA4, 0xA5, 0xA6, 0xA7};
u8 GXTexImage0Ids[8] = {0x88, 0x89, 0x8A, 0x8B, 0xA8, 0xA9, 0xAA, 0xAB};
u8 GXTexImage1Ids[8] = {0x8C, 0x8D, 0x8E, 0x8F, 0xAC, 0xAD, 0xAE, 0xAF};
u8 GXTexImage2Ids[8] = {0x90, 0x91, 0x92, 0x93, 0xB0, 0xB1, 0xB2, 0xB3};
u8 GXTexImage3Ids[8] = {0x94, 0x95, 0x96, 0x97, 0xB4, 0xB5, 0xB6, 0xB7};
u8 GXTexTlutIds[8] = {0x98, 0x99, 0x9A, 0x9B, 0xB8, 0xB9, 0xBA, 0xBB};
u8 GX2HWFiltConv[6] = {0x00, 0x04, 0x01, 0x05, 0x02, 0x06};

void __GXGetTexTileShift(GXTexFmt fmt, u32* rowTileS, u32* colTileS) {
    switch (fmt) {
    case GX_TF_I4:
    case 0x8:
    case GX_TF_CMPR:
    case GX_CTF_R4:
    case GX_CTF_Z4:
        *rowTileS = 3;
        *colTileS = 3;
        break;
    case GX_TF_I8:
    case GX_TF_IA4:
    case 0x9:
    case GX_TF_Z8:
    case GX_CTF_RA4:
    case GX_TF_A8:
    case GX_CTF_R8:
    case GX_CTF_G8:
    case GX_CTF_B8:
    case GX_CTF_Z8M:
    case GX_CTF_Z8L:
        *rowTileS = 3;
        *colTileS = 2;
        break;
    case GX_TF_IA8:
    case GX_TF_RGB565:
    case GX_TF_RGB5A3:
    case GX_TF_RGBA8:
    case 0xA:
    case GX_TF_Z16:
    case GX_TF_Z24X8:
    case GX_CTF_RA8:
    case GX_CTF_RG8:
    case GX_CTF_GB8:
    case GX_CTF_Z16L:
        *rowTileS = 2;
        *colTileS = 2;
        break;
    default:
        *rowTileS = *colTileS = 0;
        ASSERTMSGLINEV(444, 0, "%s: invalid texture format", "GX");
        break;
    }
}

u32 GXGetTexBufferSize(u16 width, u16 height, u32 format, GXBool mipmap, u8 max_lod) {
    u32 tileShiftX;
    u32 tileShiftY;
    u32 tileBytes;
    u32 bufferSize;
    u32 nx;
    u32 ny;
    u32 level;

    ASSERTMSGLINEV(460, width <= 1024, "%s: width too large", "GXGetTexBufferSize");
    ASSERTMSGLINEV(461, height <= 1024, "%s: height too large", "GXGetTexBufferSize");

    __GXGetTexTileShift(format, &tileShiftX, &tileShiftY);
    if (format == GX_TF_RGBA8 || format == GX_TF_Z24X8) {
        tileBytes = 64;
    } else {
        tileBytes = 32;
    }

    if (mipmap == GX_TRUE) {
        nx = 1 << (31 - __cntlzw(width));
        ASSERTMSGLINEV(479, width == nx, "%s: width must be a power of 2", "GXGetTexBufferSize");
        ny = 1 << (31 - __cntlzw(height));
        ASSERTMSGLINEV(482, height == ny, "%s: height must be a power of 2", "GXGetTexBufferSize");

        bufferSize = 0;
        for (level = 0; level < max_lod; level++) {
            nx = (width + (1 << tileShiftX) - 1) >> tileShiftX;
            ny = (height + (1 << tileShiftY) - 1) >> tileShiftY;
            bufferSize += tileBytes * (nx * ny);
            if (width == 1 && height == 1) {
                break;
            }
            width = (width > 1) ? width >> 1 : 1;
            height = (height > 1) ? height >> 1 : 1;
        }
    } else {
        nx = (width + (1 << tileShiftX) - 1) >> tileShiftX;
        ny = (height + (1 << tileShiftY) - 1) >> tileShiftY;
        bufferSize = nx * ny * tileBytes;
    }

    return bufferSize;
}

void __GetImageTileCount(GXTexFmt fmt, u16 wd, u16 ht, u32* rowTiles, u32* colTiles, u32* cmpTiles) {
    u32 texRowShift;
    u32 texColShift;

    __GXGetTexTileShift(fmt, &texRowShift, &texColShift);
    if (wd == 0) {
        wd = 1;
    }
    if (ht == 0) {
        ht = 1;
    }
    *rowTiles = (wd + (1 << texRowShift) - 1) >> texRowShift;
    *colTiles = (ht + (1 << texColShift) - 1) >> texColShift;
    *cmpTiles = (fmt == GX_TF_RGBA8 || fmt == GX_TF_Z24X8) ? 2 : 1;
}

void GXInitTexObj(GXTexObj* obj, void* image_ptr, u16 width, u16 height, GXTexFmt format, GXTexWrapMode wrap_s, GXTexWrapMode wrap_t, GXBool mipmap) {
    u32 imageBase;
    u32 maxLOD;
    u16 rowT;
    u16 colT;
    u32 rowC;
    u32 colC;
    __GXTexObjInt* t = (__GXTexObjInt*)obj;

    ASSERTMSGLINE(565, obj, "Texture Object Pointer is null");
    CHECK_GXBEGIN(567, "GXInitTexObj");
    ASSERTMSGLINEV(568, width <= 1024, "%s: width too large", "GXInitTexObj");
    ASSERTMSGLINEV(569, height <= 1024, "%s: height too large", "GXInitTexObj");
    ASSERTMSGLINEV(571, !(format & _GX_TF_CTF), "%s: invalid texture format", "GXInitTexObj");

#if DEBUG
    if (wrap_s != GX_CLAMP || mipmap) {
        u32 mask = 1 << (31 - __cntlzw(width));
        ASSERTMSGLINEV(581, width == mask, "%s: width must be a power of 2", "GXInitTexObj");
    }
    if (wrap_t != GX_CLAMP || mipmap) {
        u32 mask = 1 << (31 - __cntlzw(height));
        ASSERTMSGLINEV(586, height == mask, "%s: height must be a power of 2", "GXInitTexObj");
    }
#endif

    memset(t, 0, 0x20);
    t->mode0 = (t->mode0 & 0xFFFFFFFC) | wrap_s;
    t->mode0 = (t->mode0 & 0xFFFFFFF3) | (wrap_t << 2);
    t->mode0 = (t->mode0 & 0xFFFFFFEF) | 0x10;

    if (mipmap != 0) {
        u8 lmax;

        t->flags |= 1;

        if ((u32)format - GX_TF_C4 <= 2) {
            t->mode0 = (t->mode0 & 0xFFFFFF1F) | 0xA0;
        } else {
            t->mode0 = (t->mode0 & 0xFFFFFF1F) | 0xC0;
        }

        if (width > height) {
            maxLOD = 31 - __cntlzw(width);
        } else {
            maxLOD = 31 - __cntlzw(height);
        }

        lmax = 16.0f * maxLOD;
        t->mode1 = (t->mode1 & 0xFFFF00FF) | (lmax << 8);
    } else {
        t->mode0 = (t->mode0 & 0xFFFFFF1F) | 0x80;
    }

    t->fmt = format;
    t->image0 = (t->image0 & 0xFFFFFC00) | (width - 1);
    t->image0 = (t->image0 & 0xFFF003FF) | ((height - 1) << 10);
    t->image0 = (t->image0 & 0xFF0FFFFF) | ((format & 0xF) << 20);
    ASSERTMSGLINEV(654, ((u32)image_ptr & 0x1F) == 0, "%s: %s pointer not aligned to 32B", "GXInitTexObj", "image");
    imageBase = ((u32)image_ptr >> 5) & 0x01FFFFFF;
    t->image3 = (t->image3 & 0xFFE00000) | imageBase;

    switch (format & 0xF) {
    case GX_TF_I4:
    case 8:
        t->loadFmt = 1;
        rowT = 3;
        colT = 3;
        break;
    case GX_TF_I8:
    case GX_TF_IA4:
    case 9:
        t->loadFmt = 2;
        rowT = 3;
        colT = 2;
        break;
    case GX_TF_IA8:
    case GX_TF_RGB565:
    case GX_TF_RGB5A3:
    case 10:
        t->loadFmt = 2;
        rowT = 2;
        colT = 2;
        break;
    case GX_TF_RGBA8:
        t->loadFmt = 3;
        rowT = 2;
        colT = 2;
        break;
    case GX_TF_CMPR:
        t->loadFmt = 0;
        rowT = 3;
        colT = 3;
        break;
    default:
        ASSERTMSGLINEV(699, 0, "%s: invalid texture format", "GXPreLoadEntireTexture");
        t->loadFmt = 2;
        rowT = 2;
        colT = 2;
        break;
    }

    rowC = (width + (1 << rowT) - 1) >> rowT;
    colC = (height + (1 << colT) - 1) >> colT;
    t->loadCnt = (rowC * colC) & 0x7FFF;
    t->flags |= 2;
}

void GXInitTexObjLOD(GXTexObj* obj, GXTexFilter min_filt, GXTexFilter mag_filt, f32 min_lod, f32 max_lod, f32 lod_bias, u8 bias_clamp, u8 do_edge_lod, GXAnisotropy max_aniso) {
    u8 lbias;
    u32 edgeLod;
    u32 magFilt;
    u8 lmin;
    u8 lmax;
    u32 mode0;
    u32 mode1;
    __GXTexObjInt* t = (__GXTexObjInt*)obj;

    ASSERTMSGLINE(776, obj, "Texture Object Pointer is null");
    CHECK_GXBEGIN(778, "GXInitTexObjLOD");

    if (lod_bias < -4.0f) {
        lod_bias = -4.0f;
    } else if (lod_bias >= 4.0f) {
        lod_bias = 3.99f;
    }

    lbias = 32.0f * lod_bias;
    mode0 = t->mode0;
    mode0 = (mode0 & 0xFFFE01FF) | ((lbias & 0xFF) << 9);
    t->mode0 = mode0;

    ASSERTMSG1LINE(791, (u32)mag_filt <= 1, "%s: invalid mag_filt value", "GXInitTexObjLOD");
    if (mag_filt == GX_LINEAR) {
        magFilt = 1;
    } else {
        magFilt = 0;
    }
    mode0 = t->mode0;
    mode0 = (mode0 & 0xFFFFFFEF) | (magFilt << 4);
    t->mode0 = mode0;

    ASSERTMSG1LINE(795, (u32)min_filt <= 5, "%s: invalid min_filt value", "GXInitTexObjLOD");
    mode0 = t->mode0;
    mode0 = (mode0 & 0xFFFFFF1F) | (GX2HWFiltConv[min_filt] << 5);
    t->mode0 = mode0;

    if (do_edge_lod != 0) {
        edgeLod = 0;
    } else {
        edgeLod = 1;
    }
    mode0 = t->mode0;
    mode0 = (mode0 & 0xFFFFFEFF) | (edgeLod << 8);
    t->mode0 = mode0;

    mode0 = t->mode0;
    mode0 &= 0xFFFDFFFF;
    t->mode0 = mode0;

    mode0 = t->mode0;
    mode0 &= 0xFFFBFFFF;
    t->mode0 = mode0;

    mode0 = t->mode0;
    mode0 = (mode0 & 0xFFE7FFFF) | (max_aniso << 19);
    t->mode0 = mode0;

    mode0 = t->mode0;
    mode0 = (mode0 & 0xFFDFFFFF) | ((bias_clamp & 0xFF) << 21);
    t->mode0 = mode0;

    if (min_lod < 0.0f) {
        min_lod = 0.0f;
    } else if (min_lod > 10.0f) {
        min_lod = 10.0f;
    }
    lmin = 16.0f * min_lod;
    if (max_lod < 0.0f) {
        max_lod = 0.0f;
    } else if (max_lod > 10.0f) {
        max_lod = 10.0f;
    }
    lmax = 16.0f * max_lod;

    mode1 = t->mode1;
    mode1 = (mode1 & 0xFFFFFF00) | lmin;
    t->mode1 = mode1;

    mode1 = t->mode1;
    mode1 = (mode1 & 0xFFFF00FF) | (lmax << 8);
    t->mode1 = mode1;
}

void GXInitTexObjUserData(GXTexObj* obj, void* user_data) {
    __GXTexObjInt* t = (__GXTexObjInt*)obj;

    ASSERTMSGLINE(1068, obj, "Texture Object Pointer is null");
    CHECK_GXBEGIN(1069, "GXInitTexObjUserData");
    t->userData = user_data;
}

u16 GXGetTexObjWidth(const GXTexObj* to) {
    const __GXTexObjInt* t = (const __GXTexObjInt*)to;

    ASSERTMSGLINE(1114, to, "Texture Object Pointer is null");
    return (u32)GET_REG_FIELD(t->image0, 10, 0) + 1;
}

u16 GXGetTexObjHeight(const GXTexObj* to) {
    const __GXTexObjInt* t = (const __GXTexObjInt*)to;

    ASSERTMSGLINE(1120, to, "Texture Object Pointer is null");
    return (u32)GET_REG_FIELD(t->image0, 10, 10) + 1;
}

GXTexFmt GXGetTexObjFmt(const GXTexObj* to) {
    const __GXTexObjInt* t = (const __GXTexObjInt*)to;

    ASSERTMSGLINE(1126, to, "Texture Object Pointer is null");
    return t->fmt;
}

void GXLoadTexObjPreLoaded(GXTexObj* obj, GXTexRegion* region, GXTexMapID id) {
    __GXTlutRegionInt* tlr;
    __GXTexObjInt* t = (__GXTexObjInt*)obj;
    __GXTexRegionInt* r = (__GXTexRegionInt*)region;

    ASSERTMSGLINE(1257, obj, "Texture Object Pointer is null");
    ASSERTMSGLINE(1258, region, "TexRegion Object Pointer is null");
    CHECK_GXBEGIN(1259, "GXLoadTexObjPreLoaded");
    ASSERTMSGLINEV(1260, id < GX_MAX_TEXMAP, "%s: invalid texture map ID", "GXLoadTexObj");

    t->mode0 = (t->mode0 & 0x00FFFFFF) | ((u32)GXTexMode0Ids[id] << 24);
    t->mode1 = (t->mode1 & 0x00FFFFFF) | ((u32)GXTexMode1Ids[id] << 24);
    t->image0 = (t->image0 & 0x00FFFFFF) | ((u32)GXTexImage0Ids[id] << 24);
    r->image1 = (r->image1 & 0x00FFFFFF) | ((u32)GXTexImage1Ids[id] << 24);
    r->image2 = (r->image2 & 0x00FFFFFF) | ((u32)GXTexImage2Ids[id] << 24);
    t->image3 = (t->image3 & 0x00FFFFFF) | ((u32)GXTexImage3Ids[id] << 24);

    GX_WRITE_RAS_REG(t->mode0);
    GX_WRITE_RAS_REG(t->mode1);
    GX_WRITE_RAS_REG(t->image0);
    GX_WRITE_RAS_REG(r->image1);
    GX_WRITE_RAS_REG(r->image2);
    GX_WRITE_RAS_REG(t->image3);

    if (!(t->flags & 2)) {
        ASSERTMSGLINEV(1287, gx->tlutRegionCallback, "%s: Tex/Tlut Region Callback not set", "GXLoadTexObj/PreLoaded");
        tlr = (__GXTlutRegionInt*)gx->tlutRegionCallback(t->tlutName);
        ASSERTMSGLINEV(1289, tlr, "%s: Tex/Tlut Region Callback returns NULL", "GXLoadTexObj/PreLoaded");

        tlr->tlutObj.tlut = (tlr->tlutObj.tlut & 0x00FFFFFF) | ((u32)GXTexTlutIds[id] << 24);
        GX_WRITE_RAS_REG(tlr->tlutObj.tlut);
    }

    (*((GXData * volatile*)&gx))->tImage0[id] = t->image0;
    (*((GXData * volatile*)&gx))->tMode0[id] = t->mode0;
    (*((GXData * volatile*)&gx))->dirtyState |= 1;
    (*((GXData * volatile*)&gx))->bpSentNot = 0;
}

void GXLoadTexObj(GXTexObj* obj, GXTexMapID id) {
    GXTexRegion* r;

    CHECK_GXBEGIN(1318, "GXLoadTexObj");
    ASSERTMSGLINEV(1319, id < 8, "%s: invalid texture map ID", "GXLoadTexObj");
    ASSERTMSGLINEV(1324, ((GXDataCallbacksView*)gx)->texRegionCallback, "%s: Tex/Tlut Region Callback not set", "GXLoadTexObj");
    r = ((GXDataCallbacksView*)gx)->texRegionCallback(obj, id);
    ASSERTMSGLINEV(1326, r, "%s: Tex/Tlut Region Callback returns NULL", "GXLoadTexObj");
    GXLoadTexObjPreLoaded(obj, r, id);
}

void GXInitTexCacheRegion(GXTexRegion* region, u8 is_32b_mipmap, u32 tmem_even, GXTexCacheSize size_even, u32 tmem_odd, GXTexCacheSize size_odd) {
    u32 widthExp2;
    __GXTexRegionInt* t = (__GXTexRegionInt*)region;

    ASSERTMSGLINE(1484, region, "TexRegion Object Pointer is null");
    CHECK_GXBEGIN(1486, "GXInitTexCacheRegion");
    ASSERTMSGLINEV(1488, (tmem_even & 0x1F) == 0, "%s: %s pointer not aligned to 32B", "GXInitTexCacheRegion", "tmem even");
    ASSERTMSGLINEV(1490, (tmem_odd & 0x1F) == 0, "%s: %s pointer not aligned to 32B", "GXInitTexCacheRegion", "tmem odd");

    switch (size_even) {
    case GX_TEXCACHE_32K:
        widthExp2 = 3;
        break;
    case GX_TEXCACHE_128K:
        widthExp2 = 4;
        break;
    case GX_TEXCACHE_512K:
        widthExp2 = 5;
        break;
    default:
        ASSERTMSGLINEV(1498, 0, "%s: Invalid %s size", "GXInitTexCacheRegion", "tmem even");
        break;
    }

    t->image1 = 0;
    t->image1 = (t->image1 & 0xFFFF8000) | (tmem_even >> 5);
    t->image1 = (t->image1 & 0xFFFC7FFF) | (widthExp2 << 15);
    t->image1 = (t->image1 & 0xFFE3FFFF) | (widthExp2 << 18);
    t->image1 &= 0xFFDFFFFF;

    switch (size_odd) {
    case GX_TEXCACHE_32K:
        widthExp2 = 3;
        break;
    case GX_TEXCACHE_128K:
        widthExp2 = 4;
        break;
    case GX_TEXCACHE_512K:
        widthExp2 = 5;
        break;
    case GX_TEXCACHE_NONE:
        widthExp2 = 0;
        break;
    default:
        ASSERTMSGLINEV(1514, 0, "%s: Invalid %s size", "GXInitTexCacheRegion", "tmem odd");
        break;
    }

    t->image2 = 0;
    t->image2 = (t->image2 & 0xFFFF8000) | (tmem_odd >> 5);
    t->image2 = (t->image2 & 0xFFFC7FFF) | (widthExp2 << 15);
    t->image2 = (t->image2 & 0xFFE3FFFF) | (widthExp2 << 18);
    t->is32bMipmap = is_32b_mipmap;
    t->isCached = 1;
}

void GXInitTlutRegion(GXTlutRegion* region, u32 tmem_addr, GXTlutSize tlut_size) {
    __GXTlutRegionInt* t = (__GXTlutRegionInt*)region;

    ASSERTMSGLINE(1652, region, "TLutRegion Object Pointer is null");
    CHECK_GXBEGIN(1654, "GXInitTlutRegion");
    ASSERTMSGLINEV(1655, (tmem_addr & 0x1FF) == 0, "%s: tmem pointer is not aligned to 512B", "GXInitTlutRegion");
    ASSERTMSGLINEV(1656, tlut_size <= 0x400, "%s: tlut size exceeds 16K", "GXInitTlutRegion");
    t->loadTlut1 = 0;
    t->loadTlut1 = (t->loadTlut1 & 0xFFFFFC00) | ((tmem_addr - 0x80000U) >> 9);
    t->loadTlut1 = (t->loadTlut1 & 0xFFE003FF) | ((u32)tlut_size << 10);
    t->loadTlut1 = (t->loadTlut1 & 0x00FFFFFF) | 0x65000000;
}

void GXInvalidateTexAll(void) {
    u32 reg0;
    u32 reg1;

    CHECK_GXBEGIN(1755, "GXInvalidateTexAll");
    reg0 = 0x66001000;
    reg1 = 0x66001100;
    __GXFlushTextureState();
    GX_WRITE_RAS_REG(reg0);
    GX_WRITE_RAS_REG(reg1);
    __GXFlushTextureState();
}

GXTexRegionCallback GXSetTexRegionCallback(GXTexRegionCallback f) {
    GXTexRegionCallback oldcb = gx->texRegionCallback;

    gx->texRegionCallback = f;
    return oldcb;
}

GXTlutRegionCallback GXSetTlutRegionCallback(GXTlutRegionCallback f) {
    GXTlutRegionCallback oldcb = gx->tlutRegionCallback;

    gx->tlutRegionCallback = f;
    return oldcb;
}

void GXPreLoadEntireTexture(GXTexObj* tex_obj, GXTexRegion* region) {
    u8 isMipMap;
    u8 is32bit;
    u32 wd;
    u32 ht;
    u32 maxLevelIndex;
    u32 loadImage0;
    u32 loadImage1;
    u32 loadImage2;
    u32 loadImage3;
    u32 base;
    u32 tmem1;
    u32 tmem2;
    u32 tmemAR;
    u32 tmemGB;
    u32 nTiles;
    u32 rowTiles;
    u32 colTiles;
    u32 cmpTiles;
    u32 i;
    __GXTexObjInt* t = (__GXTexObjInt*)tex_obj;
    __GXTexRegionInt* r = (__GXTexRegionInt*)region;

    ASSERTMSGLINE(1820, tex_obj, "Texture Object Pointer is null");
    ASSERTMSGLINE(1820, region, "TexRegion Object Pointer is null");
    CHECK_GXBEGIN(1822, "GXPreLoadEntireTexture");
    isMipMap = (t->flags & 1) == 1;
    is32bit = GET_REG_FIELD(t->image0, 4, 20) == 6;

    loadImage0 = 0;
    SET_REG_FIELD(0, loadImage0, 8, 24, 0x60);
    base = t->image3 & 0x1FFFFF;
    SET_REG_FIELD(1831, loadImage0, 21, 0, base);

    loadImage1 = 0;
    SET_REG_FIELD(0, loadImage1, 8, 24, 0x61);
    tmem1 = r->image1 & 0x7FFF;
    SET_REG_FIELD(1837, loadImage1, 15, 0, tmem1);

    loadImage2 = 0;
    SET_REG_FIELD(0, loadImage2, 8, 24, 0x62);
    tmem2 = r->image2 & 0x7FFF;
    SET_REG_FIELD(1843, loadImage2, 15, 0, tmem2);

    loadImage3 = 0;
    SET_REG_FIELD(0, loadImage3, 8, 24, 0x63);
    SET_REG_FIELD(1848, loadImage3, 15, 0, t->loadCnt);
    SET_REG_FIELD(1849, loadImage3, 2, 15, t->loadFmt);
    maxLevelIndex = 0;
    nTiles = t->loadCnt;
    if (isMipMap != 0) {
        wd = GET_REG_FIELD(t->image0, 10, 0) + 1;
        ht = GET_REG_FIELD(t->image0, 10, 10) + 1;
        if (wd > ht) {
            maxLevelIndex = (u16)(31 - __cntlzw(wd));
        } else {
            maxLevelIndex = (u16)(31 - __cntlzw(ht));
        }
    }

    __GXFlushTextureState();
    GX_WRITE_RAS_REG(loadImage0);
    GX_WRITE_RAS_REG(loadImage1);
    GX_WRITE_RAS_REG(loadImage2);
    GX_WRITE_RAS_REG(loadImage3);

    if (maxLevelIndex != 0) {
        tmemAR = tmem1;
        tmemGB = tmem2;
        for (i = 0; i < maxLevelIndex; i++) {
            if (is32bit != 0) {
                base += nTiles * 2;
                tmemAR += nTiles;
                tmemGB += nTiles;
            } else {
                base += nTiles;
                if (i & 1) {
                    tmemGB += nTiles;
                } else {
                    tmemAR += nTiles;
                }
            }
            tmem1 = (i & 1) ? tmemAR : tmemGB;
            tmem2 = (i & 1) ? tmemGB : tmemAR;
            __GetImageTileCount(t->fmt, (u16)(wd >> (i + 1)), (u16)(ht >> (i + 1)), &rowTiles, &colTiles, &cmpTiles);
            nTiles = rowTiles * colTiles;
            SET_REG_FIELD(1957, loadImage0, 21, 0, base);
            SET_REG_FIELD(1958, loadImage1, 15, 0, tmem1);
            SET_REG_FIELD(1959, loadImage2, 15, 0, tmem2);
            SET_REG_FIELD(1960, loadImage3, 15, 0, nTiles);
            GX_WRITE_RAS_REG(loadImage0);
            GX_WRITE_RAS_REG(loadImage1);
            GX_WRITE_RAS_REG(loadImage2);
            GX_WRITE_RAS_REG(loadImage3);
        }
    }

    __GXFlushTextureState();
}

static void __SetSURegs(u32 tmap, u32 tcoord) {
    u32 w;
    u32 h;
    u8 s_bias;
    u8 t_bias;

    w = GET_REG_FIELD(gx->tImage0[tmap], 10, 0);
    h = GET_REG_FIELD(gx->tImage0[tmap], 10, 10);
    SET_REG_FIELD(2089, gx->suTs0[tcoord], 16, 0, w);
    SET_REG_FIELD(2090, gx->suTs1[tcoord], 16, 0, h);
    s_bias = GET_REG_FIELD(gx->tMode0[tmap], 2, 0) == 1;
    t_bias = GET_REG_FIELD(gx->tMode0[tmap], 2, 2) == 1;
    SET_REG_FIELD(2096, gx->suTs0[tcoord], 1, 16, s_bias);
    SET_REG_FIELD(2097, gx->suTs1[tcoord], 1, 16, t_bias);
    GX_WRITE_RAS_REG(gx->suTs0[tcoord]);
    GX_WRITE_RAS_REG(gx->suTs1[tcoord]);
    gx->bpSentNot = 0;
}

void __GXSetSUTexRegs(void) {
    u32 nStages;
    u32 nIndStages;
    u32 i;
    u32 map;
    u32 tmap;
    u32 coord;
    u32* ptref;

    if (gx->tcsManEnab != 0xFF) {
        nStages = GET_REG_FIELD(gx->genMode, 4, 10) + 1;
        nIndStages = GET_REG_FIELD(gx->genMode, 3, 16);
        for (i = 0; i < nIndStages; i++) {
            switch (i) {
            case 0:
                tmap = GET_REG_FIELD(gx->iref, 3, 0);
                coord = GET_REG_FIELD(gx->iref, 3, 3);
                break;
            case 1:
                tmap = GET_REG_FIELD(gx->iref, 3, 6);
                coord = GET_REG_FIELD(gx->iref, 3, 9);
                break;
            case 2:
                tmap = GET_REG_FIELD(gx->iref, 3, 12);
                coord = GET_REG_FIELD(gx->iref, 3, 15);
                break;
            case 3:
                tmap = GET_REG_FIELD(gx->iref, 3, 18);
                coord = GET_REG_FIELD(gx->iref, 3, 21);
                break;
            }
            if (!(gx->tcsManEnab & (1 << coord))) {
                __SetSURegs(tmap, coord);
            }
        }

        for (i = 0; i < nStages; i++) {
            ptref = &gx->tref[i / 2];
            map = gx->texmapId[i];
            tmap = map & 0xFFFFFEFF;
            if (i & 1) {
                coord = GET_REG_FIELD(*ptref, 3, 15);
            } else {
                coord = GET_REG_FIELD(*ptref, 3, 3);
            }
            if ((tmap != 0xFF) && !(gx->tcsManEnab & (1 << coord)) && (gx->tevTcEnab & (1 << i))) {
                __SetSURegs(tmap, coord);
            }
        }
    }
}

void __GXSetTmemConfig(u32 config) {
    switch (config) {
    case 1:
        GX_WRITE_RAS_REG(0x8C0D8000);
        GX_WRITE_RAS_REG(0x900DC000);
        GX_WRITE_RAS_REG(0x8D0D8800);
        GX_WRITE_RAS_REG(0x910DC800);
        GX_WRITE_RAS_REG(0x8E0D9000);
        GX_WRITE_RAS_REG(0x920DD000);
        GX_WRITE_RAS_REG(0x8F0D9800);
        GX_WRITE_RAS_REG(0x930DD800);
        GX_WRITE_RAS_REG(0xAC0DA000);
        GX_WRITE_RAS_REG(0xB00DE000);
        GX_WRITE_RAS_REG(0xAD0DA800);
        GX_WRITE_RAS_REG(0xB10DE800);
        GX_WRITE_RAS_REG(0xAE0DB000);
        GX_WRITE_RAS_REG(0xB20DF000);
        GX_WRITE_RAS_REG(0xAF0DB800);
        GX_WRITE_RAS_REG(0xB30DF800);
        break;
    case 0:
    default:
        GX_WRITE_RAS_REG(0x8C0D8000);
        GX_WRITE_RAS_REG(0x900DC000);
        GX_WRITE_RAS_REG(0x8D0D8400);
        GX_WRITE_RAS_REG(0x910DC400);
        GX_WRITE_RAS_REG(0x8E0D8800);
        GX_WRITE_RAS_REG(0x920DC800);
        GX_WRITE_RAS_REG(0x8F0D8C00);
        GX_WRITE_RAS_REG(0x930DCC00);
        GX_WRITE_RAS_REG(0xAC0D9000);
        GX_WRITE_RAS_REG(0xB00DD000);
        GX_WRITE_RAS_REG(0xAD0D9400);
        GX_WRITE_RAS_REG(0xB10DD400);
        GX_WRITE_RAS_REG(0xAE0D9800);
        GX_WRITE_RAS_REG(0xB20DD800);
        GX_WRITE_RAS_REG(0xAF0D9C00);
        GX_WRITE_RAS_REG(0xB30DDC00);
        break;
    }
}
