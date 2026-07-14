#ifndef DOLPHIN_GX_GXDATA_H_
#define DOLPHIN_GX_GXDATA_H_

#include <dolphin/gx.h>

typedef struct __GXData_struct {
    u16 vNumNot;
    u16 bpSentNot;
    u16 vNum;
    u16 vLim;
    u32 cpEnable;
    u32 cpStatus;
    u32 cpClr;
    u32 vcdLo;
    u32 vcdHi;
    u32 vatA[8];
    u32 vatB[8];
    u32 vatC[8];
    u32 lpSize;
    u32 matIdxA;
    u32 matIdxB;
    u32 indexBase[4];
    u32 indexStride[4];
    u32 ambColor[2];
    u32 matColor[2];
    u32 suTs0[8];
    u32 suTs1[8];
    u32 suScis0;
    u32 suScis1;
    u32 tref[8];
    u32 iref;
    u32 bpMask;
    u32 IndTexScale0;
    u32 IndTexScale1;
    u32 tevc[16];
    u32 teva[16];
    u32 tevKsel[8];
    u32 cmode0;
    u32 cmode1;
    u32 zmode;
    u32 peCtrl;
    u32 cpDispSrc;
    u32 cpDispSize;
    u32 cpDispStride;
    u32 cpDisp;
    u32 cpTexSrc;
    u32 cpTexSize;
    u32 cpTexStride;
    u32 cpTex;
    u8 cpTexZ;
    u32 genMode;
    union {
        GXTexRegion TexRegions0[8];
        GXTexRegion TexRegions[8];
    };
    union {
        GXTexRegion TexRegions1[4];
        GXTexRegion TexRegionsCI[4];
    };
    u32 nextTexRgn;
    u32 nextTexRgnCI;
    GXTlutRegion TlutRegions[20];
    GXTexRegion* (*texRegionCallback)(GXTexObj*, GXTexMapID);
    GXTlutRegion* (*tlutRegionCallback)(u32);
    GXAttrType nrmType;
    u8 hasNrms;
    u8 hasBiNrms;
    u32 projType;
    f32 projMtx[6];
    f32 vpLeft;
    f32 vpTop;
    f32 vpWd;
    f32 vpHt;
    f32 vpNearz;
    f32 vpFarz;
    union {
        struct {
            u8 fgRange;
            u8 _pad_vp[3];
            f32 fgSideX;
        };
        struct {
            f32 zOffset;
            f32 zScale;
        };
    };
    u32 tImage0[8];
    u32 tMode0[8];
    u32 texmapId[16];
    u32 tcsManEnab;
    u32 tevTcEnab;
    GXPerf0 perf0;
    GXPerf1 perf1;
    u32 perfSel;
    u8 inDispList;
    u8 dlSaveContext;
    u8 dirtyVAT;
    u8 abtWaitPECopy;
    u32 dirtyState;
} GXData;

extern GXData* gx;
extern GXData* const __GXData;

#endif /* DOLPHIN_GX_GXDATA_H_ */
