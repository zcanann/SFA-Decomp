#ifndef _DOLPHIN_GX_GXFRAMEBUFFER_H_
#define _DOLPHIN_GX_GXFRAMEBUFFER_H_

#ifdef __REVOLUTION_SDK__
#include <revolution/gx/GXFrameBuffer.h>
#else
#include <dolphin/gx/GXStruct.h>
#include <dolphin/gx/GXEnum.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	GX_MAX_Z24	0x00ffffff

extern GXRenderModeObj GXNtsc480IntDf;
extern GXRenderModeObj GXNtsc480Prog;
extern GXRenderModeObj GXMpal480IntDf;
extern GXRenderModeObj GXPal528IntDf;
extern GXRenderModeObj GXEurgb60Hz480IntDf;

void GXAdjustForOverscan(const GXRenderModeObj* rmin, GXRenderModeObj* rmout, u16 hor, u16 ver);
void GXSetDispCopySrc(u16 left, u16 top, u16 wd, u16 ht);
void GXSetTexCopySrc(u16 left, u16 top, u16 wd, u16 ht);
void GXSetDispCopyDst(u16 wd, u16 ht);
void GXSetTexCopyDst(u16 wd, u16 ht, GXTexFmt fmt, GXBool mipmap);
void GXSetDispCopyFrame2Field(GXCopyMode mode);
void GXSetCopyClamp(GXFBClamp clamp);
u32 GXSetDispCopyYScale(f32 vscale);
void GXSetCopyClear(GXColor clear_clr, u32 clear_z);
void GXSetCopyFilter(GXBool aa, const u8 sample_pattern[12][2], GXBool vf, const u8 vfilter[7]);
void GXSetDispCopyGamma(GXGamma gamma);
void GXCopyDisp(void* dest, GXBool clear);
void GXCopyTex(void* dest, GXBool clear);
void GXClearBoundingBox(void);
f32 GXGetYScaleFactor(u16 efbHeight, u16 xfbHeight);

#ifdef __cplusplus
}
#endif

#endif
#endif
