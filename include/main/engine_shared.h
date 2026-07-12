#ifndef MAIN_ENGINE_SHARED_H_
#define MAIN_ENGINE_SHARED_H_

#include "ghidra_import.h"
#include "main/asset_load.h"
#include "main/audio.h"
#include "main/audio/inp_midi.h"
#include "main/audio/sfx.h"
#include "main/audio/snd_core.h"
#include "main/camera.h"
#include "main/curve.h"
#include "main/effect_interfaces.h"
#include "main/fileio.h"
#include "main/frame_timing.h"
#include "main/gametext.h"
#include "main/model_engine.h"
#include "main/mm.h"
#include "main/newclouds.h"
#include "main/pad.h"
#include "main/resource.h"
#include "main/render.h"
#include "main/sky_interface.h"
#include "main/table_file.h"
#include "main/voxmaps.h"
#include "main/vecmath.h"
#include "dolphin/ai.h"
#include "dolphin/ar.h"

extern s32 gAttractMovieState;
extern int sndFXKeyOff(u32 handle);
extern int sndFXCheck(u32 handle);
extern int sndFXCtrl(u32 handle, u32 ctrl, u32 value);
extern int sndFXCtrl14(u32 handle, u32 ctrl, u32 value);
extern BOOL Movie_SetVolumeFade(int volume, int fadeFrames);
extern s32 DVDCancelStreamAsync(void *streamInfo, void *callback);
extern void OSReport(char *message, ...);
extern s32 getGameState(void);
extern u32 mainGetBit(u32 bit);
extern void PSMTXConcat(f32 *a, f32 *b, f32 *out);
extern void PSMTXCopy(f32 *src, f32 *dst);
extern void PSMTXMultVec(f32 *matrix, f32 *in, f32 *out);
extern void PSVECNormalize(f32 *in, f32 *out);
extern void PSVECScale(f32 *in, f32 *out, f32 scale);
extern void PSVECSubtract(f32 *a, f32 *b, f32 *out);
extern void GXLoadPosMtxImm(f32 *matrix, s32 slot);
extern void C_MTXOrtho(f32* matrix, f32 top, f32 bottom, f32 left, f32 right, f32 nearPlane, f32 farPlane);
extern void C_MTXPerspective(f32* matrix, f32 fovY, f32 aspect, f32 nearPlane, f32 farPlane);
extern void C_MTXLightPerspective(f32* matrix, f32 fovY, f32 aspect, f32 scaleS, f32 scaleT, f32 transS, f32 transT);
extern void GXSetProjection(f32* matrix, s32 projectionMode);
extern void GXSetViewport(f32 left, f32 top, f32 width, f32 height, f32 nearPlane, f32 farPlane);
extern void GXSetViewportJitter(f32 left, f32 top, f32 width, f32 height, f32 nearPlane, f32 farPlane, u32 field);
extern u8 pauseMenuGetState(void);
extern void matrixFn_8006ff0c(f32* matrix, s16* out, f32 fovY, f32 aspect, f32 nearPlane, f32 farPlane, f32 scale);
extern void *memmove(void *dest, const void *src, u32 count);
extern void sndSeqVolume(int voice, int a, int handle, int b);
extern int randomGetRange(int min, int max);
extern int sndFXStartEx(s16 a, int b, int c, int d);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern void *Obj_GetPlayerObject(void);
extern int Obj_IsLoadingLocked(void);
extern int getCurSeqNo(void);
extern void PSVECAdd(f32 *a, f32 *b, f32 *out);
extern f32 PSVECMag(f32 *v);
extern f32 sqrtf(f32 x);
extern void debugPrintf(char *message, ...);
extern int DVDGetDriveStatus(void);
extern int DVDCheckDisk(void);
extern void DVDGetStreamPlayAddrAsync(void *buf, void *callback);
extern void setTimeStop(int frames);
extern void cutsceneFadeInOut(int mode);
extern f32 fabsf(f32 x);
extern u32 getScreenResolution(void);
extern void gxSetScissorRect(int p1, int p2, int x, int y, int x2, int y2);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern int memcmp(const void* lhs, const void* rhs, u32 size);
extern void* memcpy(void* dst, const void* src, u32 size);
extern void* memset(void* dst, int value, u32 size);
extern int lbl_803DC9C8;
extern u8 lbl_8033A540[];
extern int sprintf(char* buf, const char* fmt, ...);
extern char* strcpy(char* dst, const char* src);
extern char* strcat(char* dst, const char* src);
extern void PADControlMotor(s32 chan, u32 command);
extern int PADInit(void);
extern int PADRecalibrate(u32 mask);
extern int PADReset(u32 mask);
extern u8 lbl_803DCCA5;
extern void sndMasterVolume(u8 volume, u16 time, u8 musicFlag, u8 fxFlag);
extern int DVDOpen(char* path, void* fileInfo);
extern void DVDSetAutoInvalidation(int autoInval);
extern void DCStoreRange(void* addr, u32 nBytes);
extern int DVDReadAsyncPrio(void* fileInfo, void* buf, int size, int offset, void (*cb)(void*), int prio);
extern void checkReset(void);
extern void waitNextFrame(void);
extern int DVDPrepareStreamAsync(void* fileInfo, int a, int b, void (*cb)(void));
extern int DVDStopStreamAtEndAsync(void* fileInfo, int a);
extern u8 pauseMenuState;
extern int getHudHiddenFrameCount(void);
extern int getMinimapY(void);
extern void drawHudBox(int a, s16 b, int c, int d, int e, int f);
extern void sndSeqStop(int handle);
extern void sndSeqMute(int handle, int a, int b);
extern void sndSeqContinue(int handle);
extern void *textureAlloc(int w, int h, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern f32 fastFloorf(f32 v);
extern void *mapGetBlockAtPos(int x, int y, int z);
extern void *fn_80059334(int a, int b);
extern void *voxLoadVoxMapActual(int mapArg, int slot, int b9, int b8);
extern void sndOutputMode(int mode);
extern u32 OSGetSoundMode(void);
extern void OSSetSoundMode(int mode);
extern int fn_800119FC(s16 *dest, s16 *start, s16 *out);
extern void sndSetHooks(int *hooks);
extern void sndInit(int a, int b, int c, int d, int e, int f);
extern void sndAuxCallbackUpdateSettingsReverbSTD(void *settings);
extern void sndAuxCallbackReverbSTD(void);
extern void sndSetAuxProcessingCallbacks(int a, void *cb, void *settings, int d, int e, int f, int g, int h, int i);
extern void sndVolume(int a, int b, int c);
extern int sndPushGroup(void *project, u16 group, void *sampleBuffer, void *sampleDir, void *pool);


#endif
