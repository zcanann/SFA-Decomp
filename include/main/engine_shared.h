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
#include "dolphin/dvd.h"
#include "dolphin/gx/GXLegacy.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSReport.h"
#include "dolphin/os/OSRtc.h"
#include "dolphin/pad.h"

extern s32 gAttractMovieState;
extern int sndFXKeyOff(u32 handle);
extern int sndFXCheck(u32 handle);
extern int sndFXCtrl(u32 handle, u32 ctrl, u32 value);
extern int sndFXCtrl14(u32 handle, u32 ctrl, u32 value);
extern BOOL Movie_SetVolumeFade(int volume, int fadeFrames);
extern s32 getGameState(void);
extern u32 mainGetBit(u32 bit);
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
extern f32 sqrtf(f32 x);
extern void debugPrintf(char *message, ...);
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
extern u8 lbl_803DCCA5;
extern void sndMasterVolume(u8 volume, u16 time, u8 musicFlag, u8 fxFlag);
extern void checkReset(void);
extern void waitNextFrame(void);
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
extern int fn_800119FC(s16 *dest, s16 *start, s16 *out);
extern void sndSetHooks(int *hooks);
extern void sndInit(int a, int b, int c, int d, int e, int f);
extern void sndAuxCallbackUpdateSettingsReverbSTD(void *settings);
extern void sndAuxCallbackReverbSTD(void);
extern void sndSetAuxProcessingCallbacks(int a, void *cb, void *settings, int d, int e, int f, int g, int h, int i);
extern void sndVolume(int a, int b, int c);
extern int sndPushGroup(void *project, u16 group, void *sampleBuffer, void *sampleDir, void *pool);


#endif
