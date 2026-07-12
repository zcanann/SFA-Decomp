#ifndef MAIN_ENGINE_SHARED_H_
#define MAIN_ENGINE_SHARED_H_

#include "ghidra_import.h"
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
#include "main/voxmaps.h"

extern s32 gAttractMovieState;
extern f32 lbl_803DE5F0;
extern void AIReset(void);
extern int sndFXKeyOff(u32 handle);
extern int sndFXCheck(u32 handle);
extern int sndFXCtrl(u32 handle, u32 ctrl, u32 value);
extern int sndFXCtrl14(u32 handle, u32 ctrl, u32 value);
extern BOOL Movie_SetVolumeFade(int volume, int fadeFrames);
extern void AISetStreamPlayState(u32 state);
extern void AISetStreamVolLeft(u8 volume);
extern void AISetStreamVolRight(u8 volume);
extern s32 DVDCancelStreamAsync(void *streamInfo, void *callback);
extern void OSReport(char *message, ...);
extern s32 getGameState(void);
extern u32 mainGetBit(u32 bit);
extern void Matrix_TransformVector(f32 *matrix, f32 *in, f32 *out);
extern void Matrix_TransformPoint(f32 *matrix, f64 x, f64 y, f64 z, f32 *outX, f32 *outY, f32 *outZ);
extern void setMatrixFromObjectPos(f32 *matrix, void *obj);
extern void mtx44ScaleRow1(f32 *matrix, f32 scale);
extern void mtx44_multSafe(f32 *dst, f32 *src, f32 *out);
extern void mtxRotateByVec3s(f32 *matrix, void *transform);
extern void mtx44Transpose(f32 *src, f32 *dst);
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
extern void copyMatrix44(f32* src, f32* dst);
extern void *memmove(void *dest, const void *src, u32 count);
extern void getTabEntry(void* dst, int kind, int offset, int size);
extern int lbl_802C18C0[];
extern int lbl_802C1A24[];
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
extern f32 lbl_803DE658;
extern f32 lbl_803DE674;
extern f32 gCurveSegmentCount;
extern f32 lbl_803DE67C;
extern f32 lbl_803DE660;
extern f32 lbl_803DE680;
extern f32 gCurveForwardDiffStep;
extern int gCurveCachedSampleCount;
extern f32 gCurveForwardDiffCoeffs[];
extern void debugPrintf(char *message, ...);
extern char sCurvesSetupMoveNetworkCurveTooFewControlPoints[];
extern char sCurvesSetupMoveNetworkCurveBadControlPointCount[];
extern char sCurvesMoveTooFewControlPoints[];
extern char sCurvesMoveBadControlPointCount[];
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
extern int Sfx_ResolveObjectSfxId(int *outChannel, u16 *sfxId);
extern int memcmp(const void* lhs, const void* rhs, u32 size);
extern void* memcpy(void* dst, const void* src, u32 size);
extern void* memset(void* dst, int value, u32 size);
extern void* gResourceLoadedHandles[];
extern u16 gResourceRefCounts[];
extern f32 lbl_803DE6B8;
extern f32 lbl_803DE6D4;
extern f32 lbl_803DE6E0;
extern f32 lbl_803DE6E8;
extern int lbl_803DC9C8;
extern u8 lbl_8033A540[];
extern void ARQPostRequest(void* req, u32 owner, u32 type, u32 prio, u32 src, u32 dst, u32 size, void (*cb)(void*));
extern int sprintf(char* buf, const char* fmt, ...);
extern char* strcpy(char* dst, const char* src);
extern char* strcat(char* dst, const char* src);
extern void PADControlMotor(s32 chan, u32 command);
extern int PADInit(void);
extern int PADRecalibrate(u32 mask);
extern int PADReset(u32 mask);
extern u8 lbl_803DCCA5;
extern char* lbl_803DC9C4;
extern char* gameStrcpy(char* dst, char* src);
extern void sndMasterVolume(u8 volume, u16 time, u8 musicFlag, u8 fxFlag);
extern void fn_80008F38(void *addr, u32 dest, u32 size);
extern f32 lbl_803DE6B0;
extern int lbl_803DC9AC;
extern int lbl_803DC9B0;
extern int lbl_803DC9B4;
extern int lbl_803DC9B8;
extern int lbl_803DC9BC;
extern int DVDOpen(char* path, void* fileInfo);
extern void DVDSetAutoInvalidation(int autoInval);
extern void DCStoreRange(void* addr, u32 nBytes);
extern int DVDReadAsyncPrio(void* fileInfo, void* buf, int size, int offset, void (*cb)(void*), int prio);
extern void checkReset(void);
extern void waitNextFrame(void);
extern f32 lbl_803DE5D4;
extern int DVDPrepareStreamAsync(void* fileInfo, int a, int b, void (*cb)(void));
extern int DVDStopStreamAtEndAsync(void* fileInfo, int a);
extern f32 lbl_803DE6BC;
extern f32 lbl_803DE6C0;
extern f32 lbl_803DE6C4;
extern f32 lbl_803DE6C8;
extern f32 lbl_803DE6CC;
extern f32 lbl_803DE6D0;
extern char lbl_803DB294;
extern char lbl_803DB29C;
extern char lbl_803DB2A0;
extern int lbl_803DB27C;
extern int lbl_803DB280;
extern int lbl_803DB284;
extern int lbl_803DB288;
extern u8 pauseMenuState;
extern int getHudHiddenFrameCount(void);
extern int getMinimapY(void);
extern void drawHudBox(int a, s16 b, int c, int d, int e, int f);
extern f32 lbl_803DE568;
extern void sndSeqStop(int handle);
extern void sndSeqMute(int handle, int a, int b);
extern void sndSeqContinue(int handle);
extern void loadAssetFileById(void **out, int id);
extern void *textureAlloc(int w, int h, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern f32 fastFloorf(f32 v);
extern void *mapGetBlockAtPos(int x, int y, int z);
extern void *fn_80059334(int a, int b);
extern void *voxLoadVoxMapActual(int mapArg, int slot, int b9, int b8);
extern int getTableFileEntry(int fileId, int index, int *out);
extern void sndOutputMode(int mode);
extern u32 OSGetSoundMode(void);
extern void OSSetSoundMode(int mode);
extern int fn_800119FC(s16 *dest, s16 *start, s16 *out);
extern u8 lbl_803DC9A4;
extern u8 lbl_803DC9A5;
extern u8 lbl_803DC9A6;
extern u8 lbl_803DC9A7;
extern int lbl_803DC9C0;
extern u16 lbl_803DC9AA;
extern u16 lbl_803DC9A8;
extern void *lbl_803DB378;
extern f32 lbl_803DE704;
extern f32 lbl_803DE708;
extern int lbl_803DC984;
extern f32 lbl_803DC9A0;
extern u8 lbl_803DC990;
extern u8 lbl_803DC991;
extern u8 lbl_803DC992;
extern u8 lbl_803399C0[];
extern f32 lbl_803DC994;
extern int lbl_803DC998;
extern int lbl_803DC99C;
extern f32 lbl_803DE700;
extern f32 lbl_803DB3D0;
extern f32 lbl_803DE550;
extern f32 lbl_803DE554;
extern f32 lbl_803DE558;
extern f32 lbl_803DE55C;
extern void ARInit(void *arena, int count);
extern void ARQInit(void);
extern void AIInit(int arg);
extern void AISetDSPSampleRate(int rate);
extern void sndSetHooks(int *hooks);
extern void sndInit(int a, int b, int c, int d, int e, int f);
extern void sndAuxCallbackUpdateSettingsReverbSTD(void *settings);
extern void sndAuxCallbackReverbSTD(void);
extern void sndSetAuxProcessingCallbacks(int a, void *cb, void *settings, int d, int e, int f, int g, int h, int i);
extern void sndVolume(int a, int b, int c);
extern int sndPushGroup(void *project, u16 group, void *sampleBuffer, void *sampleDir, void *pool);

void Sfx_RotateVectorByAngles(s16 angX, s16 angY, s16 angZ, f32 *v);
f32 Sfx_GetListenerRelativeDistance(f32 *soundPos, f32 *outDelta);
void Obj_UpdateWorldTransform(s16 *obj);
s32 Angle_AddWrappedS16(s32 angle, s16 *delta);
s32 Angle_SubWrappedS16(s32 angle, s16 *delta);
void Obj_BuildTransformMatricesForYaw(u32 obj, s32 yawIndex);
void Obj_BuildTransformMatrices(u32 obj);
s32 Obj_BuildTransformMatrixSlot(u32 obj);
int return0xFFFF_80008B6C(void);
int return0x64_8000A378(void);
void doNothing_8000CF54(void);
void doNothing_endOfFrame(void);
void audioFn_8000b694(u32 value);
void* fn_8000E814(void);
void screenFn_8000e944(void* viewportArg);
void viewportEffectFn_8000e380(void);
void fn_8000F83C(void);
void fn_8000F8F8(void);
void fn_8000F9B4(void);
u16 fn_8000FA70(void);
u16 fn_8000FA90(void);
int concatThreeStrings(char* dst, void* unused, const char* first, const char* second, const char* third);
int isSpace(u32 c);
void fn_80009008(void);
void MIDIWADLoadedCallback(int status, void* fileInfo);
int musicInitMidiWad(void);
void poolDataMLoadedCallback(int status, void* fileInfo);
void poolDataSLoadedCallback(int status, void* fileInfo);
void projectDataMLoadedCallback(int status, void* fileInfo);
void projectDataSLoadedCallback(int status, void* fileInfo);
void sampleBufferMLoadedCallback(int status, void* fileInfo);
void sampleBufferSLoadedCallback(int status, void* fileInfo);
void sampleDirectoryMLoadedCallback(int status, void* fileInfo);
void sampleDirectorySLoadedCallback(int status, void* fileInfo);
void sfxTriggersLoadedCallback(int status, void* fileInfo);
void musicTriggersLoadedCallback(int status, void* fileInfo);
void streamsLoadedCallback(int status, void* fileInfo);
void fn_80008F38(void* addr, u32 dest, u32 size);
void audioAllocFn_80008df4(void* source, u32 size, void** outBuf, u32 cb, u32 cbArg1, u32 cbArg2, u32 cbArg3);
int Sfx_ResolveObjectSfxId(int* outChannel, u16* sfxId);
u32 Sfx_PlayFromObjectLimited(u32 obj, int sfxId, int limit);
void audioSetSoundMode(int mode, u8 forceFlag);
int utf8GetNextChar(u8* str, int* outLen);
char *gameStrcpy(char *dst, char *src);
void audioLoadTriggerData(void);
int audioInit(void);

#endif
