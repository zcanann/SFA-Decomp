#include "ghidra_import.h"
#include "main/dll/FRONT/dll_3B.h"
#include "main/dll/FRONT/dll_39.h"
#include "dolphin/os.h"
#include "dolphin/thp/THPAudio.h"
#include "dolphin/thp/THPFile.h"
#include "dolphin/thp/THPInfo.h"

extern void audioSetVolumes(int channel, int volume, int frames, int arg3, int arg4);
extern void audioStopByMask(int mask);
extern void audioFn_8000b694(int arg);
extern int getUiDllFn_80014930(void);
extern void gameTimerStop(void);
extern void gameTextLoadDir(int dirId);
extern void setDrawLights(int arg);
extern void setIsOvercast(int arg);
extern void saveFn_8007d960(int arg);
extern void envFxActFn_800887f8(int arg);
extern void Movie_SetVolumeFade(int volume, int fadeFrames);
extern void setLinkIsRotated(void);
extern void titleScreenPositionElements(f32 x, f32 y);
extern void titleScreenFn_801368a4(u8 arg);
extern void *PopReadedBuffer(void);
extern void PushReadedBuffer2(void *arg);

extern TitleMenuTextEntry lbl_8031A1D8[1];
extern TitleMenuTextEntry lbl_8031A214[4];
extern OSMessageQueue lbl_803A4460;
extern OSMessageQueue lbl_803A4480;
extern OSThread lbl_803A54A0;
extern u8 *lbl_803DD498;
extern u8 lbl_803DB424;
extern s32 lbl_803DD610;
extern u8 lbl_803DD614;
extern u8 lbl_803DD616;
extern u8 lbl_803DD619;
extern u8 lbl_803DD61A;
extern s32 lbl_803DD648;
extern u8 lbl_803DD64C;
extern u8 lbl_803DD64D;
extern u8 lbl_803DD64E;
extern u8 lbl_803DD64F;
extern u8 lbl_803DD650;
extern u8 lbl_803DD651;
extern u8 lbl_803DD652;
extern u8 lbl_803DD680;
extern s32 lbl_803DD698;
extern s32 lbl_803DD658;
extern TitleMenuControl *gScreenTransitionInterface;
extern TitleMenuControl *gTitleMenuLinkInterface;
extern f32 lbl_803E1D10;
extern f32 lbl_803E1D18;

static void TitleMenu_OpenPanel(TitleMenuTextEntry *entries, int count)
{
  ((void (**)(TitleMenuTextEntry *, int, int, int, int, int, int, int, int, int, int, int))
      gTitleMenuLinkInterface->vtable)[1](entries,count,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
}

static void TitleMenu_SetPanelSelection(int selection)
{
  ((void (**)(int))gTitleMenuLinkInterface->vtable)[6](selection);
}

static void TitleMenu_BindEntries(TitleMenuTextEntry *entries)
{
  ((void (**)(TitleMenuTextEntry *))gTitleMenuLinkInterface->vtable)[11](entries);
}

static void TitleMenu_SetEntryHighlight(void)
{
  int i;

  for (i = 0; i < 4; i++) {
    if (i == gTitleMenuSelection) {
      lbl_8031A214[i].flags &= ~0x4000;
    } else {
      lbl_8031A214[i].flags |= 0x4000;
    }
  }
  TitleMenu_BindEntries(lbl_8031A214);
}

static void TitleMenu_PlayPopup(int id, int arg)
{
  ((void (**)(int, int))gScreenTransitionInterface->vtable)[3](id,arg);
}

/*
 * --INFO--
 *
 * Function: TitleMenu_initialise
 * EN v1.0 Address: 0x80116F84
 * EN v1.0 Size: 904b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void TitleMenu_initialise(void)
{
  int mode;

  if ((lbl_803DD498[0x21] & 0x80) != 0) {
    lbl_803DD61A = 0;
  } else {
    lbl_803DD61A = 1;
  }
  if (lbl_803DB424 >= 0xfe) {
    saveFn_8007d960(0);
  }
  gameTextLoadDir(0x15);
  lbl_803DD650 = 0;
  lbl_803DD651 = 0;
  mode = getUiDllFn_80014930();
  if (mode == 3) {
    TitleMenu_OpenPanel(lbl_8031A1D8,1);
    lbl_803DD652 = 0;
  } else {
    TitleMenu_OpenPanel(lbl_8031A214,4);
    lbl_803DD652 = 1;
  }
  TitleMenu_SetPanelSelection(gTitleMenuSelection);
  titleScreenFn_801368a4(0);

  mode = getUiDllFn_80014930();
  if ((((mode == 0xd) || (mode = getUiDllFn_80014930(), mode == 7)) ||
       (mode = getUiDllFn_80014930(), mode == 6)) ||
      (mode = getUiDllFn_80014930(), mode == 5)) {
    TitleMenu_PlayPopup(0x23,5);
  } else {
    audioStopByMask(0xf);
    TitleMenu_PlayPopup(0x3c,1);
  }

  setLinkIsRotated();
  TitleMenu_SetEntryHighlight();
  gAttractMoviePreparePending = 0;
  gAttractMovieRetraceCountdown = 0;
  lbl_803DD64C = 1;
  lbl_803DD648 = 0x3c;
  lbl_803DD680 = 0;

  if ((lbl_803DD61A != 0) &&
      ((gAttractMovieState == NATTRACTMODE_MOVIE_READY) ||
       (gAttractMovieState == NATTRACTMODE_MOVIE_STATE_RELEASED))) {
    n_attractmode_prepareMovie();
    titleScreenPositionElements(lbl_803E1D10,lbl_803E1D18);
    gAttractMoviePlaybackEnabled = 1;
    Movie_SetVolumeFade(0,0);
    audioSetVolumes(0,10,1,0,0);
    lbl_803DD616 = 0;
  } else {
    titleScreenPositionElements(lbl_803E1D10,lbl_803E1D18);
    gAttractMoviePlaybackEnabled = 0;
    Movie_SetVolumeFade(0,1);
  }
  setIsOvercast(0);
  setDrawLights(0);
  lbl_803DD64E = 0;
  envFxActFn_800887f8(0);
  gameTimerStop();
  audioFn_8000b694(0);
  gAttractMovieIdleFrameCount = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void *PopDecodedAudioBuffer(int flags)
{
  void *message;

  if (OSReceiveMessage(&lbl_803A4460,&message,flags) == 1) {
    return message;
  }
  return NULL;
}

void PushFreeAudioBuffer(void *message)
{
  OSSendMessage(&lbl_803A4480,message,0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void AttractMovieAudio_Decode(void *readBufferArg)
{
  u32 *audioFrameSizes;
  u8 *audioFrame;
  AttractMovieReadBuffer *readBuffer;
  AttractMovieAudioBuffer *audioBuf;
  u32 track;

  readBuffer = (AttractMovieReadBuffer *)readBufferArg;
  audioFrameSizes = (u32 *)(readBuffer->ptr + 8);
  audioFrame = readBuffer->ptr + (lbl_803A5D60.compInfo.mNumComponents * sizeof(u32)) + 8;
  {
    AttractMovieAudioBuffer *received;
    OSReceiveMessage(&lbl_803A4480,&received,1);
    audioBuf = received;
  }
  for (track = 0; track < lbl_803A5D60.compInfo.mNumComponents; track++) {
    if (lbl_803A5D60.compInfo.mFrameComp[track] == 1) {
      audioBuf->validSample = THPAudioDecode(audioBuf->buffer,audioFrame,0);
      audioBuf->curPtr = audioBuf->buffer;
      audioBuf->frameNumber = readBuffer->frameNumber;
      OSSendMessage(&lbl_803A4460,audioBuf,1);
    } else {
    }
    audioFrame += *audioFrameSizes;
    audioFrameSizes++;
  }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void *AudioDecoderForOnMemory(void *param)
{
  int frame;
  int stride;
  u32 framesPerGroup;
  u32 frameInGroup;
  AttractMovieReadBuffer readBuffer;

  stride = lbl_803A5D60.frameStride;
  readBuffer.ptr = param;
  frame = 0;
  while (true) {
    readBuffer.frameNumber = frame;
    AttractMovieAudio_Decode(&readBuffer);
    framesPerGroup = lbl_803A5D60.header.mNumFrames;
    frameInGroup = (frame + lbl_803A5D60.initReadFrame) % framesPerGroup;
    if (frameInGroup == (framesPerGroup - 1)) {
      if ((lbl_803A5D60.playFlags & 1) != 0) {
        stride = *(int *)readBuffer.ptr;
        readBuffer.ptr = lbl_803A5D60.loopFrame;
      } else {
        OSSuspendThread(&lbl_803A54A0);
      }
    } else {
      int newStride = *(int *)readBuffer.ptr;
      readBuffer.ptr += stride;
      stride = newStride;
    }
    frame++;
  }
}
#pragma peephole reset
#pragma scheduling reset

void *AudioDecoder(void *param)
{
  void *token;

  (void)param;
  while (true) {
    token = PopReadedBuffer();
    AttractMovieAudio_Decode(token);
    PushReadedBuffer2(token);
  }
}

void AudioDecodeThreadCancel(void)
{
  if (lbl_803DD658 != 0) {
    OSCancelThread(&lbl_803A54A0);
    lbl_803DD658 = 0;
  }
}

void AudioDecodeThreadStart(void)
{
  if (lbl_803DD658 != 0) {
    OSResumeThread(&lbl_803A54A0);
  }
}
