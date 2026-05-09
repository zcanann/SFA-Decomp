#include "ghidra_import.h"
#include "main/dll/FRONT/dll_3B.h"
#include "main/dll/FRONT/dll_39.h"
#include "dolphin/os.h"
#include "dolphin/thp/THPAudio.h"

typedef struct TitleMenuTextEntry {
  u8 pad0[0x16];
  u16 flags;
  u8 pad18[0x24];
} TitleMenuTextEntry;

typedef struct TitleMenuControl {
  void *vtable;
} TitleMenuControl;

typedef struct MovieAudioPacket {
  s16 *audioBuffer;
  s16 *decodedBuffer;
  u32 decodedSize;
  int frameIndex;
} MovieAudioPacket;

typedef struct MovieAudioCursor {
  u8 *frame;
  int frameIndex;
} MovieAudioCursor;

typedef struct MovieAudioState {
  u8 pad0[0x50];
  u32 framesPerGroup;
  u8 pad54[0x18];
  u32 audioTrackCount;
  u8 audioTrackEnabled[0x2e];
  u8 flags;
  u8 pad9f[0xd];
  void *loopFrame;
  u8 padb0[4];
  int frameStride;
  u32 frameOffset;
} MovieAudioState;

extern void audioSetVolumes(int channel, int volume, int frames, int arg3, int arg4);
extern void audioStopByMask(int mask);
extern void fn_8000B694(int arg);
extern int fn_80014930(void);
extern void gameTimerStop(void);
extern void gameTextLoadDir(int dirId);
extern void setDrawLights(int arg);
extern void setIsOvercast(int arg);
extern void saveFn_8007d960(int arg);
extern void envFxActFn_800887f8(int arg);
extern void movieFn_80117b68(int fade, int frames);
extern void fn_80130478(void);
extern void titleScreenPositionElements(f32 x, f32 y);
extern void titleScreenFn_801368a4(u8 arg);
extern void *fn_801194EC(void);
extern void fn_80119458(void *arg);

extern TitleMenuTextEntry lbl_8031A1D8[1];
extern TitleMenuTextEntry lbl_8031A214[4];
extern OSMessageQueue lbl_803A4460;
extern OSMessageQueue lbl_803A4480;
extern OSThread lbl_803A54A0;
extern MovieAudioState lbl_803A5D60;
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
extern TitleMenuControl *lbl_803DCA4C;
extern TitleMenuControl *lbl_803DCAA0;
extern f32 lbl_803E1D10;
extern f32 lbl_803E1D18;

static void TitleMenu_OpenPanel(TitleMenuTextEntry *entries, int count)
{
  ((void (**)(TitleMenuTextEntry *, int, int, int, int, int, int, int, int, int, int, int))
      lbl_803DCAA0->vtable)[1](entries,count,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
}

static void TitleMenu_SetPanelSelection(int selection)
{
  ((void (**)(int))lbl_803DCAA0->vtable)[6](selection);
}

static void TitleMenu_BindEntries(TitleMenuTextEntry *entries)
{
  ((void (**)(TitleMenuTextEntry *))lbl_803DCAA0->vtable)[11](entries);
}

static void TitleMenu_SetEntryHighlight(int entry)
{
  int i;

  for (i = 0; i < 4; i++) {
    if (i == entry) {
      lbl_8031A214[i].flags &= ~0x4000;
    } else {
      lbl_8031A214[i].flags |= 0x4000;
    }
  }
  TitleMenu_BindEntries(lbl_8031A214);
}

static void TitleMenu_PlayPopup(int id, int arg)
{
  ((void (**)(int, int))lbl_803DCA4C->vtable)[3](id,arg);
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
  mode = fn_80014930();
  if (mode == 3) {
    TitleMenu_OpenPanel(lbl_8031A1D8,1);
    lbl_803DD652 = 0;
  } else {
    TitleMenu_OpenPanel(lbl_8031A214,4);
    lbl_803DD652 = 1;
  }
  TitleMenu_SetPanelSelection(lbl_803DD614);
  titleScreenFn_801368a4(0);

  mode = fn_80014930();
  if ((((mode == 0xd) || (mode = fn_80014930(), mode == 7)) ||
       (mode = fn_80014930(), mode == 6)) ||
      (mode = fn_80014930(), mode == 5)) {
    TitleMenu_PlayPopup(0x23,5);
  } else {
    audioStopByMask(0xf);
    TitleMenu_PlayPopup(0x3c,1);
  }

  fn_80130478();
  TitleMenu_SetEntryHighlight(lbl_803DD614);
  lbl_803DD619 = 0;
  lbl_803DD64D = 0;
  lbl_803DD64C = 1;
  lbl_803DD648 = 0x3c;
  lbl_803DD680 = 0;

  if ((lbl_803DD61A != 0) &&
      ((lbl_803DD610 == NATTRACTMODE_MOVIE_READY) ||
       (lbl_803DD610 == NATTRACTMODE_MOVIE_STATE_RELEASED))) {
    n_attractmode_prepareMovie();
    titleScreenPositionElements(lbl_803E1D10,lbl_803E1D18);
    lbl_803DD64F = 1;
    movieFn_80117b68(0,0);
    audioSetVolumes(0,10,1,0,0);
    lbl_803DD616 = 0;
  } else {
    titleScreenPositionElements(lbl_803E1D10,lbl_803E1D18);
    lbl_803DD64F = 0;
    movieFn_80117b68(0,1);
  }
  setIsOvercast(0);
  setDrawLights(0);
  lbl_803DD64E = 0;
  envFxActFn_800887f8(0);
  gameTimerStop();
  fn_8000B694(0);
  lbl_803DD698 = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void *fn_8011730C(int flags)
{
  void *message;

  if (OSReceiveMessage(&lbl_803A4460,&message,flags) == 1) {
    return message;
  }
  return NULL;
}

void fn_80117350(void *message)
{
  OSSendMessage(&lbl_803A4480,message,0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void thpAudioFn_80117380(void *cursorArg)
{
  u32 *audioFrameSizes;
  u8 *audioFrame;
  MovieAudioCursor *cursor;
  MovieAudioPacket *packet;
  u32 track;

  cursor = (MovieAudioCursor *)cursorArg;
  audioFrameSizes = (u32 *)(cursor->frame + 8);
  audioFrame = cursor->frame + (lbl_803A5D60.audioTrackCount * 4) + 8;
  {
    MovieAudioPacket *received;
    OSReceiveMessage(&lbl_803A4480,&received,1);
    packet = received;
  }
  for (track = 0; track < lbl_803A5D60.audioTrackCount; track++) {
    if (lbl_803A5D60.audioTrackEnabled[track] == 1) {
      packet->decodedSize = THPAudioDecode(packet->audioBuffer,audioFrame,0);
      packet->decodedBuffer = packet->audioBuffer;
      packet->frameIndex = cursor->frameIndex;
      OSSendMessage(&lbl_803A4460,packet,1);
    }
    audioFrame += *audioFrameSizes++;
  }
}
#pragma dont_inline reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void *threadMainAlt_80117460(void *param)
{
  int frame;
  int stride;
  MovieAudioCursor cursor;

  stride = lbl_803A5D60.frameStride;
  cursor.frame = param;
  frame = 0;
  while (true) {
    cursor.frameIndex = frame;
    thpAudioFn_80117380(&cursor);
    if (((frame + lbl_803A5D60.frameOffset) % lbl_803A5D60.framesPerGroup) ==
        (lbl_803A5D60.framesPerGroup - 1)) {
      if ((lbl_803A5D60.flags & 1) != 0) {
        stride = *(int *)cursor.frame;
        cursor.frame = lbl_803A5D60.loopFrame;
      } else {
        OSSuspendThread(&lbl_803A54A0);
      }
    } else {
      int newStride = *(int *)cursor.frame;
      cursor.frame += stride;
      stride = newStride;
    }
    frame++;
  }
}
#pragma peephole reset
#pragma scheduling reset

void *thpAudioThreadMain(void *param)
{
  void *token;

  (void)param;
  while (true) {
    token = fn_801194EC();
    thpAudioFn_80117380(token);
    fn_80119458(token);
  }
}

void AXInit(void)
{
  if (lbl_803DD658 != 0) {
    OSCancelThread(&lbl_803A54A0);
    lbl_803DD658 = 0;
  }
}

void AXQuit(void)
{
  if (lbl_803DD658 != 0) {
    OSResumeThread(&lbl_803A54A0);
  }
}
