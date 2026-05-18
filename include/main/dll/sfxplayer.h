#ifndef MAIN_DLL_SFXPLAYER_H_
#define MAIN_DLL_SFXPLAYER_H_

#include "ghidra_import.h"

typedef struct SfxplayerStateFlags {
  u8 bit80 : 1;
  u8 bit40 : 1;
  u8 bit20 : 1;
  u8 bit10 : 1;
  u8 lowBits : 4;
} SfxplayerStateFlags;

typedef struct SfxplayerState {
  union {
    s16 eventId;
    s16 unused0;
  };
  union {
    s16 unk2;
    s16 effectSfxBaseId;
  };
  union {
    s16 unk4;
    s16 variantSfxTimer;
  };
  union {
    struct {
      u8 config19;
      u8 ringCount;
    };
    u8 unused6[2];
  };
  union {
    SfxplayerStateFlags flags;
    u8 effectFlags;
  };
} SfxplayerState;

extern int gSfxplayerEffectHandles[8];

void sfxplayer_update(int obj);
void sfxplayer_init(int obj,int config);
void sfxplayer_release(void);
void sfxplayer_initialise(void);

#endif /* MAIN_DLL_SFXPLAYER_H_ */
