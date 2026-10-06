#ifndef MAIN_DLL_FRONT_ATTRACT_MOVIE_H_
#define MAIN_DLL_FRONT_ATTRACT_MOVIE_H_

#include "types.h"
#include "global.h"
#include "dolphin/dvd.h"
#include "dolphin/thp/THPFile.h"
#include "dolphin/thp/THPInfo.h"

#define ATTRACT_MOVIE_READ_BUFFER_COUNT 10

#define ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE 0x280
#define ATTRACT_MOVIE_AUDIO_DMA_BUFFER_COUNT 2
#define ATTRACT_MOVIE_AUDIO_DMA_BUFFER_BYTES \
    (ATTRACT_MOVIE_AUDIO_DMA_BUFFER_SIZE * ATTRACT_MOVIE_AUDIO_DMA_BUFFER_COUNT)
#define ATTRACT_MOVIE_AUDIO_DMA_SAMPLE_COUNT 0xA0

typedef struct AttractMovieVideoInfo {
    u32 xSize;
    u32 ySize;
} AttractMovieVideoInfo;

typedef struct AttractMovieAudioInfo {
    u32 channelCount;
    u32 frequency;
    u32 sampleCount;
} AttractMovieAudioInfo;

typedef struct AttractMovieReadBuffer {
    u8 *ptr;
    s32 frameNumber;
} AttractMovieReadBuffer;

STATIC_ASSERT(sizeof(AttractMovieReadBuffer) == 8);
STATIC_ASSERT(offsetof(AttractMovieReadBuffer, ptr) == 0);
STATIC_ASSERT(offsetof(AttractMovieReadBuffer, frameNumber) == 4);

typedef struct AttractMovieTextureSet {
    u8 *yTexture;
    u8 *uTexture;
    u8 *vTexture;
    s32 frameNumber;
} AttractMovieTextureSet;

typedef struct AttractMovieAudioBuffer {
    s16 *buffer;
    s16 *curPtr;
    u32 validSample;
    s32 frameNumber;
} AttractMovieAudioBuffer;

typedef struct AttractMoviePlayer {
    DVDFileInfo fileInfo;
    THPHeader header;
    THPFrameCompInfo compInfo;
    AttractMovieVideoInfo videoInfo;
    AttractMovieAudioInfo audioInfo;
    void *thpWorkArea;
    s32 isOpen;
    u8 state;
    u8 internalState;
    union {
        u8 playFlag;
        u8 playFlags;
    };
    u8 audioExists;
    s32 dvdError;
    s32 videoError;
    s32 isOnMemory;
    union {
        u8 *movieData;
        void *loopFrame;
    };
    s32 initOffset;
    union {
        s32 initReadSize;
        int frameStride;
    };
    s32 initReadFrame;
    u32 curField;
    s64 retraceCount;
    s32 prevCount;
    s32 curCount;
    s32 videoDecodeCount;
    f32 curVolume;
    f32 targetVolume;
    f32 deltaVolume;
    s32 rampCount;
    union {
        s32 curAudioTrack;
        s32 curVideoFrameNumber;
    };
    union {
        s32 curVideoNumber;
        s32 curAudioFrameNumber;
    };
    union {
        s32 curAudioNumber;
        AttractMovieTextureSet *curTextureSet;
    };
    union {
        AttractMovieTextureSet *dispTextureSet;
        AttractMovieAudioBuffer *curAudioBuffer;
    };
    AttractMovieReadBuffer readBuffer[ATTRACT_MOVIE_READ_BUFFER_COUNT];
    AttractMovieTextureSet textureSet[3];
    AttractMovieAudioBuffer audioBuffer[3];
    u8 pad1A4[4];
} AttractMoviePlayer;

STATIC_ASSERT(sizeof(AttractMoviePlayer) == 0x1A8);
STATIC_ASSERT(offsetof(AttractMoviePlayer, header) == 0x3C);
STATIC_ASSERT(offsetof(AttractMoviePlayer, isOpen) == 0x98);
STATIC_ASSERT(offsetof(AttractMoviePlayer, state) == 0x9C);
STATIC_ASSERT(offsetof(AttractMoviePlayer, internalState) == 0x9D);
STATIC_ASSERT(offsetof(AttractMoviePlayer, playFlags) == 0x9E);
STATIC_ASSERT(offsetof(AttractMoviePlayer, audioExists) == 0x9F);
STATIC_ASSERT(offsetof(AttractMoviePlayer, isOnMemory) == 0xA8);
STATIC_ASSERT(offsetof(AttractMoviePlayer, movieData) == 0xAC);
STATIC_ASSERT(offsetof(AttractMoviePlayer, initOffset) == 0xB0);
STATIC_ASSERT(offsetof(AttractMoviePlayer, initReadSize) == 0xB4);
STATIC_ASSERT(offsetof(AttractMoviePlayer, initReadFrame) == 0xB8);
STATIC_ASSERT(offsetof(AttractMoviePlayer, videoDecodeCount) == 0xD0);
STATIC_ASSERT(offsetof(AttractMoviePlayer, curVideoFrameNumber) == 0xE4);
STATIC_ASSERT(offsetof(AttractMoviePlayer, curAudioFrameNumber) == 0xE8);
STATIC_ASSERT(offsetof(AttractMoviePlayer, curTextureSet) == 0xEC);
STATIC_ASSERT(offsetof(AttractMoviePlayer, curAudioBuffer) == 0xF0);

extern AttractMoviePlayer gAttractMoviePlayer;

extern s32 gAttractMovieAudioActive;

#endif /* MAIN_DLL_FRONT_ATTRACT_MOVIE_H_ */
