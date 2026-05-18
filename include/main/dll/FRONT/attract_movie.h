#ifndef MAIN_DLL_FRONT_ATTRACT_MOVIE_H_
#define MAIN_DLL_FRONT_ATTRACT_MOVIE_H_

#include "ghidra_import.h"
#include "dolphin/dvd.h"
#include "dolphin/thp/THPFile.h"
#include "dolphin/thp/THPInfo.h"

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
    s32 curAudioTrack;
    s32 curVideoNumber;
    s32 curAudioNumber;
    AttractMovieTextureSet *dispTextureSet;
    AttractMovieReadBuffer readBuffer[10];
    AttractMovieTextureSet textureSet[3];
    AttractMovieAudioBuffer audioBuffer[3];
    u8 pad1A4[4];
} AttractMoviePlayer;

extern AttractMoviePlayer lbl_803A5D60;

#endif /* MAIN_DLL_FRONT_ATTRACT_MOVIE_H_ */
