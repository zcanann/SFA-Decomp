/*
 * attractmovie (DLL 0x44) - THP video playback for the attract / title-screen
 * demo movie.  The player singleton (lbl_803A5D60) is populated by
 * AttractMovie_OpenFile (not in this TU).  This TU owns the three exported
 * entry-points called by the front-end after the file is opened:
 *   AttractMovie_AssignBuffers - hand caller-allocated read, texture and audio
 *     buffers to the player; also the THP decompressor work area.
 *   AttractMovie_GetBufferSizes - query how large each caller buffer must be.
 *   AttractMovie_CloseFile      - close the DVD file handle when playback ends.
 */
#include "main/dll/FRONT/dll_44.h"

extern void DCInvalidateRange(void* start, u32 nBytes);

#define ALIGN_NEXT_32(value) (((value) + 0x1f) & ~0x1f)

int AttractMovie_AssignBuffers(void* movieOrReadBuffer, void* yTextureBuffer,
                               void* uTextureBuffer, void* vTextureBuffer, void* audioBuffer,
                               void* thpWorkBuffer)
{
    AttractMoviePlayer* player;
    AttractMovieReadBuffer* readBuffer;
    AttractMovieTextureSet* textureSet;
    AttractMovieAudioBuffer* audioBuf;
    u8* curr;
    u32 frameBufferSize;
    u32 yTextureSize;
    u32 uvTextureSize;
    u32 i;

    player = &lbl_803A5D60;
    if (player->isOpen == 0) goto fail;
    if (player->state != 0) goto fail;

    if (player->isOnMemory != 0)
    {
        player->movieData = movieOrReadBuffer;
        curr = (u8*)movieOrReadBuffer + player->header.mMovieDataSize;
    }
    else
    {
        readBuffer = player->readBuffer;
        curr = movieOrReadBuffer;
        for (i = 0; i < 10; i++)
        {
            readBuffer[i].ptr = curr;
            frameBufferSize = ALIGN_NEXT_32(player->header.mBufferSize);
            curr += frameBufferSize;
        }
    }

    player = &lbl_803A5D60;
    yTextureSize = ALIGN_NEXT_32(player->videoInfo.xSize * player->videoInfo.ySize);
    uvTextureSize = ALIGN_NEXT_32((player->videoInfo.xSize * player->videoInfo.ySize) >> 2);
    textureSet = player->textureSet;
    for (i = 0; i < 3; i++)
    {
        textureSet->yTexture = yTextureBuffer;
        DCInvalidateRange(curr, yTextureSize);
        textureSet->uTexture = uTextureBuffer;
        DCInvalidateRange(curr, uvTextureSize);
        textureSet->vTexture = vTextureBuffer;
        DCInvalidateRange(curr, uvTextureSize);
        curr += uvTextureSize;
        textureSet++;
    }

    player = &lbl_803A5D60;
    if (player->audioExists != 0)
    {
        audioBuf = player->audioBuffer;
        audioBuf[0].buffer = audioBuffer;
        audioBuf[0].curPtr = audioBuffer;
        audioBuf[0].validSample = 0;
        {
            u32 audioBufferSize = ALIGN_NEXT_32(player->header.mAudioMaxSamples * 4);
            s16* nextAudioBuffer = (s16*)((u8*)audioBuffer + audioBufferSize);
            audioBuf[1].buffer = nextAudioBuffer;
            audioBuf[1].curPtr = nextAudioBuffer;
            audioBuf[1].validSample = 0;
            nextAudioBuffer = (s16*)((u8*)nextAudioBuffer + audioBufferSize);
            audioBuf[2].buffer = nextAudioBuffer;
            audioBuf[2].curPtr = nextAudioBuffer;
            audioBuf[2].validSample = 0;
        }
    }

    lbl_803A5D60.thpWorkArea = thpWorkBuffer;
    return 1;

fail:
    return 0;
}

void AttractMovie_GetBufferSizes(uint* movieOrReadBufferSize, int* yTextureBufferSize,
                                 int* uTextureBufferSize, int* vTextureBufferSize,
                                 uint* audioBufferSize, int* thpWorkBufferSize)
{
    AttractMoviePlayer* player;
    u32 movieOrReadSize;
    int size;

    player = &lbl_803A5D60;
    if (player->isOpen != 0)
    {
        if (player->isOnMemory != 0)
        {
            movieOrReadSize = ALIGN_NEXT_32(player->header.mMovieDataSize);
        }
        else
        {
            movieOrReadSize = ALIGN_NEXT_32(player->header.mBufferSize) * 10;
        }
        *movieOrReadBufferSize = movieOrReadSize;
        player = &lbl_803A5D60;
        *yTextureBufferSize = ALIGN_NEXT_32(player->videoInfo.xSize * player->videoInfo.ySize) * 3;
        *uTextureBufferSize = ALIGN_NEXT_32((u32)(player->videoInfo.xSize * player->videoInfo.ySize) >> 2) * 3;
        *vTextureBufferSize = ALIGN_NEXT_32((u32)(player->videoInfo.xSize * player->videoInfo.ySize) >> 2) * 3;
        if (player->audioExists != 0)
        {
            size = ALIGN_NEXT_32(player->header.mAudioMaxSamples * 4) * 3;
        }
        else
        {
            size = 0;
        }
        *audioBufferSize = size;
        *thpWorkBufferSize = 0x1000;
        return;
    }

    *movieOrReadBufferSize = 0;
    *yTextureBufferSize = 0;
    *uTextureBufferSize = 0;
    *vTextureBufferSize = 0;
    *audioBufferSize = 0;
    *thpWorkBufferSize = 0;
}

int AttractMovie_CloseFile(void)
{
    AttractMoviePlayer* player;

    player = &lbl_803A5D60;
    if ((player->isOpen != 0) && (player->state == 0))
    {
        player->isOpen = 0;
        DVDClose(&player->fileInfo);
        return 1;
    }

    return 0;
}
