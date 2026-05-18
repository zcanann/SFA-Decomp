#include "ghidra_import.h"
#include "main/dll/FRONT/dll_44.h"
#include "dolphin/dvd.h"
#include "dolphin/thp/THPFile.h"
#include "dolphin/thp/THPInfo.h"

extern void DCInvalidateRange(void *start, u32 nBytes);

#define ALIGN_NEXT_32(value) (((value) + 0x1f) & ~0x1f)

#pragma peephole off
#pragma scheduling off

/*
 * --INFO--
 *
 * Function: AttractMovie_AssignBuffers
 * EN v1.0 Address: 0x80118C88
 * EN v1.0 Size: 548b
 */
int AttractMovie_AssignBuffers(void *movieOrReadBuffer, void *yTextureBuffer,
                               void *uTextureBuffer, void *vTextureBuffer, void *audioBuffer,
                               void *thpWorkBuffer)
{
    u8 *base;
    u8 *base2;
    int curr;
    u32 align1;
    u32 align2;
    u32 i;

    base = (u8 *)&lbl_803A5D60;
    if (*(int *)(base + 0x98) == 0) goto fail;
    if (*(u8 *)(base + 0x9c) != 0) goto fail;

    if (*(int *)(base + 0xa8) != 0) {
        *(void **)(base + 0xac) = movieOrReadBuffer;
        curr = (int)movieOrReadBuffer + *(int *)(base + 0x58);
    } else {
        *(void **)(base + 0xf4) = movieOrReadBuffer;
        *(int *)(base + 0xfc) = (int)movieOrReadBuffer + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x104) = *(int *)(base + 0xfc) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x10c) = *(int *)(base + 0x104) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x114) = *(int *)(base + 0x10c) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x11c) = *(int *)(base + 0x114) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x124) = *(int *)(base + 0x11c) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x12c) = *(int *)(base + 0x124) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x134) = *(int *)(base + 0x12c) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        *(int *)(base + 0x13c) = *(int *)(base + 0x134) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
        curr = *(int *)(base + 0x13c) + ((*(int *)(base + 0x44) + 0x1f) & ~0x1f);
    }

    base2 = (u8 *)&lbl_803A5D60;
    align1 = (*(int *)(base2 + 0x80) * *(int *)(base2 + 0x84) + 0x1f) & ~0x1f;
    align2 = ((u32)(*(int *)(base2 + 0x80) * *(int *)(base2 + 0x84)) >> 2) + 0x1f & ~0x1f;
    i = 0;
    do {
        *(void **)(base2 + 0x144) = yTextureBuffer;
        DCInvalidateRange((void *)curr, align1);
        *(void **)(base2 + 0x148) = uTextureBuffer;
        DCInvalidateRange((void *)curr, align2);
        *(void **)(base2 + 0x14c) = vTextureBuffer;
        DCInvalidateRange((void *)curr, align2);
        curr += align2;
        base2 += 0x10;
        i++;
    } while (i < 3);

    base = (u8 *)&lbl_803A5D60;
    if (*(u8 *)(base + 0x9f) != 0) {
        *(void **)(base + 0x174) = audioBuffer;
        *(void **)(base + 0x178) = audioBuffer;
        *(int *)(base + 0x17c) = 0;
        {
            int sz = (*(int *)(base + 0x48) * 4 + 0x1f) & ~0x1f;
            int p2 = (int)audioBuffer + sz;
            *(int *)(base + 0x184) = p2;
            *(int *)(base + 0x188) = p2;
            *(int *)(base + 0x18c) = 0;
            p2 += sz;
            *(int *)(base + 0x194) = p2;
            *(int *)(base + 0x198) = p2;
            *(int *)(base + 0x19c) = 0;
        }
    }

    *(void **)((u8 *)&lbl_803A5D60 + 0x94) = thpWorkBuffer;
    return 1;

fail:
    return 0;
}

/*
 * --INFO--
 *
 * Function: AttractMovie_GetBufferSizes
 * EN v1.0 Address: 0x80118EAC
 * EN v1.0 Size: 256b
 */
void AttractMovie_GetBufferSizes(uint *movieOrReadBufferSize, int *yTextureBufferSize,
                                 int *uTextureBufferSize, int *vTextureBufferSize,
                                 uint *audioBufferSize, int *thpWorkBufferSize)
{
    AttractMoviePlayer *player;
    u32 movieOrReadSize;
    int size;

    player = &lbl_803A5D60;
    if (player->isOpen != 0) {
        if (player->isOnMemory != 0) {
            movieOrReadSize = ALIGN_NEXT_32(player->header.mMovieDataSize);
        } else {
            movieOrReadSize = ALIGN_NEXT_32(player->header.mBufferSize) * 10;
        }
        *movieOrReadBufferSize = movieOrReadSize;
        *yTextureBufferSize = ALIGN_NEXT_32(player->videoInfo.xSize * player->videoInfo.ySize) * 3;
        *uTextureBufferSize = ALIGN_NEXT_32((u32)(player->videoInfo.xSize * player->videoInfo.ySize) >> 2) * 3;
        *vTextureBufferSize = ALIGN_NEXT_32((u32)(player->videoInfo.xSize * player->videoInfo.ySize) >> 2) * 3;
        if (player->audioExists != 0) {
            size = ALIGN_NEXT_32(player->header.mAudioMaxSamples * 4) * 3;
        } else {
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

/*
 * --INFO--
 *
 * Function: AttractMovie_CloseFile
 * EN v1.0 Address: 0x80118FAC
 * EN v1.0 Size: 84b
 */
int AttractMovie_CloseFile(void)
{
    AttractMoviePlayer *player;

    player = &lbl_803A5D60;
    if ((player->isOpen != 0) && (player->state == 0)) {
        player->isOpen = 0;
        DVDClose(&player->fileInfo);
        return 1;
    }

    return 0;
}

#pragma peephole reset
#pragma scheduling reset
