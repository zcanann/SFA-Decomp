#include "main/rcp_dolphin_api.h"
#include "main/textrender_api.h"
#include "main/textrender_internal.h"
#include "dolphin/os/OSCache.h"

void gameTextInitFn_8001c794(void)
{
    Texture** q;
    s16* p;
    int x0;
    int off;
    int x3;
    int x2;
    int x1;
    u16* dst;
    int x;
    int y;
    u8* rowBase;
    int i;
    int j;
    Texture* tex;
    int count;

    count = 1;
    p = &gGameTextBoxTexAssets + 1;
    q = &gGameTextBoxBgTexture + 1;
    while (p--, q--, count-- != 0)
    {
        *q = textureLoadAsset(*p);
    }

    tex = textureAlloc(0x10, 0x10, 5, 0, 0, 0, 0, 1, 1);
    gGameTextBoxCornerTexture = tex;
    dst = (u16*)(tex + 1);
    i = 0;
    y = 0;
    for (; i < 4; i++)
    {
        j = 0;
        x = 0;
        x0 = 0;
        while (j++ < 2)
        {
            x1 = (x + 1) * 2;
            x2 = (x + 2) * 2;
            x3 = (x + 3) * 2;
            off = y * 32;
            rowBase = (u8*)gGameTextBoxCornerTexSrc + off;
            dst[0] = *(u16*)(rowBase + x0);
            dst[1] = *(u16*)(rowBase + x1);
            dst[2] = *(u16*)(rowBase + x2);
            dst[3] = *(u16*)(rowBase + x3);
            off += 32;
            rowBase = (u8*)gGameTextBoxCornerTexSrc + off;
            dst[4] = *(u16*)(rowBase + x0);
            dst[5] = *(u16*)(rowBase + x1);
            dst[6] = *(u16*)(rowBase + x2);
            dst[7] = *(u16*)(rowBase + x3);
            off += 32;
            rowBase = (u8*)gGameTextBoxCornerTexSrc + off;
            dst[8] = *(u16*)(rowBase + x0);
            dst[9] = *(u16*)(rowBase + x1);
            dst[10] = *(u16*)(rowBase + x2);
            dst[11] = *(u16*)(rowBase + x3);
            off += 32;
            rowBase = (u8*)gGameTextBoxCornerTexSrc + off;
            dst[12] = *(u16*)(rowBase + x0);
            dst[13] = *(u16*)(rowBase + x1);
            dst[14] = *(u16*)(rowBase + x2);
            dst[15] = *(u16*)(rowBase + x3);
            x0 += 8;
            x1 = (x + 5) * 2;
            x2 = (x + 6) * 2;
            x3 = (x + 7) * 2;
            off = y * 32;
            rowBase = (u8*)gGameTextBoxCornerTexSrc + off;
            dst[16] = *(u16*)(rowBase + x0);
            dst[17] = *(u16*)(rowBase + x1);
            dst[18] = *(u16*)(rowBase + x2);
            dst[19] = *(u16*)(rowBase + x3);
            off += 32;
            rowBase = (u8*)gGameTextBoxCornerTexSrc + off;
            dst[20] = *(u16*)(rowBase + x0);
            dst[21] = *(u16*)(rowBase + x1);
            dst[22] = *(u16*)(rowBase + x2);
            dst[23] = *(u16*)(rowBase + x3);
            off += 32;
            rowBase = (u8*)gGameTextBoxCornerTexSrc + off;
            dst[24] = *(u16*)(rowBase + x0);
            dst[25] = *(u16*)(rowBase + x1);
            dst[26] = *(u16*)(rowBase + x2);
            dst[27] = *(u16*)(rowBase + x3);
            off += 32;
            rowBase = (u8*)gGameTextBoxCornerTexSrc + off;
            dst[28] = *(u16*)(rowBase + x0);
            dst[29] = *(u16*)(rowBase + x1);
            dst[30] = *(u16*)(rowBase + x2);
            dst[31] = *(u16*)(rowBase + x3);
            dst += 32;
            x += 8;
            x0 += 8;
        }
        y += 4;
    }
    DCFlushRange(gGameTextBoxCornerTexture + 1, 0x200);

    tex = textureAlloc(0x14, 0x14, 5, 0, 0, 0, 0, 1, 1);
    gGameTextBoxEdgeTexture = tex;
    dst = (u16*)(tex + 1);
    i = 0;
    y = 0;
    for (; i < 5; i++)
    {
        j = 0;
        x0 = 0;
        for (; j < 20;)
        {
            x1 = (j + 1) * 2;
            x2 = (j + 2) * 2;
            x3 = (j + 3) * 2;
            off = y * 40;
            rowBase = (u8*)&lbl_802CA100 + off;
            dst[0] = *(u16*)(rowBase + x0);
            dst[1] = *(u16*)(rowBase + x1);
            dst[2] = *(u16*)(rowBase + x2);
            dst[3] = *(u16*)(rowBase + x3);
            off += 40;
            rowBase = (u8*)&lbl_802CA100 + off;
            dst[4] = *(u16*)(rowBase + x0);
            dst[5] = *(u16*)(rowBase + x1);
            dst[6] = *(u16*)(rowBase + x2);
            dst[7] = *(u16*)(rowBase + x3);
            off += 40;
            rowBase = (u8*)&lbl_802CA100 + off;
            dst[8] = *(u16*)(rowBase + x0);
            dst[9] = *(u16*)(rowBase + x1);
            dst[10] = *(u16*)(rowBase + x2);
            dst[11] = *(u16*)(rowBase + x3);
            off += 40;
            rowBase = (u8*)&lbl_802CA100 + off;
            dst[12] = *(u16*)(rowBase + x0);
            dst[13] = *(u16*)(rowBase + x1);
            dst[14] = *(u16*)(rowBase + x2);
            dst[15] = *(u16*)(rowBase + x3);
            dst += 16;
            j += 4;
            x0 += 8;
        }
        y += 4;
    }
    DCFlushRange(gGameTextBoxEdgeTexture + 1, 800);
}
