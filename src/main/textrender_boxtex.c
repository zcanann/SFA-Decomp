#include "main/rcp_dolphin_api.h"
#include "main/textrender_api.h"
#include "main/textrender_internal.h"
#include "dolphin/os/OSCache.h"

Texture* gGameTextBoxBgTexture;
Texture* gGameTextBoxCornerTexture;
Texture* gGameTextBoxEdgeTexture;

static inline void gameTextTileBoxTexture(u16* dst, const u16* src, int width) {
    const u16* sourceRow;
    int tileRow;
    int tileColumn, texelX, texelY;
    for (tileRow = 0; tileRow < width / 4; tileRow++) {
        for (tileColumn = 0; tileColumn < width / 4; tileColumn++) {
            for (texelY = 0; texelY < 4; texelY++) {
                sourceRow = src + (tileRow * 4 + texelY) * width;
                for (texelX = 0; texelX < 4; texelX++) {
                    *dst++ = sourceRow[tileColumn * 4 + texelX];
                }
            }
        }
    }
}

void gameTextInitBoxTextures(void) {
    Texture** textureSlot;
    s16* textureAsset;
    int assetCount;
    Texture* texture;

    assetCount = 1;
    textureAsset = &gGameTextBoxTexAssets + 1;
    textureSlot = &gGameTextBoxBgTexture + 1;
    while (textureAsset--, textureSlot--, assetCount-- != 0) {
        *textureSlot = textureLoadAsset(*textureAsset);
    }

    texture = textureAlloc(16, 16, GX_TF_RGB5A3, 0, 0, 0, 0, 1, 1);
    gGameTextBoxCornerTexture = texture;
    gameTextTileBoxTexture((u16*)(texture + 1), gGameTextBoxCornerTexSrc, 16);
    DCFlushRange(gGameTextBoxCornerTexture + 1, 512);

    texture = textureAlloc(20, 20, GX_TF_RGB5A3, 0, 0, 0, 0, 1, 1);
    gGameTextBoxEdgeTexture = texture;
    gameTextTileBoxTexture((u16*)(texture + 1), gGameTextBoxEdgeTexSrc, 20);
    DCFlushRange(gGameTextBoxEdgeTexture + 1, 800);
}
