#include "main/rcp_dolphin_api.h"
#include "main/textrender_api.h"
#include "main/textrender_internal.h"
#include "dolphin/os/OSCache.h"

Texture* gGameTextBoxBgTexture;
Texture* gGameTextBoxCornerTexture;
Texture* gGameTextBoxEdgeTexture;

void gameTextInitBoxTextures(void) {
    Texture** textureSlot;
    s16* textureAsset;
    int assetCount;
    Texture* texture;
    u16* sourceRow;
    u16* cornerDst;
    int cornerTileRow;
    u16* edgeDst;
    int edgeTileRow;
    int tileColumn, texelX, texelY;

    assetCount = 1;
    textureAsset = &gGameTextBoxTexAssets + 1;
    textureSlot = &gGameTextBoxBgTexture + 1;
    while (textureAsset--, textureSlot--, assetCount-- != 0) {
        *textureSlot = textureLoadAsset(*textureAsset);
    }

    texture = textureAlloc(16, 16, GX_TF_RGB5A3, 0, 0, 0, 0, 1, 1);
    gGameTextBoxCornerTexture = texture;
    cornerDst = (u16*)(texture + 1);
    for (cornerTileRow = 0; cornerTileRow < 4; cornerTileRow++) {
        for (tileColumn = 0; tileColumn < 4; tileColumn++) {
            for (texelY = 0; texelY < 4; texelY++) {
                sourceRow = gGameTextBoxCornerTexSrc + (cornerTileRow * 4 + texelY) * 16;
                for (texelX = 0; texelX < 4; texelX++) {
                    *cornerDst++ = sourceRow[tileColumn * 4 + texelX];
                }
            }
        }
    }
    DCFlushRange(gGameTextBoxCornerTexture + 1, 512);

    texture = textureAlloc(20, 20, GX_TF_RGB5A3, 0, 0, 0, 0, 1, 1);
    gGameTextBoxEdgeTexture = texture;
    edgeDst = (u16*)(texture + 1);
    for (edgeTileRow = 0; edgeTileRow < 5; edgeTileRow++) {
        for (tileColumn = 0; tileColumn < 5; tileColumn++) {
            for (texelY = 0; texelY < 4; texelY++) {
                sourceRow = gGameTextBoxEdgeTexSrc + (edgeTileRow * 4 + texelY) * 20;
                for (texelX = 0; texelX < 4; texelX++) {
                    *edgeDst++ = sourceRow[tileColumn * 4 + texelX];
                }
            }
        }
    }
    DCFlushRange(gGameTextBoxEdgeTexture + 1, 800);
}
