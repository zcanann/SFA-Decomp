#include "main/rcp_dolphin_api.h"
#include "main/textrender_api.h"
#include "main/textrender_internal.h"
#include "dolphin/os/OSCache.h"

Texture* gGameTextBoxBgTexture;
Texture* gGameTextBoxCornerTexture;
Texture* gGameTextBoxEdgeTexture;

void gameTextInitBoxTextures(void) {
    u16* dst;
    int tileRow, tileColumn, tileLeft, texelY, texelX;
    Texture* texture;
    Texture** textureSlot;
    s16* textureAsset;
    int assetCount;

    assetCount = 1;
    textureAsset = &gGameTextBoxTexAssets + 1;
    textureSlot = &gGameTextBoxBgTexture + 1;
    while (textureAsset--, textureSlot--, assetCount-- != 0) {
        *textureSlot = textureLoadAsset(*textureAsset);
    }

    texture = textureAlloc(16, 16, GX_TF_RGB5A3, 0, 0, 0, 0, 1, 1);
    gGameTextBoxCornerTexture = texture;
    dst = (u16*)(texture + 1);
    for (tileRow = 0; tileRow < 4; tileRow++) {
        for (tileColumn = 0; tileColumn < 4; tileColumn++) {
            for (texelY = 0; texelY < 4; texelY++) {
                for (texelX = 0; texelX < 4; texelX++) {
                    *dst++ = gGameTextBoxCornerTexSrc[tileRow * 4 + texelY][tileColumn * 4 + texelX];
                }
            }
        }
    }
    DCFlushRange(gGameTextBoxCornerTexture + 1, 512);

    texture = textureAlloc(20, 20, GX_TF_RGB5A3, 0, 0, 0, 0, 1, 1);
    gGameTextBoxEdgeTexture = texture;
    dst = (u16*)(texture + 1);
    for (tileRow = 0; tileRow < 5; tileRow++) {
        for (tileLeft = 0; tileLeft < 20; tileLeft += 4) {
            for (texelY = 0; texelY < 4; texelY++) {
                for (texelX = 0; texelX < 4; texelX++) {
                    *dst++ = gGameTextBoxEdgeTexSrc[tileRow * 4 + texelY][tileLeft + texelX];
                }
            }
        }
    }
    DCFlushRange(gGameTextBoxEdgeTexture + 1, 800);
}
