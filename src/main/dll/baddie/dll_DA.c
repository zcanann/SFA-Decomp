#include "ghidra_import.h"
#include "main/dll/baddie/dll_DA.h"

#pragma peephole off
#pragma scheduling off

typedef struct LinkTexture {
    void *texture;
    u8 pad4[2];
    u8 width;
    u8 pad7;
} LinkTexture;

typedef struct LinkMenuItem {
    u16 textId;
    u16 boxId;
    s16 field04;
    s16 field06;
    u8 pad08[2];
    s16 x;
    s16 y;
    u8 pad0E[2];
    void *texture;
    u16 field14;
    u16 flags;
    u8 pad18[2];
    u8 field1A;
    u8 pad1B[3];
    s8 state;
    s8 slots[25];
    s8 timer;
    u8 pad39[3];
} LinkMenuItem;

extern void drawTexture(void *texture, u8 alpha, f32 x, f32 y, u16 scale);
extern void gameTextFn_80016810(int textId, int arg1, int arg2);
extern void *gameTextGetBox(int boxId);
extern void gameTextSetColor(int red, int green, int blue, int alpha);
extern void gameTextShow(int textId);
extern void gameTextShowStr(void *text, int boxId, int arg2, int arg3);
extern void MWTRACE(int boxId);

extern LinkTexture linkTextures[6];
extern LinkMenuItem lbl_803A9458[40];
extern void *saveFileSelect_saveSlots;
extern s16 lbl_803DD8FA;
extern s16 lbl_803DD8FC;
extern s16 lbl_803DD8FE;
extern s16 lbl_803DD900;
extern s16 lbl_803DD902;
extern s16 lbl_803DD904;
extern s16 linkItemOpacity;
extern s16 linkCount_803dd90e;
extern s8 lbl_803DD911;
extern s8 linkSelected;
extern f64 lbl_803E21E0;

/*
 * --INFO--
 *
 * Function: Link_render
 * EN v1.0 Address: 0x80130888
 * EN v1.0 Size: 1128b
 * EN v1.1 Address: 0x801309A8
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Link_render(void)
{
    LinkMenuItem *item;
    LinkMenuItem *drawItem;
    int i;
    int slotIndex;
    int textureIndex;
    int opacity;
    int alpha;
    int red;
    int green;
    int blue;
    int textId;
    int x;
    int y;
    u16 flags;

    item = lbl_803A9458;
    for (i = 0; i < lbl_803DD911; i++) {
        drawItem = item;
        flags = item->flags;

        if ((flags & 0x4000) == 0) {
            if ((flags & 0x1040) != 0) {
                item->timer--;
                if (item->timer < 0) {
                    item->timer = 0;
                }
            } else {
                if (item->state != -1) {
                    drawItem = &lbl_803A9458[item->state];
                }

                flags = drawItem->flags;
                if ((flags & 4) != 0) {
                    slotIndex = 0;
                    x = drawItem->x;
                    y = drawItem->y;
                    while (drawItem->slots[slotIndex] != -1 && slotIndex < 25) {
                        textureIndex = drawItem->slots[slotIndex];
                        drawTexture(linkTextures[textureIndex].texture, 0xff, (f32)x, (f32)y, 0x100);
                        x += linkTextures[drawItem->slots[slotIndex]].width;
                        slotIndex++;
                    }
                }

                if ((flags & 0x800) != 0) {
                    opacity = linkItemOpacity * 200 >> 8;
                } else {
                    opacity = linkItemOpacity;
                }

                MWTRACE(drawItem->boxId);
                if (linkSelected == i) {
                    alpha = opacity;
                } else {
                    alpha = (((u32)opacity >> 31) + opacity) >> 1;
                }
                *(u8 *)((char *)gameTextGetBox(drawItem->boxId) + 0x1e) = (u8)alpha;

                if ((flags & 0x100) != 0) {
                    gameTextSetColor(0, 0, 0, (u8)(((linkCount_803dd90e + 1) * linkItemOpacity) >> 8));
                    gameTextFn_80016810(drawItem->textId, 2, 2);
                }

                if ((flags & 0x80) != 0) {
                    if (linkSelected == i) {
                        red = lbl_803DD904 + ((linkCount_803dd90e * (lbl_803DD8FE - lbl_803DD904)) >> 8);
                        green = lbl_803DD902 + ((linkCount_803dd90e * (lbl_803DD8FC - lbl_803DD902)) >> 8);
                        blue = lbl_803DD900 + ((linkCount_803dd90e * (lbl_803DD8FA - lbl_803DD900)) >> 8);
                        if ((flags & 0x800) != 0) {
                            alpha = linkItemOpacity * 200 >> 8;
                        } else {
                            alpha = linkItemOpacity;
                        }
                        gameTextSetColor((u8)red, (u8)green, (u8)blue, (u8)alpha);
                    } else {
                        gameTextSetColor((u8)lbl_803DD904, (u8)lbl_803DD902, (u8)lbl_803DD900,
                                         (u8)((((u32)opacity >> 31) + opacity) >> 1));
                    }
                } else {
                    gameTextSetColor(0xff, 0xff, 0xff, (u8)opacity);
                }

                textId = drawItem->textId;
                if (textId > 0x14 && textId != 0xffff) {
                    gameTextShow(textId);
                } else if (textId != 0xffff) {
                    gameTextShowStr((char *)saveFileSelect_saveSlots + textId * 0x24, drawItem->boxId, 0, 0);
                }

                if (drawItem->texture != NULL) {
                    if ((flags & 4) != 0) {
                        x = drawItem->x + 11;
                    } else {
                        x = drawItem->x;
                    }
                    y = drawItem->y;
                    if ((flags & 0x800) != 0) {
                        alpha = linkItemOpacity * 200 >> 8;
                    } else {
                        alpha = linkItemOpacity;
                    }
                    drawTexture(drawItem->texture, (u8)alpha, (f32)x, (f32)y, 0x100);
                }

                drawItem->timer--;
                if (drawItem->timer < 0) {
                    drawItem->timer = 0;
                }
            }
        }

        item++;
    }

    MWTRACE(0xff);
}
