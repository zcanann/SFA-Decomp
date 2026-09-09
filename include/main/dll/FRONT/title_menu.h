#ifndef MAIN_DLL_FRONT_TITLE_MENU_H_
#define MAIN_DLL_FRONT_TITLE_MENU_H_

#include "types.h"
#include "main/gameloop_api.h"
#include "main/dll/dll_003C_link.h"

#define TITLE_MENU_TEXT_ENTRY_SLOTS 25

typedef struct TitleMenuTextEntry {
    u16 textId;
    u16 boxId;
    s16 rightX;
    s16 textTop;
    s16 slotWidth;
    s16 x;
    s16 y;
    u8 pad0E[2];
    union {
        s32 textureAssetId;
        void* texture;
    };
    u16 width;
    u16 flags;
    u8 unk18[2];
    s8 upLink;
    s8 downLink;
    s8 leftLink;
    s8 rightLink;
    s8 state;
    s8 slots[TITLE_MENU_TEXT_ENTRY_SLOTS];
    s8 timer;
    u8 pad39[3];
} TitleMenuTextEntry;

STATIC_ASSERT(offsetof(TitleMenuTextEntry, rightX) == 0x04);
STATIC_ASSERT(offsetof(TitleMenuTextEntry, textTop) == 0x06);
STATIC_ASSERT(offsetof(TitleMenuTextEntry, x) == 0x0A);
STATIC_ASSERT(offsetof(TitleMenuTextEntry, y) == 0x0C);
STATIC_ASSERT(offsetof(TitleMenuTextEntry, textureAssetId) == 0x10);
STATIC_ASSERT(offsetof(TitleMenuTextEntry, texture) == 0x10);
STATIC_ASSERT(offsetof(TitleMenuTextEntry, width) == 0x14);
STATIC_ASSERT(offsetof(TitleMenuTextEntry, flags) == 0x16);
STATIC_ASSERT(offsetof(TitleMenuTextEntry, upLink) == 0x1A);
STATIC_ASSERT(offsetof(TitleMenuTextEntry, downLink) == 0x1B);
STATIC_ASSERT(offsetof(TitleMenuTextEntry, slots) == 0x1F);
STATIC_ASSERT(sizeof(TitleMenuTextEntry) == 0x3C);

#define TITLE_MENU_TEXT_ENTRY_SELECTABLE         0x1
#define TITLE_MENU_TEXT_ENTRY_DISABLED           0x2
#define TITLE_MENU_TEXT_ENTRY_HIDDEN             0x4000
#define TITLE_MENU_CAMERA_ACTION_ACTIVE          0x57
#define TITLE_MENU_ATTRACT_MOVIE_STATE           4
#define TITLE_MENU_ATTRACT_INPUT_COOLDOWN_FRAMES 0x3c
#define TITLE_MENU_SELECTION_FADE_MAX            0xff
#define TITLE_MENU_SELECTION_INVALID             0xff
#define TITLE_MENU_SELECTION_FADE_STEP           0x19

typedef struct TitleMenuControl {
    void* vtable;
} TitleMenuControl;

typedef struct MenuPanelGroup {
    u8 pad00[0x30];
    TitleMenuTextEntry* entries;
    u32 unused34;
    u8 count;
    u8 pad39[7];
} MenuPanelGroup;

extern u8 gTitleMenuSelection;

#endif /* MAIN_DLL_FRONT_TITLE_MENU_H_ */
