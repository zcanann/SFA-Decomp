#include "main/audio/sfx_ids.h"
#include "main/dll/baddie/dll_003C_TumbleweedBush.h"

typedef struct TitleMenuItem
{
    s16 x;
    s16 y;
    u8 flags;
    u8 kind;
    s8 frameDelay;
    u8 pad7;
    s16 minValue;
    s16 maxValue;
    s16 value;

    union
    {
        s16 textId;

        struct
        {
            u16 phraseId;
            u16 windowId;
        } window;
    } extra;
} TitleMenuItem;



#define TITLE_MENU_FLAG_ENABLED        0x01
#define TITLE_MENU_FLAG_WRAP           0x02
#define TITLE_MENU_FLAG_MOVED_LEFT     0x04
#define TITLE_MENU_FLAG_MOVED_RIGHT    0x08
#define TITLE_MENU_FLAG_CHANGED        0x10
#define TITLE_MENU_FLAG_A_TOGGLE       0x20
#define TITLE_MENU_FLAG_VOLUME_PREVIEW 0x40
#define TITLE_MENU_FLAG_MUSIC_PREVIEW  0x80



extern u32 getButtonsJustPressed(int pad);


/*
 * --INFO--
 *
 * Function: Link_update
 * EN v1.0 Address: 0x80130CF0
 * EN v1.0 Size: 936b
 * EN v1.1 Address: 0x80131078
 * EN v1.1 Size: 1168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* ===== EN v1.0 retargeted leaves ========================================= */

/* EN v1.0 0x80131570  size: 12b  Read changed bit from item->flags. */
int TitleMenuItem_isChanged(TitleMenuItem* item);

/* EN v1.0 0x8013157C  size: 20b  Set item->value and item->frameDelay = 2.
 * Logic-only ? target has `extsh r0,r4; sth r0,0xc(r3)` but MWCC -O4
 * strips the redundant extsh before sth (same family as GameUI_func0F /
 * CMenu_SetShouldClose). */
void TitleMenuItem_setVal(TitleMenuItem* item, int val);

/* EN v1.0 0x80131590  size: 8b   Getter for item->value. */
s16 TitleMenuItem_getVal(TitleMenuItem* item);

extern s16 lbl_803DD918;
extern f32 lbl_803DD91C;
extern s8 lbl_803DD920;
extern void* lbl_803A9DB8[6];
extern f32 lbl_803E21F0;
extern f32 lbl_803E21F4;
extern f32 lbl_803E21F8;
extern s8 padGetStickX(int port);
extern void Sfx_PlayFromObject(u32 obj, u32 sfxId);
extern void Sfx_KeepAliveLoopedObjectSound(u32 obj, u32 sfxId);
extern void Sfx_SetObjectSfxVolume(u32 obj, u32 sfxId, u8 volume, f32 volumeScale);
extern void Music_PlayTrackByIndex(int index);
extern void drawTexture(void* texture, u8 alpha, f32 x, f32 y, u16 scale);
extern void* gameTextGetPhrase(int textId, int variant);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextSetWindowStrPos(int windowId, int x, int y);
extern void gameTextAppendStr(void* str, int windowId);

/* EN v1.0 0x80131598  size: 116b  Toggle enabled bit on item->flags. */
void TitleMenuItem_setEnabled(TitleMenuItem* item, int flag);

/* EN v1.0 0x8013160C  size: 12b  Read enabled bit from item->flags. */
int TitleMenuItem_isEnabled(TitleMenuItem* item);

/* EN v1.0 0x80131618  size: 808b  Render title menu item. */
void TitleMenuItem_render(TitleMenuItem* item, int unused, int alpha);

/* EN v1.0 0x80131940  size: 948b  Update title menu item input state. */
void TitleMenuItem_update(TitleMenuItem* item);

/* EN v1.0 0x80132008  size: 8b   Trivial 1-returner. */
int Dummy3E_func05_ret_1(void) { return 1; }

/* EN v1.0 0x80132010  size: 4b   Empty no-op. */
void Dummy3E_func04_nop(void)
{
}

/* EN v1.0 0x80132014  size: 8b   Trivial 0-returner. */
int Dummy3E_func03_ret_0(void) { return 0; }

/* EN v1.0 0x8013201C  size: 4b   Empty no-op. */
void Dummy3E_release(void)
{
}

/* EN v1.0 0x80132020  size: 4b   Empty no-op. */
void Dummy3E_initialise(void)
{
}

extern u8 linkTextures[0x30];
extern s16 lbl_8031C2A8[6];
extern void mm_free(void);

/* EN v1.0 0x80131540  size: 48b  Toggle A-button bit of item->flags. */
void TitleMenuItem_setAButtonToggle(TitleMenuItem* item, int flag);

/* EN v1.0 0x80131CF4  size: 32b  Wrapper for mm_free. */
void TitleMenuItem_free(void);

/* EN v1.0 0x80131FE0  size: 40b  Zero 6 u32s at lbl_803A9DB8. */
void TitleMenuItem_initialise(void);

/* Drift-recovery: add new fns with v1.0 names. */
extern void* textureLoadAsset(int id);
extern void textureFree(void* p);
extern void* mmAlloc(int size, int heap, int flags);


/* EN v1.0 0x80131D14  size: 168b  Create text-window title menu item. */
TitleMenuItem* TitleMenuItem_createWithWindow(int phraseId, int windowId, s16 minValue, s16 maxValue, s16 value);

/* EN v1.0 0x80131DBC  size: 164b  Create simple title menu item. */
TitleMenuItem* TitleMenuItem_create(s16 x, s16 y, s16 minValue, s16 maxValue, s16 value);

/* EN v1.0 0x80131E60  size: 172b  Create text-backed title menu item. */
TitleMenuItem* TitleMenuItem_createWithText(s16 x, s16 y, s16 minValue, s16 maxValue, s16 value, int textId);

void fn_80131F0C(void);

void Link_release(void);



void TitleMenuItem_release(void);

void Link_free(void);

