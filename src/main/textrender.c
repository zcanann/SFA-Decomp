#include "track/intersect_hud_api.h"
#include "main/gametext_shared_internal.h"
#include "main/mm.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "main/frame_timing.h"
#include "main/fileio.h"
#include "main/textrender_api.h"
#include "main/textrender_internal.h"
#include "main/lightmap_text_color_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/dll/dll_0015_save_settings.h"
#include "track/intersect_api.h"
#include "string.h"
#include "main/lightmap.h"
#include "track/intersect_render_setup_api.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXGet.h"

struct JapaneseDiscStatusResource;
struct EnglishDiscStatusResource;
extern struct JapaneseDiscStatusResource sJpDiscStatusMessageTable;
extern struct EnglishDiscStatusResource sDiscStatusMessageTable;
extern char sDiscReadingMessage[];
extern char sDiscInsertPromptLine[];
extern char sDiscInsertGameDiscLine[];

void* gGameTextStringStore = (void*)-1;
char sJpDiscErrorTopSpacerLine[4] = {0};
char sJpDiscErrorBottomSpacerLine[4] = {0};
char sJpDiscReadErrorTopSpacerLine[4] = {0};
char sJpDiscReadingTopSpacerLine[4] = {0};
char sJpDiscCoverOpenTopSpacerLine[4] = {0};
char sJpDiscInsertTopSpacerLine[4] = {0};
char sJpDiscInsertBottomSpacerLine[4] = {0};
char sJpWrongDiscTopSpacerLine[4] = {0};
char sJpWrongDiscMiddleSpacerLine[4] = "\xE3\x80\x80";
char* sJpDiscLoadingMessageLines[1] = {(char*)&sJpDiscStatusMessageTable};
char sDiscErrorSpacerLine[4] = {0};
char sDiscReadErrorSpacerLine[4] = {0};
char* sDiscReadingMessageLines[1] = {sDiscReadingMessage};
char sDiscCoverOpenSpacerLine[4] = {0};
char* sDiscInsertMessageLines[2] = {sDiscInsertPromptLine, sDiscInsertGameDiscLine};
char sWrongDiscSpacerLine[4] = {0};
char* sDiscLoadingMessageLines[1] = {(char*)&sDiscStatusMessageTable};
int gGameTextFontTexRowPitch = 0x800;
GXColor gGameTextClearColor = {0, 0, 0, 0xC0};
int gGameTextFlagGlyphRaise = 3;
f32 gGameTextRevealSpeed = 0.4f;
char sGameTextBlankFormat[] = "    ";
char lbl_803DB3DC[4] = {0};
int gGameTextSavedDir = -1;
char lbl_803DB3E4[4] = {0};
s16 gGameTextBoxTexAssets = 0x1C4;
int gGameTextBoxCornerInset = 2;
int gGameTextBoxInset = 0xE;
int gGameTextBoxColorR = 0xFF;
int gGameTextBoxColorG = 0xFF;
int gGameTextBoxColorB = 0xFF;
int gGameTextBoxColorA = 0xFF;
char lbl_803DB404[4] = {0};

extern const f32 lbl_803DE70C;
extern const f32 lbl_803DE710;
extern u32 sSubtitleCtrlCmdScratch[];

static void translateToDinoLanguage(u8* str);

/*
 * The disc-error/loading screens' self-contained resources: the SJIS->glyph
 * remap table, the built-in font metrics, and the Japanese and English
 * disc-status message text. These screens must be able to draw without
 * loading anything from disc, so the whole resource lives in the executable.
 */

u16 gGameTextSjisGlyphTable[256] = {
    0x30A8, 0x8347, 0x30E9, 0x8389, 0x30FC, 0x815B, 0x304C, 0x82AA, 0x767A, 0x94AD, 0x751F, 0x90B6, 0x3057, 0x82B5,
    0x307E, 0x82DC, 0x305F, 0x82BD, 0x3002, 0x8142, 0x0020, 0x0020, 0x672C, 0x967B, 0x4F53, 0x91CC, 0x306E, 0x82CC,
    0x30D1, 0x8370, 0x30EF, 0x838F, 0x30DC, 0x837B, 0x30BF, 0x835E, 0x30F3, 0x8393, 0x3092, 0x82F0, 0x62BC, 0x899F,
    0x3066, 0x82C4, 0x96FB, 0x9364, 0x6E90, 0x8CB9, 0x004F, 0x004F, 0x0046, 0x0046, 0x306B, 0x82C9, 0x53D6, 0x8EE6,
    0x6271, 0x88B5, 0x8AAC, 0x90E0, 0x660E, 0x96BE, 0x66F8, 0x8F91, 0x6307, 0x8E77, 0x793A, 0x8EA6, 0x5F93, 0x8F5D,
    0x3063, 0x82C1, 0x4E0B, 0x89BA, 0x3055, 0x82B3, 0x3044, 0x82A2, 0x30C7, 0x8366, 0x30A3, 0x8342, 0x30B9, 0x8358,
    0x30AF, 0x834E, 0x8AAD, 0x93C7, 0x3081, 0x82DF, 0x305B, 0x82B9, 0x3093, 0x82F1, 0x3067, 0x82C5, 0x304F, 0x82AD,
    0x308F, 0x82ED, 0x306F, 0x82CD, 0x304A, 0x82A8, 0x307F, 0x82DD, 0x8FBC, 0x8D9E, 0x3059, 0x82B7, 0x30AB, 0x834A,
    0x30D0, 0x836F, 0x958B, 0x8A4A, 0x30B2, 0x8351, 0x30E0, 0x8380, 0x7D9A, 0x91B1, 0x3051, 0x82AF, 0x308B, 0x82E9,
    0x5834, 0x8FEA, 0x5408, 0x8D87, 0x9589, 0x95C2, 0x300C, 0x8175, 0x30D5, 0x8374, 0x30A9, 0x8348, 0x30C3, 0x8362,
    0x30A2, 0x8341, 0x30C9, 0x8368, 0x30D9, 0x8378, 0x30C1, 0x8360, 0x30E3, 0x8383, 0x300D, 0x8176, 0x30BB, 0x835A,
    0x30C8, 0x8367, 0x3053, 0x82B1, 0x3042, 0x82A0, 0x308A, 0x82E8, 0x30ED, 0x838D, 0x4E2D, 0x9286, 0x2026, 0x8163,
    0x0053, 0x0053, 0x0065, 0x0065, 0x0020, 0x0020, 0x0068, 0x0068, 0x0061, 0x0061, 0x0070, 0x0070, 0x0072, 0x0072,
    0x006F, 0x006F, 0x0064, 0x0064, 0x0075, 0x0075, 0x0063, 0x0063, 0x0069, 0x0069, 0x006E, 0x006E, 0x002E, 0x002E,
    0x0041, 0x0041, 0x0067, 0x0067, 0x006C, 0x006C, 0x0073, 0x0073, 0x0079, 0x0079, 0x0074, 0x0074, 0x006D, 0x006D,
    0x004E, 0x004E, 0x0049, 0x0049, 0x0054, 0x0054, 0x0045, 0x0045, 0x0044, 0x0044, 0x004F, 0x004F, 0x0047, 0x0047,
    0x004D, 0x004D, 0x0043, 0x0043, 0x0055, 0x0055, 0x0042, 0x0042, 0x0028, 0x0028, 0x0029, 0x0029, 0x0062, 0x0062,
    0x00E1, 0x0000, 0x0066, 0x0066, 0x00F3, 0x0000, 0x004C, 0x004C, 0x0046, 0x0046, 0x0078, 0x0078, 0x0076, 0x0076,
    0x00C9, 0x0000, 0x0000, 0x0000,
};

char gGameTextFontData[1360] = {
    0x00, 0x00, 0x30, 0xA8, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x03, 0x02, 0x14, 0x10, 0x00, 0x00, 0x00, 0x00, 0x30,
    0xE9, 0x00, 0x16, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x13, 0x12, 0x00, 0x00, 0x00, 0x00, 0x30, 0xFC, 0x00, 0x2A,
    0x00, 0x01, 0x00, 0x01, 0x08, 0x0A, 0x14, 0x03, 0x00, 0x00, 0x00, 0x00, 0x30, 0x4C, 0x00, 0x3F, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x01, 0x15, 0x14, 0x00, 0x00, 0x00, 0x00, 0x76, 0x7A, 0x00, 0x55, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
    0x14, 0x14, 0x00, 0x00, 0x00, 0x00, 0x75, 0x1F, 0x00, 0x6A, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x14, 0x13, 0x00,
    0x00, 0x00, 0x00, 0x30, 0x57, 0x00, 0x7F, 0x00, 0x01, 0x03, 0x02, 0x01, 0x01, 0x10, 0x13, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x7E, 0x00, 0x90, 0x00, 0x01, 0x01, 0x02, 0x01, 0x01, 0x12, 0x13, 0x00, 0x00, 0x00, 0x00, 0x30, 0x5F, 0x00,
    0xA3, 0x00, 0x01, 0x00, 0x02, 0x01, 0x01, 0x13, 0x13, 0x00, 0x00, 0x00, 0x00, 0x30, 0x02, 0x00, 0xB7, 0x00, 0x01,
    0x00, 0x0D, 0x0D, 0x01, 0x08, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0xC0, 0x00, 0x01, 0x0C, 0x00, 0x15,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x67, 0x2C, 0x00, 0xC1, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x14, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x4F, 0x53, 0x00, 0xD6, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x14, 0x15, 0x00, 0x00, 0x00,
    0x00, 0x30, 0x6E, 0x00, 0xEB, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x13, 0x12, 0x00, 0x00, 0x00, 0x00, 0x30, 0xD1,
    0x00, 0xFF, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x15, 0x14, 0x00, 0x00, 0x00, 0x00, 0x30, 0xEF, 0x01, 0x15, 0x00,
    0x01, 0x01, 0x02, 0x02, 0x01, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x30, 0xDC, 0x01, 0x28, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x01, 0x15, 0x14, 0x00, 0x00, 0x00, 0x00, 0x30, 0xBF, 0x01, 0x3E, 0x00, 0x01, 0x00, 0x02, 0x02, 0x01, 0x13,
    0x12, 0x00, 0x00, 0x00, 0x00, 0x30, 0xF3, 0x01, 0x52, 0x00, 0x01, 0x01, 0x02, 0x02, 0x01, 0x12, 0x12, 0x00, 0x00,
    0x00, 0x00, 0x30, 0x92, 0x01, 0x65, 0x00, 0x01, 0x00, 0x02, 0x01, 0x01, 0x13, 0x13, 0x00, 0x00, 0x00, 0x00, 0x62,
    0xBC, 0x01, 0x79, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x14, 0x15, 0x00, 0x00, 0x00, 0x00, 0x30, 0x66, 0x01, 0x8E,
    0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x13, 0x12, 0x00, 0x00, 0x00, 0x00, 0x96, 0xFB, 0x01, 0xA2, 0x00, 0x01, 0x00,
    0x01, 0x01, 0x01, 0x14, 0x13, 0x00, 0x00, 0x00, 0x00, 0x6E, 0x90, 0x01, 0xB7, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
    0x14, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4F, 0x01, 0xCC, 0x00, 0x01, 0x00, 0x01, 0x01, 0x02, 0x0B, 0x12, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x46, 0x01, 0xD8, 0x00, 0x01, 0x01, 0x01, 0x01, 0x02, 0x0A, 0x12, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x6B, 0x01, 0xE3, 0x00, 0x01, 0x01, 0x02, 0x01, 0x01, 0x12, 0x13, 0x00, 0x00, 0x00, 0x00, 0x53, 0xD6, 0x00,
    0x01, 0x00, 0x17, 0x00, 0x01, 0x01, 0x00, 0x14, 0x14, 0x00, 0x00, 0x00, 0x00, 0x62, 0x71, 0x00, 0x16, 0x00, 0x17,
    0x00, 0x01, 0x00, 0x01, 0x14, 0x14, 0x00, 0x00, 0x00, 0x00, 0x8A, 0xAC, 0x00, 0x2B, 0x00, 0x17, 0x00, 0x01, 0x00,
    0x01, 0x14, 0x14, 0x00, 0x00, 0x00, 0x00, 0x66, 0x0E, 0x00, 0x40, 0x00, 0x17, 0x01, 0x02, 0x01, 0x01, 0x12, 0x13,
    0x00, 0x00, 0x00, 0x00, 0x66, 0xF8, 0x00, 0x53, 0x00, 0x17, 0x00, 0x01, 0x00, 0x00, 0x14, 0x15, 0x00, 0x00, 0x00,
    0x00, 0x63, 0x07, 0x00, 0x68, 0x00, 0x17, 0x00, 0x01, 0x00, 0x00, 0x14, 0x15, 0x00, 0x00, 0x00, 0x00, 0x79, 0x3A,
    0x00, 0x7D, 0x00, 0x17, 0x00, 0x01, 0x01, 0x01, 0x14, 0x13, 0x00, 0x00, 0x00, 0x00, 0x5F, 0x93, 0x00, 0x92, 0x00,
    0x17, 0x00, 0x01, 0x00, 0x01, 0x14, 0x14, 0x00, 0x00, 0x00, 0x00, 0x30, 0x63, 0x00, 0xA7, 0x00, 0x17, 0x01, 0x03,
    0x05, 0x02, 0x11, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x4E, 0x0B, 0x00, 0xB9, 0x00, 0x17, 0x00, 0x01, 0x01, 0x01, 0x14,
    0x13, 0x00, 0x00, 0x00, 0x00, 0x30, 0x55, 0x00, 0xCE, 0x00, 0x17, 0x01, 0x01, 0x01, 0x01, 0x13, 0x13, 0x00, 0x00,
    0x00, 0x00, 0x30, 0x44, 0x00, 0xE2, 0x00, 0x17, 0x01, 0x02, 0x02, 0x02, 0x12, 0x11, 0x00, 0x00, 0x00, 0x00, 0x30,
    0xC7, 0x00, 0xF5, 0x00, 0x17, 0x00, 0x00, 0x00, 0x01, 0x15, 0x14, 0x00, 0x00, 0x00, 0x00, 0x30, 0xA3, 0x01, 0x0B,
    0x00, 0x17, 0x02, 0x03, 0x03, 0x00, 0x10, 0x12, 0x00, 0x00, 0x00, 0x00, 0x30, 0xB9, 0x01, 0x1C, 0x00, 0x17, 0x01,
    0x01, 0x02, 0x01, 0x13, 0x12, 0x00, 0x00, 0x00, 0x00, 0x30, 0xAF, 0x01, 0x30, 0x00, 0x17, 0x00, 0x02, 0x02, 0x01,
    0x13, 0x12, 0x00, 0x00, 0x00, 0x00, 0x8A, 0xAD, 0x01, 0x44, 0x00, 0x17, 0x00, 0x01, 0x00, 0x01, 0x14, 0x14, 0x00,
    0x00, 0x00, 0x00, 0x30, 0x81, 0x01, 0x59, 0x00, 0x17, 0x00, 0x01, 0x01, 0x01, 0x14, 0x13, 0x00, 0x00, 0x00, 0x00,
    0x30, 0x5B, 0x01, 0x6E, 0x00, 0x17, 0x00, 0x01, 0x01, 0x01, 0x14, 0x13, 0x00, 0x00, 0x00, 0x00, 0x30, 0x93, 0x01,
    0x83, 0x00, 0x17, 0x00, 0x01, 0x01, 0x01, 0x14, 0x13, 0x00, 0x00, 0x00, 0x00, 0x30, 0x67, 0x01, 0x98, 0x00, 0x17,
    0x01, 0x00, 0x02, 0x01, 0x14, 0x12, 0x00, 0x00, 0x00, 0x00, 0x30, 0x4F, 0x01, 0xAD, 0x00, 0x17, 0x02, 0x03, 0x01,
    0x01, 0x10, 0x13, 0x00, 0x00, 0x00, 0x00, 0x30, 0x8F, 0x01, 0xBE, 0x00, 0x17, 0x00, 0x01, 0x01, 0x01, 0x14, 0x13,
    0x00, 0x00, 0x00, 0x00, 0x30, 0x6F, 0x01, 0xD3, 0x00, 0x17, 0x01, 0x01, 0x01, 0x01, 0x13, 0x13, 0x00, 0x00, 0x00,
    0x00, 0x30, 0x4A, 0x01, 0xE7, 0x00, 0x17, 0x00, 0x01, 0x01, 0x01, 0x14, 0x13, 0x00, 0x00, 0x00, 0x00, 0x30, 0x7F,
    0x00, 0x01, 0x00, 0x2D, 0x00, 0x01, 0x01, 0x01, 0x14, 0x13, 0x00, 0x00, 0x00, 0x00, 0x8F, 0xBC, 0x00, 0x16, 0x00,
    0x2D, 0x00, 0x01, 0x01, 0x01, 0x14, 0x13, 0x00, 0x00, 0x00, 0x00, 0x30, 0x59, 0x00, 0x2B, 0x00, 0x2D, 0x00, 0x01,
    0x00, 0x01, 0x14, 0x14, 0x00, 0x00, 0x00, 0x00, 0x30, 0xAB, 0x00, 0x40, 0x00, 0x2D, 0x00, 0x02, 0x01, 0x02, 0x13,
    0x12, 0x00, 0x00, 0x00, 0x00, 0x30, 0xD0, 0x00, 0x54, 0x00, 0x2D, 0x00, 0x01, 0x01, 0x01, 0x14, 0x13, 0x00, 0x00,
    0x00, 0x00, 0x95, 0x8B, 0x00, 0x69, 0x00, 0x2D, 0x01, 0x02, 0x01, 0x00, 0x12, 0x14, 0x00, 0x00, 0x00, 0x00, 0x30,
    0xB2, 0x00, 0x7C, 0x00, 0x2D, 0x00, 0x00, 0x00, 0x01, 0x15, 0x14, 0x00, 0x00, 0x00, 0x00, 0x30, 0xE0, 0x00, 0x92,
    0x00, 0x2D, 0x00, 0x01, 0x01, 0x02, 0x14, 0x12, 0x00, 0x00, 0x00, 0x00, 0x7D, 0x9A, 0x00, 0xA7, 0x00, 0x2D, 0x00,
    0x01, 0x00, 0x01, 0x14, 0x14, 0x00, 0x00, 0x00, 0x00, 0x30, 0x51, 0x00, 0xBC, 0x00, 0x2D, 0x02, 0x01, 0x01, 0x01,
    0x12, 0x13, 0x00, 0x00, 0x00, 0x00, 0x30, 0x8B, 0x00, 0xCF, 0x00, 0x2D, 0x01, 0x02, 0x02, 0x01, 0x12, 0x12, 0x00,
    0x00, 0x00, 0x00, 0x58, 0x34, 0x00, 0xE2, 0x00, 0x2D, 0x00, 0x01, 0x01, 0x00, 0x14, 0x14, 0x00, 0x00, 0x00, 0x00,
    0x54, 0x08, 0x00, 0xF7, 0x00, 0x2D, 0x00, 0x01, 0x00, 0x00, 0x14, 0x15, 0x00, 0x00, 0x00, 0x00, 0x95, 0x89, 0x01,
    0x0C, 0x00, 0x2D, 0x01, 0x02, 0x01, 0x00, 0x12, 0x14, 0x00, 0x00, 0x00, 0x00, 0x30, 0x0C, 0x01, 0x1F, 0x00, 0x2D,
    0x0C, 0x01, 0x00, 0x04, 0x08, 0x11, 0x00, 0x00, 0x00, 0x00, 0x30, 0xD5, 0x01, 0x28, 0x00, 0x2D, 0x01, 0x02, 0x02,
    0x01, 0x12, 0x12, 0x00, 0x00, 0x00, 0x00, 0x30, 0xA9, 0x01, 0x3B, 0x00, 0x2D, 0x02, 0x02, 0x03, 0x01, 0x11, 0x11,
    0x00, 0x00, 0x00, 0x00, 0x30, 0xC3, 0x01, 0x4D, 0x00, 0x2D, 0x02, 0x03, 0x04, 0x01, 0x10, 0x10, 0x00, 0x00, 0x00,
    0x00, 0x30, 0xA2, 0x01, 0x5E, 0x00, 0x2D, 0x01, 0x01, 0x02, 0x01, 0x13, 0x12, 0x00, 0x00, 0x00, 0x00, 0x30, 0xC9,
    0x01, 0x72, 0x00, 0x2D, 0x03, 0x01, 0x01, 0x01, 0x11, 0x13, 0x00, 0x00, 0x00, 0x00, 0x30, 0xD9, 0x01, 0x84, 0x00,
    0x2D, 0x00, 0x00, 0x01, 0x02, 0x15, 0x12, 0x00, 0x00, 0x00, 0x00, 0x30, 0xC1, 0x01, 0x9A, 0x00, 0x2D, 0x00, 0x01,
    0x01, 0x01, 0x14, 0x13, 0x00, 0x00, 0x00, 0x00, 0x30, 0xE3, 0x01, 0xAF, 0x00, 0x2D, 0x01, 0x02, 0x03, 0x01, 0x12,
    0x11, 0x00, 0x00, 0x00, 0x00, 0x30, 0x0D, 0x01, 0xC2, 0x00, 0x2D, 0x00, 0x0D, 0x03, 0x00, 0x08, 0x12, 0x00, 0x00,
    0x00, 0x00, 0x30, 0xBB, 0x01, 0xCB, 0x00, 0x2D, 0x00, 0x02, 0x01, 0x02, 0x13, 0x12, 0x00, 0x00, 0x00, 0x00, 0x30,
    0xC8, 0x01, 0xDF, 0x00, 0x2D, 0x03, 0x02, 0x01, 0x01, 0x10, 0x13, 0x00, 0x00, 0x00, 0x00, 0x30, 0x53, 0x00, 0x01,
    0x00, 0x43, 0x01, 0x02, 0x03, 0x02, 0x12, 0x10, 0x00, 0x00, 0x00, 0x00, 0x30, 0x42, 0x00, 0x14, 0x00, 0x43, 0x01,
    0x02, 0x00, 0x01, 0x12, 0x14, 0x00, 0x00, 0x00, 0x00, 0x30, 0x8A, 0x00, 0x27, 0x00, 0x43, 0x03, 0x03, 0x01, 0x01,
    0x0F, 0x13, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x37, 0x00, 0x43, 0x15, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x30, 0xED, 0x00, 0x38, 0x00, 0x43, 0x01, 0x02, 0x02, 0x02, 0x12, 0x11, 0x00, 0x00, 0x00, 0x00,
    0x4E, 0x2D, 0x00, 0x4B, 0x00, 0x43, 0x01, 0x02, 0x00, 0x00, 0x12, 0x15, 0x00, 0x00, 0x00, 0x00, 0x20, 0x26, 0x00,
    0x5E, 0x00, 0x43, 0x01, 0x02, 0x08, 0x09, 0x12, 0x04, 0x00, 0x00,
};

/* Japanese disc-status message lines (UTF-8 encoded). */
/* "An error has occurred." */
char sJpDiscErrorOccurredLine[0x24] = "\xe3\x82\xa8\xe3\x83\xa9\xe3\x83\xbc\xe3\x81\x8c\xe7\x99\xba\xe7\x94\x9f\xe3\x81\x97\xe3\x81"
                          "\xbe\xe3\x81\x97\xe3\x81\x9f\xe3\x80\x82\x20";
/* "(press) the unit's POWER Button" */
char sJpDiscErrorPowerButtonLine[0x20] = "\xe6\x9c\xac\xe4\xbd\x93\xe3\x81\xae\xe3\x83\x91\xe3\x83\xaf\xe3\x83\xbc\xe3\x83\x9c\xe3\x82"
                          "\xbf\xe3\x83\xb3\xe3\x82\x92";
/* "to turn the power OFF, and" */
char sJpDiscErrorPowerOffLine[0x1c] =
    "\xe6\x8a\xbc\xe3\x81\x97\xe3\x81\xa6\xe9\x9b\xbb\xe6\xba\x90\xe3\x82\x92\x4f\x46\x46\xe3\x81\xab\xe3\x81\x97";
/* "(refer to) the unit's Instruction Booklet" */
char sJpDiscErrorInstructionBookletLine[0x1c] =
    "\xe6\x9c\xac\xe4\xbd\x93\xe3\x81\xae\xe5\x8f\x96\xe6\x89\xb1\xe8\xaa\xac\xe6\x98\x8e\xe6\x9b\xb8\xe3\x81\xae";
/* "and follow its instructions." */
char sJpDiscErrorFollowInstructionsLine[0x20] = "\xe6\x8c\x87\xe7\xa4\xba\xe3\x81\xab\xe5\xbe\x93\xe3\x81\xa3\xe3\x81\xa6\xe4\xb8\x8b\xe3\x81"
                          "\x95\xe3\x81\x84\xe3\x80\x82";

char* sJpDiscErrorOccurredMessageLines[] = {
    sJpDiscErrorTopSpacerLine, sJpDiscErrorOccurredLine, sJpDiscErrorPowerButtonLine, sJpDiscErrorPowerOffLine, sJpDiscErrorInstructionBookletLine, sJpDiscErrorFollowInstructionsLine, sJpDiscErrorBottomSpacerLine,
};

/* "The Game Disc could not be read." */
char sJpDiscReadErrorLine[0x2c] = "\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xb9\xe3\x82\xaf\xe3\x82\x92\xe8\xaa\xad\xe3\x82\x81\xe3\x81"
                          "\xbe\xe3\x81\x9b\xe3\x82\x93\xe3\x81\xa7\xe3\x81\x97\xe3\x81\x9f\xe3\x80\x82";
/* "For details, (see) the unit's Instruction Booklet" */
char sJpDiscReadErrorInstructionBookletLine[0x2c] = "\xe3\x81\x8f\xe3\x82\x8f\xe3\x81\x97\xe3\x81\x8f\xe3\x81\xaf\xe6\x9c\xac\xe4\xbd\x93\xe3\x81"
                          "\xae\xe5\x8f\x96\xe6\x89\xb1\xe8\xaa\xac\xe6\x98\x8e\xe6\x9b\xb8\xe3\x82\x92";
/* "please read it." */
char sJpDiscReadErrorPleaseReadLine[0x18] = "\xe3\x81\x8a\xe8\xaa\xad\xe3\x81\xbf\xe4\xb8\x8b\xe3\x81\x95\xe3\x81\x84\xe3\x80\x82";

char* sJpDiscReadErrorMessageLines[] = {
    sJpDiscReadErrorTopSpacerLine,
    sJpDiscReadErrorLine,
    sJpDiscReadErrorInstructionBookletLine,
    sJpDiscReadErrorPleaseReadLine,
};

/* "The disc" */
char sJpDiscReadingDiscLine[0x10] = "\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xb9\xe3\x82\xaf\xe3\x82\x92";
/* "is being read." */
char sJpDiscReadingInProgressLine[0x1c] =
    "\xe8\xaa\xad\xe3\x81\xbf\xe8\xbe\xbc\xe3\x82\x93\xe3\x81\xa7\xe3\x81\x84\xe3\x81\xbe\xe3\x81\x99\xe3\x80\x82";

char* sJpDiscReadingMessageLines[] = {
    sJpDiscReadingTopSpacerLine,
    sJpDiscReadingDiscLine,
    sJpDiscReadingInProgressLine,
};

/* "The Disc Cover" */
char sJpDiscCoverLine[0x1c] =
    "\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xb9\xe3\x82\xaf\xe3\x82\xab\xe3\x83\x90\xe3\x83\xbc\xe3\x81\x8c";
/* "is open." */
char sJpDiscCoverIsOpenLine[0x18] = "\xe9\x96\x8b\xe3\x81\x84\xe3\x81\xa6\xe3\x81\x84\xe3\x81\xbe\xe3\x81\x99\xe3\x80\x82";
/* "To continue the game," */
char sJpDiscCoverContinuePromptLine[0x20] = "\xe3\x82\xb2\xe3\x83\xbc\xe3\x83\xa0\xe3\x82\x92\xe7\xb6\x9a\xe3\x81\x91\xe3\x82\x8b\xe5\xa0"
                          "\xb4\xe5\x90\x88\xe3\x81\xaf";
/* "the Disc Cover" */
char sJpDiscCoverCloseTargetLine[0x1c] =
    "\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xb9\xe3\x82\xaf\xe3\x82\xab\xe3\x83\x90\xe3\x83\xbc\xe3\x82\x92";
/* "please close." */
char sJpDiscCoverClosePromptLine[0x18] = "\xe9\x96\x89\xe3\x82\x81\xe3\x81\xa6\xe4\xb8\x8b\xe3\x81\x95\xe3\x81\x84\xe3\x80\x82";

char* sJpDiscCoverOpenMessageLines[] = {
    sJpDiscCoverOpenTopSpacerLine, sJpDiscCoverLine, sJpDiscCoverIsOpenLine, sJpDiscCoverContinuePromptLine, sJpDiscCoverCloseTargetLine, sJpDiscCoverClosePromptLine,
};

/* ""Star Fox" */
char sJpDiscInsertGameNameLine[0x1c] =
    "\xe3\x80\x8c\xe3\x82\xb9\xe3\x82\xbf\xe3\x83\xbc\xe3\x83\x95\xe3\x82\xa9\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9";
/* "Adventure"'s" */
char sJpDiscInsertGameSubtitleLine[0x1c] =
    "\xe3\x82\xa2\xe3\x83\x89\xe3\x83\x99\xe3\x83\xb3\xe3\x83\x81\xe3\x83\xa3\xe3\x83\xbc\xe3\x80\x8d\xe3\x81\xae";
/* "disc" */
char sJpDiscInsertGameDiscLine[0x10] = "\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xb9\xe3\x82\xaf\xe3\x82\x92";
/* "please insert." */
char sJpDiscInsertPromptLine[0x1c] =
    "\xe3\x82\xbb\xe3\x83\x83\xe3\x83\x88\xe3\x81\x97\xe3\x81\xa6\xe4\xb8\x8b\xe3\x81\x95\xe3\x81\x84\xe3\x80\x82";

char* sJpDiscInsertMessageLines[] = {
    sJpDiscInsertTopSpacerLine, sJpDiscInsertGameNameLine, sJpDiscInsertGameSubtitleLine, sJpDiscInsertGameDiscLine, sJpDiscInsertPromptLine, sJpDiscInsertBottomSpacerLine,
};

/* "This disc is" */
char sJpWrongDiscThisIsNotLine[0x18] = "\xe3\x81\x93\xe3\x81\xae\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xb9\xe3\x82\xaf\xe3\x81\xaf";
/* "Star Fox" */
char sJpWrongDiscGameNameLine[0x1c] =
    "\xe3\x82\xb9\xe3\x82\xbf\xe3\x83\xbc\xe3\x83\x95\xe3\x82\xa9\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9";
/* "Adventure's" */
char sJpWrongDiscGameSubtitleLine[0x1c] =
    "\xe3\x82\xa2\xe3\x83\x89\xe3\x83\x99\xe3\x83\xb3\xe3\x83\x81\xe3\x83\xa3\xe3\x83\xbc\xe3\x81\xae";
/* "not the disc." */
char sJpWrongDiscNotGameDiscLine[0x28] = "\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xb9\xe3\x82\xaf\xe3\x81\xa7\xe3\x81\xaf\xe3\x81\x82\xe3\x82"
                          "\x8a\xe3\x81\xbe\xe3\x81\x9b\xe3\x82\x93\xe3\x80\x82";
/* "Star Fox" */
char sJpWrongDiscInsertGameNameLine[0x1c] =
    "\xe3\x82\xb9\xe3\x82\xbf\xe3\x83\xbc\xe3\x83\x95\xe3\x82\xa9\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9";
/* "Adventure's" */
char sJpWrongDiscInsertGameSubtitleLine[0x1c] =
    "\xe3\x82\xa2\xe3\x83\x89\xe3\x83\x99\xe3\x83\xb3\xe3\x83\x81\xe3\x83\xa3\xe3\x83\xbc\xe3\x81\xae";
/* "please insert the disc." */
char sJpWrongDiscInsertPromptLine[0x2c] = "\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xb9\xe3\x82\xaf\xe3\x82\x92\xe3\x82\xbb\xe3\x83\x83\xe3\x83"
                          "\x88\xe3\x81\x97\xe3\x81\xa6\xe4\xb8\x8b\xe3\x81\x95\xe3\x81\x84\xe3\x80\x82";

char* sJpWrongDiscMessageLines[] = {
    sJpWrongDiscTopSpacerLine, sJpWrongDiscThisIsNotLine, sJpWrongDiscGameNameLine, sJpWrongDiscGameSubtitleLine, sJpWrongDiscNotGameDiscLine,
    sJpWrongDiscMiddleSpacerLine, sJpWrongDiscInsertGameNameLine, sJpWrongDiscInsertGameSubtitleLine, sJpWrongDiscInsertPromptLine,
};

/*
 * The Japanese disc-status resource: the "Now loading..." text, the seven
 * status messages, and the latin glyphs (lang 4) the messages still need
 * ("OFF", "NINTENDO GAMECUBE", ...).
 */
struct JapaneseDiscStatusResource
{
    char loadingMessage[16]; /* "Now loading..." */
    GameTextDef messages[7];
    TextGlyph glyphs[43];
} sJpDiscStatusMessageTable = {
    "\xe3\x83\xad\xe3\x83\xbc\xe3\x83\x89\xe4\xb8\xad\xe2\x80\xa6",
    {
        {0x339, 7, 0x81, 0, 0, 4, sJpDiscErrorOccurredMessageLines},
        {0x33a, 4, 0x81, 0, 0, 4, sJpDiscReadErrorMessageLines},
        {0x33b, 3, 0x81, 0, 0, 4, sJpDiscReadingMessageLines},
        {0x33c, 6, 0x81, 0, 0, 4, sJpDiscCoverOpenMessageLines},
        {0x33d, 6, 0x81, 0, 0, 4, sJpDiscInsertMessageLines},
        {0x33e, 9, 0x81, 0, 0, 4, sJpWrongDiscMessageLines},
        {0x565, 1, 0x93, 0, 0, 4, sJpDiscLoadingMessageLines},
    },
    {
        {0x41, 0x01, 0x1, 0, 1, 3, 4, 0x0d, 0x0e, 4, 0},  {0x6e, 0x0f, 0x1, 0, 1, 7, 4, 0x09, 0x0a, 4, 0},
        {0x20, 0x19, 0x1, 6, 0, 15, 6, 0x00, 0x00, 4, 0}, {0x65, 0x1a, 0x1, 0, 1, 6, 4, 0x0a, 0x0b, 4, 0},
        {0x72, 0x25, 0x1, 0, 1, 7, 4, 0x08, 0x0a, 4, 0},  {0x6f, 0x2e, 0x1, 0, 1, 7, 4, 0x0a, 0x0a, 4, 0},
        {0x68, 0x39, 0x1, 0, 1, 3, 4, 0x09, 0x0e, 4, 0},  {0x61, 0x43, 0x1, 0, 1, 6, 4, 0x09, 0x0b, 4, 0},
        {0x73, 0x4d, 0x1, 0, 1, 7, 4, 0x09, 0x0a, 4, 0},  {0x63, 0x57, 0x1, 0, 1, 6, 4, 0x09, 0x0b, 4, 0},
        {0x75, 0x61, 0x1, 0, 1, 7, 4, 0x09, 0x0a, 4, 0},  {0x64, 0x6b, 0x1, 0, 1, 3, 4, 0x09, 0x0e, 4, 0},
        {0x2e, 0x75, 0x1, 0, 1, 14, 4, 0x03, 0x03, 4, 0}, {0x54, 0x79, 0x1, 0, 1, 3, 4, 0x0b, 0x0e, 4, 0},
        {0x74, 0x85, 0x1, 0, 1, 4, 4, 0x07, 0x0d, 4, 0},  {0x70, 0x8d, 0x1, 0, 1, 7, 0, 0x09, 0x0e, 4, 0},
        {0x77, 0x97, 0x1, 0, 1, 7, 4, 0x0e, 0x0a, 4, 0},  {0x4f, 0xa6, 0x1, 0, 1, 3, 3, 0x0c, 0x0f, 4, 0},
        {0x46, 0xb3, 0x1, 0, 1, 3, 4, 0x0a, 0x0e, 4, 0},  {0x6b, 0xbe, 0x1, 0, 1, 3, 4, 0x09, 0x0e, 4, 0},
        {0x4e, 0xc8, 0x1, 0, 1, 3, 4, 0x0d, 0x0e, 4, 0},  {0x49, 0xd6, 0x1, 0, 1, 3, 4, 0x03, 0x0e, 4, 0},
        {0x45, 0xda, 0x1, 0, 1, 3, 4, 0x09, 0x0e, 4, 0},  {0x44, 0xe4, 0x1, 0, 1, 3, 4, 0x0c, 0x0e, 4, 0},
        {0x47, 0xf1, 0x1, 0, 1, 3, 4, 0x0c, 0x0e, 4, 0},  {0x4d, 0xfe, 0x1, 0, 1, 3, 4, 0x10, 0x0e, 4, 0},
        {0x43, 0x10f, 0x1, 0, 1, 3, 4, 0x0c, 0x0e, 4, 0}, {0x55, 0x11c, 0x1, 0, 1, 3, 4, 0x0c, 0x0e, 4, 0},
        {0x42, 0x129, 0x1, 0, 1, 3, 4, 0x0c, 0x0e, 4, 0}, {0x69, 0x136, 0x1, 0, 1, 3, 4, 0x03, 0x0e, 4, 0},
        {0x6c, 0x13a, 0x1, 0, 1, 3, 4, 0x03, 0x0e, 4, 0}, {0x66, 0x13e, 0x1, 0, 1, 3, 4, 0x06, 0x0e, 4, 0},
        {0x6d, 0x145, 0x1, 0, 1, 6, 4, 0x0f, 0x0b, 4, 0}, {0x62, 0x155, 0x1, 0, 1, 3, 4, 0x09, 0x0e, 4, 0},
        {0x50, 0x15f, 0x1, 0, 1, 3, 4, 0x0b, 0x0e, 4, 0}, {0x52, 0x16b, 0x1, 0, 1, 3, 4, 0x0b, 0x0e, 4, 0},
        {0x67, 0x177, 0x1, 0, 1, 6, 0, 0x09, 0x0f, 4, 0}, {0x76, 0x181, 0x1, 0, 1, 6, 4, 0x09, 0x0b, 4, 0},
        {0x79, 0x18b, 0x1, 0, 1, 7, 0, 0x09, 0x0e, 4, 0}, {0x2c, 0x195, 0x1, 0, 1, 14, 2, 0x03, 0x05, 4, 0},
        {0x53, 0x199, 0x1, 0, 1, 3, 4, 0x0b, 0x0e, 4, 0}, {0x78, 0x1a5, 0x1, 0, 1, 7, 4, 0x09, 0x0a, 4, 0},
        {0x4c, 0x1af, 0x1, 0, 1, 3, 4, 0x09, 0x0e, 4, 0},
    },
};

/* English disc-status message lines. */
char sDiscErrorOccurredLine[] = "An error has occurred.";
char sDiscErrorInstructionBookletLine[] =
    "Turn the power OFF and check the NINTENDO GAMECUBE Instruction Booklet for further instructions.";

char* sDiscErrorOccurredMessageLines[] = {
    sDiscErrorOccurredLine,
    sDiscErrorSpacerLine,
    sDiscErrorInstructionBookletLine,
};

char sDiscReadErrorLine[] = "The Game Disc could not be read.";
char sDiscReadErrorInstructionBookletLine[] =
    "Please read the NINTENDO GAMECUBE Instruction Booklet for more information.";

char* sDiscReadErrorMessageLines[] = {
    sDiscReadErrorLine,
    sDiscReadErrorSpacerLine,
    sDiscReadErrorInstructionBookletLine,
};

char sDiscReadingMessage[] = "Reading disc...";

char sDiscCoverOpenLine[] = "The Disc Cover is open.";
char sDiscCoverContinuePromptLine[] = "If you want to continue the game,";
char sDiscCoverClosePromptLine[] = "please close the Disc Cover.";

char* sDiscCoverOpenMessageLines[] = {
    sDiscCoverOpenLine,
    sDiscCoverOpenSpacerLine,
    sDiscCoverContinuePromptLine,
    sDiscCoverClosePromptLine,
};

char sDiscInsertPromptLine[] = "Please insert a";
char sDiscInsertGameDiscLine[] = "Star Fox Adventures Game Disc.";

char sWrongDiscThisIsNotLine[] = "This is not the";
char sWrongDiscGameNameLine[] = "Star Fox Adventures";
char sWrongDiscGameDiscLine[] = "Game Disc.";
char sWrongDiscInsertPromptLine[] = "Please insert a";
char sWrongDiscInsertGameDiscLine[] = "Star Fox Adventures Game Disc.";

char* sWrongDiscMessageLines[] = {
    sWrongDiscThisIsNotLine,    sWrongDiscGameNameLine,       sWrongDiscGameDiscLine, sWrongDiscSpacerLine,
    sWrongDiscInsertPromptLine, sWrongDiscInsertGameDiscLine,
};

/* The English disc-status resource ("Loading..." plus the seven messages). */
struct EnglishDiscStatusResource
{
    char loadingMessage[12];
    GameTextDef messages[7];
} sDiscStatusMessageTable = {
    "Loading...",
    {
        {0x339, 3, 0x81, 0, 0, 0, sDiscErrorOccurredMessageLines},
        {0x33a, 3, 0x81, 0, 0, 0, sDiscReadErrorMessageLines},
        {0x33b, 1, 0x81, 0, 0, 0, sDiscReadingMessageLines},
        {0x33c, 4, 0x81, 0, 0, 0, sDiscCoverOpenMessageLines},
        {0x33d, 2, 0x81, 0, 0, 0, sDiscInsertMessageLines},
        {0x33e, 6, 0x81, 0, 0, 0, sWrongDiscMessageLines},
        {0x565, 1, 0x93, 0, 0, 0, sDiscLoadingMessageLines},
    },
};

/* Dino-language glyph substitution order (see translateToDinoLanguage). */
u8 sGameTextGlyphOrder[0x1b] = "urstovwxazbcmdefghtkilnpoq";


static inline int ctrlCharLen(u32 c)
{
    CtrlCharEntry* p = gGameTextCtrlCodeArgCounts;
    int i = 46;
    while (i--)
    {
        if (p->key == c)
        {
            return p->len;
        }
        p++;
    }
    return 0;
}

void gameTextSetWindowById(int boxId)
{
    int i = gGameTextCommandCount;
    GameTextSlot* cmd;
    void* box;

    gGameTextCommandCount = i + 1;
    cmd = &gGameTextCommandSlots[i];
    if (boxId == 0xff)
    {
        box = NULL;
    }
    else
    {
        box = &gTextBoxes[boxId];
    }
    gCurTextBox = box;
    cmd->opcode = GAMETEXT_COMMAND_SET_WINDOW;
    cmd->arg0 = boxId;
}

void gameTextSetWindow(u8* textBox)
{
    int i;
    GameTextSlot* cmd;
    int idx;

    if (textBox == NULL)
    {
        i = gGameTextCommandCount;
        gGameTextCommandCount = i + 1;
        cmd = &gGameTextCommandSlots[i];
        gCurTextBox = NULL;
        cmd->opcode = GAMETEXT_COMMAND_SET_WINDOW;
        cmd->arg0 = 0xff;
    }
    else
    {
        i = gGameTextCommandCount;
        gGameTextCommandCount = i + 1;
        cmd = &gGameTextCommandSlots[i];
        idx = (textBox - (u8*)gTextBoxes) / 0x20;
        if (idx == 0xff)
        {
            gCurTextBox = NULL;
        }
        else
        {
            gCurTextBox = (u8*)gTextBoxes + idx * 0x20;
        }
        cmd->opcode = GAMETEXT_COMMAND_SET_WINDOW;
        cmd->arg0 = idx;
    }
}

static inline TextGlyph* findGlyph(u32 ch, int glyphLang)
{
    int cnt;
    TextGlyph* g;

    g = gameTextFonts->glyphs;
    cnt = gameTextFonts->glyphCount;
    while (cnt-- != 0)
    {
        if (g->key == ch && g->font == glyphLang)
        {
            return g;
        }
        g++;
    }
    return NULL;
}

void textRenderStr(char* str, GameTextBox* win, f32 x, f32 y, f32 lineH, int mode)
{
    int realign;
    f32 fx0, fy0, fx1, fy1;
    int byteOff;
    f32 u0, v0;
    int charLen;
    int controlArgCount;
    int i;
    int skipGlyph;
    TextGlyph* g;
    u8* p;
    GameTextBox* winBase;
    int glyphLang;
    Texture* tex;
    f32 spaceExtra;
    f32 measW;
    f32 measN;
    int curTexPage;
    u32 ch;
    int params[8];
    u32 scisX, scisY, scisW, scisH;
    f32 e710;

    byteOff = 0;
    spaceExtra = 0.0f;
    if (gameTextCharset == 2)
    {
        glyphLang = 6;
    }
    else
    {
        glyphLang = sLanguageNameTable[curLanguage].fontId;
    }
    curTexPage = -1;
    realign = 1;
    if (str == NULL || gameTextFonts->status != 2)
    {
        return;
    }

    if (curLanguage != 4 && mode == 1 && saveFileStruct_isCheatActive(CHEAT_DINO_LANGUAGE) &&
        win == &gTextBoxes[10])
    {
        translateToDinoLanguage((u8*)str);
    }

    gameTextMeasureString((u8*)str, gGameTextScale, &measW, &measN, 0, 0, -1);
    if (gGameTextMeasureOnly == 0)
    {
        setTextColor(0, gGameTextColorR, gGameTextColorG, gGameTextColorB, gGameTextColorA);
        _textSetColor(0, gGameTextColorR, gGameTextColorG, gGameTextColorB, gGameTextColorA);
        gxTevResetStages();
        textRenderSetup();
        gxTevCommitStages();
        gxSetAlphaBlendNoZTest();
    }

    x = x + win->x;
    y = y + win->y;
    winBase = gTextBoxes;

    while (p = (u8*)str + byteOff, (ch = utf8GetNextChar(p, &charLen)) != 0)
    {
        byteOff += charLen;
        skipGlyph = 0;
        if (ch >= 0xe000 && ch <= 0xf8ff)
        {
            controlArgCount = ctrlCharLen(ch);
            for (i = 0; i < controlArgCount; i++)
            {
                int hi = ((u8*)str)[byteOff++];
                int lo = ((u8*)str)[byteOff++];
                params[i] = (hi << 8) | lo;
            }
            switch (ch)
            {
            case TEXT_CTRL_SCALE:
                gGameTextScale = params[0] * lbl_803DE708;
                break;
            case TEXT_CTRL_FONT:
                glyphLang = params[0];
                break;
            case TEXT_CTRL_ALIGN_LEFT:
                win->alignment = TEXT_ALIGN_LEFT;
                realign = 1;
                break;
            case TEXT_CTRL_ALIGN_RIGHT:
                win->alignment = TEXT_ALIGN_RIGHT;
                realign = 1;
                break;
            case TEXT_CTRL_ALIGN_CENTER:
                win->alignment = TEXT_ALIGN_CENTER;
                realign = 1;
                break;
            case TEXT_CTRL_ALIGN_JUSTIFY:
                win->alignment = TEXT_ALIGN_JUSTIFY;
                realign = 1;
                break;
            case TEXT_CTRL_COLOR:
                if (mode == 0)
                {
                    {
                        u8 c3 = params[3] * (gGameTextColorA + 1) >> 8;
                        u8 c2 = params[2];
                        u8 c1 = params[1];
                        u8 c0 = params[0];
                        gGameTextColorR = c0;
                        gGameTextColorG = c1;
                        gGameTextColorB = c2;
                        gGameTextColorA = c3;
                    }
                    if (gGameTextMeasureOnly == 0)
                    {
                        setTextColor(0, gGameTextColorR, gGameTextColorG, gGameTextColorB, gGameTextColorA);
                        _textSetColor(0, gGameTextColorR, gGameTextColorG, gGameTextColorB, gGameTextColorA);
                        gxTevResetStages();
                        textRenderSetup();
                        gxTevCommitStages();
                        gxSetAlphaBlendNoZTest();
                    }
                }
                skipGlyph = 1;
                break;
            }
            if (skipGlyph)
            {
                continue;
            }
        }
        else
        {
            if (mode == 0)
            {
                gGameTextDrawnCharIndex++;
            }
        }

        if (realign != 0)
        {
            switch (win->alignment)
            {
            case TEXT_ALIGN_LEFT:
                spaceExtra = 0.0f;
                break;
            case TEXT_ALIGN_RIGHT:
                spaceExtra = 0.0f;
                gameTextMeasureString(p, gGameTextScale, &measW, NULL, 0, 0, -1);
                x = win->x + (win->width - measW);
                break;
            case TEXT_ALIGN_CENTER:
                spaceExtra = 0.0f;
                gameTextMeasureString(p, gGameTextScale, &measW, NULL, 0, 0, -1);
                x = win->width - measW;
                x = x * lbl_803DE70C + win->x;
                break;
            case TEXT_ALIGN_JUSTIFY:
            {
                int spaceCount;
                int acc;
                u32 innerCh;
                int innerLen;
                gameTextMeasureString(p, gGameTextScale, &measW, NULL, 0, 0, -1);
                acc = 0;
                spaceCount = acc;
                while ((innerCh = utf8GetNextChar(p + acc, &innerLen)) != 0)
                {
                    acc += innerLen;
                    if (innerCh == 0x20)
                    {
                        spaceCount++;
                    }
                    if (innerCh >= 0xe000 && innerCh <= 0xf8ff)
                    {
                        acc += ctrlCharLen(innerCh) * 2;
                    }
                }
                spaceExtra = (win->width - measW) / spaceCount;
                break;
            }
            }
            realign = 0;
        }

        g = findGlyph(ch, glyphLang);
        if (g == NULL)
        {
            continue;
        }

        if (ch == 0xa)
        {
            x = 0.0f;
            y = y + lineH;
            continue;
        }
        if (ch == 0x20)
        {
            x = gGameTextScale * (f32)(g->advanceX + (g->width + g->offsetX)) + x;
            x = x + spaceExtra;
            continue;
        }

        u0 = (f32)(g->u << 5);
        v0 = (f32)(g->v << 5);
        e710 = lbl_803DE710;
        fx0 = (f32)g->offsetX * gGameTextScale;
        fx0 = x + fx0;
        fx0 = e710 * fx0;
        fy0 = (f32)g->offsetY * gGameTextScale;
        fy0 = y + fy0;
        fy0 = e710 * fy0;
        fx1 = e710 * ((f32)(u32)g->width * gGameTextScale) + fx0;
        fy1 = e710 * ((f32)(u32)g->height * gGameTextScale) + fy0;
        if (fx0 < 0.0f && fx1 > 0.0f)
        {
            u0 = 8.0f * -fx0 + u0;
            fx0 = 0.0f;
        }
        if (fy0 < 0.0f && fy1 > 0.0f)
        {
            v0 = 8.0f * -fy0 + v0;
            fy0 = 0.0f;
        }

        if (gGameTextMeasureOnly != 0)
        {
            if (fx0 < gGameTextBoundsMinX)
            {
                gGameTextBoundsMinX = fx0;
            }
            if (fx1 > gGameTextBoundsMaxX)
            {
                gGameTextBoundsMaxX = fx1;
            }
            if (fy0 < gGameTextBoundsMinY)
            {
                gGameTextBoundsMinY = fy0;
            }
            if (fy1 > gGameTextBoundsMaxY)
            {
                gGameTextBoundsMaxY = fy1;
            }
        }
        else
        {
            if (g->font == GAMETEXT_FONT_FLAG)
            {
                int shift = gGameTextFlagGlyphRaise << 2;
                fy0 = fy0 - shift;
                fy1 = fy1 - shift;
                GXGetScissor(&scisX, &scisY, &scisW, &scisH);
                GXSetScissor(scisX, (scisY >= gGameTextFlagGlyphRaise) ? scisY - gGameTextFlagGlyphRaise : 0, scisW, scisH);
            }
            if (g->font == GAMETEXT_FONT_FACE)
            {
                int iw = g->advanceX + (g->width + g->offsetX);
                int ih = g->advanceY + (g->height + g->offsetY);
                GXGetScissor(&scisX, &scisY, &scisW, &scisH);
                gxSetScissorRect(0, 0, winBase[126].x, winBase[126].y, winBase[126].x + winBase[126].width,
                                 winBase[126].y + winBase[126].height);
                fx0 = (f32)(winBase[126].x + ((winBase[126].width - iw) >> 1));
                fx1 = fx0 + iw;
                fy0 = (f32)(winBase[126].y + ((winBase[126].height - ih) >> 1));
                fy1 = fy0 + ih;
                fx0 = fx0 * lbl_803DE710;
                fx1 = fx1 * lbl_803DE710;
                fy0 = fy0 * lbl_803DE710;
                fy1 = fy1 * lbl_803DE710;
            }

            if (mode != 0)
            {
                int ox = gGameTextShadowOffsetX;
                int oy = gGameTextShadowOffsetY;
                fx0 = fx0 + ox;
                fx1 = fx1 + ox;
                fy0 = fy0 + oy;
                fy1 = fy1 + oy;
            }

            if (gGameTextMeasureOnly == 0)
            {
                if (curTexPage != g->page)
                {
                    curTexPage = g->page;
                    tex = gameTextFonts->textures[g->page];
                    selectTexture(tex, 0);
                    if (gGameTextFontMetrics[g->font].unk06 == 1)
                    {
                        if (mode != 0)
                        {
                            setTextColor(0, 0, 0, 0, gGameTextColorA);
                        }
                        else
                        {
                            setTextColor(0, 0xff, 0xff, 0xff, gGameTextColorA);
                            gxTevResetStages();
                            gxTevTextureTimesColor1Stage();
                            gxTevCommitStages();
                        }
                    }
                    else
                    {
                        setTextColor(0, gGameTextColorR, gGameTextColorG, gGameTextColorB, gGameTextColorA);
                        _textSetColor(0, gGameTextColorR, gGameTextColorG, gGameTextColorB, gGameTextColorA);
                        gxTevResetStages();
                        textRenderSetup();
                        gxTevCommitStages();
                    }
                }
            }

            if (gGameTextRevealActive != 0 && mode == 0 && g->font != GAMETEXT_FONT_FACE && gGameTextDrawnCharIndex >= gGameTextRevealProgress)
            {
                setTextColor(0, 0, 0, 0, 0);
            }

            if (gameTextDrawFunc != NULL)
            {
                f32 sH = 32.0f * tex->height;
                f32 sW = 32.0f * tex->width;
                gameTextDrawFunc(fx0, fy0, fx1, fy1, u0 / sW, v0 / sH, (u0 + (f32)(g->width << 5)) / sW,
                                 (v0 + (f32)(g->height << 5)) / sH);
            }
            else
            {
                f32 sH = 32.0f * tex->height;
                f32 sW = 32.0f * tex->width;
                textRenderChar((int)fx0, fy0, fx1, fy1, u0 / sW, v0 / sH, (u0 + (f32)(g->width << 5)) / sW,
                               (v0 + (f32)(g->height << 5)) / sH);
            }

            if (g->font == GAMETEXT_FONT_FLAG || g->font == GAMETEXT_FONT_FACE)
            {
                GXSetScissor(scisX, scisY, scisW, scisH);
            }
        }

        if ((int)g->font != GAMETEXT_FONT_FACE)
        {
            x = gGameTextScale * (f32)(g->advanceX + (g->width + g->offsetX)) + x;
        }
    }
}

/* Placeholder strings the gametext parser hands back for bad lookups. */
struct
{
    char uninitialised[16];
    char loading[12];
    char fileEmpty[16];
    char noFile[12];
    char notInFile[20];
    char noPhrase[32];
} sGameTextParserMessages = {
    "<uninitialised>", "<loading>", "<file empty!>", "<no file!>", "<%d's not in %s>", "<%d, doesn't have phrase %d>",
};

static void translateToDinoLanguage(u8* str)
{
    int byteOff = 0;
    u32 ch;
    int charLen;
    u8* p;

    if (str == NULL)
    {
        return;
    }
    while (p = str + byteOff, (ch = utf8GetNextChar(p, &charLen)) != 0)
    {
        if (ch >= 0xe000 && ch <= 0xf8ff)
        {
            byteOff += ctrlCharLen(ch) * 2;
        }
        else
        {
            int base;
            if (ch >= 0x61 && ch <= 0x7a)
            {
                base = 0x61;
            }
            else if (ch >= 0x41 && ch <= 0x5a)
            {
                base = 0x41;
            }
            else
            {
                base = 0;
            }
            if (base != 0)
            {
                *p = sGameTextGlyphOrder[ch - base] - 0x61 + base;
            }
        }
        byteOff += charLen;
    }
}

int GameText_CountPrintableChars(u8* str)
{
    int count;
    int off;
    int len;
    u32 ch;

    count = 0;
    off = 0;
    if (str == NULL)
    {
        return 0;
    }
    while ((ch = utf8GetNextChar(str + off, &len)) != 0)
    {
        off += len;
        if (ch >= 0xE000 && ch <= 0xF8FF)
        {
            off += ctrlCharLen(ch) * 2;
        }
        else
        {
            count++;
        }
    }
    return count;
}

void gameTextMeasureString(u8* str, f32 scale, f32* outW, f32* outZero, f32* outMaxAdv, f32* outMaxH, int glyphLang)
{
    int byteOff;
    u32 ch;
    int charLen;
    int n2;
    int i;
    u8* p;
    TextGlyph* g;
    u8* tbl;
    f32 width;
    f32 mAdv;
    f32 mH;
    int params[8];

    byteOff = 0;
    width = 0.0f;
    if (str == NULL)
    {
        return;
    }
    if (glyphLang == -1)
    {
        if (gameTextCharset == 2)
        {
            glyphLang = 6;
        }
        else
        {
            glyphLang = sLanguageNameTable[curLanguage].fontId;
        }
    }
    tbl = (u8*)gGameTextFontMetrics + glyphLang * 16;
    if (glyphLang != GAMETEXT_FONT_FACE)
    {
        if (outMaxAdv != NULL)
        {
            *outMaxAdv = (f32)(u32)((FontMetrics*)tbl)->maxWidth * scale;
        }
        if (outMaxH != NULL)
        {
            *outMaxH = (f32)(u32)((FontMetrics*)tbl)->lineHeight * scale;
        }
    }

    while (p = str + byteOff, (ch = utf8GetNextChar(p, &charLen)) != 0)
    {
        byteOff += charLen;
        if (ch >= 0xe000 && ch <= 0xf8ff)
        {
            n2 = ctrlCharLen(ch);
            for (i = 0; i < n2; i++)
            {
                int hi = str[byteOff++];
                int lo = str[byteOff++];
                params[i] = (hi << 8) | lo;
            }
            switch (ch)
            {
            case TEXT_CTRL_SCALE:
                scale = params[0] * lbl_803DE708;
                break;
            case TEXT_CTRL_FONT:
                glyphLang = params[0];
                tbl = (u8*)gGameTextFontMetrics + glyphLang * 16;
                if (glyphLang != GAMETEXT_FONT_FACE)
                {
                    mAdv = (f32)(u32)((FontMetrics*)tbl)->maxWidth * scale;
                    if (outMaxAdv != NULL && mAdv > *outMaxAdv)
                    {
                        *outMaxAdv = mAdv;
                    }
                    mH = (f32)(u32)((FontMetrics*)tbl)->lineHeight * scale;
                    if (outMaxH != NULL && mH > *outMaxH)
                    {
                        *outMaxH = mH;
                    }
                }
                break;
            }
            continue;
        }

        g = findGlyph(ch, glyphLang);
        if (g == NULL)
        {
            continue;
        }
        if (glyphLang == GAMETEXT_FONT_FACE)
        {
            continue;
        }
        width = scale * (f32)(g->advanceX + (g->width + g->offsetX)) + width;
    }

    if (outW != NULL)
    {
        *outW = width;
    }
    if (outZero != NULL)
    {
        *outZero = 0.0f;
    }
}

SubtitleCmd* subtitleParseControlCmds(char* str, int* count)
{
    int off;
    int n;
    u8* tbl;
    int len;
    u32 ch;

    off = 0;
    n = 0;
    tbl = (u8*)sSubtitleCtrlCmdScratch;
    if ((u8*)str == NULL)
    {
        return NULL;
    }
    while ((ch = utf8GetNextChar((u8*)(str + off), &len)) != 0)
    {
        off += len;
        if (ch >= 0xE000 && ch <= 0xF8FF)
        {
            int i;
            int n2;
            u16* q;

            n++;
            if (n > 0x10)
            {
                break;
            }
            *(u32*)tbl = ch;
            q = (u16*)(tbl + 4);
            n2 = ctrlCharLen(ch);
            if (n2 > 4)
            {
                n2 = 4;
            }
            for (i = 0; i < n2; i++)
            {
                u32 hi = ((u8*)str)[off++];
                u32 lo = ((u8*)str)[off++];
                *q++ = (hi << 8) | lo;
            }
        }
    }
    if (n == 0)
    {
        return NULL;
    }
    {
        int size = n * 0xc;
        u8* buf = mmAlloc(size, 0x1a, 0);
        memcpy(buf, sSubtitleCtrlCmdScratch, size);
        *count = n;
        return (SubtitleCmd*)buf;
    }
}

GameTextLoadSlot curGameTexts[GAMETEXT_LOAD_SLOT_COUNT];

TextFont gGameTextCharsets[0xA0 / sizeof(TextFont)];

int GameText_FindControlCodeArgs(u8* str, u32 target, int* out)
{
    int off;
    int len;
    u32 ch;
    int n;
    int i;

    off = 0;
    if (str == NULL)
    {
        return 0;
    }
    while ((ch = utf8GetNextChar(str + off, &len)) != 0)
    {
        off += len;
        if (ch >= 0xE000 && ch <= 0xF8FF)
        {
            n = ctrlCharLen(ch);
            if (ch == target)
            {
                for (i = 0; i < n; i++)
                {
                    u32 hi = str[off++];
                    u32 lo = str[off++];
                    out[i] = (hi << 8) | lo;
                }
                return 1;
            }
            off += n * 2;
        }
    }
    return 0;
}

int getControlCharLen(u32 c)
{
    CtrlCharEntry* p = gGameTextCtrlCodeArgCounts;
    int i = 46;
    while (i--)
    {
        if (p->key == c)
        {
            return p->len;
        }
        p++;
    }
    return 0;
}

GameTextSlot gGameTextCommandSlots[0xA00 / sizeof(GameTextSlot)];
u32 sSubtitleCtrlCmdScratch[0x240];
u8 sGameTextFallbackDefs[0x280];
u8 sGameTextFallbackBufSlots[0x20];
u8 gGameTextBase[0x20];
