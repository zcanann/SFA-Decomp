#include "main/gametext_api.h"
#include "main/gametext_internal.h"
#include "main/gametext_shared_internal.h"
#include "main/textrender_api.h"
#include "main/audio/sfx.h"
#include "main/camera.h"
#include "main/frame_timing.h"
#include "main/gametext_box_api.h"
#include "main/gametext_color_api.h"
#include "main/gametext_command_api.h"
#include "main/gametext_show_api.h"
#include "main/gametext_show_str_api.h"
#include "main/gametext_task_api.h"
#include "main/mm.h"
#include "main/rcp_dolphin_api.h"
#include "main/textrender_internal.h"
#include "main/audio/sfx_trigger_ids.h"
#include "track/intersect_hud_api.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "main/fileio.h"
#include "main/lightmap_text_color_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/dll_0015_save_settings.h"
#include "track/intersect_api.h"
#include "string.h"
#include "main/lightmap.h"
#include "track/intersect_render_setup_api.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXGet.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "types.h"
#include "main/gameloop_api.h"
#include "main/gametext_charset_api.h"
#include "main/gx_scissor_api.h"
#include "dolphin/os/OSFont.h"
#include "main/dll/savedata_struct.h"
#include "main/audio/sfx_stop_object_api.h"

static inline int gameTextIdExists(int id);
static inline int textCountChars(char* lineStr);

int isSpace(u32 c);

static char* gameStrcpy(char* dst, char* src);

u8 gUtf8CharClassTable[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
};

int gUtf8ClassOffsetTable[6] = {0, 12416, 925824, 63447168, -100130688, -2113396608};

char* sMapDirectoryNameTable[74] = {
    "Animtest",     "Arwing",       "BOSSAndross",   "Boot",         "BossDrakor",   "BossGaldon",   "BossTrex",
    "CRFort",       "CapeClaw",     "CloudDungeon",  "CloudRace",    "Communicator", "DBShrine",     "DFPTop",
    "DFShrine",     "DarkIceMines", "DarkIceMines2", "Desert",       "DragRock",     "DragRockBot",  "ECShrine",
    "FrontEnd",     "GPShrine",     "GameMaze",      "IceMountain",  "InsideGal",    "LINKG",        "LightFoot",
    "Link",         "LinkB",        "LinkC",         "LinkD",        "LinkE",        "LinkF",        "LinkH",
    "LinkJ",        "MMPass",       "MMShrine",      "MagicCave",    "NWShrine",     "NWastes",      "Sequences",
    "ShipBattle",   "Shop",         "SwapHol",       "TaskTexts000", "TaskTexts001", "TaskTexts002", "TaskTexts003",
    "TaskTexts004", "TaskTexts005", "TaskTexts006",  "TaskTexts007", "TaskTexts008", "TaskTexts009", "TaskTexts010",
    "TaskTexts011", "TaskTexts012", "TaskTexts013",  "TaskTexts014", "TaskTexts015", "TaskTexts016", "TaskTexts017",
    "TaskTexts018", "TaskTexts019", "TaskTexts021",  "TaskTexts022", "TaskTexts023", "TaskTexts024", "Volcano",
    "WallCity",     "Warlock",      "WorldMap",      NULL,
};

char sLanguageNameEnglish[] = "English";
char sLanguageNameFrench[] = "French";
char sLanguageNameGerman[] = "German";
char sLanguageNameItalian[] = "Italian";
char sLanguageNameSpanish[] = "Spanish";
char sLanguageNameJapanese[] = "Japanese";

LanguageName sLanguageNameTable[6] = {
    {sLanguageNameEnglish, 4, {0, 0, 0}}, {sLanguageNameFrench, 4, {0, 0, 0}},   {sLanguageNameGerman, 4, {0, 0, 0}},
    {sLanguageNameItalian, 4, {0, 0, 0}}, {sLanguageNameJapanese, 0, {0, 0, 0}}, {sLanguageNameSpanish, 4, {0, 0, 0}},
};

GameTextBox gTextBoxes[GAMETEXT_BOX_COUNT] = {
    {560, 560, 400, 400, 560, 400, 1.0f, 2, 0, 2, 5, 40, 40, 0, 0, 0, 0, 0},
    {256, 256, 96, 96, 256, 96, 1.0f, 3, 0, 3, 6, 30, 30, 0, 0, 0, 0, 0},
    {580, 580, 400, 400, 580, 400, 1.0f, 2, 1, 2, 5, 30, 40, 0, 0, 0, 0, 0},
    {16, 320, 16, 110, 320, 110, 1.0f, 0, 1, 0, 7, 40, 40, 0, 0, 0, 0, 0},
    {330, 330, 256, 256, 330, 256, 1.0f, 0, 0, 0, 5, 30, 100, 0, 0, 0, 0, 0},
    {330, 330, 330, 330, 330, 330, 1.0f, 0, 0, 0, 5, 30, 240, 0, 0, 0, 0, 0},
    {230, 230, 256, 256, 230, 256, 1.0f, 2, 0, 2, 5, 380, 100, 0, 0, 0, 0, 0},
    {230, 230, 256, 256, 230, 256, 1.0f, 2, 0, 2, 5, 380, 240, 0, 0, 0, 0, 0},
    {16, 200, 100, 256, 200, 256, 1.0f, 1, 0, 1, 5, 361, 63, 0, 0, 0, 0, 0},
    {16, 200, 16, 256, 200, 256, 1.0f, 1, 0, 1, 5, 346, 88, 0, 0, 0, 0, 0},
    {580, 580, 25, 25, 580, 25, 1.0f, 2, 0, 2, 5, 30, 415, 0, 0, 0, 0, 0},
    {580, 580, 480, 480, 580, 480, 1.0f, 2, 0, 2, 5, 30, 0, 0, 0, 0, 0, 0},
    {390, 390, 200, 200, 390, 200, 1.0f, 2, 0, 2, 7, 40, 50, 0, 0, 0, 0, 0},
    {150, 150, 16, 40, 150, 40, 1.2f, 0, 1, 0, 5, 54, 300, 0, 0, 0, 0, 0},
    {16, 502, 16, 32, 502, 32, 1.0f, 2, 0, 2, 3, 69, 263, 0, 0, 0, 0, 0},
    {16, 502, 16, 32, 502, 32, 1.0f, 2, 0, 2, 3, 69, 314, 0, 0, 0, 0, 0},
    {260, 260, 16, 32, 260, 32, 1.0f, 1, 0, 1, 5, 56, 0, 0, 0, 0, 0, 0},
    {260, 260, 16, 32, 260, 32, 1.0f, 1, 0, 1, 5, 56, -34, 0, 0, 0, 0, 0},
    {16, 502, 16, 32, 502, 32, 1.0f, 2, 0, 2, 3, 69, 161, 0, 0, 0, 0, 0},
    {16, 502, 16, 32, 502, 32, 1.0f, 2, 0, 2, 3, 69, 215, 0, 0, 0, 0, 0},
    {16, 502, 16, 32, 502, 32, 1.0f, 2, 0, 2, 3, 69, 269, 0, 0, 0, 0, 0},
    {640, 640, 16, 32, 640, 32, 1.0f, 2, 0, 2, 5, 0, 416, 0, 0, 0, 0, 0},
    {260, 260, 16, 32, 260, 32, 1.0f, 0, 0, 0, 5, 56, 0, 0, 0, 0, 0, 0},
    {260, 260, 16, 32, 260, 32, 1.0f, 0, 0, 0, 5, 56, 26, 0, 0, 0, 0, 0},
    {260, 260, 16, 32, 260, 32, 1.0f, 0, 0, 0, 5, 56, 52, 0, 0, 0, 0, 0},
    {260, 260, 16, 52, 260, 52, 1.0f, 0, 0, 0, 5, 56, 78, 0, 0, 0, 0, 0},
    {260, 260, 16, 32, 260, 32, 1.0f, 0, 0, 0, 5, 56, 104, 0, 0, 0, 0, 0},
    {260, 260, 16, 52, 260, 52, 1.0f, 0, 0, 0, 5, 56, 130, 0, 0, 0, 0, 0},
    {260, 260, 16, 32, 260, 32, 1.0f, 0, 0, 0, 5, 56, 156, 0, 0, 0, 0, 0},
    {260, 260, 16, 52, 260, 52, 1.0f, 0, 0, 0, 5, 56, 182, 0, 0, 0, 0, 0},
    {260, 260, 16, 52, 260, 52, 1.0f, 0, 0, 0, 5, 56, 208, 0, 0, 0, 0, 0},
    {240, 240, 16, 32, 240, 32, 1.0f, 0, 0, 0, 5, 76, 52, 0, 0, 0, 0, 0},
    {240, 240, 16, 32, 240, 32, 1.0f, 0, 0, 0, 5, 76, 94, 0, 0, 0, 0, 0},
    {240, 240, 16, 32, 240, 32, 1.0f, 0, 0, 0, 5, 76, 136, 0, 0, 0, 0, 0},
    {260, 260, 128, 128, 260, 128, 1.0f, 1, 0, 1, 5, 56, 26, 0, 0, 0, 0, 0},
    {260, 260, 128, 128, 260, 128, 1.0f, 1, 0, 1, 5, 56, 52, 0, 0, 0, 0, 0},
    {260, 260, 128, 128, 260, 128, 1.0f, 1, 0, 1, 5, 56, 78, 0, 0, 0, 0, 0},
    {260, 260, 128, 128, 260, 128, 1.0f, 1, 0, 1, 5, 56, 104, 0, 0, 0, 0, 0},
    {260, 260, 128, 128, 260, 128, 1.0f, 1, 0, 1, 5, 56, 130, 0, 0, 0, 0, 0},
    {260, 260, 128, 128, 260, 128, 1.0f, 1, 0, 1, 5, 56, 156, 0, 0, 0, 0, 0},
    {260, 260, 128, 128, 260, 128, 1.0f, 1, 0, 1, 5, 56, 182, 0, 0, 0, 0, 0},
    {260, 260, 128, 128, 260, 128, 1.0f, 1, 0, 1, 5, 56, 208, 0, 0, 0, 0, 0},
    {32, 32, 16, 32, 32, 32, 1.0f, 2, 0, 2, 5, 142, 26, 0, 0, 0, 0, 0},
    {32, 32, 16, 32, 32, 32, 1.0f, 2, 0, 2, 5, 169, 26, 0, 0, 0, 0, 0},
    {32, 32, 16, 32, 32, 32, 1.0f, 2, 0, 2, 5, 196, 26, 0, 0, 0, 0, 0},
    {260, 260, 32, 32, 260, 32, 1.0f, 0, 0, 0, 5, 56, 0, 0, 0, 0, 0, 0},
    {260, 260, 32, 32, 260, 32, 1.0f, 0, 0, 0, 5, 56, 234, 0, 0, 0, 0, 0},
    {16, 256, 32, 32, 256, 32, 1.0f, 2, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0},
    {16, 256, 32, 32, 256, 32, 1.0f, 2, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0},
    {16, 256, 32, 32, 256, 32, 1.0f, 2, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0},
    {16, 256, 32, 32, 256, 32, 1.0f, 2, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0},
    {16, 256, 32, 32, 256, 32, 1.0f, 2, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0},
    {16, 256, 32, 32, 256, 32, 1.0f, 2, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0},
    {16, 260, 32, 32, 260, 32, 1.0f, 2, 0, 2, 3, 56, 397, 0, 0, 0, 0, 0},
    {400, 400, 300, 300, 400, 300, 1.0f, 2, 0, 2, 5, 120, 90, 0, 0, 0, 0, 0},
    {16, 160, 24, 24, 160, 24, 1.0f, 0, 2, 0, 5, 450, 263, 0, 0, 0, 0, 0},
    {16, 187, 24, 24, 187, 24, 1.0f, 0, 2, 0, 5, 423, 292, 0, 0, 0, 0, 0},
    {16, 256, 24, 24, 256, 24, 1.0f, 0, 2, 0, 5, 64, 97, 0, 0, 0, 0, 0},
    {16, 256, 24, 24, 256, 24, 1.0f, 0, 2, 0, 5, 353, 113, 0, 0, 0, 0, 0},
    {16, 190, 24, 24, 190, 24, 1.0f, 2, 2, 2, 5, 111, 125, 0, 0, 0, 0, 0},
    {16, 244, 24, 24, 244, 24, 1.0f, 0, 2, 0, 5, 366, 219, 0, 0, 0, 0, 0},
    {16, 208, 24, 24, 208, 24, 1.0f, 0, 2, 0, 5, 402, 180, 0, 0, 0, 0, 0},
    {16, 189, 24, 24, 189, 24, 1.0f, 0, 2, 0, 5, 421, 152, 0, 0, 0, 0, 0},
    {16, 256, 24, 24, 256, 24, 1.0f, 0, 2, 0, 5, 67, 359, 0, 0, 0, 0, 0},
    {16, 225, 24, 24, 225, 24, 1.0f, 0, 2, 0, 5, 385, 324, 0, 0, 0, 0, 0},
    {260, 260, 16, 32, 260, 32, 1.0f, 0, 0, 0, 5, 56, 0, 0, 0, 0, 0, 0},
    {260, 260, 128, 128, 260, 128, 1.0f, 1, 0, 1, 5, 56, 0, 0, 0, 0, 0, 0},
    {260, 260, 16, 32, 260, 32, 1.0f, 0, 0, 0, 5, 56, 26, 0, 0, 0, 0, 0},
    {200, 200, 128, 128, 200, 128, 1.0f, 1, 0, 1, 5, 121, 26, 0, 0, 0, 0, 0},
    {200, 160, 128, 128, 160, 128, 1.0f, 1, 0, 1, 5, 121, 26, 0, 0, 0, 0, 0},
    {200, 200, 24, 24, 200, 24, 1.0f, 2, 0, 2, 7, 370, 300, 0, 0, 0, 0, 0},
    {200, 200, 24, 24, 200, 24, 1.0f, 2, 0, 2, 7, 70, 300, 0, 0, 0, 0, 0},
    {200, 200, 24, 24, 200, 24, 1.0f, 2, 0, 2, 7, 220, 260, 0, 0, 0, 0, 0},
    {0, 500, 46, 46, 500, 46, 1.0f, 2, 1, 2, 2, 60, 52, 0, 0, 0, 0, 0},
    {100, 100, 16, 32, 100, 32, 1.0f, 0, 0, 0, 5, 130, 178, 0, 0, 0, 0, 0},
    {100, 100, 16, 32, 100, 32, 1.0f, 0, 0, 0, 5, 130, 204, 0, 0, 0, 0, 0},
    {100, 100, 16, 32, 100, 32, 1.0f, 0, 0, 0, 5, 130, 230, 0, 0, 0, 0, 0},
    {100, 100, 16, 32, 100, 32, 1.0f, 0, 0, 0, 5, 130, 256, 0, 0, 0, 0, 0},
    {100, 100, 16, 32, 100, 32, 1.0f, 0, 0, 0, 5, 130, 282, 0, 0, 0, 0, 0},
    {100, 100, 16, 32, 100, 32, 1.0f, 0, 0, 0, 5, 401, 178, 0, 0, 0, 0, 0},
    {100, 100, 16, 32, 100, 32, 1.0f, 0, 0, 0, 5, 401, 204, 0, 0, 0, 0, 0},
    {100, 100, 16, 32, 100, 32, 1.0f, 0, 0, 0, 5, 401, 230, 0, 0, 0, 0, 0},
    {100, 100, 16, 32, 100, 32, 1.0f, 0, 0, 0, 5, 401, 256, 0, 0, 0, 0, 0},
    {100, 100, 16, 32, 100, 32, 1.0f, 0, 0, 0, 5, 401, 282, 0, 0, 0, 0, 0},
    {200, 200, 16, 32, 200, 32, 1.0f, 2, 0, 2, 5, 70, 110, 0, 0, 0, 0, 0},
    {200, 200, 16, 32, 200, 32, 1.0f, 2, 0, 2, 5, 370, 110, 0, 0, 0, 0, 0},
    {1600, 1600, 24, 24, 1600, 24, 1.0f, 0, 0, 0, 5, 50, 78, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 152, 200, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 200, 200, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 248, 200, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 296, 200, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 344, 200, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 392, 200, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 440, 200, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 488, 200, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 128, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 176, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 224, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 272, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 320, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 368, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 416, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 464, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 104, 296, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 152, 296, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 200, 296, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 248, 296, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 296, 296, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 344, 296, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 392, 296, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 440, 296, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 488, 296, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 200, 344, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 248, 344, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 296, 344, 0, 0, 0, 0, 0},
    {48, 48, 24, 24, 48, 24, 1.0f, 2, 0, 2, 7, 344, 344, 0, 0, 0, 0, 0},
    {400, 400, 24, 24, 400, 24, 1.0f, 2, 0, 2, 5, 120, 228, 0, 0, 0, 0, 0},
    {400, 400, 24, 24, 400, 24, 1.0f, 2, 0, 2, 5, 120, 254, 0, 0, 0, 0, 0},
    {400, 400, 24, 24, 400, 24, 1.0f, 2, 0, 2, 5, 120, 280, 0, 0, 0, 0, 0},
    {400, 400, 24, 24, 400, 24, 1.0f, 2, 0, 2, 5, 120, 306, 0, 0, 0, 0, 0},
    {400, 400, 24, 24, 400, 24, 1.0f, 2, 0, 2, 5, 120, 332, 0, 0, 0, 0, 0},
    {360, 360, 16, 420, 360, 420, 1.0f, 2, 1, 2, 5, 140, 60, 0, 0, 0, 0, 0},
    {560, 560, 45, 45, 560, 45, 1.0f, 3, 0, 3, 5, 40, 395, 0, 0, 0, 0, 0},
    {560, 560, 480, 480, 560, 480, 1.0f, 2, 0, 2, 5, 40, 0, 0, 0, 0, 0, 0},
    {512, 512, 25, 25, 512, 25, 1.0f, 2, 0, 2, 5, 84, 415, 0, 0, 0, 0, 0},
    {512, 512, 480, 480, 512, 480, 1.0f, 3, 0, 3, 5, 84, 0, 0, 0, 0, 0, 0},
    {48, 48, 56, 56, 48, 56, 1.0f, 2, 1, 2, 5, 32, 415, 0, 0, 0, 0, 0},
    {160, 160, 16, 256, 160, 256, 1.0f, 1, 0, 1, 5, 140, 60, 0, 0, 0, 0, 0},
    {160, 160, 16, 256, 160, 256, 1.0f, 0, 0, 0, 5, 340, 60, 0, 0, 0, 0, 0},
    {340, 340, 300, 300, 340, 300, 1.0f, 2, 0, 2, 7, 150, 60, 0, 0, 0, 0, 0},
    {240, 240, 256, 256, 240, 256, 1.0f, 2, 0, 2, 7, 360, 60, 0, 0, 0, 0, 0},
    {112, 192, 100, 100, 192, 100, 1.0f, 2, 1, 2, 5, 54, 340, 0, 0, 0, 0, 0},
    {640, 640, 100, 100, 640, 100, 1.7f, 2, 0, 2, 5, 0, 230, 0, 0, 0, 0, 0},
    {640, 640, 350, 350, 640, 350, 1.7f, 2, 0, 2, 5, 0, 100, 0, 0, 0, 0, 0},
    {180, 180, 300, 300, 180, 300, 1.0f, 1, 0, 1, 5, 120, 90, 0, 0, 0, 0, 0},
    {180, 180, 300, 300, 180, 300, 1.0f, 0, 0, 0, 5, 340, 90, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 128, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 176, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 224, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 272, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 320, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 0, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 0, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 0, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 0, 248, 0, 0, 0, 0, 0},
    {24, 24, 24, 24, 24, 24, 1.0f, 2, 0, 2, 7, 0, 248, 0, 0, 0, 0, 0},
    {16, 320, 16, 110, 320, 110, 1.0f, 0, 1, 0, 7, 250, 150, 0, 0, 0, 0, 0},
    {640, 640, 480, 480, 640, 480, 1.0f, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0},
};

FontMetrics gGameTextFontMetrics[7] = {
    {0, {14, 170}, 21, 10, 2, 0, 21, 21, {0, 0, 0, 0}}, {0, {0, 1}, 14, 7, 1, 0, 14, 21, {0, 0, 0, 0}},
    {0, {0, 11}, 30, 15, 1, 0, 30, 22, {0, 0, 0, 0}},   {0, {0, 6}, 32, 16, 1, 0, 32, 24, {0, 0, 0, 0}},
    {0, {0, 136}, 21, 10, 2, 0, 21, 21, {0, 0, 0, 0}},  {0, {0, 8}, 46, 23, 1, 0, 46, 55, {0, 0, 0, 0}},
    {0, {0, 0}, 0, 0, 0, 0, 0, 0, {0, 0, 0, 0}},
};

CtrlCharEntry gGameTextCtrlCodeArgCounts[46] = {
    {0x0000F8F2, 0x00000002}, {0x0000F8F3, 0x00000000}, {0x0000F8F4, 0x00000001}, {0x0000F8F5, 0x00000001},
    {0x0000F8F6, 0x00000001}, {0x0000F8F7, 0x00000001}, {0x0000F8F8, 0x00000000}, {0x0000F8F9, 0x00000000},
    {0x0000F8FA, 0x00000000}, {0x0000F8FB, 0x00000000}, {0x0000F8FC, 0x00000000}, {0x0000F8FD, 0x00000000},
    {0x0000F8FE, 0x00000000}, {0x0000F8FF, 0x00000004}, {0x0000E000, 0x00000001}, {0x0000E018, 0x00000003},
    {0x0000E020, 0x00000001}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004},
    {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004},
    {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004},
    {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004},
    {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004},
    {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004},
    {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004},
    {0x0000F8FF, 0x00000004}, {0x0000F8FF, 0x00000004},
};

TaskTextEntry gTaskTextTable[208] = {
    {0x0004, 0x0029, 0x00D1}, {0x0006, 0x0029, 0x04F7}, {0x0009, 0x0029, 0x017C}, {0x000B, 0x0029, 0x004B},
    {0x000C, 0x0029, 0x0285}, {0x000E, 0x0029, 0x04EA}, {0x0010, 0x0029, 0x0041}, {0x0011, 0x0029, 0x047A},
    {0x0013, 0x0029, 0x046C}, {0x0015, 0x0029, 0x01D7}, {0x0016, 0x0029, 0x0477}, {0x0031, 0x0029, 0x0205},
    {0x0037, 0x0029, 0x01B0}, {0x0038, 0x0029, 0x0075}, {0x003C, 0x0029, 0x02E5}, {0x003D, 0x0029, 0x0078},
    {0x003F, 0x0029, 0x0499}, {0x0042, 0x0029, 0x001E}, {0x0043, 0x0029, 0x000C}, {0x0048, 0x0029, 0x0027},
    {0x004B, 0x0029, 0x00A7}, {0x0056, 0x0029, 0x00AD}, {0x005A, 0x0029, 0x020F}, {0x005F, 0x0029, 0x0023},
    {0x0092, 0x0029, 0x04C3}, {0x00A6, 0x0029, 0x00E4}, {0x00A7, 0x0029, 0x001C}, {0x00AA, 0x0029, 0x00FE},
    {0x00AB, 0x0029, 0x0105}, {0x00AD, 0x0029, 0x00FF}, {0x00AE, 0x0029, 0x0121}, {0x00AF, 0x0029, 0x056A},
    {0x00B1, 0x0029, 0x00FA}, {0x00B2, 0x0029, 0x00FB}, {0x00B3, 0x0029, 0x00FC}, {0x00B8, 0x0029, 0x01AA},
    {0x00B9, 0x0029, 0x01AB}, {0x00CA, 0x0029, 0x016E}, {0x00CB, 0x0029, 0x01A4}, {0x00E6, 0x0029, 0x007A},
    {0x00F0, 0x0029, 0x0324}, {0x01F8, 0x0029, 0x0338}, {0x01FE, 0x0029, 0x035A}, {0x0203, 0x0029, 0x049C},
    {0x0205, 0x0029, 0x053E}, {0x020A, 0x0029, 0x0510}, {0x020B, 0x0029, 0x0544}, {0x0265, 0x0029, 0x0462},
    {0x0288, 0x0029, 0x0532}, {0x0289, 0x0029, 0x008E}, {0x028A, 0x0029, 0x0282}, {0x028C, 0x0029, 0x01DB},
    {0x028E, 0x0029, 0x0045}, {0x02A0, 0x0029, 0x00E3}, {0x02B4, 0x0029, 0x001F}, {0x02B9, 0x0029, 0x04E8},
    {0x02BA, 0x0029, 0x04E9}, {0x02F1, 0x0029, 0x0127}, {0x02F2, 0x0029, 0x0128}, {0x02F3, 0x0029, 0x0487},
    {0x02F4, 0x0029, 0x03C4}, {0x02F5, 0x0029, 0x03C8}, {0x4E21, 0x0029, 0x0464}, {0x4E22, 0x0029, 0x0481},
    {0x4E23, 0x0029, 0x0483}, {0x4E24, 0x0029, 0x053D}, {0x4E25, 0x0029, 0x02D8}, {0x4E26, 0x0029, 0x04FB},
    {0x4E27, 0x0029, 0x04FE}, {0x4E28, 0x0029, 0x0505}, {0x4E29, 0x0029, 0x0503}, {0x4E2A, 0x0029, 0x0052},
    {0x4E2B, 0x0029, 0x004F}, {0x4E2C, 0x0029, 0x0050}, {0x4E2D, 0x0029, 0x011B}, {0x4E2E, 0x0029, 0x0571},
    {0x4E2F, 0x0029, 0x0074}, {0x4E30, 0x0029, 0x007B}, {0x4E31, 0x0029, 0x0383}, {0x4E32, 0x0029, 0x0384},
    {0x4E34, 0x0029, 0x0515}, {0x4E35, 0x0029, 0x0549}, {0x4E36, 0x0029, 0x0148}, {0x4E37, 0x0029, 0x014A},
    {0x4E38, 0x0029, 0x033A}, {0x4E3D, 0x0029, 0x001D}, {0x4E40, 0x0029, 0x0020}, {0x4E41, 0x0029, 0x0388},
    {0x4E42, 0x0029, 0x0395}, {0x4E43, 0x0029, 0x015C}, {0x4E44, 0x0029, 0x058B}, {0x4E45, 0x0029, 0x0283},
    {0x4E46, 0x0029, 0x02AA}, {0x4E84, 0x0029, 0x0064}, {0x4E89, 0x0029, 0x0069}, {0x4E8B, 0x0029, 0x0083},
    {0x4E8C, 0x0029, 0x0490}, {0x4EAB, 0x0029, 0x008B}, {0x4EAC, 0x0029, 0x0598}, {0x4EB6, 0x0029, 0x059A},
    {0x4EE9, 0x0029, 0x00C9}, {0x4EEA, 0x0029, 0x00CA}, {0x4EEB, 0x0029, 0x00CB}, {0x4EF2, 0x0029, 0x00D2},
    {0x4EF5, 0x0029, 0x00D5}, {0x4F0A, 0x0029, 0x00EA}, {0x4F35, 0x0029, 0x0115}, {0x4F38, 0x0029, 0x0118},
    {0x4F3E, 0x0029, 0x011E}, {0x501A, 0x0029, 0x01FA}, {0x501C, 0x0029, 0x01FC}, {0x5078, 0x0029, 0x0080},
    {0x509B, 0x0029, 0x0271}, {0x50B5, 0x0029, 0x0493}, {0x50D7, 0x0029, 0x006D}, {0x50D8, 0x0029, 0x0180},
    {0x50DC, 0x0029, 0x059C}, {0x517F, 0x0029, 0x035F}, {0x529F, 0x0029, 0x047F}, {0x52B2, 0x0029, 0x0492},
    {0x52BD, 0x0029, 0x049D}, {0x5368, 0x0029, 0x0548}, {0xFFFF, 0x0000, 0x0000}, {0x0000, 0x0000, 0xFFFF},
    {0xFFFF, 0x0000, 0x0000}, {0x0006, 0x0006, 0x0006}, {0x0006, 0x0006, 0x0006}, {0xFFFF, 0xFFFF, 0x0002},
    {0x0002, 0x0005, 0x0005}, {0x0005, 0x0005, 0x0006}, {0xFFFF, 0xFFFF, 0x0006}, {0x0006, 0x0006, 0x0006},
    {0x0006, 0x0006, 0xFFFF}, {0x0005, 0x0005, 0x0005}, {0x0006, 0x0007, 0xFFFF}, {0x0007, 0x0007, 0x0007},
    {0x0007, 0x0007, 0x0007}, {0x0007, 0x0007, 0x0007}, {0x0007, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0x0007},
    {0x0006, 0x0009, 0x0009}, {0x000A, 0x000A, 0x000A}, {0x000A, 0x000A, 0xFFFF}, {0x0009, 0x0009, 0x0009},
    {0x0009, 0x0009, 0x0009}, {0x0006, 0xFFFF, 0x0000}, {0x0000, 0x000C, 0xFFFF}, {0x000C, 0xFFFF, 0xFFFF},
    {0x000C, 0x0006, 0x000B}, {0xFFFF, 0x000B, 0x000B}, {0x000B, 0x000B, 0x000B}, {0x000B, 0xFFFF, 0xFFFF},
    {0xFFFF, 0xFFFF, 0x000B}, {0xFFFF, 0x000C, 0x0008}, {0x0008, 0x0008, 0x0008}, {0xFFFF, 0xFFFF, 0xFFFF},
    {0x0006, 0x0004, 0x0004}, {0x0004, 0xFFFF, 0x0004}, {0xFFFF, 0xFFFF, 0xFFFF}, {0x0004, 0xFFFF, 0x0000},
    {0x0006, 0x0006, 0x0003}, {0xFFFF, 0x0003, 0x0003}, {0x0003, 0x0003, 0xFFFF}, {0xFFFF, 0xFFFF, 0x0003},
    {0x000A, 0x000A, 0x000A}, {0x000A, 0xFFFF, 0x0006}, {0xFFFF, 0x0006, 0x0005}, {0x0005, 0x0005, 0xFFFF},
    {0x0000, 0xFFFF, 0x0006}, {0x0001, 0xFFFF, 0xFFFF}, {0x0001, 0x0001, 0x0001}, {0x0001, 0xFFFF, 0x0001},
    {0x0001, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0x0001, 0x000C}, {0x0008, 0xFFFF, 0x0008},
    {0xFFFF, 0xFFFF, 0x0006}, {0x0006, 0x0003, 0x0003}, {0xFFFF, 0x0003, 0xFFFF}, {0xFFFF, 0xFFFF, 0x0003},
    {0x0003, 0x0000, 0x0000}, {0x0000, 0x0000, 0x0000}, {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF},
    {0x0000, 0x0000, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF},
    {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF},
    {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF},
    {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF},
    {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF},
    {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF}, {0xFFFF, 0xFFFF, 0xFFFF}, {0x0000, 0x0000, 0x0000},
};

/* In-string formatting control codes (Unicode PUA). */
#define TEXT_CTRL_SCALE 0xf8f4
#define TEXT_CTRL_FONT  0xf8f7

int isSpace(u32 c);

static inline int gameTextCtrlCharLen(u32 c);

static inline int gameTextCountChars(char* str);

static inline TextGlyph* gameTextFindGlyph(u32 ch, int langIdx);

static inline char* gameTextBreakLine(char* dst, char** buffer, int lineIdx);

extern char sJpDiscLoadingMessage[];
extern char sDiscLoadingMessage[];
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
char* sJpDiscLoadingMessageLines[1] = {sJpDiscLoadingMessage};
char sDiscErrorSpacerLine[4] = {0};
char sDiscReadErrorSpacerLine[4] = {0};
char* sDiscReadingMessageLines[1] = {sDiscReadingMessage};
char sDiscCoverOpenSpacerLine[4] = {0};
char* sDiscInsertMessageLines[2] = {sDiscInsertPromptLine, sDiscInsertGameDiscLine};
char sWrongDiscSpacerLine[4] = {0};
char* sDiscLoadingMessageLines[1] = {sDiscLoadingMessage};
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

TextGlyph sJpDiscStatusGlyphs[85] = {
    {0x30A8, 1, 1, 0, 1, 3, 2, 20, 16, 0, 0},    {0x30E9, 22, 1, 1, 1, 2, 1, 19, 18, 0, 0},
    {0x30FC, 42, 1, 0, 1, 8, 10, 20, 3, 0, 0},   {0x304C, 63, 1, 0, 0, 0, 1, 21, 20, 0, 0},
    {0x767A, 85, 1, 0, 1, 0, 1, 20, 20, 0, 0},   {0x751F, 106, 1, 0, 1, 0, 2, 20, 19, 0, 0},
    {0x3057, 127, 1, 3, 2, 1, 1, 16, 19, 0, 0},  {0x307E, 144, 1, 1, 2, 1, 1, 18, 19, 0, 0},
    {0x305F, 163, 1, 0, 2, 1, 1, 19, 19, 0, 0},  {0x3002, 183, 1, 0, 13, 13, 1, 8, 7, 0, 0},
    {0x0020, 192, 1, 12, 0, 21, 0, 0, 0, 0, 0},  {0x672C, 193, 1, 0, 1, 0, 1, 20, 20, 0, 0},
    {0x4F53, 214, 1, 0, 1, 0, 0, 20, 21, 0, 0},  {0x306E, 235, 1, 1, 1, 1, 2, 19, 18, 0, 0},
    {0x30D1, 255, 1, 0, 0, 0, 1, 21, 20, 0, 0},  {0x30EF, 277, 1, 1, 2, 2, 1, 18, 18, 0, 0},
    {0x30DC, 296, 1, 0, 0, 0, 1, 21, 20, 0, 0},  {0x30BF, 318, 1, 0, 2, 2, 1, 19, 18, 0, 0},
    {0x30F3, 338, 1, 1, 2, 2, 1, 18, 18, 0, 0},  {0x3092, 357, 1, 0, 2, 1, 1, 19, 19, 0, 0},
    {0x62BC, 377, 1, 0, 1, 0, 0, 20, 21, 0, 0},  {0x3066, 398, 1, 1, 1, 2, 1, 19, 18, 0, 0},
    {0x96FB, 418, 1, 0, 1, 1, 1, 20, 19, 0, 0},  {0x6E90, 439, 1, 0, 1, 0, 1, 20, 20, 0, 0},
    {0x004F, 460, 1, 0, 1, 1, 2, 11, 18, 0, 0},  {0x0046, 472, 1, 1, 1, 1, 2, 10, 18, 0, 0},
    {0x306B, 483, 1, 1, 2, 1, 1, 18, 19, 0, 0},  {0x53D6, 1, 23, 0, 1, 1, 0, 20, 20, 0, 0},
    {0x6271, 22, 23, 0, 1, 0, 1, 20, 20, 0, 0},  {0x8AAC, 43, 23, 0, 1, 0, 1, 20, 20, 0, 0},
    {0x660E, 64, 23, 1, 2, 1, 1, 18, 19, 0, 0},  {0x66F8, 83, 23, 0, 1, 0, 0, 20, 21, 0, 0},
    {0x6307, 104, 23, 0, 1, 0, 0, 20, 21, 0, 0}, {0x793A, 125, 23, 0, 1, 1, 1, 20, 19, 0, 0},
    {0x5F93, 146, 23, 0, 1, 0, 1, 20, 20, 0, 0}, {0x3063, 167, 23, 1, 3, 5, 2, 17, 14, 0, 0},
    {0x4E0B, 185, 23, 0, 1, 1, 1, 20, 19, 0, 0}, {0x3055, 206, 23, 1, 1, 1, 1, 19, 19, 0, 0},
    {0x3044, 226, 23, 1, 2, 2, 2, 18, 17, 0, 0}, {0x30C7, 245, 23, 0, 0, 0, 1, 21, 20, 0, 0},
    {0x30A3, 267, 23, 2, 3, 3, 0, 16, 18, 0, 0}, {0x30B9, 284, 23, 1, 1, 2, 1, 19, 18, 0, 0},
    {0x30AF, 304, 23, 0, 2, 2, 1, 19, 18, 0, 0}, {0x8AAD, 324, 23, 0, 1, 0, 1, 20, 20, 0, 0},
    {0x3081, 345, 23, 0, 1, 1, 1, 20, 19, 0, 0}, {0x305B, 366, 23, 0, 1, 1, 1, 20, 19, 0, 0},
    {0x3093, 387, 23, 0, 1, 1, 1, 20, 19, 0, 0}, {0x3067, 408, 23, 1, 0, 2, 1, 20, 18, 0, 0},
    {0x304F, 429, 23, 2, 3, 1, 1, 16, 19, 0, 0}, {0x308F, 446, 23, 0, 1, 1, 1, 20, 19, 0, 0},
    {0x306F, 467, 23, 1, 1, 1, 1, 19, 19, 0, 0}, {0x304A, 487, 23, 0, 1, 1, 1, 20, 19, 0, 0},
    {0x307F, 1, 45, 0, 1, 1, 1, 20, 19, 0, 0},   {0x8FBC, 22, 45, 0, 1, 1, 1, 20, 19, 0, 0},
    {0x3059, 43, 45, 0, 1, 0, 1, 20, 20, 0, 0},  {0x30AB, 64, 45, 0, 2, 1, 2, 19, 18, 0, 0},
    {0x30D0, 84, 45, 0, 1, 1, 1, 20, 19, 0, 0},  {0x958B, 105, 45, 1, 2, 1, 0, 18, 20, 0, 0},
    {0x30B2, 124, 45, 0, 0, 0, 1, 21, 20, 0, 0}, {0x30E0, 146, 45, 0, 1, 1, 2, 20, 18, 0, 0},
    {0x7D9A, 167, 45, 0, 1, 0, 1, 20, 20, 0, 0}, {0x3051, 188, 45, 2, 1, 1, 1, 18, 19, 0, 0},
    {0x308B, 207, 45, 1, 2, 2, 1, 18, 18, 0, 0}, {0x5834, 226, 45, 0, 1, 1, 0, 20, 20, 0, 0},
    {0x5408, 247, 45, 0, 1, 0, 0, 20, 21, 0, 0}, {0x9589, 268, 45, 1, 2, 1, 0, 18, 20, 0, 0},
    {0x300C, 287, 45, 12, 1, 0, 4, 8, 17, 0, 0}, {0x30D5, 296, 45, 1, 2, 2, 1, 18, 18, 0, 0},
    {0x30A9, 315, 45, 2, 2, 3, 1, 17, 17, 0, 0}, {0x30C3, 333, 45, 2, 3, 4, 1, 16, 16, 0, 0},
    {0x30A2, 350, 45, 1, 1, 2, 1, 19, 18, 0, 0}, {0x30C9, 370, 45, 3, 1, 1, 1, 17, 19, 0, 0},
    {0x30D9, 388, 45, 0, 0, 1, 2, 21, 18, 0, 0}, {0x30C1, 410, 45, 0, 1, 1, 1, 20, 19, 0, 0},
    {0x30E3, 431, 45, 1, 2, 3, 1, 18, 17, 0, 0}, {0x300D, 450, 45, 0, 13, 3, 0, 8, 18, 0, 0},
    {0x30BB, 459, 45, 0, 2, 1, 2, 19, 18, 0, 0}, {0x30C8, 479, 45, 3, 2, 1, 1, 16, 19, 0, 0},
    {0x3053, 1, 67, 1, 2, 3, 2, 18, 16, 0, 0},   {0x3042, 20, 67, 1, 2, 0, 1, 18, 20, 0, 0},
    {0x308A, 39, 67, 3, 3, 1, 1, 15, 19, 0, 0},  {0x3000, 55, 67, 21, 0, 21, 0, 0, 0, 0, 0},
    {0x30ED, 56, 67, 1, 2, 2, 2, 18, 17, 0, 0},  {0x4E2D, 75, 67, 1, 2, 0, 0, 18, 21, 0, 0},
    {0x2026, 94, 67, 1, 2, 8, 9, 18, 4, 0, 0},
};

/* Japanese disc-status message lines (UTF-8 encoded). */
/* "An error has occurred." */
char sJpDiscErrorOccurredLine[0x24] =
    "\xe3\x82\xa8\xe3\x83\xa9\xe3\x83\xbc\xe3\x81\x8c\xe7\x99\xba\xe7\x94\x9f\xe3\x81\x97\xe3\x81"
    "\xbe\xe3\x81\x97\xe3\x81\x9f\xe3\x80\x82\x20";
/* "(press) the unit's POWER Button" */
char sJpDiscErrorPowerButtonLine[0x20] =
    "\xe6\x9c\xac\xe4\xbd\x93\xe3\x81\xae\xe3\x83\x91\xe3\x83\xaf\xe3\x83\xbc\xe3\x83\x9c\xe3\x82"
    "\xbf\xe3\x83\xb3\xe3\x82\x92";
/* "to turn the power OFF, and" */
char sJpDiscErrorPowerOffLine[0x1c] =
    "\xe6\x8a\xbc\xe3\x81\x97\xe3\x81\xa6\xe9\x9b\xbb\xe6\xba\x90\xe3\x82\x92\x4f\x46\x46\xe3\x81\xab\xe3\x81\x97";
/* "(refer to) the unit's Instruction Booklet" */
char sJpDiscErrorInstructionBookletLine[0x1c] =
    "\xe6\x9c\xac\xe4\xbd\x93\xe3\x81\xae\xe5\x8f\x96\xe6\x89\xb1\xe8\xaa\xac\xe6\x98\x8e\xe6\x9b\xb8\xe3\x81\xae";
/* "and follow its instructions." */
char sJpDiscErrorFollowInstructionsLine[0x20] =
    "\xe6\x8c\x87\xe7\xa4\xba\xe3\x81\xab\xe5\xbe\x93\xe3\x81\xa3\xe3\x81\xa6\xe4\xb8\x8b\xe3\x81"
    "\x95\xe3\x81\x84\xe3\x80\x82";

char* sJpDiscErrorOccurredMessageLines[] = {
    sJpDiscErrorTopSpacerLine,    sJpDiscErrorOccurredLine,           sJpDiscErrorPowerButtonLine,
    sJpDiscErrorPowerOffLine,     sJpDiscErrorInstructionBookletLine, sJpDiscErrorFollowInstructionsLine,
    sJpDiscErrorBottomSpacerLine,
};

/* "The Game Disc could not be read." */
char sJpDiscReadErrorLine[0x2c] =
    "\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xb9\xe3\x82\xaf\xe3\x82\x92\xe8\xaa\xad\xe3\x82\x81\xe3\x81"
    "\xbe\xe3\x81\x9b\xe3\x82\x93\xe3\x81\xa7\xe3\x81\x97\xe3\x81\x9f\xe3\x80\x82";
/* "For details, (see) the unit's Instruction Booklet" */
char sJpDiscReadErrorInstructionBookletLine[0x2c] =
    "\xe3\x81\x8f\xe3\x82\x8f\xe3\x81\x97\xe3\x81\x8f\xe3\x81\xaf\xe6\x9c\xac\xe4\xbd\x93\xe3\x81"
    "\xae\xe5\x8f\x96\xe6\x89\xb1\xe8\xaa\xac\xe6\x98\x8e\xe6\x9b\xb8\xe3\x82\x92";
/* "please read it." */
char sJpDiscReadErrorPleaseReadLine[0x18] =
    "\xe3\x81\x8a\xe8\xaa\xad\xe3\x81\xbf\xe4\xb8\x8b\xe3\x81\x95\xe3\x81\x84\xe3\x80\x82";

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
char sJpDiscCoverIsOpenLine[0x18] =
    "\xe9\x96\x8b\xe3\x81\x84\xe3\x81\xa6\xe3\x81\x84\xe3\x81\xbe\xe3\x81\x99\xe3\x80\x82";
/* "To continue the game," */
char sJpDiscCoverContinuePromptLine[0x20] =
    "\xe3\x82\xb2\xe3\x83\xbc\xe3\x83\xa0\xe3\x82\x92\xe7\xb6\x9a\xe3\x81\x91\xe3\x82\x8b\xe5\xa0"
    "\xb4\xe5\x90\x88\xe3\x81\xaf";
/* "the Disc Cover" */
char sJpDiscCoverCloseTargetLine[0x1c] =
    "\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xb9\xe3\x82\xaf\xe3\x82\xab\xe3\x83\x90\xe3\x83\xbc\xe3\x82\x92";
/* "please close." */
char sJpDiscCoverClosePromptLine[0x18] =
    "\xe9\x96\x89\xe3\x82\x81\xe3\x81\xa6\xe4\xb8\x8b\xe3\x81\x95\xe3\x81\x84\xe3\x80\x82";

char* sJpDiscCoverOpenMessageLines[] = {
    sJpDiscCoverOpenTopSpacerLine, sJpDiscCoverLine,
    sJpDiscCoverIsOpenLine,        sJpDiscCoverContinuePromptLine,
    sJpDiscCoverCloseTargetLine,   sJpDiscCoverClosePromptLine,
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
    sJpDiscInsertTopSpacerLine, sJpDiscInsertGameNameLine, sJpDiscInsertGameSubtitleLine,
    sJpDiscInsertGameDiscLine,  sJpDiscInsertPromptLine,   sJpDiscInsertBottomSpacerLine,
};

/* "This disc is" */
char sJpWrongDiscThisIsNotLine[0x18] =
    "\xe3\x81\x93\xe3\x81\xae\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xb9\xe3\x82\xaf\xe3\x81\xaf";
/* "Star Fox" */
char sJpWrongDiscGameNameLine[0x1c] =
    "\xe3\x82\xb9\xe3\x82\xbf\xe3\x83\xbc\xe3\x83\x95\xe3\x82\xa9\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9";
/* "Adventure's" */
char sJpWrongDiscGameSubtitleLine[0x1c] =
    "\xe3\x82\xa2\xe3\x83\x89\xe3\x83\x99\xe3\x83\xb3\xe3\x83\x81\xe3\x83\xa3\xe3\x83\xbc\xe3\x81\xae";
/* "not the disc." */
char sJpWrongDiscNotGameDiscLine[0x28] =
    "\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xb9\xe3\x82\xaf\xe3\x81\xa7\xe3\x81\xaf\xe3\x81\x82\xe3\x82"
    "\x8a\xe3\x81\xbe\xe3\x81\x9b\xe3\x82\x93\xe3\x80\x82";
/* "Star Fox" */
char sJpWrongDiscInsertGameNameLine[0x1c] =
    "\xe3\x82\xb9\xe3\x82\xbf\xe3\x83\xbc\xe3\x83\x95\xe3\x82\xa9\xe3\x83\x83\xe3\x82\xaf\xe3\x82\xb9";
/* "Adventure's" */
char sJpWrongDiscInsertGameSubtitleLine[0x1c] =
    "\xe3\x82\xa2\xe3\x83\x89\xe3\x83\x99\xe3\x83\xb3\xe3\x83\x81\xe3\x83\xa3\xe3\x83\xbc\xe3\x81\xae";
/* "please insert the disc." */
char sJpWrongDiscInsertPromptLine[0x2c] =
    "\xe3\x83\x87\xe3\x82\xa3\xe3\x82\xb9\xe3\x82\xaf\xe3\x82\x92\xe3\x82\xbb\xe3\x83\x83\xe3\x83"
    "\x88\xe3\x81\x97\xe3\x81\xa6\xe4\xb8\x8b\xe3\x81\x95\xe3\x81\x84\xe3\x80\x82";

char* sJpWrongDiscMessageLines[] = {
    sJpWrongDiscTopSpacerLine,      sJpWrongDiscThisIsNotLine,          sJpWrongDiscGameNameLine,
    sJpWrongDiscGameSubtitleLine,   sJpWrongDiscNotGameDiscLine,        sJpWrongDiscMiddleSpacerLine,
    sJpWrongDiscInsertGameNameLine, sJpWrongDiscInsertGameSubtitleLine, sJpWrongDiscInsertPromptLine,
};

/* Japanese disc-status messages, followed by the English glyph table. */
char sJpDiscLoadingMessage[] = "\xe3\x83\xad\xe3\x83\xbc\xe3\x83\x89\xe4\xb8\xad\xe2\x80\xa6";

GameTextDef sJpDiscStatusMessageTable[7] = {
    {0x339, 7, 0x81, 0, 0, 4, sJpDiscErrorOccurredMessageLines},
    {0x33a, 4, 0x81, 0, 0, 4, sJpDiscReadErrorMessageLines},
    {0x33b, 3, 0x81, 0, 0, 4, sJpDiscReadingMessageLines},
    {0x33c, 6, 0x81, 0, 0, 4, sJpDiscCoverOpenMessageLines},
    {0x33d, 6, 0x81, 0, 0, 4, sJpDiscInsertMessageLines},
    {0x33e, 9, 0x81, 0, 0, 4, sJpWrongDiscMessageLines},
    {0x565, 1, 0x93, 0, 0, 4, sJpDiscLoadingMessageLines},
};

TextGlyph sDiscStatusGlyphs[43] = {
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
    sWrongDiscThisIsNotLine, sWrongDiscGameNameLine,     sWrongDiscGameDiscLine,
    sWrongDiscSpacerLine,    sWrongDiscInsertPromptLine, sWrongDiscInsertGameDiscLine,
};

/* The English disc-status resource ("Loading..." plus the seven messages). */
char sDiscLoadingMessage[] = "Loading...";

GameTextDef sDiscStatusMessageTable[7] = {
    {0x339, 3, 0x81, 0, 0, 0, sDiscErrorOccurredMessageLines}, {0x33a, 3, 0x81, 0, 0, 0, sDiscReadErrorMessageLines},
    {0x33b, 1, 0x81, 0, 0, 0, sDiscReadingMessageLines},       {0x33c, 4, 0x81, 0, 0, 0, sDiscCoverOpenMessageLines},
    {0x33d, 2, 0x81, 0, 0, 0, sDiscInsertMessageLines},        {0x33e, 6, 0x81, 0, 0, 0, sWrongDiscMessageLines},
    {0x565, 1, 0x93, 0, 0, 0, sDiscLoadingMessageLines},
};

/* Dino-language glyph substitution order (see translateToDinoLanguage). */
u8 sGameTextGlyphOrder[0x1b] = "urstovwxazbcmdefghtkilnpoq";

static inline int ctrlCharLen(u32 c);

static inline TextGlyph* findGlyph(u32 ch, int glyphLang);

static inline void gameTextSelectFallbackBuffer(void);

TextFont* gameTextFonts;
int gameTextCharset;
int curLanguage;
int gGameTextLastLanguage;
int curGameTextDir;
int gGameTextLastDir;
int lbl_803DC9D4;
int lbl_803DC9D0;
void* gCurTextBox;
int lbl_803DC9C8;
char* gGameTextCommandStringCursor;
int gGameTextRenderingById;
int gGameTextMeasureOnly;
int gGameTextBoundsMinY;
int gGameTextBoundsMaxY;
int gGameTextBoundsMinX;
int gGameTextBoundsMaxX;
u16 gGameTextCursorX;
u16 gGameTextCursorY;
u8 gGameTextColorR;
u8 gGameTextColorG;
u8 gGameTextColorB;
u8 gGameTextColorA;
f32 gGameTextScale;
int gGameTextRevealActive;
int gGameTextDrawnCharIndex;
f32 gGameTextRevealProgress;
u8 gGameTextShadowColorR;
u8 gGameTextShadowColorG;
u8 gGameTextShadowColorB;
int gGameTextShadowOffsetX;
int gGameTextShadowOffsetY;
int gGameTextShadowEnabled;
u8 lbl_803DC980;
int gGameTextBufferIndex;
char* gCurTextBuffer;
GameTextDef* gGameTextLastEntry;
f32* gGameTextFallbackRequestDelta;
GameTextDrawFunc gameTextDrawFunc;
u8 gGameTextFontIsSjis;

SubtitleCmd* subtitleParseControlCmds(char* str, int* count);

typedef struct GameTextGlyphTable {
    int count;
    TextGlyph glyphs[];
} GameTextGlyphTable;
STATIC_ASSERT(sizeof(GameTextGlyphTable) == 4);
STATIC_ASSERT(offsetof(GameTextGlyphTable, glyphs) == 4);

typedef struct GameTextTableHeader {
    u16 entryCount;
    u16 stringDataSize;
} GameTextTableHeader;
STATIC_ASSERT(sizeof(GameTextTableHeader) == 4);
STATIC_ASSERT(offsetof(GameTextTableHeader, stringDataSize) == 2);

typedef struct GameTextStringTable {
    int count;
    int offsets[];
} GameTextStringTable;

typedef struct GameTextTextureHeader {
    u16 format;
    u16 bitsPerPixel;
    u16 width;
    u16 height;
} GameTextTextureHeader;
STATIC_ASSERT(sizeof(GameTextTextureHeader) == 8);
STATIC_ASSERT(offsetof(GameTextTextureHeader, bitsPerPixel) == 2);
STATIC_ASSERT(offsetof(GameTextTextureHeader, width) == 4);
STATIC_ASSERT(offsetof(GameTextTextureHeader, height) == 6);

typedef struct GameTextDiscDef {
    u16 identifier;
    u16 count;
    u8 boxId;
    u8 alignH;
    u8 alignV;
    u8 language;
    s32 strings;
} GameTextDiscDef;
STATIC_ASSERT(sizeof(GameTextDiscDef) == 0xc);

static void gameTextLoadCancelCallback(s32 result, DVDCommandBlock* block);
static void gameTextLoadCompleteCallback(s32 status, DVDFileInfo* fileInfo);

int gameTextGetState(int i);

static inline GameTextLoadSlot* gameTextFindFreeLoadSlot(void);

static inline u32 lookupSjisGlyph(int c);

/* Install a completed language/charset load, upload its textures, and compact
   the relocatable text tables. */
void gameTextFinalizeLoad(GameTextLoadSlot* loadSlot);

GameTextLoadSlot curGameTexts[GAMETEXT_LOAD_SLOT_COUNT];
TextFont gGameTextCharsets[GAMETEXT_PENDING_SOURCE_COUNT];
GameTextSlot gGameTextCommandSlots[0xA00 / sizeof(GameTextSlot)];
char sGameTextCommandStringBuffer[0x800];
char sGameTextPath[0x40];
SubtitleCmd sSubtitleCtrlCmdScratch[SUBTITLE_CONTROL_COMMAND_COUNT];
char sGameTextFallbackBuffers[GAMETEXT_FALLBACK_COUNT][GAMETEXT_FALLBACK_BUFFER_SIZE];
char* sGameTextFallbackStrings[GAMETEXT_FALLBACK_COUNT];
GameTextDef sGameTextFallbackDefs[GAMETEXT_FALLBACK_COUNT];
f32 sGameTextFallbackRequestDelta[GAMETEXT_FALLBACK_COUNT];
f32 sGameTextFallbackElapsedFrames[GAMETEXT_FALLBACK_COUNT];

int gameTextSaveDir(int x) {
    if (gGameTextSequenceMode == 0) {
        gGameTextSavedDir = x;
        return 1;
    }
    return 0;
}

void gameTextSetDrawFunc(void* fn) {
    gameTextDrawFunc = fn;
}

static void gameTextLoadCompleteCallback(s32 status, DVDFileInfo* fileInfo) {
    int i;
    GameTextLoadSlot* slot = curGameTexts;
    if (status != -1 && status != -3) {
        for (i = 8; i != 0; i--) {
            if (fileInfo == &slot->fileInfo) {
                slot->state = 2;
                return;
            }
            slot++;
        }
    } else {
        slot = curGameTexts;
        for (i = 8; i != 0; i--) {
            if (fileInfo == &slot->fileInfo) {
                slot->state = 5;
                return;
            }
            slot++;
        }
    }
}

static void gameTextLoadCancelCallback(s32 result, DVDCommandBlock* block) {
    int i;
    GameTextLoadSlot* slot = curGameTexts;
    (void)result;
    for (i = 8; i != 0; i--) {
        if (block == &slot->fileInfo.cb) {
            slot->state = 5;
            return;
        }
        slot++;
    }
}

void gameTextFinalizeLoad(GameTextLoadSlot* loadSlot) {
    int textureIndex;
    u16* loadedResource;
    u32 bitsPerPixel;
    int stringDataSize;
    GameTextStringTable* stringTable;
    u32 width;
    u32 height;
    int i;
    u8* stringData;
    int* paddingBlock;
    GameTextTableHeader* tableHeader;
    u16* textureDataStart;
    GameTextGlyphTable* resource;
    u16 textureFormat;
    GameTextDef* definitions;
    int stringCount;
    int* stringPointers;
    TextFont* charset;
    u32 tableBytes;
    u16* compactedResource;
    u16* textureCursor;
    int relocationDelta;
    int* relocatedStringPointers;
    int remainingUnits;

    DCStoreRange(loadSlot->loadHandle, loadSlot->loadedSize);
    if (loadSlot->sourceId == GAMETEXT_SLOT_CUTSCENE) {
        charset = &gGameTextCharsets[GAMETEXT_SLOT_CUTSCENE];
    } else if (loadSlot->sourceId == GAMETEXT_SLOT_HUD) {
        charset = &gGameTextCharsets[GAMETEXT_SLOT_HUD];
    } else {
        charset = &gGameTextCharsets[GAMETEXT_SLOT_DIALOGUE];
        curGameTextDir = loadSlot->dirId;
        curLanguage = loadSlot->languageId;
    }
    resource = loadSlot->loadHandle;
    charset->glyphCount = resource->count;
    if (charset->glyphCount == 0) {
        charset->status = 3;
        loadSlot->state = 6;
        return;
    }
    charset->glyphs = resource->glyphs;
    tableHeader = (GameTextTableHeader*)((char*)(resource + 1) + charset->glyphCount * sizeof(TextGlyph));
    charset->entryCount = tableHeader->entryCount;
    stringDataSize = tableHeader->stringDataSize;
    definitions = (GameTextDef*)(tableHeader + 1);
    charset->entries = definitions;
    stringTable = (GameTextStringTable*)(definitions + charset->entryCount);
    stringCount = stringTable->count;
    stringPointers = stringTable->offsets;
    for (i = 0; i < charset->entryCount; i++) {
        charset->entries[i].strings = (char**)(stringPointers + (int)charset->entries[i].strings);
    }
    stringData = (u8*)stringTable + (stringCount * sizeof(*stringPointers) + sizeof(*stringTable));
    {
        int j;
        for (j = 0; j < stringCount; j++) {
            stringPointers[j] = stringPointers[j] + (int)stringData;
        }
    }
    paddingBlock = (int*)(stringData + stringDataSize);
    textureCursor = (u16*)((u8*)paddingBlock + paddingBlock[0]);
    textureCursor += 2;
    textureDataStart = textureCursor;
    textureIndex = 0;
    while (1) {
        GameTextTextureHeader* textureHeader = (GameTextTextureHeader*)textureCursor;
        textureFormat = textureHeader->format;
        bitsPerPixel = textureHeader->bitsPerPixel;
        width = textureHeader->width;
        height = textureHeader->height;
        textureCursor = (u16*)(textureHeader + 1);
        if (width == 0 && height == 0) {
            break;
        }
        switch (textureFormat) {
        case 1:
            textureFormat = GX_TF_RGB5A3;
            break;
        case 2:
            textureFormat = GX_TF_I4;
            break;
        }
        if (charset->textures[textureIndex] != NULL) {
            mmSetFreeDelay(0);
            mm_free(charset->textures[textureIndex]);
            mmSetFreeDelay(2);
        }
        charset->textures[textureIndex] = textureAlloc(width, height, textureFormat, 0, 0, 0, 0, 1, 1);
        if (charset->textures[textureIndex] != NULL) {
            if (bitsPerPixel == 4) {
                u8* src8 = (u8*)textureCursor;
                u8* dst8 = textureGetImageData(charset->textures[textureIndex]);
                remainingUnits = (int)(width * height) >> 1;
                while (remainingUnits--) {
                    *dst8++ = *src8++;
                }
                DCFlushRange(textureGetImageData(charset->textures[textureIndex]),
                             charset->textures[textureIndex]->dataSize);
            } else {
                u16* src16 = textureCursor;
                u16* dst16 = textureGetImageData(charset->textures[textureIndex]);
                remainingUnits = width * height;
                while (remainingUnits--) {
                    *dst16++ = *src16++;
                }
                DCFlushRange(textureGetImageData(charset->textures[textureIndex]),
                             charset->textures[textureIndex]->dataSize);
            }
        }
        {
            u32 area = width * height;
            textureCursor += (int)(area * bitsPerPixel) >> 4;
        }
        textureIndex++;
    }
    tableBytes = (u32)((u8*)textureDataStart - (u8*)loadSlot->loadHandle);
    compactedResource = mmAlloc(tableBytes, 0x1a, 0);
    remainingUnits = tableBytes >> 1;
    {
        u16* destination = compactedResource;
        u16* source;
        loadedResource = loadSlot->loadHandle;
        source = loadedResource;
        relocationDelta = (u8*)compactedResource - (u8*)loadedResource;
        while (remainingUnits--) {
            *destination++ = *source++;
        }
    }
    charset->glyphs = (TextGlyph*)((u8*)charset->glyphs + relocationDelta);
    charset->entries = (GameTextDef*)((u8*)charset->entries + relocationDelta);
    for (i = 0; i < charset->entryCount; i++) {
        int phrasePointers = (int)charset->entries[i].strings;
        charset->entries[i].strings = (char**)(phrasePointers + relocationDelta);
    }
    relocatedStringPointers = (int*)((u8*)stringPointers + relocationDelta);
    for (i = 0; i < stringCount; i++) {
        relocatedStringPointers[i] += relocationDelta;
    }
    mmSetFreeDelay(0);
    mm_free(loadSlot->loadHandle);
    loadSlot->loadHandle = NULL;
    mmSetFreeDelay(2);
    loadSlot->loadHandle = compactedResource;
    charset->status = 2;
    loadSlot->state = 3;
}

void gameTextBuildSystemFontAtlas(void) {
    int glyphWidthTiles;
    int glyphCount;
    FontMetrics* fontMetrics;
    TextFont* charset;
    u8* glyphImage;
    int compressedFontSize;
    int atlasY;
    int fontDataSize;
    int atlasX;
    u8* compressedFont;
    OSFontHeader* fontData;
    int previousHeapOverride;
    int remainingGlyphs;
    TextGlyph* glyph;
    u8 encodedChar[3];
    s32 glyphWidth;

    fontMetrics = gGameTextFontMetrics;
    charset = &gGameTextCharsets[GAMETEXT_SLOT_ERROR];
    previousHeapOverride = mmSetForceHeap3Only(0);
    glyphImage = mmAlloc(0x120, 0x1a, 0);
    switch (OSGetFontEncode()) {
    case OS_FONT_ENCODE_ANSI:
        compressedFontSize = OS_FONT_ROM_SIZE_ANSI;
        fontDataSize = 0x10120;
        curLanguage = LANGUAGE_ENGLISH;
        gGameTextFontIsSjis = 0;
        break;
    case OS_FONT_ENCODE_SJIS:
        compressedFontSize = OS_FONT_ROM_SIZE_SJIS;
        fontDataSize = 0x90ee4;
        curLanguage = LANGUAGE_JAPANESE;
        gGameTextFontIsSjis = 1;
        break;
    }
    compressedFont = mmAlloc(compressedFontSize, 0x1a, 0);
    fontData = mmAlloc(fontDataSize, 0x1a, 0);
    OSLoadFont(fontData, compressedFont);
    if (charset->glyphCount == 0) {
        if (gGameTextFontIsSjis) {
            charset->glyphs = sJpDiscStatusGlyphs;
            charset->glyphCount = ARRAY_COUNT(sJpDiscStatusGlyphs);
            charset->entries = sJpDiscStatusMessageTable;
            charset->entryCount = ARRAY_COUNT(sJpDiscStatusMessageTable);
        } else {
            charset->glyphs = sDiscStatusGlyphs;
            charset->glyphCount = ARRAY_COUNT(sDiscStatusGlyphs);
            charset->entries = sDiscStatusMessageTable;
            charset->entryCount = ARRAY_COUNT(sDiscStatusMessageTable);
        }
    }
    charset->textures[0] = textureAlloc(0x200, 0x60, GX_TF_I4, 0, 0, 0, 0, 1, 1);
    glyphCount = charset->glyphCount;
    fontMetrics[GAMETEXT_FONT_SYSTEM].glyphCount = glyphCount;
    fontMetrics[GAMETEXT_FONT_SYSTEM].unk04 = 0x30;
    fontMetrics[GAMETEXT_FONT_SYSTEM].unk05 = 0x20;
    fontMetrics[GAMETEXT_FONT_SYSTEM].maxWidth = 0;
    fontMetrics[GAMETEXT_FONT_SYSTEM].lineHeight = 0x18;
    remainingGlyphs = glyphCount;
    glyph = charset->glyphs;
    atlasX = 0;
    atlasY = 0;
    while (remainingGlyphs--) {
        if (gGameTextFontIsSjis) {
            int codePoint;
            u32 sjisCode;
            int leadByte;
            u8 trailByte;
            codePoint = glyph->key;
            sjisCode = lookupSjisGlyph(codePoint);
            leadByte = (sjisCode >> 8) & 0xff;
            trailByte = sjisCode;
            if (leadByte == 0) {
                encodedChar[0] = trailByte;
                encodedChar[1] = 0;
            } else {
                encodedChar[0] = leadByte;
                encodedChar[1] = trailByte;
                encodedChar[2] = 0;
            }
        } else {
            encodedChar[0] = glyph->key;
            encodedChar[1] = 0;
        }
        OSGetFontWidth((const char*)encodedChar, &glyphWidth);
        if (glyphWidth > fontMetrics[GAMETEXT_FONT_SYSTEM].maxWidth) {
            fontMetrics[GAMETEXT_FONT_SYSTEM].maxWidth = glyphWidth;
        }
        glyphWidthTiles = glyphWidth >> 3;
        if ((glyphWidth & 7) != 0) {
            glyphWidthTiles++;
        }
        {
            int remainingWords;
            u32* clearWord = (u32*)glyphImage;
            remainingWords = 0x48;
            while (remainingWords--) {
                *clearWord++ = 0;
            }
        }
        OSGetFontTexel((const char*)encodedChar, glyphImage, 0, 6, &glyphWidth);
        if (atlasX + 0x18 > 0x200) {
            atlasX = 0;
            atlasY += 0x18;
        }
        glyph->u = atlasX;
        glyph->v = atlasY;
        glyph->offsetX = 0;
        glyph->advanceX = 0;
        glyph->offsetY = 0;
        glyph->advanceY = 0;
        glyph->width = glyphWidth;
        glyph->height = 0x18;
        glyph->font = GAMETEXT_FONT_SYSTEM;
        glyph->page = 0;
        {
            int firstTileRow;
            int tileRowEnd;
            int firstTileColumn;
            int tileColumnEnd;
            int tileRow;
            u8* tileDestination;
            u32* glyphPixels;
            int tileColumn;

            glyphPixels = (u32*)glyphImage;
            firstTileRow = glyph->v >> 3;
            firstTileColumn = glyph->u >> 3;
            tileRow = firstTileRow;
            tileColumnEnd = firstTileColumn + 3;
            tileRowEnd = firstTileRow + 3;
            for (; tileRow < tileRowEnd; tileRow++) {
                for (tileColumn = firstTileColumn; tileColumn < tileColumnEnd; tileColumn++) {
                    int wordIndex;
                    tileDestination = (u8*)charset->textures[0] + (tileColumn << 5);
                    tileDestination += gGameTextFontTexRowPitch * tileRow;
                    for (wordIndex = 0; wordIndex < 8; wordIndex++) {
                        *(u32*)(tileDestination + sizeof(Texture) + wordIndex * 4) = *glyphPixels++;
                    }
                }
            }
        }
        atlasX += glyphWidthTiles << 3;
        glyph++;
    }
    DCFlushRange(textureGetImageData(charset->textures[0]), 0x20000);
    mm_free(compressedFont);
    mm_free(fontData);
    mm_free(glyphImage);
    mmSetForceHeap3Only(previousHeapOverride);
    charset->status = 2;
}

void gameTextLoadForCurMap(int sourceId) {
    u8* dirPtr;
    u8* langPtr;
    int oldHeap;
    int dirId;
    int languageId;
    GameTextLoadSlot* slot;
    GameTextLoadSlot* freeSlot;
    int i;

    oldHeap = mmSetForceHeap3Only(0);
    if (getGameState() != 0 && getGameState() != 1) {
        mmSetForceHeap3Only(oldHeap);
        return;
    }

    gGameTextLastDir = dirId = curGameTextDir;
    gGameTextLastLanguage = languageId = curLanguage;
    if (dirId < 0 || dirId >= GAMETEXT_MAP_DIR_COUNT || languageId < 0 || languageId >= GAMETEXT_LANGUAGE_COUNT) {
        mmSetForceHeap3Only(oldHeap);
        return;
    }

    slot = curGameTexts;
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do {
        if (slot->sourceId == sourceId) {
            if (slot->state == 1) {
                slot->state = 4;
                DVDCancelAsync(&slot->fileInfo.cb, gameTextLoadCancelCallback);
            }
            if (slot->state == 3 && slot->active != 0) {
                mmSetFreeDelay(0);
                if (slot->loadHandle != NULL) {
                    mm_free(slot->loadHandle);
                }
                mmSetFreeDelay(2);
                slot->loadHandle = NULL;
                slot->loadedSize = 0;
                slot->active = 0;
            }
        }
        slot++;
    } while (i-- != 0);

    gGameTextCharsets[sourceId].status = 1;
    *(dirPtr = &gGameTextCharsets[sourceId].dirId) = (u8)curGameTextDir;
    *(langPtr = &gGameTextCharsets[sourceId].languageId) = curLanguage;

    freeSlot = gameTextFindFreeLoadSlot();

    if (freeSlot != NULL) {
        int slotDir = *dirPtr;
        int slotLang = *langPtr;
        freeSlot->state = 1;
        freeSlot->dirId = slotDir;
        freeSlot->languageId = slotLang;
        freeSlot->active = 1;
        freeSlot->sourceId = sourceId;
        sprintf(sGameTextPath, "gametext/%s/%s.bin", sMapDirectoryNameTable[slotDir],
                sLanguageNameTable[slotLang].name);
        setFileInfo(&freeSlot->fileInfo);
        freeSlot->loadHandle =
            loadFileByPathAsync(sGameTextPath, &freeSlot->loadedSize, 1, gameTextLoadCompleteCallback);
        setFileInfo(NULL);
        *dirPtr = GAMETEXT_INVALID_DIR;
        *langPtr = GAMETEXT_INVALID_LANGUAGE;
    }

    mmSetForceHeap3Only(oldHeap);
}

void loadGameTextSequence(int sequenceSlotDir, int sequenceId) {
    GameTextLoadSlot* slot;
    int oldHeap;
    LanguageName* language;
    int i;

    language = &sLanguageNameTable[curLanguage];
    oldHeap = mmSetForceHeap3Only(0);
    if (getGameState() != 0 && getGameState() != 1) {
        mmSetForceHeap3Only(oldHeap);
        return;
    }

    lbl_803DC9D0 = lbl_803DC9D4;
    if (curLanguage < 0 || curLanguage >= 6) {
        mmSetForceHeap3Only(oldHeap);
        return;
    }

    slot = curGameTexts;
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do {
        if (slot->sourceId == GAMETEXT_SEQUENCE_SOURCE_ID) {
            if (slot->state == 1) {
                slot->state = 4;
                DVDCancelAsync(&slot->fileInfo.cb, gameTextLoadCancelCallback);
            }
            if (slot->state == 3 && slot->active != 0) {
                mmSetFreeDelay(0);
                mm_free(slot->loadHandle);
                mmSetFreeDelay(2);
                slot->loadHandle = NULL;
                slot->loadedSize = 0;
                slot->active = 0;
            }
        }
        slot++;
    } while (i-- != 0);

    gGameTextCharsets[GAMETEXT_SLOT_CUTSCENE].status = 1;
    slot = gameTextFindFreeLoadSlot();

    slot->state = 1;
    slot->dirId = sequenceSlotDir;
    slot->languageId = curLanguage;
    slot->active = 1;
    slot->sourceId = GAMETEXT_SEQUENCE_SOURCE_ID;
    sprintf(sGameTextPath, "gametext/Sequences/%d_%s.bin", sequenceId, language->name);
    setFileInfo(&slot->fileInfo);
    slot->loadHandle = loadFileByPathAsync(sGameTextPath, &slot->loadedSize, 1, gameTextLoadCompleteCallback);
    setFileInfo(NULL);
    mmSetForceHeap3Only(oldHeap);
}

static inline void gameTextResetFont(TextFont* font) {
    int i;
    font->glyphCount = 0;
    font->entryCount = 0;
    font->glyphs = NULL;
    font->entries = NULL;
    font->status = 0;
    font->timer = 0.0f;
    font->dirId = GAMETEXT_INVALID_DIR;
    font->languageId = GAMETEXT_INVALID_LANGUAGE;
    for (i = ARRAY_COUNT(font->textures); i-- != 0;) {
        font->textures[i] = NULL;
    }
}

void gameTextInitRendererState(void) {
    int fallbackCount;
    int i;
    int j;

    for (i = GAMETEXT_BOX_COUNT; i-- != 0;) {
        gTextBoxes[i].width = gTextBoxes[i].maxWidth;
        gTextBoxes[i].height = gTextBoxes[i].maxHeight;
    }

    for (fallbackCount = GAMETEXT_FALLBACK_COUNT; fallbackCount-- != 0;) {
        sGameTextFallbackStrings[fallbackCount] = sGameTextFallbackBuffers[fallbackCount];
        sGameTextFallbackDefs[fallbackCount].identifier = 0xffff;
        sGameTextFallbackDefs[fallbackCount].count = 1;
        sGameTextFallbackDefs[fallbackCount].boxId = 0xff;
        sGameTextFallbackDefs[fallbackCount].alignH = 0;
        sGameTextFallbackDefs[fallbackCount].alignV = 0;
        sGameTextFallbackDefs[fallbackCount].language = 0;
        sGameTextFallbackDefs[fallbackCount].strings = &sGameTextFallbackStrings[fallbackCount];
    }

    for (i = GAMETEXT_BOX_COUNT; i-- != 0;) {
        gTextBoxes[i].alpha = 0xff;
    }

    for (j = GAMETEXT_PENDING_SOURCE_COUNT; j-- != 0;) {
        gameTextResetFont(&gGameTextCharsets[j]);
    }

    gameTextFonts = &gGameTextCharsets[GAMETEXT_SLOT_ERROR];
    gameTextCharset = 2;
    curLanguage = -1;
    curGameTextDir = -1;
    gCurTextBox = NULL;
    gGameTextLastLanguage = -1;
    gGameTextLastDir = -1;
    gGameTextMeasureOnly = 0;
    gGameTextColorR = 0xff;
    gGameTextColorG = 0xff;
    gGameTextColorB = 0xff;
    gGameTextColorA = 0xff;
    gGameTextCommandCount = 0;
    gGameTextCommandStringCursor = sGameTextCommandStringBuffer;
    gGameTextBufferIndex = 0;
    gGameTextLastEntry = sGameTextFallbackDefs;
    gCurTextBuffer = *gGameTextLastEntry->strings;
    gGameTextShadowColorR = 0;
    gGameTextShadowColorG = 0;
    gGameTextShadowColorB = 0;
    gGameTextShadowOffsetX = 5;
    gGameTextShadowOffsetY = 5;
    gGameTextShadowEnabled = 1;
    lbl_803DC980 = 0;
    gameTextBuildSystemFontAtlas();
    curGameTextDir = 3;
    gGameTextStringStore = (void*)mmCreateMemoryStore(0x800);
}

void gameTextInit(void) {
    gameTextInitBoxTextures();
    lbl_803DC980 = 1;
    gameTextLoadDir(0x1c);
}

static inline u32 lookupSjisGlyph(int c) {
    int i = 0xfe;
    u16* p = gGameTextSjisGlyphTable;
    while (i--) {
        if (p[0] == c) {
            return p[1];
        }
        p++;
    }
    return 0;
}

static inline void gameTextSelectCharset(int charset) {
    gameTextFonts = &gGameTextCharsets[charset];
    gameTextCharset = charset;
    if (charset == 2) {
        GXColor color = gGameTextClearColor;
        hudDrawRect(0, 0, 0xa00, 0x780, color);
        gGameTextRevealActive = 0;
    }
}

static inline void gameTextApplyWindowPosition(int index, int x, int y) {
    gTextBoxes[index].cursorX = x;
    gTextBoxes[index].cursorY = y;
}

void gameTextRun(void) {
    GameTextLoadSlot* loadSlot;
    TextFont* pending;
    int sourceId;
    GameTextSlot* cmd;
    int i;
    GameTextLoadSlot* freeSlot;
    int dirId;
    int languageId;
    GameTextBox* textBox;
    f32 fadeLimit;
    f32 zero;

    cmd = gGameTextCommandSlots;

    loadSlot = curGameTexts;
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do {
        if (loadSlot->state == 2) {
            gameTextFinalizeLoad(loadSlot);
        }
        loadSlot++;
    } while (i-- != 0);

    sourceId = 0;
    pending = gGameTextCharsets;
    do {
        if (pending->dirId != GAMETEXT_INVALID_DIR) {
            freeSlot = gameTextFindFreeLoadSlot();

            if (freeSlot != NULL) {
                dirId = pending->dirId;
                languageId = pending->languageId;
                freeSlot->state = 1;
                freeSlot->dirId = (u8)dirId;
                freeSlot->languageId = languageId;
                freeSlot->active = 1;
                freeSlot->sourceId = sourceId;
                sprintf(sGameTextPath, "gametext/%s/%s.bin", sMapDirectoryNameTable[dirId],
                        sLanguageNameTable[languageId].name);
                setFileInfo(&freeSlot->fileInfo);
                freeSlot->loadHandle =
                    loadFileByPathAsync(sGameTextPath, &freeSlot->loadedSize, 1, gameTextLoadCompleteCallback);
                setFileInfo(NULL);
                pending->dirId = GAMETEXT_INVALID_DIR;
                pending->languageId = GAMETEXT_INVALID_LANGUAGE;
            }
        }
        pending++;
        sourceId++;
    } while (sourceId < GAMETEXT_PENDING_SOURCE_COUNT);

    loadSlot = curGameTexts;
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do {
        if ((loadSlot->state == 5 || loadSlot->state == 6) && loadSlot->loadHandle != NULL) {
            mm_free(loadSlot->loadHandle);
            loadSlot->loadHandle = NULL;
            loadSlot->loadedSize = 0;
            loadSlot->active = 0;
        }
        loadSlot++;
    } while (i-- != 0);

    zero = 0.0f;
    fadeLimit = 120.0f;
    for (i = GAMETEXT_FALLBACK_COUNT; i-- != 0;) {
        if (sGameTextFallbackRequestDelta[i] > zero) {
            sGameTextFallbackElapsedFrames[i] += timeDelta;
            if (sGameTextFallbackElapsedFrames[i] > fadeLimit) {
                sGameTextFallbackRequestDelta[i] = zero;
                sGameTextFallbackElapsedFrames[i] = zero;
                sprintf(*sGameTextFallbackDefs[i].strings, sGameTextBlankFormat);
            }
        }
    }

    if (gameTextFonts->status == 1) {
        gameTextFonts->timer += timeDelta;
    } else {
        gameTextFonts->timer = 0.0f;
    }

    textBox = gTextBoxes;
    for (i = GAMETEXT_BOX_COUNT; i != 0; i--) {
        textBox->flags &= ~1;
        textBox++;
    }

    gGameTextRevealActive = 0;
    gGameTextCursorX = 0;
    gGameTextCursorY = 0;

    i = gGameTextCommandCount;
    while (i-- != 0) {
        switch (cmd->opcode) {
        case 3: {
            u8 c1, c2, c3;
            c3 = cmd->arg3;
            c2 = cmd->arg2;
            c1 = cmd->arg1;
            gGameTextColorR = cmd->arg0;
            gGameTextColorG = c1;
            gGameTextColorB = c2;
            gGameTextColorA = c3;
            break;
        }
        case GAMETEXT_COMMAND_SET_WINDOW_POSITION: {
            gameTextApplyWindowPosition(cmd->arg0, cmd->arg1, cmd->arg2);
            break;
        }
        case GAMETEXT_COMMAND_TICK_REVEAL:
            gameTextTickReveal(cmd->arg0, (struct TextDisplayState*)cmd->arg1);
            break;
        case GAMETEXT_COMMAND_RENDER_BY_ID:
            gameTextRenderById(cmd->arg0, cmd->arg1, cmd->arg2);
            break;
        case GAMETEXT_COMMAND_SHOW_TIME_STRING: {
            int strId = cmd->arg0;
            if (gCurTextBox != NULL) {
                gameTextRenderStrs((char*)strId, ((u8*)gCurTextBox - (u8*)gTextBoxes) / 0x20);
            }
            break;
        }
        case GAMETEXT_COMMAND_APPEND_STRING:
            gameTextRenderStrs((char*)cmd->arg0, cmd->arg1);
            break;
        case GAMETEXT_COMMAND_SHOW_STRING_AT: {
            int t3 = cmd->arg3;
            int t2 = cmd->arg1;
            int t1 = cmd->arg0;
            textBox = &gTextBoxes[t2];
            textBox->cursorX = cmd->arg2;
            textBox->cursorY = t3;
            gameTextRenderStrs((char*)t1, t2);
            break;
        }
        case GAMETEXT_COMMAND_SET_WINDOW:
            if (cmd->arg0 == 0xff) {
                gCurTextBox = NULL;
            } else {
                gCurTextBox = &gTextBoxes[cmd->arg0];
            }
            break;
        case 9:
            ((void (*)(void))cmd->arg0)();
            break;
        case 10: {
            u16 b1 = cmd->arg1;
            gGameTextCursorX = (u16)cmd->arg0;
            gGameTextCursorY = b1;
            break;
        }
        case 11:
            gGameTextCursorX = 0;
            gGameTextCursorY = 0;
            break;
        case 12:
            gGameTextShadowEnabled = cmd->arg0;
            break;
        case 14: {
            u8 e1, e2;
            e2 = cmd->arg2;
            e1 = cmd->arg1;
            gGameTextShadowColorR = cmd->arg0;
            gGameTextShadowColorG = e1;
            gGameTextShadowColorB = e2;
            break;
        }
        case GAMETEXT_COMMAND_SET_SHADOW_OFFSET: {
            int sy = cmd->arg1;
            gGameTextShadowOffsetX = cmd->arg0;
            gGameTextShadowOffsetY = sy;
            break;
        }
        case GAMETEXT_COMMAND_SET_CHARSET:
            gameTextSelectCharset(cmd->arg0);
            break;
        }
        cmd++;
    }

    if (gGameTextRevealActive == 0) {
        Sfx_StopFromObject(0, SFXTRIG_clock_loop);
    }
    gGameTextCommandCount = 0;
    gGameTextCommandStringCursor = sGameTextCommandStringBuffer;

    for (i = GAMETEXT_BOX_COUNT; i-- != 0;) {
        gTextBoxes[i].cursorX = 0;
        gTextBoxes[i].cursorY = 0;
    }
    gCurTextBox = NULL;
}

static inline GameTextLoadSlot* gameTextFindFreeLoadSlot(void) {
    GameTextLoadSlot* slot = curGameTexts;
    int i;

    for (i = GAMETEXT_LOAD_SLOT_COUNT; i-- != 0; slot++) {
        if (slot->active == 0) {
            return slot;
        }
    }
    return NULL;
}

int gameTextGetState(int i) {
    return gGameTextCharsets[i].status;
}

f32 gameTextGetTimer(void) {
    return gameTextFonts->timer;
}

int getCurLanguage(void) {
    return curLanguage;
}

int getCurGameText(void) {
    return curGameTextDir;
}

void gameTextSetCharset(int charset, int flags) {
    if (gameTextDrawFunc != NULL || (flags & 1)) {
        gameTextSelectCharset(charset);
    }
    if (gameTextDrawFunc == NULL || (flags & 2)) {
        int i = gGameTextCommandCount;
        GameTextSlot* cmd;
        gGameTextCommandCount = i + 1;
        cmd = &gGameTextCommandSlots[i];
        cmd->opcode = 0xf;
        cmd->arg0 = charset;
    }
}

int gameTextGetCharset(void) {
    return gameTextCharset;
}

void gameTextLoadDir(int dirId) {
    GameTextSlot* cmd;
    GXColor color;
    int slotIndex;

    gGameTextColorR = 0xff;
    gGameTextColorG = 0xff;
    gGameTextColorB = 0xff;
    gGameTextColorA = 0xff;

    if (dirId == 3) {
        gameTextFonts = &gGameTextCharsets[GAMETEXT_SLOT_ERROR];
        gameTextCharset = GAMETEXT_SLOT_ERROR;
        color = gGameTextClearColor;
        hudDrawRect(0, 0, 0xa00, 0x780, color);
        gGameTextRevealActive = 0;
        if (gameTextDrawFunc == NULL) {
            slotIndex = gGameTextCommandCount;
            gGameTextCommandCount = slotIndex + 1;
            cmd = &gGameTextCommandSlots[slotIndex];
            cmd->opcode = GAMETEXT_COMMAND_SET_CHARSET;
            cmd->arg0 = GAMETEXT_SLOT_ERROR;
        }
    } else if (dirId == 0x1c) {
        curGameTextDir = dirId;
        gameTextFonts = &gGameTextCharsets[GAMETEXT_SLOT_HUD];
        gameTextCharset = GAMETEXT_SLOT_HUD;
        if (gameTextDrawFunc == NULL) {
            slotIndex = gGameTextCommandCount;
            gGameTextCommandCount = slotIndex + 1;
            cmd = &gGameTextCommandSlots[slotIndex];
            cmd->opcode = GAMETEXT_COMMAND_SET_CHARSET;
            cmd->arg0 = GAMETEXT_SLOT_HUD;
        }
        gameTextLoadForCurMap(GAMETEXT_SLOT_HUD);
    } else {
        gameTextFonts = &gGameTextCharsets[GAMETEXT_SLOT_DIALOGUE];
        gameTextCharset = GAMETEXT_SLOT_DIALOGUE;
        if (gameTextDrawFunc == NULL) {
            slotIndex = gGameTextCommandCount;
            gGameTextCommandCount = slotIndex + 1;
            cmd = &gGameTextCommandSlots[slotIndex];
            cmd->opcode = GAMETEXT_COMMAND_SET_CHARSET;
            cmd->arg0 = GAMETEXT_SLOT_DIALOGUE;
        }
        curGameTextDir = dirId;
        if ((subtitleIsActive() == 0 || gameTextSaveDir(dirId) == 0) && curGameTextDir != gGameTextLastDir) {
            gameTextLoadForCurMap(GAMETEXT_SLOT_DIALOGUE);
        }
    }
}

/* Byte parameters retain the public int prototype through default argument promotion. */
void gameTextSetColor(r, g, b, a) u8 r, g, b, a;
{
    if (gameTextDrawFunc != NULL) {
        gGameTextColorR = r;
        gGameTextColorG = g;
        gGameTextColorB = b;
        gGameTextColorA = a;
    } else {
        int i = gGameTextCommandCount;
        GameTextSlot* cmd;
        gGameTextCommandCount = i + 1;
        cmd = &gGameTextCommandSlots[i];
        cmd->opcode = 3;
        cmd->arg0 = (u8)r;
        cmd->arg1 = (u8)g;
        cmd->arg2 = (u8)b;
        cmd->arg3 = (u8)a;
    }
}

void gameTextSetWindowStrPos(int idx, int x, int y) {
    if (gameTextDrawFunc != NULL) {
        gameTextApplyWindowPosition(idx, x, y);
    } else {
        int i = gGameTextCommandCount;
        GameTextSlot* cmd;
        gGameTextCommandCount = i + 1;
        cmd = &gGameTextCommandSlots[i];
        cmd->opcode = GAMETEXT_COMMAND_SET_WINDOW_POSITION;
        cmd->arg0 = idx;
        cmd->arg1 = x;
        cmd->arg2 = y;
    }
}

void gameTextSetCursor(u16 x, u16 y, int flags) {
    if (flags & 1) {
        gGameTextCursorX = x;
        gGameTextCursorY = y;
    }
    if (flags & 2) {
        int i = gGameTextCommandCount;
        GameTextSlot* cmd;
        gGameTextCommandCount = i + 1;
        cmd = &gGameTextCommandSlots[i];
        cmd->opcode = 0xa;
        cmd->arg0 = x;
        cmd->arg1 = y;
    }
}

void gameTextResetCursor(int flags) {
    if (flags & 1) {
        gGameTextCursorX = 0;
        gGameTextCursorY = 0;
    }
    if (flags & 2) {
        GameTextCommand* p = &gGameTextCommandSlots[gGameTextCommandCount++].opcode;
        *p = GAMETEXT_COMMAND_RESET_CURSOR;
    }
}

void* gameTextGet(int textId) {
    TextFont* fonts;
    GameTextDef* entry;
    int count;
    int slotIndex;
    GameTextDef* cachedEntry;
    f32 zero;
    f32* cachedRequestDelta;

    fonts = gameTextFonts;

    if (fonts->status != 2) {
        gameTextSelectFallbackBuffer();

        switch (gameTextFonts->status) {
        case 0:
            sprintf(gCurTextBuffer, "<uninitialised>");
            break;
        case 1:
            sprintf(gCurTextBuffer, "<loading>");
            break;
        case 3:
            sprintf(gCurTextBuffer, "<file empty!>");
            break;
        case 4:
            sprintf(gCurTextBuffer, "<no file!>");
            break;
        }
        return gGameTextLastEntry;
    }

    entry = fonts->entries;
    count = fonts->entryCount;
    while (count != 0) {
        if (entry->identifier == textId) {
            return entry;
        }
        entry++;
        count--;
    }

    slotIndex = GAMETEXT_FALLBACK_COUNT;
    cachedEntry = sGameTextFallbackDefs + GAMETEXT_FALLBACK_COUNT;
    while (cachedEntry--, slotIndex-- != 0) {
        if (cachedEntry->identifier == textId) {
            zero = sGameTextFallbackElapsedFrames[slotIndex] = 0.0f;
            cachedRequestDelta = &sGameTextFallbackRequestDelta[slotIndex];
            if (zero < 120.0f) {
                f32 requestDelta = zero + timeDelta;
                *cachedRequestDelta = requestDelta;
                if (requestDelta >= 120.0f) {
                    sprintf(*cachedEntry->strings, "<%d's not in %s>", textId, sMapDirectoryNameTable[curGameTextDir]);
                }
            }
            return cachedEntry;
        }
    }

    gameTextSelectFallbackBuffer();
    sprintf(gCurTextBuffer, sGameTextBlankFormat, textId, sMapDirectoryNameTable[curGameTextDir]);
    gGameTextLastEntry->identifier = textId;
    *gGameTextFallbackRequestDelta = 0.0f;
    return gGameTextLastEntry;
}

void* gameTextGetStr(int textId) {
    GameTextDef* textEntry;

    if (gameTextFonts->status != 2) {
        gameTextSelectFallbackBuffer();
        switch (gameTextFonts->status) {
        case 0:
            sprintf(gCurTextBuffer, "<uninitialised>");
            break;
        case 1:
            sprintf(gCurTextBuffer, "<loading>");
            break;
        case 3:
            sprintf(gCurTextBuffer, "<file empty!>");
            break;
        case 4:
            sprintf(gCurTextBuffer, "<no file!>");
            break;
        }
        return gGameTextLastEntry;
    }
    textEntry = gameTextGet(textId);
    return *textEntry->strings;
}

void* gameTextGetPhrase(int textId, int phraseIndex) {
    GameTextDef* entry;

    if (gameTextFonts->status != 2) {
        gameTextSelectFallbackBuffer();
        switch (gameTextFonts->status) {
        case 0:
            sprintf(gCurTextBuffer, "<uninitialised>");
            break;
        case 1:
            sprintf(gCurTextBuffer, "<loading>");
            break;
        case 3:
            sprintf(gCurTextBuffer, "<file empty!>");
            break;
        case 4:
            sprintf(gCurTextBuffer, "<no file!>");
            break;
        }
        return gGameTextLastEntry;
    }

    entry = gameTextGet(textId);
    if (entry->identifier == 0xffff) {
        gameTextSelectFallbackBuffer();
        sprintf(gCurTextBuffer, "<%d's not in %s>", textId, sMapDirectoryNameTable[curGameTextDir]);
        return gGameTextLastEntry;
    }

    if (phraseIndex >= entry->count) {
        gameTextSelectFallbackBuffer();
        sprintf(gCurTextBuffer, "<%d, doesn't have phrase %d>", textId, phraseIndex);
        return gGameTextLastEntry;
    }

    return entry->strings[phraseIndex];
}

static inline void gameTextSelectFallbackBuffer(void) {
    gGameTextBufferIndex++;
    if (gGameTextBufferIndex >= GAMETEXT_FALLBACK_COUNT) {
        gGameTextBufferIndex = 0;
    }
    gGameTextLastEntry = &sGameTextFallbackDefs[gGameTextBufferIndex];
    gCurTextBuffer = *gGameTextLastEntry->strings;
    gGameTextLastEntry->identifier = 0xffff;
    gGameTextFallbackRequestDelta = &sGameTextFallbackRequestDelta[gGameTextBufferIndex];
}

int getControlCharLen(u32 c) {
    CtrlCharEntry* p = gGameTextCtrlCodeArgCounts;
    int i = 46;
    while (i--) {
        if (p->key == c) {
            return p->len;
        }
        p++;
    }
    return 0;
}

int GameText_FindControlCodeArgs(u8* str, u32 target, int* out) {
    int off;
    int len;
    u32 ch;
    int n;
    int i;

    off = 0;
    if (str == NULL) {
        return 0;
    }
    while ((ch = utf8GetNextChar(str + off, &len)) != 0) {
        off += len;
        if (ch >= 0xE000 && ch <= 0xF8FF) {
            n = ctrlCharLen(ch);
            if (ch == target) {
                for (i = 0; i < n; i++) {
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

SubtitleCmd* subtitleParseControlCmds(char* str, int* count) {
    int off;
    int n;
    u8* tbl;
    int len;
    u32 ch;

    off = 0;
    n = 0;
    /* Retail repeatedly overwrites the first record; the cursor never advances. */
    tbl = (u8*)sSubtitleCtrlCmdScratch;
    if ((u8*)str == NULL) {
        return NULL;
    }
    while ((ch = utf8GetNextChar((u8*)(str + off), &len)) != 0) {
        off += len;
        if (ch >= 0xE000 && ch <= 0xF8FF) {
            int i;
            int n2;
            u16* q;

            n++;
            if (n > SUBTITLE_CONTROL_COMMAND_COUNT) {
                break;
            }
            *(u32*)tbl = ch;
            q = (u16*)(tbl + 4);
            n2 = ctrlCharLen(ch);
            if (n2 > 4) {
                n2 = 4;
            }
            for (i = 0; i < n2; i++) {
                u32 hi = ((u8*)str)[off++];
                u32 lo = ((u8*)str)[off++];
                *q++ = (hi << 8) | lo;
            }
        }
    }
    if (n == 0) {
        return NULL;
    }
    {
        int size = n * sizeof(SubtitleCmd);
        u8* buf = mmAlloc(size, 0x1a, 0);
        /* The seventeenth command overreads 12 path-buffer bytes beyond scratch. */
        memcpy(buf, (u8*)sSubtitleCtrlCmdScratch, size);
        *count = n;
        return (SubtitleCmd*)buf;
    }
}

/* Scale commands encode 1.0 as 0x100. */
static inline f32 gameTextDecodeScale(int scale256) {
    return (f32)scale256 / 256.0f;
}

void gameTextMeasureString(u8* str, f32 scale, f32* outW, f32* outZero, f32* outMaxAdv, f32* outMaxH, int glyphLang) {
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
    if (str == NULL) {
        return;
    }
    if (glyphLang == -1) {
        if (gameTextCharset == 2) {
            glyphLang = 6;
        } else {
            glyphLang = sLanguageNameTable[curLanguage].fontId;
        }
    }
    tbl = (u8*)gGameTextFontMetrics + glyphLang * 16;
    if (glyphLang != GAMETEXT_FONT_FACE) {
        if (outMaxAdv != NULL) {
            *outMaxAdv = (f32)(u32)((FontMetrics*)tbl)->maxWidth * scale;
        }
        if (outMaxH != NULL) {
            *outMaxH = (f32)(u32)((FontMetrics*)tbl)->lineHeight * scale;
        }
    }

    while (p = str + byteOff, (ch = utf8GetNextChar(p, &charLen)) != 0) {
        byteOff += charLen;
        if (ch >= 0xe000 && ch <= 0xf8ff) {
            n2 = ctrlCharLen(ch);
            for (i = 0; i < n2; i++) {
                int hi = str[byteOff++];
                int lo = str[byteOff++];
                params[i] = (hi << 8) | lo;
            }
            switch (ch) {
            case TEXT_CTRL_SCALE:
                scale = gameTextDecodeScale(params[0]);
                break;
            case TEXT_CTRL_FONT:
                glyphLang = params[0];
                tbl = (u8*)gGameTextFontMetrics + glyphLang * 16;
                if (glyphLang != GAMETEXT_FONT_FACE) {
                    mAdv = (f32)(u32)((FontMetrics*)tbl)->maxWidth * scale;
                    if (outMaxAdv != NULL && mAdv > *outMaxAdv) {
                        *outMaxAdv = mAdv;
                    }
                    mH = (f32)(u32)((FontMetrics*)tbl)->lineHeight * scale;
                    if (outMaxH != NULL && mH > *outMaxH) {
                        *outMaxH = mH;
                    }
                }
                break;
            }
            continue;
        }

        g = findGlyph(ch, glyphLang);
        if (g == NULL) {
            continue;
        }
        if (glyphLang == GAMETEXT_FONT_FACE) {
            continue;
        }
        width = scale * (f32)(g->advanceX + (g->width + g->offsetX)) + width;
    }

    if (outW != NULL) {
        *outW = width;
    }
    if (outZero != NULL) {
        *outZero = 0.0f;
    }
}

int GameText_CountPrintableChars(u8* str) {
    int count;
    int off;
    int len;
    u32 ch;

    count = 0;
    off = 0;
    if (str == NULL) {
        return 0;
    }
    while ((ch = utf8GetNextChar(str + off, &len)) != 0) {
        off += len;
        if (ch >= 0xE000 && ch <= 0xF8FF) {
            off += ctrlCharLen(ch) * 2;
        } else {
            count++;
        }
    }
    return count;
}

static void translateToDinoLanguage(u8* str) {
    int byteOff = 0;
    u32 ch;
    int charLen;
    u8* p;

    if (str == NULL) {
        return;
    }
    while (p = str + byteOff, (ch = utf8GetNextChar(p, &charLen)) != 0) {
        if (ch >= 0xe000 && ch <= 0xf8ff) {
            byteOff += ctrlCharLen(ch) * 2;
        } else {
            int base;
            if (ch >= 0x61 && ch <= 0x7a) {
                base = 0x61;
            } else if (ch >= 0x41 && ch <= 0x5a) {
                base = 0x41;
            } else {
                base = 0;
            }
            if (base != 0) {
                *p = sGameTextGlyphOrder[ch - base] - 0x61 + base;
            }
        }
        byteOff += charLen;
    }
}

void textRenderStr(char* str, GameTextBox* win, f32 x, f32 y, f32 lineH, int mode) {
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
    if (gameTextCharset == 2) {
        glyphLang = 6;
    } else {
        glyphLang = sLanguageNameTable[curLanguage].fontId;
    }
    curTexPage = -1;
    realign = 1;
    if (str == NULL || gameTextFonts->status != 2) {
        return;
    }

    if (curLanguage != 4 && mode == 1 && saveFileStruct_isCheatActive(CHEAT_DINO_LANGUAGE) && win == &gTextBoxes[10]) {
        translateToDinoLanguage((u8*)str);
    }

    gameTextMeasureString((u8*)str, gGameTextScale, &measW, &measN, 0, 0, -1);
    if (gGameTextMeasureOnly == 0) {
        setTextColor(0, gGameTextColorR, gGameTextColorG, gGameTextColorB, gGameTextColorA);
        _textSetColor(0, gGameTextColorR, gGameTextColorG, gGameTextColorB, gGameTextColorA);
        gxTevResetStages();
        textRenderSetup();
        gxTevCommitStages();
        gxSetAlphaBlendNoZTest();
    }

    x += win->x;
    y += win->y;
    winBase = gTextBoxes;

    while (p = (u8*)str + byteOff, (ch = utf8GetNextChar(p, &charLen)) != 0) {
        byteOff += charLen;
        skipGlyph = 0;
        if (ch >= 0xe000 && ch <= 0xf8ff) {
            controlArgCount = ctrlCharLen(ch);
            for (i = 0; i < controlArgCount; i++) {
                int hi = ((u8*)str)[byteOff++];
                int lo = ((u8*)str)[byteOff++];
                params[i] = (hi << 8) | lo;
            }
            switch (ch) {
            case TEXT_CTRL_SCALE:
                gGameTextScale = gameTextDecodeScale(params[0]);
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
                if (mode == 0) {
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
                    if (gGameTextMeasureOnly == 0) {
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
            if (skipGlyph) {
                continue;
            }
        } else {
            if (mode == 0) {
                gGameTextDrawnCharIndex++;
            }
        }

        if (realign != 0) {
            switch (win->alignment) {
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
                x = x * 0.5f + win->x;
                break;
            case TEXT_ALIGN_JUSTIFY: {
                int spaceCount;
                int acc;
                u32 innerCh;
                int innerLen;
                gameTextMeasureString(p, gGameTextScale, &measW, NULL, 0, 0, -1);
                acc = 0;
                spaceCount = acc;
                while ((innerCh = utf8GetNextChar(p + acc, &innerLen)) != 0) {
                    acc += innerLen;
                    if (innerCh == 0x20) {
                        spaceCount++;
                    }
                    if (innerCh >= 0xe000 && innerCh <= 0xf8ff) {
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
        if (g == NULL) {
            continue;
        }

        if (ch == 0xa) {
            x = 0.0f;
            y += lineH;
            continue;
        }
        if (ch == 0x20) {
            x = gGameTextScale * (f32)(g->advanceX + (g->width + g->offsetX)) + x;
            x += spaceExtra;
            continue;
        }

        u0 = (f32)(g->u << 5);
        v0 = (f32)(g->v << 5);
        e710 = 4.0f;
        fx0 = (f32)g->offsetX * gGameTextScale;
        fx0 = x + fx0;
        fx0 = e710 * fx0;
        fy0 = (f32)g->offsetY * gGameTextScale;
        fy0 = y + fy0;
        fy0 = e710 * fy0;
        fx1 = e710 * ((f32)(u32)g->width * gGameTextScale) + fx0;
        fy1 = e710 * ((f32)(u32)g->height * gGameTextScale) + fy0;
        if (fx0 < 0.0f && fx1 > 0.0f) {
            u0 = 8.0f * -fx0 + u0;
            fx0 = 0.0f;
        }
        if (fy0 < 0.0f && fy1 > 0.0f) {
            v0 = 8.0f * -fy0 + v0;
            fy0 = 0.0f;
        }

        if (gGameTextMeasureOnly != 0) {
            if (fx0 < gGameTextBoundsMinX) {
                gGameTextBoundsMinX = fx0;
            }
            if (fx1 > gGameTextBoundsMaxX) {
                gGameTextBoundsMaxX = fx1;
            }
            if (fy0 < gGameTextBoundsMinY) {
                gGameTextBoundsMinY = fy0;
            }
            if (fy1 > gGameTextBoundsMaxY) {
                gGameTextBoundsMaxY = fy1;
            }
        } else {
            if (g->font == GAMETEXT_FONT_FLAG) {
                int shift = gGameTextFlagGlyphRaise << 2;
                fy0 -= shift;
                fy1 -= shift;
                GXGetScissor(&scisX, &scisY, &scisW, &scisH);
                GXSetScissor(scisX, (scisY >= gGameTextFlagGlyphRaise) ? scisY - gGameTextFlagGlyphRaise : 0, scisW,
                             scisH);
            }
            if (g->font == GAMETEXT_FONT_FACE) {
                int iw = g->advanceX + (g->width + g->offsetX);
                int ih = g->advanceY + (g->height + g->offsetY);
                GXGetScissor(&scisX, &scisY, &scisW, &scisH);
                gxSetScissorRect(0, 0, winBase[126].x, winBase[126].y, winBase[126].x + winBase[126].width,
                                 winBase[126].y + winBase[126].height);
                fx0 = (f32)(winBase[126].x + ((winBase[126].width - iw) >> 1));
                fx1 = fx0 + iw;
                fy0 = (f32)(winBase[126].y + ((winBase[126].height - ih) >> 1));
                fy1 = fy0 + ih;
                fx0 *= 4.0f;
                fx1 *= 4.0f;
                fy0 *= 4.0f;
                fy1 *= 4.0f;
            }

            if (mode != 0) {
                int ox = gGameTextShadowOffsetX;
                int oy = gGameTextShadowOffsetY;
                fx0 += ox;
                fx1 += ox;
                fy0 += oy;
                fy1 += oy;
            }

            if (gGameTextMeasureOnly == 0) {
                if (curTexPage != g->page) {
                    curTexPage = g->page;
                    tex = gameTextFonts->textures[g->page];
                    selectTexture(tex, 0);
                    if (gGameTextFontMetrics[g->font].unk06 == 1) {
                        if (mode != 0) {
                            setTextColor(0, 0, 0, 0, gGameTextColorA);
                        } else {
                            setTextColor(0, 0xff, 0xff, 0xff, gGameTextColorA);
                            gxTevResetStages();
                            gxTevTextureTimesColor1Stage();
                            gxTevCommitStages();
                        }
                    } else {
                        setTextColor(0, gGameTextColorR, gGameTextColorG, gGameTextColorB, gGameTextColorA);
                        _textSetColor(0, gGameTextColorR, gGameTextColorG, gGameTextColorB, gGameTextColorA);
                        gxTevResetStages();
                        textRenderSetup();
                        gxTevCommitStages();
                    }
                }
            }

            if (gGameTextRevealActive != 0 && mode == 0 && g->font != GAMETEXT_FONT_FACE &&
                gGameTextDrawnCharIndex >= gGameTextRevealProgress) {
                setTextColor(0, 0, 0, 0, 0);
            }

            if (gameTextDrawFunc != NULL) {
                f32 sH = 32.0f * tex->height;
                f32 sW = 32.0f * tex->width;
                gameTextDrawFunc(fx0, fy0, fx1, fy1, u0 / sW, v0 / sH, (u0 + (f32)(g->width << 5)) / sW,
                                 (v0 + (f32)(g->height << 5)) / sH);
            } else {
                f32 sH = 32.0f * tex->height;
                f32 sW = 32.0f * tex->width;
                textRenderChar((int)fx0, fy0, fx1, fy1, u0 / sW, v0 / sH, (u0 + (f32)(g->width << 5)) / sW,
                               (v0 + (f32)(g->height << 5)) / sH);
            }

            if (g->font == GAMETEXT_FONT_FLAG || g->font == GAMETEXT_FONT_FACE) {
                GXSetScissor(scisX, scisY, scisW, scisH);
            }
        }

        if ((int)g->font != GAMETEXT_FONT_FACE) {
            x = gGameTextScale * (f32)(g->advanceX + (g->width + g->offsetX)) + x;
        }
    }
}

static inline TextGlyph* findGlyph(u32 ch, int glyphLang) {
    int cnt;
    TextGlyph* g;

    g = gameTextFonts->glyphs;
    cnt = gameTextFonts->glyphCount;
    while (cnt-- != 0) {
        if (g->key == ch && g->font == glyphLang) {
            return g;
        }
        g++;
    }
    return NULL;
}

void gameTextSetWindow(u8* textBox) {
    int i;
    GameTextSlot* cmd;
    int idx;

    if (textBox == NULL) {
        i = gGameTextCommandCount;
        gGameTextCommandCount = i + 1;
        cmd = &gGameTextCommandSlots[i];
        gCurTextBox = NULL;
        cmd->opcode = 8;
        cmd->arg0 = 0xff;
    } else {
        i = gGameTextCommandCount;
        gGameTextCommandCount = i + 1;
        cmd = &gGameTextCommandSlots[i];
        idx = (textBox - (u8*)gTextBoxes) / 0x20;
        if (idx == 0xff) {
            gCurTextBox = NULL;
        } else {
            gCurTextBox = (u8*)gTextBoxes + idx * 0x20;
        }
        cmd->opcode = 8;
        cmd->arg0 = idx;
    }
}

void gameTextSetWindowById(int boxId) {
    int i = gGameTextCommandCount;
    GameTextSlot* cmd;
    void* box;

    gGameTextCommandCount = i + 1;
    cmd = &gGameTextCommandSlots[i];
    if (boxId == 0xff) {
        box = NULL;
    } else {
        box = &gTextBoxes[boxId];
    }
    gCurTextBox = box;
    cmd->opcode = 8;
    cmd->arg0 = boxId;
}

static inline int ctrlCharLen(u32 c) {
    CtrlCharEntry* p = gGameTextCtrlCodeArgCounts;
    int i = 46;
    while (i--) {
        if (p->key == c) {
            return p->len;
        }
        p++;
    }
    return 0;
}

void* gameTextGetCurBox(void) {
    return gCurTextBox;
}

void* gameTextGetBox(int box) {
    return &gTextBoxes[box];
}

char** gameTextWrapLines(char* str, f32 width, f32 height, int* outCount, f32* outLineH) {
    int charPos;
    int cursor;
    int* boundary;
    int langIdx;
    FontMetrics* sizeEntry;
    int lineOff;
    int* bp;
    int lineCount;
    int breakPos;
    int haveSpace;
    int lineIdx;
    char* src;
    char** buffer;
    char* dst;
    int lineStarts[32];
    int params[8];
    f32 penX;
    int charLen;
    int i;
    u32 ch;
    lineCount = 0;
    lineOff = 0;
    cursor = 0;
    breakPos = 0;
    haveSpace = 0;
    penX = 0.0f;
    if (gameTextCharset == 2) {
        i = 6;
    } else {
        i = sLanguageNameTable[curLanguage].fontId;
    }
    langIdx = i;
    sizeEntry = &gGameTextFontMetrics[i];

    *outCount = 0;
    if (outLineH != NULL) {
        *outLineH = (f32)(u32)sizeEntry->lineHeight * height;
    }
    if (str == NULL) {
        return 0;
    }
    if (gGameTextCursorX != 0 || gGameTextCursorY != 0) {
        width = (f32)(u32)gGameTextCursorX;
    }

    lineStarts[0] = 0;
    boundary = lineStarts;
    bp = boundary;

    while ((ch = utf8GetNextChar((u8*)(str + cursor), &charLen)) != 0) {
        cursor += charLen;
        if (ch == 0x20) {
            breakPos = cursor;
            haveSpace = 1;
        }
        if (ch >= 0xe000 && ch <= 0xf8ff) {
            int n;
            int sel;
            n = gameTextCtrlCharLen(ch);
            for (i = 0; i < n; i++) {
                int b0 = ((u8*)str)[cursor++];
                int b1 = ((u8*)str)[cursor++];
                params[i] = (b0 << 8) | b1;
            }
            sel = 1;
            switch (ch) {
            case TEXT_CTRL_SCALE:
                height = gameTextDecodeScale(params[0]);
                break;
            case TEXT_CTRL_FONT:
                langIdx = params[0];
                sizeEntry = &gGameTextFontMetrics[langIdx];
                break;
            default:
                sel = 0;
            }
            if (sel != 0 && langIdx != 5) {
                f32 lh = (f32)(u32)sizeEntry->lineHeight * height;
                if (outLineH != NULL && lh > *outLineH) {
                    *outLineH = lh;
                }
            }
        } else {
            TextGlyph* found = gameTextFindGlyph(ch, langIdx);
            if (found != NULL) {
                int advance = (found->width + found->offsetX) + found->advanceX;
                penX += height * (f32)advance;
                if (penX >= width) {
                    if (haveSpace == 0) {
                        breakPos = cursor - charLen;
                    }
                    bp++;
                    lineCount++;
                    *(int*)((char*)lineStarts + (lineOff += 4)) = breakPos;
                    if (lineCount > 1 && bp[0] == bp[-1]) {
                        return 0;
                    }
                    if (lineCount >= 0x1e) {
                        return 0;
                    }
                    penX = 0.0f;
                    cursor = breakPos;
                    haveSpace = 0;
                }
            }
        }
    }

    lineOff = (lineCount = lineCount + 1) << 2;
    *(int*)((char*)lineStarts + lineOff) = cursor;
    *outCount = lineCount;
    if (cursor == 0) {
        return 0;
    }
    charLen = cursor + lineCount + lineOff;
    if (outLineH != NULL) {
        buffer = mmAllocateFromFBMemoryStore((int)gGameTextStringStore, charLen);
    } else {
        buffer = mmAlloc(charLen, 0, 0);
    }
    if (buffer == NULL) {
        return 0;
    }
    dst = (char*)buffer;
    i = charLen;
    while (i-- != 0) {
        *dst++ = 0;
    }

    {
        char* p = (char*)buffer + lineOff;
        buffer[0] = p;
        dst = p;
    }
    lineIdx = 0;
    charPos = 0;
    src = str;
    while (charPos < cursor) {
        *dst++ = *src;
        if (charPos == boundary[1]) {
            dst = gameTextBreakLine(dst - 1, buffer, lineIdx);
            boundary++;
            lineIdx++;
        }
        src++;
        charPos++;
    }
    *dst = 0;
    return buffer;
}

static inline char* gameTextBreakLine(char* dst, char** buffer, int lineIdx) {
    char* q;
    int k;
    int charLen2;
    u32 ch;

    q = dst;
    for (;;) {
        k = 6;
        do {
            ch = utf8GetNextChar((u8*)(dst - k), &charLen2);
            if (k != charLen2) {
                continue;
            }
            if (isSpace(ch)) {
                int j = charLen2;
                while (j-- != 0) {
                    *--dst = 0;
                }
                break;
            }
            q[1] = q[0];
            q[0] = 0;
            dst = q + 1;
            *(char**)((char*)buffer + ((lineIdx + 1) << 2)) = dst++;
            return dst;
        } while (--k > 0);
    }
}

void gameTextFreePhrase(NpcDialoguePhraseState* p) {
    p->display.active = 0;
    p->display.charIndex = 0;
    p->display.f8 = 0;
    p->display.fC = 0;
    if (p->phraseBuffer != NULL) {
        mm_free(p->phraseBuffer);
        p->phraseBuffer = NULL;
    }
}

static inline TextGlyph* gameTextFindGlyph(u32 ch, int langIdx) {
    TextGlyph* g;
    int cnt;

    g = gameTextFonts->glyphs;
    cnt = gameTextFonts->glyphCount;
    while (cnt-- != 0) {
        if (g->key == ch && g->font == langIdx) {
            return g;
        }
        g++;
    }
    return NULL;
}

void gameTextQueueReveal(int a, TextDisplayState* b) {
    int i = gGameTextCommandCount++;
    GameTextSlot* e = &gGameTextCommandSlots[i];
    e->opcode = GAMETEXT_COMMAND_TICK_REVEAL;
    e->arg0 = a;
    e->arg1 = (int)b;
}

void gameTextTickReveal(int textId, TextDisplayState* state) {
    GameTextDef* def;
    s32 charCount;
    char* lineStr;
    int special;

    if (gameTextFonts->status == 1) {
        return;
    }
    def = gameTextGet(textId);
    special = 0;
    if (def >= sGameTextFallbackDefs && def < sGameTextFallbackDefs + GAMETEXT_FALLBACK_COUNT) {
        special = 1;
    }
    if (special) {
        state->f8 = 1;
        return;
    }
    lineStr = def->strings[state->charIndex];
    charCount = gameTextCountChars(lineStr);
    if (state->active == 0) {
        gGameTextDrawnCharIndex = 0;
        gGameTextRevealProgress = 2.0f;
        state->f10 = def->count;
        state->f8 = 0;
        state->active = 1;
    }
    if (gGameTextRevealProgress == 2.0f) {
        Sfx_PlayFromObject(0, SFXTRIG_clock_loop);
    }
    gGameTextRevealActive = 1;
    gGameTextDrawnCharIndex = 0;
    gGameTextRevealProgress = timeDelta * gGameTextRevealSpeed + gGameTextRevealProgress;
    if (gGameTextRevealProgress >= (f32)(charCount - 2)) {
        Sfx_StopFromObject(0, SFXTRIG_clock_loop);
    }
    if (state->fC != 0) {
        if (gGameTextRevealProgress < charCount) {
            gGameTextRevealProgress = charCount;
        } else {
            for (;;) {
                if (state->fC > 0) {
                    state->charIndex++;
                } else {
                    state->charIndex--;
                }
                if (state->charIndex < def->count && (u8)def->strings[state->charIndex][0] == 0) {
                    continue;
                }
                break;
            }
            if (state->charIndex < 0) {
                state->charIndex = 0;
            } else if (state->charIndex >= def->count) {
                state->charIndex = def->count - 1;
            } else {
                gGameTextRevealProgress = 2.0f;
            }
            if (state->charIndex < 0) {
                state->charIndex = 0;
            }
            if (state->charIndex == def->count - 1 && (state->fC = 1) != 0 && gGameTextRevealProgress >= charCount) {
                state->f8 = 1;
            } else {
                state->f8 = 0;
            }
            state->fC = 0;
        }
    }
    gameTextRenderStrs(def->strings[state->charIndex], 0x7c);
}

static inline int gameTextCountChars(char* str) {
    int charCount;
    int byteOffset;
    u32 ch;
    int charLen;

    charCount = 0;
    byteOffset = 0;
    if (str == NULL) {
        return 0;
    }
    while ((ch = utf8GetNextChar((u8*)(str + byteOffset), &charLen)) != 0) {
        byteOffset += charLen;
        if (ch >= 0xe000 && ch <= 0xf8ff) {
            byteOffset += gameTextCtrlCharLen(ch) * 2;
        } else {
            charCount++;
        }
    }
    return charCount;
}

static inline int gameTextCtrlCharLen(u32 c) {
    CtrlCharEntry* p = gGameTextCtrlCodeArgCounts;
    int i = 46;
    while (i--) {
        if (p->key == c) {
            return p->len;
        }
        p++;
    }
    return 0;
}

void gameTextShow(int textId) {
    int commandIndex;
    GameTextSlot* command;
    if (gameTextDrawFunc != NULL) {
        gameTextRenderById(textId, 0, 0);
    } else {
        commandIndex = gGameTextCommandCount++;
        command = &gGameTextCommandSlots[commandIndex];
        command->opcode = GAMETEXT_COMMAND_RENDER_BY_ID;
        command->arg0 = textId;
        command->arg1 = 0;
        command->arg2 = 0;
    }
}

void gameTextShowAt(int textId, int cursorX, int cursorY) {
    int commandIndex;
    GameTextSlot* command;
    if (gameTextDrawFunc != NULL) {
        gameTextRenderById(textId, cursorX, cursorY);
    } else {
        commandIndex = gGameTextCommandCount++;
        command = &gGameTextCommandSlots[commandIndex];
        command->opcode = GAMETEXT_COMMAND_RENDER_BY_ID;
        command->arg0 = textId;
        command->arg1 = cursorX;
        command->arg2 = cursorY;
    }
}

void gameTextRenderById(int textId, int cursorX, int cursorY) {
    GameTextDef* def = (GameTextDef*)gameTextGet(textId);
    TextSlot* slot;
    u8 savedRed = gGameTextColorR;
    u8 savedGreen = gGameTextColorG;
    u8 savedBlue = gGameTextColorB;
    u8 savedAlpha = gGameTextColorA;
    int phraseIndex;

    gGameTextRenderingById = 1;
    if (gCurTextBox != NULL) {
        slot = gCurTextBox;
    } else if (def->boxId == 255) {
        slot = (TextSlot*)gTextBoxes + 2;
    } else {
        slot = (TextSlot*)gTextBoxes + def->boxId;
    }

    if (slot == (TextSlot*)gTextBoxes + 0x85) {
        gGameTextColorR = 255;
        gGameTextColorG = 255;
        gGameTextColorB = 255;
        gGameTextColorA = 255;
    }

    if (def->alignH == 0) {
        slot->alignment = slot->alignH;
    }
    slot->cursorX = cursorX;
    slot->cursorY = cursorY;

    if (gGameTextMeasureOnly == 0) {
        int verticalAlignment;
        if (def->alignV == 0) {
            verticalAlignment = slot->alignV;
        } else {
            verticalAlignment = def->alignV;
        }
        if (verticalAlignment == 2 || verticalAlignment == 3) {
            int minX, maxX, minY, maxY;
            int remainingHeight;
            gameTextMeasureById(textId, cursorX, cursorY, &minX, &maxX, &minY, &maxY);
            remainingHeight = slot->height - (maxY - minY);
            if (verticalAlignment == 2) {
                slot->cursorY = (s16)(remainingHeight / 2);
            } else {
                slot->cursorY = remainingHeight;
            }
        }
    }

    if (gGameTextMeasureOnly == 0) {
        gameTextDrawBox(def, 0, slot);
    }
    if (gameTextDrawFunc != NULL) {
        gxSetScissorRect(0, 0, 0, 0, 640, 480);
    } else {
        if (slot->x < 0) {
            slot->x = 0;
        }
        if (slot->y < 0) {
            slot->y = 0;
        }
        if (gGameTextMeasureOnly == 0) {
            gxSetScissorRect(0, 0, slot->x, slot->y, slot->x + slot->width, slot->y + slot->height);
        }
    }

    phraseIndex = 0;
    for (; phraseIndex < def->count; phraseIndex++) {
        gameTextRenderStrs(def->strings[phraseIndex], slot - (TextSlot*)gTextBoxes);
    }

    gGameTextRenderingById = 0;
    if (gGameTextMeasureOnly == 0) {
        Camera_ApplyCurrentViewport(0);
    }
    gGameTextColorR = savedRed;
    gGameTextColorG = savedGreen;
    gGameTextColorB = savedBlue;
    gGameTextColorA = savedAlpha;
}

void gameTextMeasureStringBounds(char* str, int boxIdx, int* outMinX, int* outMaxX, int* outMinY, int* outMaxY) {
    TextSlot* box = (TextSlot*)gTextBoxes + boxIdx;
    s16 savedX = box->cursorX;
    s16 savedY = box->cursorY;
    gGameTextMeasureOnly = 1;
    gGameTextBoundsMinX = 0x7FFFFFFF;
    gGameTextBoundsMaxX = 0;
    gGameTextBoundsMinY = 0x7FFFFFFF;
    gGameTextBoundsMaxY = 0;
    gameTextRenderStrs(str, boxIdx);
    gGameTextMeasureOnly = 0;
    if (outMinY != NULL) {
        *outMinY = gGameTextBoundsMinY >> 2;
    }
    if (outMaxY != NULL) {
        *outMaxY = gGameTextBoundsMaxY >> 2;
    }
    if (outMinX != NULL) {
        *outMinX = gGameTextBoundsMinX >> 2;
    }
    if (outMaxX != NULL) {
        *outMaxX = gGameTextBoundsMaxX >> 2;
    }
    box->cursorX = savedX;
    box->cursorY = savedY;
}

void gameTextMeasureStringBoundsAt(char* str, int boxIdx, int x, int y, int* outMinX, int* outMaxX, int* outMinY,
                                   int* outMaxY) {
    TextSlot* box = (TextSlot*)gTextBoxes + boxIdx;
    s16 savedX = box->cursorX;
    s16 savedY = box->cursorY;
    gGameTextMeasureOnly = 1;
    gGameTextBoundsMinX = 0x7FFFFFFF;
    gGameTextBoundsMaxX = 0;
    gGameTextBoundsMinY = 0x7FFFFFFF;
    gGameTextBoundsMaxY = 0;
    box->cursorX = x;
    box->cursorY = y;
    gameTextRenderStrs(str, boxIdx);
    gGameTextMeasureOnly = 0;
    if (outMinY != NULL) {
        *outMinY = gGameTextBoundsMinY >> 2;
    }
    if (outMaxY != NULL) {
        *outMaxY = gGameTextBoundsMaxY >> 2;
    }
    if (outMinX != NULL) {
        *outMinX = gGameTextBoundsMinX >> 2;
    }
    if (outMaxX != NULL) {
        *outMaxX = gGameTextBoundsMaxX >> 2;
    }
    box->cursorX = savedX;
    box->cursorY = savedY;
}

void gameTextMeasureById(int textId, int cursorX, int cursorY, int* outMinX, int* outMaxX, int* outMinY, int* outMaxY) {
    if (!gameTextIdExists(textId)) {
        *outMinX = 0;
        *outMaxX = 0;
        *outMinY = 0;
        *outMaxY = 0;
        return;
    }
    gGameTextMeasureOnly = 1;
    gGameTextBoundsMinX = 0x7FFFFFFF;
    gGameTextBoundsMaxX = 0;
    gGameTextBoundsMinY = 0x7FFFFFFF;
    gGameTextBoundsMaxY = 0;
    gameTextRenderById(textId, cursorX, cursorY);
    gGameTextMeasureOnly = 0;
    if (outMinY != NULL) {
        *outMinY = gGameTextBoundsMinY >> 2;
    }
    if (outMaxY != NULL) {
        *outMaxY = gGameTextBoundsMaxY >> 2;
    }
    if (outMinX != NULL) {
        *outMinX = gGameTextBoundsMinX >> 2;
    }
    if (outMaxX != NULL) {
        *outMaxX = gGameTextBoundsMaxX >> 2;
    }
}

void gameTextShowTimeStr(char* str) {
    int i;
    GameTextSlot* e;
    char* buf;
    i = gGameTextCommandCount++;
    e = &gGameTextCommandSlots[i];
    e->opcode = GAMETEXT_COMMAND_SHOW_TIME_STRING;
    buf = gGameTextCommandStringCursor;
    gGameTextCommandStringCursor = gameStrcpy(buf, str) + 1;
    e->arg0 = (int)buf;
}

void gameTextAppendStr(char* str, int box) {
    int i;
    GameTextSlot* e;
    char* buf;
    if (gameTextDrawFunc != NULL) {
        gameTextRenderStrs(str, box);
    } else {
        i = gGameTextCommandCount++;
        e = &gGameTextCommandSlots[i];
        e->opcode = GAMETEXT_COMMAND_APPEND_STRING;
        buf = gGameTextCommandStringCursor;
        gGameTextCommandStringCursor = gameStrcpy(buf, str) + 1;
        e->arg0 = (int)buf;
        e->arg1 = box;
    }
}

void gameTextRenderStrs(char* str, int boxIdx) {
    TextSlot* slot = (TextSlot*)gTextBoxes + boxIdx;
    char** lines;
    int count;
    f32 lineH;
    int i;
    int closeAtEnd = 0;

    if (gGameTextRenderingById != 1) {
        slot->alignment = slot->alignH;
        if (gGameTextMeasureOnly == 0) {
            gameTextDrawBox(NULL, (int)str, slot);
        }
    }
    lines = gameTextWrapLines(str, (f32)(u32)slot->width, slot->scale, &count, &lineH);
    if (lines == NULL) {
        slot->cursorY = (s16)(lineH * count + slot->cursorY);
        return;
    }
    if (gameTextDrawFunc != NULL) {
        gxSetScissorRect(0, 0, 0, 0, 0x280, 0x1e0);
    } else if (gGameTextMeasureOnly == 0) {
        gxSetScissorRect(0, 0, slot->x, slot->y, slot->x + slot->width, slot->y + slot->height);
    }
    gGameTextScale = slot->scale;
    for (i = 0; i < count; i++) {
        if (i == count - 1 && slot->alignment == 3) {
            slot->alignment = 0;
            closeAtEnd = 1;
        }
        if (gGameTextShadowEnabled == 1 && gGameTextMeasureOnly == 0) {
            u8 save7 = gGameTextColorR;
            u8 save6 = gGameTextColorG;
            u8 save5 = gGameTextColorB;
            f32 saveColor = gGameTextScale;
            gGameTextColorR = gGameTextShadowColorR;
            gGameTextColorG = gGameTextShadowColorG;
            gGameTextColorB = gGameTextShadowColorB;
            textRenderStr(lines[i], slot, slot->cursorX, slot->cursorY, lineH, 1);
            gGameTextColorR = save7;
            gGameTextColorG = save6;
            gGameTextColorB = save5;
            gGameTextScale = saveColor;
        }
        textRenderStr(lines[i], slot, slot->cursorX, slot->cursorY, lineH, 0);
        slot->cursorY = (s16)((f32)slot->cursorY + lineH);
        if (closeAtEnd) {
            slot->alignment = 3;
        }
    }
    if (gGameTextMeasureOnly == 0) {
        Camera_ApplyCurrentViewport(NULL);
    }
}

void gameTextShowStr(char* text, int box, int cursorX, int cursorY) {
    int i;
    GameTextSlot* e;
    char* buf;
    if (gameTextDrawFunc != NULL) {
        TextSlot* slot = (TextSlot*)gTextBoxes + box;
        slot->cursorX = cursorX;
        slot->cursorY = cursorY;
        gameTextRenderStrs(text, box);
    } else {
        i = gGameTextCommandCount++;
        e = &gGameTextCommandSlots[i];
        e->opcode = GAMETEXT_COMMAND_SHOW_STRING_AT;
        buf = gGameTextCommandStringCursor;
        gGameTextCommandStringCursor = gameStrcpy(buf, text) + 1;
        e->arg0 = (int)buf;
        e->arg1 = box;
        e->arg2 = cursorX;
        e->arg3 = cursorY;
    }
}

int gameTextGetTaskText(int id, int* outTextSeqId, int* outDirId) {
    int i;
    TaskTextEntry* e = gTaskTextTable;
    for (i = 0; i < 0x7a; i++) {
        if (e->objSeqId == id) {
            if (outTextSeqId != NULL) {
                *outTextSeqId = e->textSeqId;
            }
            if (outDirId != NULL) {
                *outDirId = e->dirId;
            }
            return 1;
        }
        e++;
    }
    return 0;
}

int utf8GetNextChar(u8* str, int* outLen) {
    u8 first = *str;
    int cls = gUtf8CharClassTable[first];
    u32 acc = 0;
    switch (cls) {
    case 5:
        str++;
        acc = first << 6;
    case 4:
        acc += *str++;
        acc <<= 6;
    case 3:
        acc += *str++;
        acc <<= 6;
    case 2:
        acc += *str++;
        acc <<= 6;
    case 1:
        acc += *str++;
        acc <<= 6;
    case 0:
        acc += *str;
    default:
        break;
    }
    *outLen = cls + 1;
    return acc - gUtf8ClassOffsetTable[cls];
}

static char* gameStrcpy(char* dst, char* src) {
    u32 ch;
    int len;
    do {
        ch = utf8GetNextChar((u8*)src, &len);
        while (len-- != 0) {
            *dst++ = *src++;
        }
        if (ch >= 0xe000 && ch <= 0xf8ff) {
            len = getControlCharLen(ch) * 2;
            while (len-- != 0) {
                *dst++ = *src++;
            }
        }
    } while (ch != 0);
    return dst - 1;
}

static inline int textCountChars(char* lineStr) {
    int charCount;
    int byteOffset;
    u32 ch;
    int charLen;

    charCount = 0;
    byteOffset = 0;
    if (lineStr == NULL) {
        return 0;
    }
    while ((ch = utf8GetNextChar((u8*)(lineStr + byteOffset), &charLen)) != 0) {
        byteOffset += charLen;
        if (ch >= 0xe000 && ch <= 0xf8ff) {
            CtrlCharEntry* g = gGameTextCtrlCodeArgCounts;
            int n;
            int val = 0;
            for (n = 46; n-- != 0;) {
                if (g->key == ch) {
                    val = g->len;
                    break;
                }
                g++;
            }
            byteOffset += val * 2;
        } else {
            charCount++;
        }
    }
    return charCount;
}

static inline int gameTextIdExists(int id) {
    GameTextDef* e;
    int count;
    int i;

    if (gameTextFonts->status != 2) {
        return 0;
    }
    e = gameTextFonts->entries;
    count = gameTextFonts->entryCount;
    for (i = 0; i != count; i++) {
        if (e->identifier == id) {
            return 1;
        }
        e++;
    }
    return 0;
}

int isSpace(u32 c) {
    int result = 0;

    if (c == 0x20 || c == 0x3000 || c == 0x303F) {
        result = 1;
    }
    return result;
}
