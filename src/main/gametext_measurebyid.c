#include "main/audio/sfx.h"
#include "main/camera.h"
#include "main/frame_timing.h"
#include "main/gametext_api.h"
#include "main/gametext_box_api.h"
#include "main/gametext_command_api.h"
#include "main/gametext_show_api.h"
#include "main/gametext_show_str_api.h"
#include "main/gametext_task_api.h"
#include "main/gametext_internal.h"
#include "main/gametext_shared_internal.h"
#include "main/mm.h"
#include "main/rcp_dolphin_api.h"
#include "main/textrender_api.h"
#include "main/audio/sfx_trigger_ids.h"

/* In-string formatting control codes (Unicode PUA). */
#define TEXT_CTRL_SCALE 0xf8f4
#define TEXT_CTRL_FONT  0xf8f7

/* Language ids; order fixed by sLanguageNameTable[] below. */
#define LANGUAGE_ENGLISH  0
#define LANGUAGE_FRENCH   1
#define LANGUAGE_GERMAN   2
#define LANGUAGE_ITALIAN  3
#define LANGUAGE_JAPANESE 4
#define LANGUAGE_SPANISH  5

void gameTextMeasureById(int id, int a, int b, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY)
{
    GlyphEntry* e;
    GameTextFont* fonts;
    int count;
    int i;
    int found;

    fonts = gameTextFonts;
    if (fonts->mode != 2)
    {
        found = 0;
    }
    else
    {
        e = fonts->entries;
        count = fonts->count;
        for (i = 0; i != count || (found = 0, 0); i++)
        {
            if (e->id == id)
            {
                found = 1;
                break;
            }
            e++;
        }
    }
    if (!found)
    {
        *outMaxX = 0;
        *outMaxY = 0;
        *outMinX = 0;
        *outMinY = 0;
        return;
    }
    lbl_803DC9BC = 1;
    lbl_803DC9B0 = 0x7FFFFFFF;
    lbl_803DC9AC = 0;
    lbl_803DC9B8 = 0x7FFFFFFF;
    lbl_803DC9B4 = 0;
    gameTextFn_8001658c(id, a, b);
    lbl_803DC9BC = 0;
    if (outMinX != NULL)
    {
        *outMinX = lbl_803DC9B8 >> 2;
    }
    if (outMinY != NULL)
    {
        *outMinY = lbl_803DC9B4 >> 2;
    }
    if (outMaxX != NULL)
    {
        *outMaxX = lbl_803DC9B0 >> 2;
    }
    if (outMaxY != NULL)
    {
        *outMaxY = lbl_803DC9AC >> 2;
    }
}
