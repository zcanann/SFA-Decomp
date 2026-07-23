#include "ghidra_import.h"
#include "track/intersect_hud_api.h"
#include "track/intersect_render_setup_api.h"
#include "main/hud_visibility_api.h"
#include "main/audio/sfx.h"
#include "main/gametext_api.h"
#define GAMETEXT_COLOR_U8
#include "main/gametext_color_api.h"
#include "main/gameloop_api.h"
#include "main/gametext_charset_api.h"
#include "main/gametext_show_str_api.h"
#include "main/gametext_shared_internal.h"
#include "main/gametext_task_api.h"
#include "main/gx_scissor_api.h"
#include "main/mm.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSFont.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/savedata_struct.h"
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

void subtitleBuildLineTable(void)
{
    int savedCharset;
    SubtitleLineTable* s[1];
    f32 delta;
    f32 curTime;
    SubtitleTextEntry* t;
    u8* win;
    int m;
    int i;
    char* str;
    int k;
    int total;
    int oldDelay;
    char** strLines;
    int found;
    int q;
    int n;
    int count;
    int args[3];
    f32 ftotal;
    void** blk;

    s[0] = (SubtitleLineTable*)gSubtitleLineTable;
    total = 0;
    curTime = 0.0f;
    if (gGameTextSequenceMode != 0)
    {
        savedCharset = gameTextGetCharset();
        gameTextSetCharset(1, 1);
    }
    t = (SubtitleTextEntry*)gameTextGet(gGameTextPendingTextId);
    win = (u8*)gTextBoxes + 0x140;
    gSubtitleLineCount = 0;
    gSubtitleBlockCount = 0;
    for (i = 0; i < SUBTITLE_LINE_COUNT; i++)
    {
        s[0]->times[i] = gSubtitleNoTimeSentinel;
    }
    for (i = 0; i < t->count; i++)
    {
        str = t->strs[i];
        n = GameText_FindControlCodeArgs((u8*)str, TEXT_CTRL_SEQ_TIME, args);
        if (n != 0)
        {
            q = args[2] / 60;
            s[0]->times[gSubtitleLineCount] = (f32)(args[1] + args[0] * 60 + q);
        }
        strLines = textMeasureFn_80016c9c(str, (f32)(u32) * (u16*)(win + 2), *(f32*)(win + 0xc), &count, NULL);
        if (strLines != NULL)
        {
            for (k = 0; k < count; k++)
            {
                s[0]->lines[gSubtitleLineCount++] = strLines[k];
            }
            blk = (void**)((u8*)s[0] + gSubtitleBlockCount * 4);
            if (*blk != NULL)
            {
                oldDelay = mmSetFreeDelay(0);
                blk = (void**)((u8*)s[0] + gSubtitleBlockCount * 4);
                mm_free(*blk);
                mmSetFreeDelay(oldDelay);
            }
            blk = (void**)((u8*)s[0] + gSubtitleBlockCount++ * 4);
            *blk = strLines;
        }
    }
    for (k = 0; k < gSubtitleLineCount; k++)
    {
        if (gSubtitleNoTimeSentinel != s[0]->times[k])
        {
            curTime = s[0]->times[k];
            total = GameText_CountPrintableChars((u8*)s[0]->lines[k]);
        }
        else
        {
            found = 0;
            m = k;
            for (i = 0; i < SUBTITLE_LINE_COUNT; i++)
            {
                ftotal = total;
                if (m < 255)
                {
                    if (gSubtitleNoTimeSentinel != s[0]->times[m + 1])
                    {
                        delta = s[0]->times[m + 1] - curTime;
                        found = 1;
                    }
                    n = GameText_CountPrintableChars((u8*)s[0]->lines[m]);
                    s[0]->times[m] = n;
                    total += n;
                    if (found != 0)
                    {
                        for (q = m; q >= k; q--)
                        {
                            s[0]->times[q] = s[0]->times[q + 1] - delta * (s[0]->times[q] / total);
                        }
                        break;
                    }
                    m++;
                }
            }
        }
    }
    gSubtitleLineIndex = 0;
    gSubtitleElapsedFrames = 0;
    gSubtitleActive = 2;
    if (gGameTextSequenceMode != 0)
    {
        gameTextSetCharset(savedCharset, 1);
    }
}

