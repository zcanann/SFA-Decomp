/*
 * credits (DLL 0x40) - the end-credits roll.
 *
 * Credits_initialise loads the credits texture asset (0xC5) and the
 * credits text block (0x1FD), resets the page cursor to page 0 and seeds
 * the scroll time. Credits_frameStart advances that time by timeDelta
 * each frame, steps to the next page once the time passes the page's end
 * marker (endTime), then for every line on the current page computes a
 * fade-in/hold/fade-out alpha from the four per-line time keys
 * (t0..t3) and scrolls visible lines up. Credits_release frees the
 * texture. Credits_render / Credits_frameEnd are empty stubs.
 */
#include "main/texture.h"
#include "main/engine_shared.h"
extern f32 lbl_803DD968;
extern u8 lbl_803DD970;
extern void* lbl_803DD974;
extern void* lbl_803DD96C;
extern f32 lbl_803E22A8;
extern f32 lbl_803E22AC;
extern f32 lbl_803E22B0;
extern f32 lbl_803E22B4;
extern f32 lbl_803E22B8;

typedef struct
{
    u16 t0; /* fade-in start */
    u16 t1; /* fade-in end / full-alpha start */
    u16 t2; /* full-alpha end / fade-out start */
    u16 t3; /* fade-out end */
    u8 pad8[3];
    u8 alpha;
    f32 y;
} CreditsLine;

typedef struct
{
    CreditsLine lines[9];
    u16 scrollStartTime;
    u16 endTime;
    u8 count;
    u8 pad95[3];
} CreditsPage;

CreditsPage gCreditsPages[] =
{
    {
        {
            { 128, 216, 536, 560, { 255, 0, 0 } },
        },
        536, 560, 1,
    },
    {
        {
            { 824, 864, 1052, 1112, { 0, 8, 0 } },
            { 824, 864, 1052, 1112, { 1, 9, 1 } },
        },
        1052, 1112, 2,
    },
    {
        {
            { 1200, 1240, 1884, 1944, { 2, 1, 0 } },
            { 1200, 1240, 1468, 1524, { 3, 2, 1 } },
            { 1240, 1280, 1526, 1584, { 4, 3, 1 } },
            { 1280, 1320, 1586, 1644, { 5, 4, 1 } },
            { 1320, 1360, 1644, 1704, { 6, 5, 1 } },
            { 1360, 1400, 1704, 1764, { 7, 6, 1 } },
            { 1400, 1440, 1762, 1824, { 8, 7, 1 } },
            { 1440, 1482, 1824, 1884, { 9, 8, 1 } },
            { 1482, 1526, 1884, 1944, { 10, 9, 1 } },
        },
        1884, 1944, 9,
    },
    {
        {
            { 2030, 2070, 2528, 2588, { 11, 6, 0 } },
            { 2030, 2070, 2414, 2468, { 12, 7, 1 } },
            { 2070, 2110, 2470, 2528, { 13, 8, 1 } },
            { 2110, 2150, 2528, 2588, { 14, 9, 1 } },
        },
        2528, 2588, 4,
    },
    {
        {
            { 2982, 3020, 3572, 3632, { 15, 1, 0 } },
            { 2982, 3020, 3334, 3392, { 16, 2, 1 } },
            { 3022, 3062, 3390, 3452, { 17, 3, 1 } },
            { 3062, 3102, 3452, 3512, { 18, 4, 1 } },
            { 3102, 3142, 3512, 3572, { 19, 5, 1 } },
            { 3142, 3184, 3572, 3632, { 20, 6, 1 } },
        },
        3572, 3632, 6,
    },
    {
        {
            { 3784, 3824, 4378, 4438, { 21, 3, 0 } },
            { 3784, 3824, 4188, 4258, { 22, 4, 1 } },
            { 3824, 3864, 4254, 4318, { 23, 5, 1 } },
            { 3864, 3904, 4316, 4378, { 24, 6, 1 } },
            { 3904, 3946, 4378, 4438, { 25, 7, 1 } },
        },
        4378, 4438, 5,
    },
    {
        {
            { 4540, 4580, 4946, 5006, { 26, 7, 0 } },
            { 4540, 4580, 4880, 4946, { 27, 8, 1 } },
            { 4580, 4622, 4946, 5006, { 28, 9, 1 } },
        },
        4946, 5006, 3,
    },
    {
        {
            { 5094, 5134, 5316, 5376, { 29, 1, 0 } },
            { 5094, 5134, 5316, 5376, { 30, 2, 1 } },
            { 5284, 5324, 5516, 5576, { 31, 3, 0 } },
            { 5284, 5324, 5516, 5576, { 32, 4, 1 } },
            { 5486, 5526, 5688, 5746, { 33, 5, 0 } },
            { 5486, 5526, 5688, 5746, { 34, 6, 1 } },
        },
        5688, 5746, 6,
    },
    {
        {
            { 6030, 6070, 6468, 6528, { 35, 6, 0 } },
            { 6030, 6070, 6340, 6408, { 36, 7, 1 } },
            { 6070, 6110, 6406, 6468, { 37, 8, 1 } },
            { 6110, 6150, 6468, 6528, { 38, 9, 1 } },
        },
        6468, 6528, 4,
    },
    {
        {
            { 6766, 6806, 7290, 7350, { 39, 8, 0 } },
            { 6766, 6806, 7290, 7350, { 40, 9, 1 } },
        },
        7290, 7350, 2,
    },
};

void Credits_render(void)
{
}

void Credits_frameEnd(void)
{
}

#pragma scheduling off
#pragma peephole off
#pragma opt_strength_reduction off
int Credits_frameStart(void)
{
    u8 idx;
    int i;
    f32 cur;
    f32 elapsed;
    f32 frac;
    CreditsLine* line;
    u8 alpha;
    int off;

    idx = lbl_803DD970;
    if (idx < 10)
    {
        elapsed = lbl_803DD968 + timeDelta;
        lbl_803DD968 = elapsed;
        if (elapsed >= gCreditsPages[idx].endTime)
        {
            lbl_803DD970 = idx + 1;
        }
        if (lbl_803DD970 < 10)
        {
            i = 0;
            off = 0;
            cur = *(f32*)&lbl_803DD968;
            for (; i < gCreditsPages[lbl_803DD970].count; off += 16, i++)
            {
                line = (CreditsLine*)((char*)gCreditsPages[lbl_803DD970].lines + off);
                if (cur < line->t0)
                {
                    alpha = 0;
                }
                else if (cur < line->t1)
                {
                    frac = (cur - line->t0) /
                        (f32)(line->t1 - line->t0);
                    if (frac < lbl_803E22A8)
                    {
                        frac = lbl_803E22A8;
                    }
                    else if (frac > lbl_803E22AC)
                    {
                        frac = lbl_803E22AC;
                    }
                    alpha = lbl_803E22B0 * frac;
                }
                else if (cur < line->t2)
                {
                    alpha = 0xff;
                }
                else if (cur < line->t3)
                {
                    frac = (cur - line->t2) /
                        (f32)(line->t3 - line->t2);
                    if (frac < lbl_803E22A8)
                    {
                        frac = lbl_803E22A8;
                    }
                    else if (frac > lbl_803E22AC)
                    {
                        frac = lbl_803E22AC;
                    }
                    alpha = 0xff - (int)(lbl_803E22B0 * frac);
                }
                else
                {
                    alpha = 0;
                }
                line->alpha = alpha;
                if (cur >= line->t0 && cur <= line->t3 &&
                    cur >= gCreditsPages[lbl_803DD970].scrollStartTime)
                {
                    line->y = lbl_803E22B4 * (timeDelta / lbl_803E22B8) + line->y;
                }
            }
        }
    }
    return 0;
}
#pragma opt_strength_reduction on
#pragma scheduling on
#pragma peephole on

void Credits_release(void)
{
    textureFree(lbl_803DD974);
}

#pragma scheduling off
void Credits_initialise(void)
{
    lbl_803DD974 = textureLoadAsset(0xC5);
    lbl_803DD96C = gameTextGet(0x1FD);
    lbl_803DD970 = 0;
    lbl_803DD968 = lbl_803E22A8;
}

/*__DATA_EXTERNS__*/
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* lbl_8031CC10[10] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00050000, Credits_initialise, Credits_release, (void*)0x00000000, Credits_frameStart, Credits_frameEnd, Credits_render };
