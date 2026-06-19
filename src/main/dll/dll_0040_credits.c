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

extern f32 lbl_803DD968;
extern u8 lbl_803DD970;
extern void* lbl_803DD974;
extern void* lbl_803DD96C;
extern f32 lbl_803E22A8;
extern f32 lbl_803E22AC;
extern f32 lbl_803E22B0;
extern f32 lbl_803E22B4;
extern f32 lbl_803E22B8;
extern f32 timeDelta;
extern void* gameTextGet(int textId);

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

extern CreditsPage gCreditsPages[];

void Credits_render(void)
{
}

void Credits_frameEnd(void)
{
}

#pragma scheduling off
#pragma peephole off
int Credits_frameStart(void)
{
    u8 idx;
    int i;
    f32 cur;
    f32 t;
    f32 frac;
    CreditsPage* page;
    u8 a;

    idx = lbl_803DD970;
    if (idx < 10)
    {
        t = lbl_803DD968;
        lbl_803DD968 = t + timeDelta;
        if (lbl_803DD968 >= gCreditsPages[idx].endTime)
        {
            lbl_803DD970 = idx + 1;
        }
        if (lbl_803DD970 < 10)
        {
            i = 0;
            cur = lbl_803DD968;
            page = &gCreditsPages[lbl_803DD970];
            for (; i < page->count; i++)
            {
                if (cur < page->lines[i].t0)
                {
                    a = 0;
                }
                else if (cur < page->lines[i].t1)
                {
                    frac = (cur - page->lines[i].t0) /
                        (f32)(page->lines[i].t1 - page->lines[i].t0);
                    if (frac < lbl_803E22A8)
                    {
                        frac = lbl_803E22A8;
                    }
                    else if (frac > lbl_803E22AC)
                    {
                        frac = lbl_803E22AC;
                    }
                    a = lbl_803E22B0 * frac;
                }
                else if (cur < page->lines[i].t2)
                {
                    a = 0xff;
                }
                else if (cur < page->lines[i].t3)
                {
                    frac = (cur - page->lines[i].t2) /
                        (f32)(page->lines[i].t3 - page->lines[i].t2);
                    if (frac < lbl_803E22A8)
                    {
                        frac = lbl_803E22A8;
                    }
                    else if (frac > lbl_803E22AC)
                    {
                        frac = lbl_803E22AC;
                    }
                    a = 0xff - (int)(lbl_803E22B0 * frac);
                }
                else
                {
                    a = 0;
                }
                page->lines[i].alpha = a;
                if (cur >= page->lines[i].t0 && cur <= page->lines[i].t3 &&
                    cur >= gCreditsPages[lbl_803DD970].scrollStartTime)
                {
                    page->lines[i].y = lbl_803E22B4 * (timeDelta / lbl_803E22B8) + page->lines[i].y;
                }
            }
        }
    }
    return 0;
}
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
