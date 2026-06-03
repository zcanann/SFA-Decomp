#include "ghidra_import.h"

extern int synthGetNextChannelEvent(u8 i);
extern void synthInsertChannelEvent(int slot, int item);

extern int gSynthCurrentVoice;

/*
 * fn_8026E0E4 - large voice/MIDI dispatch (~1920 instructions). Stubbed.
 */
#pragma dont_inline on
int fn_8026E0E4(int event, u8 voice, u32 *flag)
{
    return 0;
}
#pragma dont_inline reset

/*
 * Iterate 64 voice slots: for each active one, append it to the studio's
 * voice list. Uses an indirection table when present.
 *
 * EN v1.1 Address: 0x8026E864, size 168b
 */
void fn_8026E864(void)
{
    u32 i;
    u32 x;
    if (*(u32 *)(gSynthCurrentVoice + 0x14e4) == 0) {
        for (i = 0; i < 0x40; i++) {
            x = synthGetNextChannelEvent((u8)i);
            if (x != 0) {
                synthInsertChannelEvent(gSynthCurrentVoice + 0x14e8, x);
            }
        }
    } else {
        for (i = 0; i < 0x40; i++) {
            x = synthGetNextChannelEvent((u8)i);
            if (x != 0) {
                u8 *table = *(u8 **)(gSynthCurrentVoice + 0x14e4);
                synthInsertChannelEvent(gSynthCurrentVoice + table[i] * 0x38 + 0x14e8, x);
            }
        }
    }
}

void fn_8026E90C(u8 voice)
{
    u32 group;
    u32 queueOffset;
    u32 i;
    u32 x;

    if (*(u32 *)(gSynthCurrentVoice + 0x14e4) == 0) {
        for (i = 0; i < 0x40; i++) {
            x = synthGetNextChannelEvent((u8)i);
            if (x != 0) {
                synthInsertChannelEvent(gSynthCurrentVoice + 0x14e8, x);
            }
        }
    } else {
        group = voice & 0xff;
        queueOffset = group * 0x38;
        for (i = 0; i < 0x40; i++) {
            if (group == *(u8 *)(*(u32 *)(gSynthCurrentVoice + 0x14e4) + i)) {
                x = synthGetNextChannelEvent((u8)i);
                if (x != 0) {
                    synthInsertChannelEvent(gSynthCurrentVoice + queueOffset + 0x14e8, x);
                }
            }
        }
    }
}

extern int fn_8026CF78(u8 voice);

extern void fn_8026E90C(u8 voice);
extern f32 floorf(f32 x);
extern f32 lbl_803E7780;
extern f32 lbl_803E7784;
extern f32 lbl_803E7788;

#pragma dont_inline on
#pragma fp_contract off
int fn_8026E9D0(u8 voice, u32 param)
{
    u8 *vp;
    u8 *vp2;
    u8 *event;
    u32 v;
    int res;
    f32 k80;
    f32 k84;
    f32 k88;
    f64 k88abs;
    f32 ftotal;
    f32 fm;
    u32 flag;

    flag = 0;
    k88 = lbl_803E7788;
    k88abs = __fabs(k88);
    k80 = lbl_803E7780;
    k84 = lbl_803E7784;
    vp = (u8 *)(gSynthCurrentVoice + voice * 56 + 0x14e8);
    while (((event = *(u8 **)(vp + 0x1c)) == NULL ? 0 : *(u32 *)(event + 8))
           <= *(u32 *)(vp + *(u8 *)(vp + 0x30) * 8 + 0x24)) {
        if (event != NULL) {
            *(u8 **)(vp + 0x1c) = *(u8 **)event;
            if (*(int *)event != 0) {
                *(int *)(*(int *)(vp + 0x1c) + 4) = 0;
            }
        }
        if (event != NULL) {
            res = fn_8026E0E4((int)event, voice, &flag);
            if (res != 0) {
                synthInsertChannelEvent((int)vp, res);
            }
        } else {
            if (flag == 0) {
                return 0;
            }
            flag = 0;
            *(u8 *)(vp + 0x30) ^= 1;
            *(u32 *)(vp + *(u8 *)(vp + 0x30) * 8 + 0x24) = *(u32 *)(*(int *)(gSynthCurrentVoice + 0x118) + voice * 4 + 0x14);
            *(u32 *)(vp + *(u8 *)(vp + 0x30) * 8 + 0x20) = *(u32 *)(vp + (*(u8 *)(vp + 0x30) ^ 1) * 8 + 0x20);
            if (*(void **)(gSynthCurrentVoice + voice * 56 + 0x14e8) != NULL) {
                *(int *)(gSynthCurrentVoice + voice * 56 + 0x14ec) = *(int *)(gSynthCurrentVoice + voice * 56 + 0x14e8);
                fn_8026CF78(voice);
                vp2 = (u8 *)(gSynthCurrentVoice + voice * 56 + 0x14e8);
                fm = k80 * ((f32)*(u32 *)(vp2 + 8) * (f32)param) * (k84 * (f32)*(u16 *)(vp2 + 0x32));
                ftotal = k88 * fm;
                if (k88abs > __fabs(ftotal)) {
                } else {
                    ftotal -= k88 * (f32)(s64)(u64)(ftotal / k88);
                }
                *(u32 *)(vp2 + *(u8 *)(vp2 + 0x30) * 8 + 0xc) = (u32)ftotal;
                *(u32 *)(vp2 + *(u8 *)(vp2 + 0x30) * 8 + 0x10) = (int)floorf(fm);
            }
            *(u16 *)(vp + 0x34) += 1;
            fn_8026E90C(voice);
        }
    }
    return 1;
}
#pragma fp_contract reset
#pragma dont_inline reset
