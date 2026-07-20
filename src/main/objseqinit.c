#include "main/objseq.h"
#include "main/mm.h"
#include "main/maketex_sequence_api.h"

extern u8 lbl_80396918[];
extern int gObjSeqStreamTableA[];
extern u8 lbl_803DB748[4];
extern f32 lbl_803DEFB0;
extern f32 lbl_803DEFF0;
extern u8 lbl_803DD124;
extern u8 gObjSeqCameraActive;
extern int gObjSeqCamMode;
extern int gObjSeqCamModeArgB;
extern int gObjSeqCamModeArgD;
extern u8 lbl_803DD0F8;
extern f32 lbl_803DD0DC;
extern void* lbl_803DD0D4;
extern s8 gObjSeqBgCmdCount;
extern void* lbl_803DD0B8;

void ObjSeq_onMapSetup(void)
{
    u8* base = lbl_80396918;
    u8* flagsB;
    u8* flagsA;
    s16* modes;
    u8* actions;
    u8* results;
    u8* states;
    u8* pending;
    f32* frames;
    f32* dists;
    int* handles;
    u8* counts;
    u8* marks;
    int i = 0;

    flagsB = base + 0x3b9c;
    flagsA = base + 0x3b44;
    modes = (s16*)(base + 0x3a98);
    actions = base + 0x3c4c;
    results = base + 0x3bf4;
    states = base + 0x3a40;
    pending = base + 0x39e8;
    frames = (f32*)(base + 0x3894);
    dists = (f32*)(base + 0x3740);
    counts = base + 0x3590;
    handles = (int*)(base + 0x33e4);
    marks = base + 0x338c;

    {
        for (; i < 0x50; i += 8)
        {
            flagsB[0] = 0;
            flagsA[0] = 0;
            modes[0] = 0;
            actions[0] = 0;
            results[0] = 0;
            states[0] = 0;
            pending[0] = 0;
            frames[0] = lbl_803DEFB0;
            dists[0] = lbl_803DEFF0;
            counts[0] = 0;
            handles[0] = 0;
            marks[0] = 0;
            flagsB[1] = 0;
            flagsA[1] = 0;
            modes[1] = 0;
            actions[1] = 0;
            results[1] = 0;
            states[1] = 0;
            pending[1] = 0;
            frames[1] = lbl_803DEFB0;
            dists[1] = lbl_803DEFF0;
            counts[1] = 0;
            handles[1] = 0;
            marks[1] = 0;
            flagsB[2] = 0;
            flagsA[2] = 0;
            modes[2] = 0;
            actions[2] = 0;
            results[2] = 0;
            states[2] = 0;
            pending[2] = 0;
            frames[2] = lbl_803DEFB0;
            dists[2] = lbl_803DEFF0;
            counts[2] = 0;
            handles[2] = 0;
            marks[2] = 0;
            flagsB[3] = 0;
            flagsA[3] = 0;
            modes[3] = 0;
            actions[3] = 0;
            results[3] = 0;
            states[3] = 0;
            pending[3] = 0;
            frames[3] = lbl_803DEFB0;
            dists[3] = lbl_803DEFF0;
            counts[3] = 0;
            handles[3] = 0;
            marks[3] = 0;
            flagsB[4] = 0;
            flagsA[4] = 0;
            modes[4] = 0;
            actions[4] = 0;
            results[4] = 0;
            states[4] = 0;
            pending[4] = 0;
            frames[4] = lbl_803DEFB0;
            dists[4] = lbl_803DEFF0;
            counts[4] = 0;
            handles[4] = 0;
            marks[4] = 0;
            flagsB[5] = 0;
            flagsA[5] = 0;
            modes[5] = 0;
            actions[5] = 0;
            results[5] = 0;
            states[5] = 0;
            pending[5] = 0;
            frames[5] = lbl_803DEFB0;
            dists[5] = lbl_803DEFF0;
            counts[5] = 0;
            handles[5] = 0;
            marks[5] = 0;
            flagsB[6] = 0;
            flagsA[6] = 0;
            modes[6] = 0;
            actions[6] = 0;
            results[6] = 0;
            states[6] = 0;
            pending[6] = 0;
            frames[6] = lbl_803DEFB0;
            dists[6] = lbl_803DEFF0;
            counts[6] = 0;
            handles[6] = 0;
            marks[6] = 0;
            flagsB[7] = 0;
            flagsA[7] = 0;
            modes[7] = 0;
            actions[7] = 0;
            results[7] = 0;
            states[7] = 0;
            pending[7] = 0;
            frames[7] = lbl_803DEFB0;
            dists[7] = lbl_803DEFF0;
            counts[7] = 0;
            handles[7] = 0;
            marks[7] = 0;
            flagsB += 8;
            flagsA += 8;
            modes += 8;
            actions += 8;
            results += 8;
            states += 8;
            pending += 8;
            frames += 8;
            dists += 8;
            counts += 8;
            handles += 8;
            marks += 8;
        }
    }

    {
        u8* p = base + i;
        modes = (s16*)(base + 0x3a98) + i;
        handles = (int*)(base + 0x33e4) + i;
        marks = p + 0x338c;
        for (; i < 85; i++)
        {
            frames = (f32*)(handles + 300);
            dists = (f32*)(handles + 215);
            flagsA = marks + 0x810;
            flagsB = marks + 0x7b8;
            actions = marks + 0x8c0;
            results = marks + 0x868;
            states = marks + 0x6b4;
            pending = marks + 0x65c;
            counts = marks + 0x204;
            flagsA[0] = 0;
            flagsB[0] = 0;
            modes[0] = 0;
            actions[0] = 0;
            results[0] = 0;
            states[0] = 0;
            pending[0] = 0;
            frames[0] = lbl_803DEFB0;
            dists[0] = lbl_803DEFF0;
            counts[0] = 0;
            handles[0] = 0;
            marks[0] = 0;
            modes++;
            handles++;
            marks++;
        }
    }

    lbl_803DD124 = 0;
    gObjSeqCamMode = 0;
    gObjSeqCameraActive = 0;
    lbl_803DD0DC = lbl_803DEFB0;
    lbl_803DD0B8 = NULL;
    lbl_803DD0F8 = 0;
    gObjSeqBgCmdCount = 0;
}

void ObjSeq_release(void)
{
    mm_free(lbl_803DD0D4);
}

void ObjSeq_initialise(void)
{
    lbl_803DD0D4 = mmAlloc(0x10, 0x11, 0);
    ObjSeq_onMapSetup();
    gObjSeqCamModeArgB = 1;
    gObjSeqCamModeArgD = 0x5a;
    gObjSeqCamMode = 0x42;
    objSeqInitFn_80080078(gObjSeqStreamTableA, 5);
}

void fn_80088730(u8* out)
{
    u8* src;

    out[0] = lbl_803DB748[0];
    src = lbl_803DB748;
    out[1] = src[1];
    out[2] = src[2];
    out[3] = src[3];
}
