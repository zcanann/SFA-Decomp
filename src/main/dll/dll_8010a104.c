#include "main/dll/CAM/camshipbattle5C.h"
#include "main/audio/sfx.h"
#include "main/camera_interface.h"
#include "main/dll/CAM/camdebug_state.h"
#include "main/dll/CAM/dll_0045_camTalk.h"
#include "main/dll/CAM/camstatic_state.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/CAM/viewfinder_state.h"
#include "main/dll/CAM/dll_5B.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/pad.h"

extern f32 lbl_803E1888;
extern f32 lbl_803E188C;
extern f32 fn_8010AC48(int* window, f32 x, f32 y, f32 z);

void fn_8010A104(int* p1, int* p2, f32 x, f32 y, f32 z, int tag)
{
    int curve;
    int linked;
    int found;
    int i;
    int k;
    int window[4];
    int count;
    int dummy;
    int done;
    f32 dist;

    curve = (int)(*gRomCurveInterface)->getById(*p1);
    found = 1;
    for (i = 0; i < 5; i++)
    {
        if (*(int*)(curve + i * 4 + 28) > -1 &&
            ((s8) * (s8*)(curve + 27) & (1 << i)) == 0)
        {
            linked = (int)(*gRomCurveInterface)->getById(*(int*)(curve + i * 4 + 28));
            if ((u32)linked != 0 &&
                (*(u8*)(linked + 49) == tag || *(u8*)(linked + 50) == tag ||
                    *(u8*)(linked + 51) == tag))
            {
                found = 0;
                i = 5;
            }
        }
    }
    if (found != 0)
    {
        for (i = 0; i < 5; i++)
        {
            if (*(int*)(curve + i * 4 + 28) > -1 &&
                ((s8) * (s8*)(curve + 27) & (1 << i)) != 0)
            {
                linked = (int)(*gRomCurveInterface)->getById(*(int*)(curve + i * 4 + 28));
                if ((u32)linked != 0 &&
                    (*(u8*)(linked + 49) == tag || *(u8*)(linked + 50) == tag ||
                        *(u8*)(linked + 51) == tag))
                {
                    *p1 = *(int*)(curve + i * 4 + 28);
                    i = 5;
                }
            }
        }
    }
    done = 0;
    do
    {
        f32 thresh = lbl_803E1888;
        done = 1;
        curve = (int)(*gRomCurveInterface)->getById(*p1);
        pathcam_findTaggedNodeWindow((u8*)curve, window, tag);
        dist = fn_8010AC48(window, x, y, z);
        if (dist < thresh)
        {
            if (window[0] > -1)
            {
                *p1 = window[0];
                done = 0;
            }
        }
        else if (dist > lbl_803E188C)
        {
            if (window[2] > -1 && window[3] > -1)
            {
                *p1 = window[2];
                done = 0;
            }
        }
    }
    while (done == 0);
    curve = (int)(*gRomCurveInterface)->getById(*p1);
    fn_8010A47C(curve, &count, tag);
    curve = (int)(*gRomCurveInterface)->getById(*p2);
    *p2 = *(int*)(fn_8010A47C(curve, &dummy, tag) + 20);
    for (k = 0; k < count; k++)
    {
        curve = (int)(*gRomCurveInterface)->getById(*p2);
        for (i = 0; i < 5; i++)
        {
            if (*(int*)(curve + i * 4 + 28) > -1 &&
                ((s8) * (s8*)(curve + 27) & (1 << i)) == 0)
            {
                linked = (int)(*gRomCurveInterface)->getById(*(int*)(curve + i * 4 + 28));
                if ((u32)linked != 0 &&
                    (*(u8*)(linked + 49) == tag || *(u8*)(linked + 50) == tag ||
                        *(u8*)(linked + 51) == tag))
                {
                    *p2 = *(int*)(curve + i * 4 + 28);
                    i = 5;
                }
            }
        }
    }
}

int fn_8010A47C(int curve, int* count, int tag)
{
    int i;
    int done;
    int linked;

    done = 0;
    *count = 0;
    while (done == 0)
    {
        done = 1;
        if ((*(char*)(curve + 0x19) != '\x1b') && (*(char*)(curve + 0x19) != '\x1a'))
        {
            for (i = 0; i < 5; i = i + 1)
            {
                if ((*(int*)(curve + i * 4 + 0x1c) > -1) &&
                    (((int)*(char*)(curve + 0x1b) & (1 << i)) != 0))
                {
                    linked = (int)(*gRomCurveInterface)->getById(*(int*)(curve + i * 4 + 0x1c));
                    if (((u32)linked != 0) &&
                        ((*(u8*)(linked + 0x31) == tag || (*(u8*)(linked + 0x32) == tag)) ||
                            (*(u8*)(linked + 0x33) == tag)))
                    {
                        curve = linked;
                        done = 0;
                        i = 5;
                    }
                }
            }
        }
        if (done == 0)
        {
            *count = *count + 1;
        }
    }
    return curve;
}

