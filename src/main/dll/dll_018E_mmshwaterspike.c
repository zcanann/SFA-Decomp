/*
 * mmshwaterspike (DLL 0x18E) - rising water-spike hazard in Mushroom Mountain
 * (mmsh). Each instance tracks an XYZ-animator object by packed ID (stored at
 * unkF8) to read its current height; if the animator is missing it falls back to
 * hit-detect against nearby water surfaces. The spike rises toward a placement-
 * defined ceiling (maxHeight) and spawns a waterfx ripple when it surfaces.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/gameplay_runtime.h"
#include "main/dll/MMP/dll_013B_wallanimator.h"

/* placement block read via anim.placementData */
typedef struct MmshWaterspikePlacement
{
    u8 pad0[0xC - 0x0];
    f32 maxHeight;          /* 0x0C: Y ceiling the spike cannot exceed */
    u8 pad10[0x14 - 0x10];
    s32 xyzAnimId;          /* 0x14: ID of the XYZ-animator driving height (printed on miss) */
} MmshWaterspikePlacement;

/* object-def layout; unk1A/unk1C pack into the 32-bit XYZ-animator object ID */
typedef struct MmshWaterspikeObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 xyzAnimIdLow;       /* 0x1A: low 16 bits of the animator object ID */
    s16 xyzAnimIdHigh;      /* 0x1C: high 16 bits of the animator object ID */
    u8 pad1E[0x24 - 0x1E];
    u8 unk24;
    u8 pad25[0x28 - 0x25];
} MmshWaterspikeObjectDef;

extern void* ObjList_FindObjectById(int id);
extern void fn_80137948(char* fmt, ...);
extern char sWaterSpikeInvalidXyzAnimIdWarning[];
extern int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f);
extern u8 framesThisStep;
extern f32 lbl_803E4F80;
extern f32 lbl_803E4F84;
extern f32 lbl_803E4F88;

void mmsh_waterspike_free(void)
{
}

void mmsh_waterspike_hitDetect(void)
{
}

void mmsh_waterspike_release(void)
{
}

void mmsh_waterspike_initialise(void)
{
}

int mmsh_waterspike_getExtraSize(void) { return 0x0; }
int mmsh_waterspike_getObjectTypeId(void) { return 0x0; }
void mmsh_waterspike_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void mmsh_waterspike_update(int obj)
{
    void* o;
    int* p;
    int obj2;
    int n;
    int i;
    f32 d;
    f32 newY;
    f32 maxY;
    f32 dist;
    int* list;
    int placement;

    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    ObjHits_SetHitVolumeSlot(obj, 9, 1, 0);
    o = ObjList_FindObjectById(((GameObject*)obj)->unkF8);
    if (o != NULL)
    {
        dist = objFn_801948c0(o, 3) - ((GameObject*)obj)->anim.localPosY;
    }
    else
    {
        fn_80137948(sWaterSpikeInvalidXyzAnimIdWarning, ((MmshWaterspikePlacement*)placement)->xyzAnimId);
        n = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX,
                                 ((GameObject*)obj)->anim.localPosY,
                                 ((GameObject*)obj)->anim.localPosZ, &list, 0, 0);
        if (n != 0)
        {
            dist = lbl_803E4F80;
            p = list;
            for (i = 0; i < n; i++)
            {
                obj2 = *p;
                if (*(char*)(obj2 + 0x14) == 0xe)
                {
                    d = *(f32*)obj2 - ((GameObject*)obj)->anim.localPosY;
                    if (d > dist)
                    {
                        dist = d;
                    }
                }
                p = p + 1;
            }
        }
    }
    newY = ((GameObject*)obj)->anim.localPosY + dist;
    maxY = ((MmshWaterspikePlacement*)placement)->maxHeight;
    if (newY > maxY)
    {
        ((GameObject*)obj)->anim.localPosY = maxY;
    }
    else
    {
        ((GameObject*)obj)->anim.localPosY = newY;
        ((GameObject*)obj)->unkF4 = ((GameObject*)obj)->unkF4 - framesThisStep;
        if (((GameObject*)obj)->unkF4 <= 0)
        {
            ((GameObject*)obj)->unkF4 = randomGetRange(0x3c, 0xf0);
            if (lbl_803E4F84 == dist)
            {
                ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
                    ((GameObject*)obj)->anim.localPosX,
                    ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ, 0, lbl_803E4F88, 3);
            }
        }
    }
    return;
}

void mmsh_waterspike_init(int obj, s16* def)
{
    register u32 packedEventIds;
    register u32 lowEventId;
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->unkF4 = 0;
    packedEventIds = (u32)(u16)((MmshWaterspikeObjectDef*)def)->xyzAnimIdHigh << 16;
    lowEventId = (u32)(u16)((MmshWaterspikeObjectDef*)def)->xyzAnimIdLow;
    packedEventIds |= lowEventId;
    *(u32*)&((GameObject*)obj)->unkF8 = packedEventIds;
}

char sWaterSpikeInvalidXyzAnimIdWarning[] = "WARNING Water Spike [%d] as invalid xyzAnim ID\n";
