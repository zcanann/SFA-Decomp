#include "main/shader_api.h"
#include "main/sky_api.h"
#include "main/lightmap_render_queue_api.h"
#include "main/model_render_instrs_api.h"
#include "main/newclouds.h"
#include "main/objprint_render_api.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"
#include "main/pi_dolphin.h"
#include "dolphin/gx/GXLighting.h"
#include "main/sky_state.h"
#include "main/track_dolphin_api.h"
#include "main/mm.h"
#include "string.h"
#include "main/rcp_dolphin.h"
#include "main/dll/dll_0000_gameui.h"
#include "main/dll/dll_0031_minimap.h"
#include "main/sky.h"
#include "track/intersect_api.h"
#include "track/intersect_render_setup_api.h"
#include "main/trig.h"
#include "main/tex_dolphin.h"
#include "main/acosf_api.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXTransform.h"
#include "main/asset_load.h"

#include "main/lightmap_internal.h"
#include "main/dll/ppcwgpipe_struct.h"


#include "main/render_flags.h"
#include "main/lightmap_lifecycle_api.h"




volatile PPCWGPipe GXWGFifo : (0xCC008000);

static inline void GXPosition3s16(const s16 x, const s16 y, const s16 z)
{
    GXWGFifo.s16 = x;
    GXWGFifo.s16 = y;
    GXWGFifo.s16 = z;
}
static inline void GXColor4u8(const u8 r, const u8 g, const u8 b, const u8 a)
{
    GXWGFifo.u8 = r;
    GXWGFifo.u8 = g;
    GXWGFifo.u8 = b;
    GXWGFifo.u8 = a;
}
static inline void GXTexCoord2s16(const s16 s, const s16 t)
{
    GXWGFifo.s16 = s;
    GXWGFifo.s16 = t;
}
static inline void GXPosition1x8(const u8 x) { GXWGFifo.u8 = x; }


extern u32 gLightmapDrawQueue[];






#define MAP_BLOCK_LAYER_COUNT 5


static inline void fillBoxRows(u8* map, int* box)
{
    int y, x0;
    int xs, xe;
    u8* p;
    for (y = box[2]; y <= box[3]; y++)
    {
        xs = box[0];
        p = map + (y + 7) * 0x10 + xs;
        xe = box[1];
        for (x0 = xs; x0 <= xe; x0++)
        {
            p[7] = 1;
            p++;
        }
    }
}

void initMapBlocks(void)
{
    u8* mb = (u8*)gLightmapDrawQueue;
    MapLayerBuffers* buffers = (MapLayerBuffers*)gLightmapDrawQueue;
    u32 zero;
    u32* q;
    u16* p;
    void* tmp;
    int i;

    renderFlags = 0;
    gMapBlocks = mmAlloc(64 * sizeof(MapBlockData*), 5, 0);
    gMapBlockIds = mmAlloc(0x80, 5, 0);
    gMapBlockRefCounts = mmAlloc(0x40, 5, 0);
    gMapInfoBuffer = mmAlloc(0xd48, 5, 0);
    buffers->blockIndices[0] = mmAlloc(0x500, 5, 0);
    buffers->blockDescriptors[0] = mmAlloc(0x3c00, 5, 0);
    buffers->cellStates[0] = mmAlloc(0x500, 5, 0);

    for (i = 0; i < 16; i += 4)
    {
        *(u32*)(mb + 0x41f8 + i) = *(u32*)(mb + 0x41f4 + i) + 0x100;
        *(u32*)(mb + 0x41e4 + i) = *(u32*)(mb + 0x41e0 + i) + 0xc00;
        *(u32*)(mb + 0x41d0 + i) = *(u32*)(mb + 0x41cc + i) + 0x100;
    }

    loadAssetFileById(&gMapsTab, MLDF_FILEID_MAPS_TAB);
    loadAssetFileById(&gHitsTab, MLDF_FILEID_HITS_TAB);

    q = (u32*)((u8*)(mb + 0x10000) - 0x7c58);
    zero = 0;
    for (i = 0; i < 3; i++)
    {
        q[0] = zero;
        q[1] = zero;
        q[2] = zero;
        q[3] = zero;
        q[4] = zero;
        q[5] = zero;
        q[6] = zero;
        q[7] = zero;
        q[8] = zero;
        q[9] = zero;
        q[10] = zero;
        q[11] = zero;
        q[12] = zero;
        q[13] = zero;
        q[14] = zero;
        q[15] = zero;
        q[16] = zero;
        q[17] = zero;
        q[18] = zero;
        q[19] = zero;
        q[20] = zero;
        q[21] = zero;
        q[22] = zero;
        q[23] = zero;
        q[24] = zero;
        q[25] = zero;
        q[26] = zero;
        q[27] = zero;
        q[28] = zero;
        q[29] = zero;
        q[30] = zero;
        q[31] = zero;
        q[32] = zero;
        q[33] = zero;
        q[34] = zero;
        q[35] = zero;
        q[36] = zero;
        q[37] = zero;
        q[38] = zero;
        q[39] = zero;
        q += 40;
    }

    loadAssetFileById(&gTrkBlkTab, MLDF_FILEID_TRKBLK_TAB);

    gTrkBlkTabCount = 0;
    p = gTrkBlkTab;
    while (*p != 0xffff)
    {
        p++;
        gTrkBlkTabCount++;
    }
    gTrkBlkTabCount--;
    gPendingWarpIndex = -1;
    gArrivedWarpIndex = -2;

    tmp = mmAlloc(80 * sizeof(MapTextureOverride), 5, 0);
    gMapTextureOverrides = tmp;
    memset(tmp, 0, 80 * sizeof(MapTextureOverride));

    tmp = mmAlloc(0x3a0, 5, 0);
    gMapTextureScrolls = tmp;
    memset(tmp, 0, 0x3a0);

    memset(mb + 0x8818, 0, 0xfa0);
    *(u32*)(mb + 0x8818) = -1;
}

