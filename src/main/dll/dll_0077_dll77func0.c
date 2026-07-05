/*
 * dll77func0 (DLL 0x77) - particle-effect spawner.
 *
 * dll_77_func03 builds a 6-command GfxCmd list and hands it to
 * gModgfxInterface->spawnEffect; the two nop leaves are the DLL's
 * empty func00/func01 entry points.
 */
#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/effect_interfaces.h"

typedef struct GfxCmd
{
    u32 mode;
    f32 x, y, z;
    void* tex;
    s16 flags;
    u8 layer;
} GfxCmd;

STATIC_ASSERT(sizeof(GfxCmd) == 0x18);

extern ModgfxInterface** gModgfxInterface;

extern u8 lbl_80314980[];

/* referenced via *(f32*)& so the 0.0 base keeps its additive fadds (a literal
   0.0f + pos folds away) and the pool stays in address order */
static const f32 gDll77Cmd0X = 999.0f;
static const f32 gDll77Cmd0Y = 85.0f;
static const f32 gDll77Cmd0Z = 86.0f;
static const f32 gDll77Zero = 0.0f;
static const f32 gDll77CmdY = 200.0f;
static const f32 gDll77Scale = 1.0f;

void dll_77_func03(int sourceObj, int variant, int posSource, u32 flags)
{
    struct
    {
        GfxCmd* cmds;
        int ctx;
        u8 pad0[0x18];
        f32 col[3];
        f32 pos[3];
        f32 scale;
        u32 v3c;
        u32 v40;
        s16 variantId;
        s16 hw[7];
        u32 flags;
        u8 v58, v59, v5a, v5b, v5c;
        s8 count;
        u8 pad1[2];
        GfxCmd entries[32];
    } buf;
    GfxCmd* e = buf.entries;
    int ctx;
    e[0].layer = 0;
    e[0].flags = 0x8c;
    e[0].tex = NULL;
    e[0].mode = 0x20000000;
    e[0].x = *(f32*)&gDll77Cmd0X;
    e[0].y = *(f32*)&gDll77Cmd0Y;
    e[0].z = *(f32*)&gDll77Cmd0Z;
    e[1].layer = 0;
    e[1].flags = 0;
    e[1].tex = NULL;
    e[1].mode = 0x80000;
    e[1].x = *(f32*)&gDll77Zero;
    e[1].y = *(f32*)&gDll77CmdY;
    e[1].z = *(f32*)&gDll77Zero;
    e[2].layer = 1;
    e[2].flags = 0;
    e[2].tex = NULL;
    e[2].mode = 0x80000;
    e[2].x = *(f32*)&gDll77Zero;
    e[2].y = *(f32*)&gDll77Zero;
    e[2].z = *(f32*)&gDll77Zero;
    e[3].layer = 3;
    e[3].flags = 1;
    e[3].tex = NULL;
    e[3].mode = 0x2000;
    e[3].x = *(f32*)&gDll77Zero;
    e[3].y = *(f32*)&gDll77Zero;
    e[3].z = *(f32*)&gDll77Zero;
    e[4].layer = 4;
    e[4].flags = 0;
    e[4].tex = NULL;
    e[4].mode = 0x80000;
    e[4].x = *(f32*)&gDll77Zero;
    e[4].y = *(f32*)&gDll77CmdY;
    e[4].z = *(f32*)&gDll77Zero;
    e[5].layer = 5;
    e[5].flags = 0;
    e[5].tex = NULL;
    e[5].mode = 0x20000000;
    e[5].x = *(f32*)&gDll77Cmd0X;
    e[5].y = *(f32*)&gDll77Cmd0Y;
    e[5].z = *(f32*)&gDll77Cmd0Z;
    buf.v58 = 0;
    ctx = sourceObj;
    buf.ctx = ctx;
    buf.variantId = variant;
    buf.pos[0] = *(f32*)&gDll77Zero;
    buf.pos[1] = *(f32*)&gDll77Zero;
    buf.pos[2] = *(f32*)&gDll77Zero;
    buf.col[0] = *(f32*)&gDll77Zero;
    buf.col[1] = *(f32*)&gDll77Zero;
    buf.col[2] = *(f32*)&gDll77Zero;
    buf.scale = *(f32*)&gDll77Scale;
    buf.v40 = 0;
    buf.v3c = 0;
    buf.v59 = 0;
    buf.v5a = 0;
    buf.v5b = 0;
    buf.count = (e + 6) - buf.entries;
    buf.hw[0] = *(s16*)&lbl_80314980[0];
    buf.hw[1] = *(s16*)&lbl_80314980[2];
    buf.hw[2] = *(s16*)&lbl_80314980[4];
    buf.hw[3] = *(s16*)&lbl_80314980[6];
    buf.hw[4] = *(s16*)&lbl_80314980[8];
    buf.hw[5] = *(s16*)&lbl_80314980[10];
    buf.hw[6] = *(s16*)&lbl_80314980[12];
    buf.cmds = buf.entries;
    buf.flags = 0x10c00;
    buf.flags |= flags;
    if ((buf.flags & 1) != 0)
    {
        if ((u32)ctx != 0)
        {
            buf.pos[0] = *(f32*)&gDll77Zero + ((GameObject*)ctx)->anim.worldPosX;
            buf.pos[1] = *(f32*)&gDll77Zero + ((GameObject*)ctx)->anim.worldPosY;
            buf.pos[2] = *(f32*)&gDll77Zero + ((GameObject*)ctx)->anim.worldPosZ;
        }
        else
        {
            buf.pos[0] = *(f32*)&gDll77Zero + ((PartFxSpawnParams*)posSource)->posX;
            buf.pos[1] = *(f32*)&gDll77Zero + ((PartFxSpawnParams*)posSource)->posY;
            buf.pos[2] = *(f32*)&gDll77Zero + ((PartFxSpawnParams*)posSource)->posZ;
        }
    }
    (*gModgfxInterface)->spawnEffect(&buf, 0, 0, 0, 0, 0, 0, 0);
}

void dll_77_func01_nop(void)
{
}

void dll_77_func00_nop(void)
{
}
