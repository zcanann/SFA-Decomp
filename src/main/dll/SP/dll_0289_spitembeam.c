/* DLL 0x289 - SPItemBeam [801E9328-801E9344) */
#include "main/dll/DR/dll_0287_spscarab.h"
#include "main/dll/shwgpipe_struct.h"

extern void spscarab_hitDetect(void);
extern void spscarab_render(void);
extern void spscarab_free(int x);
extern int spscarab_getObjectTypeId(void);
extern int spscarab_getExtraSize(void);

ObjectDescriptor gSPScarabObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)spscarab_initialise,
    (ObjectDescriptorCallback)spscarab_release,
    0,
    (ObjectDescriptorCallback)spscarab_init,
    (ObjectDescriptorCallback)spscarab_update,
    (ObjectDescriptorCallback)spscarab_hitDetect,
    (ObjectDescriptorCallback)spscarab_render,
    (ObjectDescriptorCallback)spscarab_free,
    (ObjectDescriptorCallback)spscarab_getObjectTypeId,
    spscarab_getExtraSize,
};

#include "main/objtexture.h"
#include "main/game_object.h"

typedef struct SpitembeamPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} SpitembeamPlacement;

extern int* ObjGroup_FindNearestObject(int group, int* obj, f32* dist);
extern f32 lbl_803E5AD8;

void spitembeam_init(int obj)
{
    ((GameObject*)obj)->objectFlags = (ushort)(((GameObject*)obj)->objectFlags | 0x6000);
}

void spdrape_release(void);

void spitembeam_free(void)
{
}

void spitembeam_render(void)
{
}

void spitembeam_hitDetect(void)
{
}

void spitembeam_release(void)
{
}

void spitembeam_initialise(void)
{
}

void spitembeam_update(int* obj)
{
    int* target;
    u8* def;
    ObjTextureRuntimeSlot* tex;
    f32 d;

    target = *(int**)&((GameObject*)obj)->unkF4;
    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    d = lbl_803E5AD8;
    if (target == NULL)
    {
        *(int**)&((GameObject*)obj)->unkF4 = ObjGroup_FindNearestObject(9, obj, &d);
    }
    else
    {
        if (((int(*)(int*, s16))(**(int***)((char*)target + 0x68))[10])(target, ((SpitembeamPlacement*)def)->unk1A) == 0
            || ((int(*)(int*, s16))(**(int***)((char*)target + 0x68))[11])(target, ((SpitembeamPlacement*)def)->unk1A)
            != 0)
        {
            ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
            ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x8000);
        }
        tex = objFindTexture(obj, 0, 0);
        if (tex != NULL)
        {
            tex->offsetS += 8;
            if (tex->offsetS > 0x400)
            {
                tex->offsetS -= 0x400;
            }
        }
    }
}

int spitembeam_getExtraSize(void) { return 0x0; }
int spitembeam_getObjectTypeId(void) { return 0x0; }

volatile ShWGPipe GXWGFifo : (0xCC008000);

static inline void shPos3f32(const f32 x, const f32 y, const f32 z)
{
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}

static inline void shColor4u8(const u8 r, const u8 g, const u8 b, const u8 a)
{
    GXWGFifo.u8 = r;
    GXWGFifo.u8 = g;
    GXWGFifo.u8 = b;
    GXWGFifo.u8 = a;
}

static inline void shTexCoord2f32(const f32 s, const f32 t)
{
    GXWGFifo.f32 = s;
    GXWGFifo.f32 = t;
}
