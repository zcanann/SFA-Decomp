/*
 * DLL 0x299 - an ambient particle-effect object.
 *
 * On init it stores a placement-supplied s16 id into its 2-byte extra
 * state, acquires resource 0xA6, and seeds three 0x545 and one 0x546
 * particle bursts. Each update tick it randomly (1-in-3) invokes vtable
 * slot 1 of the acquired resource, then spawns three 0x547 particles.
 * On free it releases the exp/mod-gfx sources and the acquired resource.
 * Render/hitDetect/release/initialise are stubs.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

typedef struct
{
    void* pad;
    void (*slot1)(int, int, int, int, int, int);
} Dll299Vtable;

typedef struct
{
    s16 id;
} Dll299State;

#define DLL0299_OBJFLAG_HITDETECT_DISABLED 0x2000

#define DLL0299_RESOURCE_ID 0xa6

/* main particle burst seeded 3x once at init */
#define DLL0299_PARTFX_INIT 0x545
/* second distinct particle seeded once at init alongside the INIT trio */
#define DLL0299_PARTFX_INIT2 0x546
/* ambient particle burst spawned 3x every update tick */
#define DLL0299_PARTFX_AMBIENT 0x547

int dll_299_getExtraSize_ret_2(void)
{
    return 0x2;
}

int dll_299_getObjectTypeId(void)
{
    return 0x0;
}

void dll_299_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    (*gModgfxInterface)->freeSourceEffects((void*)obj);
    Resource_Release(lbl_803DDD80);
    lbl_803DDD80 = NULL;
}

void dll_299_render_nop(void)
{
}

void dll_299_hitDetect_nop(void)
{
}

void dll_299_update(int obj)
{
    if (randomGetRange(0, 2) == 0)
    {
        (*(Dll299Vtable**)lbl_803DDD80)->slot1(obj, 1, 0, 4, -1, 0);
    }
    (*gPartfxInterface)->spawnObject((void*)obj, DLL0299_PARTFX_AMBIENT, NULL, 4, -1, NULL);
    (*gPartfxInterface)->spawnObject((void*)obj, DLL0299_PARTFX_AMBIENT, NULL, 4, -1, NULL);
    (*gPartfxInterface)->spawnObject((void*)obj, DLL0299_PARTFX_AMBIENT, NULL, 4, -1, NULL);
}

void dll_299_init(struct GameObject* obj, int setup)
{
    ((Dll299State*)obj->extra)->id = *(s16*)(setup + 0x1e);
    obj->objectFlags |= DLL0299_OBJFLAG_HITDETECT_DISABLED;
    lbl_803DDD80 = Resource_Acquire(DLL0299_RESOURCE_ID, 1);
    (*gPartfxInterface)->spawnObject((void*)obj, DLL0299_PARTFX_INIT, NULL, 0x802, -1, NULL);
    (*gPartfxInterface)->spawnObject((void*)obj, DLL0299_PARTFX_INIT, NULL, 0x802, -1, NULL);
    (*gPartfxInterface)->spawnObject((void*)obj, DLL0299_PARTFX_INIT, NULL, 0x802, -1, NULL);
    (*gPartfxInterface)->spawnObject((void*)obj, DLL0299_PARTFX_INIT2, NULL, 0x802, -1, NULL);
}

void dll_299_release_nop(void)
{
}

void dll_299_initialise_nop(void)
{
}
