/*
 * vfpobjcreator (DLL 0x217, VFP_ObjCreator) - an invisible spawner
 * object in the Volcano Force Point Temple.
 *
 * While loading is locked it periodically allocates and launches one of
 * two kinds of object setup, selected by the placement's spawnMode:
 *  - mode 1 (falling): spawns object 0x263 within a random radius around
 *    the spawner, gated on an optional game bit, with randomised spin
 *    and downward/outward velocity;
 *  - mode 6 (projectile): spawns object 0x549 burst at the spawner's
 *    position, aimed by the spawner's pitch, with launch sfx + particle
 *    trails.
 * The spawn cadence is driven by spawnTimer counting down spawnInterval.
 */
#include "main/dll/VF/vf_shared.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/VF/dll_0217_vfpobjcreator.h"

#define VFPOBJCREATOR_OBJFLAG_HITDETECT_DISABLED 0x2000

#define VFP_OBJCREATOR_FALLING_MODE    1
#define VFP_OBJCREATOR_PROJECTILE_MODE 6

#define VFP_OBJCREATOR_FALLING_OBJECT_ID    0x263
#define VFP_OBJCREATOR_PROJECTILE_OBJECT_ID 0x549

extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern char* Obj_SetupObject(u8* setup, int a, int b, int c, int d);
extern void vecRotateZXY(s16* angles, f32* vec);

int VFP_ObjCreator_getExtraSize(void)
{
    return 0xa;
}

int VFP_ObjCreator_getObjectTypeId(void)
{
    return 0x0;
}

void VFP_ObjCreator_free(void)
{
}

void VFP_ObjCreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
        return;
}

void VFP_ObjCreator_hitDetect(void)
{
}

void VFP_ObjCreator_update(int* obj)
{
    VfpObjCreatorPlacement* placement = (VfpObjCreatorPlacement*)((GameObject*)obj)->anim.placementData;
    VfpObjCreatorState* state = ((GameObject*)obj)->extra;

    if (Obj_IsLoadingLocked() == 0)
    {
        return;
    }
    switch (placement->spawnMode)
    {
    case 0:
        break;
    case VFP_OBJCREATOR_FALLING_MODE:
        if ((u32)mainGetBit(state->gameBit) == 0 && state->gameBit != -1)
        {
            break;
        }
        state->spawnTimer -= (s16)timeDelta;
        if (state->spawnTimer <= 0)
        {
            u8* setupBuf;
            char* spawned;
            state->spawnTimer = state->spawnInterval;
            setupBuf = Obj_AllocObjectSetup(0x28, VFP_OBJCREATOR_FALLING_OBJECT_ID);
            ((VfpObjCreatorSetup*)setupBuf)->base.color[2] = 0xff;
            ((VfpObjCreatorSetup*)setupBuf)->base.color[3] = 0xff;
            ((VfpObjCreatorSetup*)setupBuf)->base.color[0] = 2;
            ((VfpObjCreatorSetup*)setupBuf)->base.color[1] = 1;
            ((VfpObjCreatorSetup*)setupBuf)->base.posX =
                ((GameObject*)obj)->anim.localPosX + (f32)(int)randomGetRange(-state->spawnRadius, state->spawnRadius);
            ((VfpObjCreatorSetup*)setupBuf)->base.posY = ((GameObject*)obj)->anim.localPosY;
            ((VfpObjCreatorSetup*)setupBuf)->base.posZ =
                ((GameObject*)obj)->anim.localPosZ + (f32)(int)randomGetRange(-state->spawnRadius, state->spawnRadius);
            ((VfpObjCreatorSetup*)setupBuf)->unk20 = 0x50;
            ((VfpObjCreatorSetup*)setupBuf)->unk1E = (s16)(randomGetRange(0, 2) + 0x16a);
            ((VfpObjCreatorSetup*)setupBuf)->unk22 = -1;
            ((VfpObjCreatorSetup*)setupBuf)->unk18 = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            ((VfpObjCreatorSetup*)setupBuf)->unk1A = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            ((VfpObjCreatorSetup*)setupBuf)->unk1C = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            ((VfpObjCreatorSetup*)setupBuf)->unk24 = 0;
            spawned = Obj_SetupObject(setupBuf, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                      *(int*)&((GameObject*)obj)->anim.parent);
            if (spawned == NULL)
            {
                break;
            }
            ((GameObject*)spawned)->anim.velocityY = 0.01f * (f32)(int)randomGetRange(0, 10) + 0.1f;
            ((GameObject*)spawned)->anim.velocityX = 0.2f * (f32)(int)randomGetRange(-10, 10);
            ((GameObject*)spawned)->anim.velocityZ = 0.2f * (f32)(int)randomGetRange(-10, 10);
        }
        break;
    case VFP_OBJCREATOR_PROJECTILE_MODE:
        state->spawnTimer -= (s16)timeDelta;
        if (state->spawnTimer <= 0)
        {
            u8* setupBuf;
            char* spawned;
            struct
            {
                s16 ang[3];
                f32 v[4];
            } launch;
            state->spawnTimer = state->spawnInterval;
            setupBuf = Obj_AllocObjectSetup(0x24, VFP_OBJCREATOR_PROJECTILE_OBJECT_ID);
            ((VfpObjCreatorSetup*)setupBuf)->base.posX = placement->base.posX;
            ((VfpObjCreatorSetup*)setupBuf)->base.posY = placement->base.posY;
            ((VfpObjCreatorSetup*)setupBuf)->base.posZ = placement->base.posZ;
            ((VfpObjCreatorSetup*)setupBuf)->base.color[0] = placement->base.color[0];
            ((VfpObjCreatorSetup*)setupBuf)->base.color[1] = placement->base.color[1];
            ((VfpObjCreatorSetup*)setupBuf)->base.color[2] = placement->base.color[2];
            ((VfpObjCreatorSetup*)setupBuf)->base.color[3] = placement->base.color[3];
            ((VfpObjCreatorSetup*)setupBuf)->unk1E = -1;
            ((VfpObjCreatorSetup*)setupBuf)->unk20 = -1;
            spawned = Obj_SetupObject(setupBuf, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                      *(int*)&((GameObject*)obj)->anim.parent);
            if (spawned == NULL)
            {
                break;
            }
            ((GameObject*)spawned)->unkF8 = 0x1f4;
            {
                f32 vz;
                f32 vxy = 0.0f;
                ((GameObject*)spawned)->anim.velocityY = vxy;
                ((GameObject*)spawned)->anim.velocityX = vxy;
                vz = 1.0f;
                ((GameObject*)spawned)->anim.velocityZ = vz;
                launch.v[1] = vxy;
                launch.v[2] = vxy;
                launch.v[3] = vxy;
                launch.v[0] = vz;
            }
            launch.ang[2] = 0;
            launch.ang[1] = 0;
            launch.ang[0] = ((GameObject*)obj)->anim.rotX;
            vecRotateZXY(launch.ang, (f32*)(spawned + 0x24));
            Sfx_PlayFromObject((int)spawned, SFXTRIG_id_10c);
            (*gPartfxInterface)->spawnObject(spawned, 0x39a, NULL, 0x10002, -1, NULL);
            (*gPartfxInterface)->spawnObject(spawned, 0x39b, NULL, 0x10002, -1, NULL);
            (*gPartfxInterface)->spawnObject(spawned, 0x39c, NULL, 0x10002, -1, NULL);
        }
        break;
    }
}

void VFP_ObjCreator_init(int* obj, u8* init)
{
    VfpObjCreatorPlacement* placement = (VfpObjCreatorPlacement*)init;
    VfpObjCreatorState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)(placement->rotXByte << 8);
    state->gameBit = placement->gameBit;
    state->spawnInterval = placement->spawnInterval;
    state->spawnTimer = state->spawnInterval;
    state->spawnParam = placement->spawnParam;
    state->spawnRadius = placement->spawnRadius;
    ((GameObject*)obj)->objectFlags |= VFPOBJCREATOR_OBJFLAG_HITDETECT_DISABLED;
}

void VFP_ObjCreator_release(void)
{
}

void VFP_ObjCreator_initialise(void)
{
}
