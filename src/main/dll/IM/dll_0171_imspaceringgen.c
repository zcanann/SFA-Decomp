/*
 * imspaceringgen (DLL 0x171) - the spawner/anchor for the space-ring
 * swarm that orbits the SpaceCraft cinematic on the Ice Mountain map.
 *
 * It locates the two reference ring objects (A and B) once they exist,
 * then fades its own alpha in/out with ring B's visibility. The first
 * time the level finishes loading it spawns a burst of ten loose ring
 * pieces (object 0x301) with randomised spin/tilt, and continuously
 * snaps its own position to ring A so the swarm stays attached.
 *
 * The generator publishes itself in gSpaceRingLeader so
 * the individual imspacering objects can track it; free() clears that
 * pointer.
 */
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/obj_list.h"
#include "main/frame_timing.h"
#include "main/dll/IM/dll_0171_imspaceringgen.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"

/* anim.seqId of the two reference ring objects the generator tracks */
#define SEQID_RING_A 0x164
#define SEQID_RING_B 0x168

/* loose ring-piece object spawned (x10) with random spin/tilt */
#define IMSPACERINGGEN_CHILD_OBJ_RING_PIECE 0x301
#define IMSPACERINGGEN_HAS_SPAWNED(obj) ((obj)->userData1)

int IMSpaceRingGen_getExtraSize(void)
{
    return sizeof(RingGenState);
}
int IMSpaceRingGen_getObjectTypeId(void)
{
    return 0x0;
}

void IMSpaceRingGen_free(GameObject* obj)
{
    gSpaceRingLeader = NULL;
}

void IMSpaceRingGen_render(GameObject* obj, int p1, int p2, int p3, int p4, s8 visible)
{
    RingGenState* state = obj->extra;
    if (visible != 0 && (state->visible != 0 || obj->anim.alpha != 0))
    {
        objRenderModelAndHitVolumes(obj, p1, p2, p3, p4, 1.0f);
    }
}

void IMSpaceRingGen_hitDetect(void)
{
}

void IMSpaceRingGen_update(GameObject* obj)
{
    int i;
    IMSpaceRingPlacement* ring;
    ObjPlacement* setup;
    RingGenState* state;
    int objIndex;
    int objCount;

    setup = obj->anim.placement;
    state = obj->extra;
    if (state->ringA == NULL || state->ringB == NULL)
    {
        GameObject** objs = (GameObject**)ObjList_GetObjects(&objIndex, &objCount);
        for (objIndex = 0; objIndex < objCount; objIndex++)
        {
            GameObject* candidate = objs[objIndex];
            if (candidate->anim.seqId == SEQID_RING_A)
            {
                state->ringA = candidate;
            }
            if (candidate->anim.seqId == SEQID_RING_B)
            {
                state->ringB = candidate;
            }
        }
    }
    else
    {
        int alpha;
        state->visible = (*(IMSpaceRingInterfaceVTable**)state->ringB->anim.dll)->isVisible(state->ringB);
        if (state->visible != 0)
        {
            alpha = obj->anim.alpha + framesThisStep * 8;
            if (alpha > 0xff)
            {
                alpha = 0xff;
            }
        }
        else
        {
            alpha = obj->anim.alpha - framesThisStep * 8;
            if (alpha < 0)
            {
                alpha = 0;
            }
        }
        obj->anim.alpha = alpha;
        if (IMSPACERINGGEN_HAS_SPAWNED(obj) == 0 && Obj_IsLoadingLocked() != 0)
        {
            for (i = 0; i < 10; i++)
            {
                ring = (IMSpaceRingPlacement*)Obj_AllocObjectSetup(sizeof(IMSpaceRingPlacement),
                                                                  IMSPACERINGGEN_CHILD_OBJ_RING_PIECE);
                ring->base.posX = obj->anim.localPosX;
                ring->base.posY = obj->anim.localPosY;
                ring->base.posZ = obj->anim.localPosZ;
                ring->initialRotX = randomGetRange(0, 0xffff);
                ring->spinSpeed = randomGetRange(200, 400);
                if ((int)randomGetRange(0, 1) == 0)
                {
                    ring->spinSpeed = -ring->spinSpeed;
                }
                ring->tiltSpeed = randomGetRange(200, 400);
                if ((int)randomGetRange(0, 1) == 0)
                {
                    ring->tiltSpeed = -ring->tiltSpeed;
                }
                ring->base.color[0] = setup->color[0];
                ring->base.color[2] = setup->color[2];
                ring->base.color[1] = 1;
                ring->base.color[3] = 0xff;
                Obj_SetupObject(&ring->base, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
            }
            IMSPACERINGGEN_HAS_SPAWNED(obj) = 1;
        }
        objMove(obj, state->ringA->anim.localPosX - obj->anim.localPosX,
                (9.0f + state->ringA->anim.localPosY) - obj->anim.localPosY,
                state->ringA->anim.localPosZ - obj->anim.localPosZ);
        obj->anim.rotX = obj->anim.rotX + framesThisStep * 0x100;
        obj->anim.rotY = obj->anim.rotY + framesThisStep * 0x20;
        obj->anim.rotZ = obj->anim.rotZ + framesThisStep * 0x40;
        obj->anim.parent = NULL;
    }
}

void IMSpaceRingGen_init(GameObject* obj)
{
    IMSPACERINGGEN_HAS_SPAWNED(obj) = 0;
    gSpaceRingLeader = obj;
}

void IMSpaceRingGen_release(void)
{
}

void IMSpaceRingGen_initialise(void)
{
}

ObjectDescriptor gIMSpaceRingGenObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)IMSpaceRingGen_initialise,
    (ObjectDescriptorCallback)IMSpaceRingGen_release,
    0,
    (ObjectDescriptorCallback)IMSpaceRingGen_init,
    (ObjectDescriptorCallback)IMSpaceRingGen_update,
    (ObjectDescriptorCallback)IMSpaceRingGen_hitDetect,
    (ObjectDescriptorCallback)IMSpaceRingGen_render,
    (ObjectDescriptorCallback)IMSpaceRingGen_free,
    (ObjectDescriptorCallback)IMSpaceRingGen_getObjectTypeId,
    IMSpaceRingGen_getExtraSize,
};
