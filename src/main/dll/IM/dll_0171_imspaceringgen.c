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
 * The generator publishes itself in gSpaceRingLeader (lbl_803DDB48) so
 * the individual imspacering objects can track it; free() clears that
 * pointer.
 */
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/gameplay_runtime.h"
#include "main/frame_timing.h"
#include "main/dll/IM/dll_0171_imspaceringgen.h"

/* anim.seqId of the two reference ring objects the generator tracks */
#define SEQID_RING_A 0x164
#define SEQID_RING_B 0x168

/* loose ring-piece object spawned (x10) as ImSpaceRingSetup with random spin/tilt */
#define IMSPACERINGGEN_CHILD_OBJ_RING_PIECE 0x301

extern GameObject* lbl_803DDB48;
extern f32 lbl_803E47C0; /* render scale */
extern f32 lbl_803E47C4; /* Y offset applied when chasing ring A */
extern void objMove(int obj, f32 dx, f32 dy, f32 dz);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int extraSize, int id);
extern void* Obj_SetupObject(int a, int b, int c, int d, int e);

int IMSpaceRingGen_getExtraSize(void)
{
    return 0xc;
}
int IMSpaceRingGen_getObjectTypeId(void)
{
    return 0x0;
}

void IMSpaceRingGen_free(void)
{
    lbl_803DDB48 = NULL;
}

void IMSpaceRingGen_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    u8* state = ((GameObject*)obj)->extra;
    if (visible != 0 && (state[8] != 0 || ((GameObject*)obj)->anim.alpha != 0))
    {
        ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p1, p2, p3, p4, lbl_803E47C0);
    }
}

void IMSpaceRingGen_hitDetect(void)
{
}

void IMSpaceRingGen_update(GameObject* obj)
{
    int i;
    int ring;
    u8* setup;
    RingGenState* state;
    int objIndex;
    int objCount;

    setup = *(u8**)&obj->anim.placementData;
    state = obj->extra;
    if (state->ringA == NULL || state->ringB == NULL)
    {
        int* objs = ObjList_GetObjects(&objIndex, &objCount);
        for (objIndex = 0; objIndex < objCount; objIndex++)
        {
            GameObject* candidate = (GameObject*)objs[objIndex];
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
        state->visible =
            ((int (*)(GameObject*))((void**)*(void**)*(int*)((char*)state->ringB + 0x68))[9])(state->ringB);
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
        if (obj->unkF4 == 0 && Obj_IsLoadingLocked() != 0)
        {
            for (i = 0; i < 10; i++)
            {
                ring = Obj_AllocObjectSetup(0x24, IMSPACERINGGEN_CHILD_OBJ_RING_PIECE);
                ((ImSpaceRingSetup*)ring)->base.posX = obj->anim.localPosX;
                ((ImSpaceRingSetup*)ring)->base.posY = obj->anim.localPosY;
                ((ImSpaceRingSetup*)ring)->base.posZ = obj->anim.localPosZ;
                ((ImSpaceRingSetup*)ring)->spinPhase = randomGetRange(0, 0xffff);
                ((ImSpaceRingSetup*)ring)->spinSpeed = randomGetRange(200, 400);
                if ((int)randomGetRange(0, 1) == 0)
                {
                    ((ImSpaceRingSetup*)ring)->spinSpeed = -((ImSpaceRingSetup*)ring)->spinSpeed;
                }
                ((ImSpaceRingSetup*)ring)->tiltSpeed = randomGetRange(200, 400);
                if ((int)randomGetRange(0, 1) == 0)
                {
                    ((ImSpaceRingSetup*)ring)->tiltSpeed = -((ImSpaceRingSetup*)ring)->tiltSpeed;
                }
                ((ImSpaceRingSetup*)ring)->base.color[0] = setup[4];
                ((ImSpaceRingSetup*)ring)->base.color[2] = setup[6];
                ((ImSpaceRingSetup*)ring)->base.color[1] = 1;
                ((ImSpaceRingSetup*)ring)->base.color[3] = 0xff;
                Obj_SetupObject(ring, 5, obj->anim.mapEventSlot, -1, *(int*)&obj->anim.parent);
            }
            obj->unkF4 = 1;
        }
        objMove((int)obj, state->ringA->anim.localPosX - obj->anim.localPosX,
                (lbl_803E47C4 + state->ringA->anim.localPosY) - obj->anim.localPosY,
                state->ringA->anim.localPosZ - obj->anim.localPosZ);
        obj->anim.rotX = obj->anim.rotX + framesThisStep * 0x100;
        obj->anim.rotY = obj->anim.rotY + framesThisStep * 0x20;
        obj->anim.rotZ = obj->anim.rotZ + framesThisStep * 0x40;
        *(int*)&obj->anim.parent = 0;
    }
}

void IMSpaceRingGen_init(GameObject* obj)
{
    obj->unkF4 = 0;
    lbl_803DDB48 = obj;
}

void IMSpaceRingGen_release(void)
{
}

void IMSpaceRingGen_initialise(void)
{
}
