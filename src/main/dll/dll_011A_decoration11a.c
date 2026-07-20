/*
 * decoration11a (DLL 0x11A) - a static decoration object with an
 * optional axis-aligned collision volume.
 *
 * init() seeds the object's rotation from the placement bytes and an
 * optional root-motion scale, then - for the three "bounded" model
 * variants (DECOR11A_MODEL_*) - walks every vertex of the model to
 * compute a local-space AABB and cache its larger half-extent magnitude.
 *
 * hitDetect() uses that bounds against group-2 objects: for each whose
 * centre is within the cached radius, it measures squared distance from
 * the object's local-space AABB and, on contact, records the hit on the
 * other object's ObjHitsPriorityState.
 *
 * The extra block is the 0x1c-byte Decoration11AState.
 */
#include "main/game_object.h"
#include "main/obj_group.h"
#include "main/model.h"
#include "main/vecmath.h"
#include "main/dll/dll_011A_decoration11a.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/object_render.h"
#include "main/object_transform.h"

/* model/seq ids of the three variants that carry a collision volume */
enum
{
    DECOR11A_MODEL_A = 0x7a1,
    DECOR11A_MODEL_B = 0x7a2,
    DECOR11A_MODEL_C = 0x7a3
};


int decoration11a_getExtraSize(void)
{
    return sizeof(Decoration11AState);
}

void decoration11a_free(void)
{
}

void decoration11a_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void decoration11a_hitDetect(GameObject* obj)
{
    s16 modelId;
    Decoration11AState* state;
    int count;
    u32* objects;
    f32 radius;
    f32 localPos[3];
    f32 sum;
    f32 delta;
    f32 term;

    modelId = obj->anim.seqId;
    if (modelId != DECOR11A_MODEL_A && modelId != DECOR11A_MODEL_B && modelId != DECOR11A_MODEL_C)
    {
        return;
    }

    state = obj->extra;
    objects = ObjGroup_GetObjects(2, &count);
    while (count != 0)
    {
        if (Vec_distance(&((GameObject*)*objects)->anim.worldPosX, &obj->anim.worldPosX) < state->radius)
        {
            if (((GameObject*)*objects)->anim.hitReactState != NULL)
            {
                radius = (f32)((ObjHitsPriorityState*)((GameObject*)*objects)->anim.hitReactState)->primaryRadius;
                objWorldToLocalPos(localPos, (ObjLocalTransform*)obj, &((GameObject*)*objects)->anim.localPosX);

                sum = 0.0f;

                {
                    f32 bMax;
                    f32 bMin;
                    f32 px;
                    bMin = state->boundsMin.x;
                    bMax = state->boundsMax.x;
                    sum += ((px = localPos[0]) < bMin) ? (px - bMin) * (px - bMin)
                           : (px > bMax)               ? (px - bMax) * (px - bMax)
                                                       : 0.0f;
                }

                {
                    f32 bMax;
                    f32 bMin;
                    bMin = state->boundsMin.y;
                    bMax = state->boundsMax.y;
                    if (localPos[1] < bMin)
                    {
                        delta = localPos[1] - bMin;
                        term = delta * delta;
                    }
                    else if (localPos[1] > bMax)
                    {
                        delta = localPos[1] - bMax;
                        term = delta * delta;
                    }
                    else
                    {
                        term = 0.0f;
                    }
                    sum += term;
                }

                {
                    f32 bMax;
                    f32 bMin;
                    bMin = state->boundsMin.z;
                    bMax = state->boundsMax.z;
                    if (localPos[2] < bMin)
                    {
                        delta = localPos[2] - bMin;
                        term = delta * delta;
                    }
                    else if (localPos[2] > bMax)
                    {
                        delta = localPos[2] - bMax;
                        term = delta * delta;
                    }
                    else
                    {
                        term = 0.0f;
                    }
                    sum += term;
                }

                if (sum < radius * radius)
                {
                    ((ObjHitsPriorityState*)((GameObject*)*objects)->anim.hitReactState)->lastHitObject = (u32)obj;
                    ((ObjHitsPriorityState*)((GameObject*)*objects)->anim.hitReactState)->contactFlags =
                        OBJHITS_CONTACT_FLAG_KIND0;
                }
            }
        }
        count--;
        objects++;
    }
}

void decoration11a_update(void)
{
}


void decoration11a_expandBoundsWithVertex(f32* vertex, f32* maxOut, f32* minOut)
{
    f32 component;
    component = vertex[0];
    if (component > maxOut[0])
        maxOut[0] = component;
    else if (component < minOut[0])
        minOut[0] = component;
    component = vertex[1];
    if (component > maxOut[1])
        maxOut[1] = component;
    else if (component < minOut[1])
        minOut[1] = component;
    component = vertex[2];
    if (component > maxOut[2])
        maxOut[2] = component;
    else if (component < minOut[2])
        minOut[2] = component;
}

void decoration11a_init(GameObject* obj, Decoration11ASetup* setup)
{
    obj->anim.rotZ = (s16)((s32)setup->rotZ << 8);
    obj->anim.rotY = (s16)((s32)setup->rotY << 8);
    obj->anim.rotX = (s16)((s32)setup->rotX << 8);
    if (setup->scale != 0)
    {
        obj->anim.rootMotionScale = (f32)(u32)setup->scale / 255.0f;
        if (!obj->anim.rootMotionScale)
        {
            obj->anim.rootMotionScale = 1.0f;
        }
        obj->anim.rootMotionScale = obj->anim.rootMotionScale * obj->anim.modelInstance->rootMotionScaleBase;
    }
    {
        s16 model = obj->anim.seqId;
        if (model != DECOR11A_MODEL_A && model != DECOR11A_MODEL_B && model != DECOR11A_MODEL_C)
        {
            return;
        }
        {
            int i;
            ModelFileHeader* m;
            Decoration11AState* state;
            f32 vertexPos[3];
            f32 magB;
            f32 maxMag;

            state = obj->extra;
            m = (ModelFileHeader*)**(int***)(*(int*)&obj->anim.banks);
            Model_GetVertexPosition(m, 0, &state->boundsMax.x);
            Model_GetVertexPosition(m, 0, &state->boundsMin.x);
            for (i = 1; i < m->vertexCount; i++)
            {
                Model_GetVertexPosition(m, i, vertexPos);
                decoration11a_expandBoundsWithVertex(vertexPos, &state->boundsMax.x, &state->boundsMin.x);
            }
            PSVECScale(&state->boundsMax.x, &state->boundsMax.x, obj->anim.rootMotionScale);
            PSVECScale(&state->boundsMin.x, &state->boundsMin.x, obj->anim.rootMotionScale);
            magB = PSVECMag(&state->boundsMin.x);
            if (PSVECMag(&state->boundsMax.x) > magB)
            {
                maxMag = PSVECMag(&state->boundsMax.x);
            }
            else
            {
                maxMag = PSVECMag(&state->boundsMin.x);
            }
            state->radius = maxMag;
        }
    }
}
