/*
 * decoration11a (DLL 0x11A) - a static decoration object with an
 * optional axis-aligned collision volume.
 *
 * init() seeds the object's rotation from the placement bytes and an
 * optional root-motion scale, then - for the three "bounded" model
 * variants (DECOR11A_MODEL_*) - walks every vertex of the model to
 * compute a local-space AABB (min/max stored in extra[0..2] / [3..5])
 * and caches the larger half-extent magnitude in extra[6].
 *
 * hitDetect() uses that bounds against group-2 objects: for each whose
 * centre is within the cached radius, it measures squared distance from
 * the object's local-space AABB and, on contact, records the hit on the
 * other object's ObjHitsPriorityState.
 *
 * The extra block is 0x1c bytes: f32 boundsMax[3], boundsMin[3], radius.
 */
#include "main/game_object.h"
#include "main/engine_shared.h"
extern void* ObjGroup_GetObjects();
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3B78;
extern f32 lbl_803E3B7C;
extern f32 lbl_803E3B88;
extern f32 Vec_distance(f32* a, f32* b);
extern void objWorldToLocalPos(f32* out, int obj, f32* pos);
extern void Model_GetVertexPosition(int* model, int idx, f32* out);

/* model/seq ids of the three variants that carry a collision volume */
enum
{
    DECOR11A_MODEL_A = 0x7a1,
    DECOR11A_MODEL_B = 0x7a2,
    DECOR11A_MODEL_C = 0x7a3
};

void decoration11a_free(void)
{
}

void decoration11a_update(void)
{
}

int decoration11a_getExtraSize(void) { return 0x1c; }

#pragma scheduling off /* TU-wide from here: hitDetect/init inherit this */
#pragma peephole off
void decoration11a_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3B78);
}

#pragma dont_inline on
#pragma peephole on
void decoration11a_expandBoundsWithVertex(f32* vertex, f32* maxOut, f32* minOut)
{
    f32 v;
    v = vertex[0];
    if (v > maxOut[0]) maxOut[0] = v;
    else if (v < minOut[0]) minOut[0] = v;
    v = vertex[1];
    if (v > maxOut[1]) maxOut[1] = v;
    else if (v < minOut[1]) minOut[1] = v;
    v = vertex[2];
    if (v > maxOut[2]) maxOut[2] = v;
    else if (v < minOut[2]) minOut[2] = v;
}
#pragma dont_inline reset

#pragma peephole off
void decoration11a_hitDetect(int obj)
{
    s16 modelId;
    f32* state;
    int count;
    int* objects;
    f32 radius;
    f32 localPos[3];
    f32 sum;
    f32 delta;
    f32 term;

    modelId = ((GameObject*)obj)->anim.seqId;
    if (modelId == DECOR11A_MODEL_A)
    {
        goto check_decor_objects;
    }
    if (modelId == DECOR11A_MODEL_B)
    {
        goto check_decor_objects;
    }
    if (modelId != DECOR11A_MODEL_C)
    {
        return;
    }

check_decor_objects:
    state = ((GameObject*)obj)->extra;
    objects = ObjGroup_GetObjects(2, &count);
    while (count != 0)
    {
        if (Vec_distance((f32*)(*objects + 0x18), (f32*)(obj + 0x18)) < state[6])
        {
            if (((GameObject*)*objects)->anim.hitReactState != NULL)
            {
                radius = (f32)((ObjHitsPriorityState*)((GameObject*)*objects)->anim.hitReactState)->primaryRadius;
                objWorldToLocalPos(localPos, obj, (f32*)(*objects + 0xc));

                sum = lbl_803E3B7C;

                {
                f32 bMax;
                f32 bMin;
                f32 px;
                bMin = state[3];
                bMax = state[0];
                sum += ((px = localPos[0]) < bMin) ? (px - bMin) * (px - bMin)
                     : (px > bMax) ? (px - bMax) * (px - bMax)
                     : lbl_803E3B7C;
                }

                {
                f32 bMax;
                f32 bMin;
                bMin = state[4];
                bMax = state[1];
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
                    term = *(f32*)&lbl_803E3B7C;
                }
                sum += term;
                }

                {
                f32 bMax;
                f32 bMin;
                bMin = state[5];
                bMax = state[2];
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
                    term = *(f32*)&lbl_803E3B7C;
                }
                sum += term;
                }

                if (sum < radius * radius)
                {
                    ((ObjHitsPriorityState*)((GameObject*)*objects)->anim.hitReactState)->lastHitObject = obj;
                    ((ObjHitsPriorityState*)((GameObject*)*objects)->anim.hitReactState)->contactFlags = OBJHITS_CONTACT_FLAG_KIND0;
                }
            }
        }
        count--;
        objects++;
    }
}

void decoration11a_init(int* obj, u8* def)
{
    ((GameObject*)obj)->anim.rotZ = (s16)((s32)def[24] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32)def[25] << 8);
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[26] << 8);
    if (def[27] != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)def[27] / lbl_803E3B88;
        if (((GameObject*)obj)->anim.rootMotionScale == lbl_803E3B7C)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3B78;
        }
        ((GameObject*)obj)->anim.rootMotionScale =
            ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    }
    {
        s16 model = ((GameObject*)obj)->anim.seqId;
        if (model == DECOR11A_MODEL_A)
        {
            goto calc_decor_bounds;
        }
        if (model == DECOR11A_MODEL_B)
        {
            goto calc_decor_bounds;
        }
        if (model == DECOR11A_MODEL_C)
        {
        calc_decor_bounds:
            {
                int i;
                int* m;
                f32* state;
                f32 tmp[3];
                f32 magB;
                f32 maxMag;

                state = ((GameObject*)obj)->extra;
                m = **(int***)(*(int*)&((GameObject*)obj)->anim.banks);
                Model_GetVertexPosition(m, 0, state);
                Model_GetVertexPosition(m, 0, state + 3);
                for (i = 1; i < *(u16*)((char*)m + 0xe4); i++)
                {
                    Model_GetVertexPosition(m, i, tmp);
                    decoration11a_expandBoundsWithVertex(tmp, state, state + 3);
                }
                PSVECScale(state, state, ((GameObject*)obj)->anim.rootMotionScale);
                PSVECScale(state + 3, state + 3, ((GameObject*)obj)->anim.rootMotionScale);
                magB = PSVECMag(state + 3);
                if (PSVECMag(state) > magB)
                {
                    maxMag = PSVECMag(state);
                }
                else
                {
                    maxMag = PSVECMag(state + 3);
                }
                state[6] = maxMag;
            }
        }
    }
}
