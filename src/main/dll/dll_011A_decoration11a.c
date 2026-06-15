#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/CF/CFBaby.h"

extern void* ObjGroup_GetObjects();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_800427c8();
extern undefined4 FUN_80042800();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80043030();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053c98();

extern f32 FLOAT_803e4830;
extern f32 FLOAT_803e4840;
extern f32 FLOAT_803e4844;
extern f32 FLOAT_803e4848;

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3B78;
extern f32 lbl_803E3B7C;
extern f32 lbl_803E3B88;
extern f32 Vec_distance(f32 * a, f32 * b);
extern void objWorldToLocalPos(f32* out, int obj, f32* pos);
extern void Model_GetVertexPosition(int* model, int idx, f32* out);
extern void PSVECScale(f32* dst, f32* src, f32 s);
extern f32 PSVECMag(f32 * v);

undefined4
FUN_80189054(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, undefined4 param_10
             , ObjAnimUpdateState* animUpdate, int param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 eventHandle;
    char mapAct;
    int mapId;
    int scratch;
    int state;
    int def;
    int eventIndex;
    undefined8 extraout_f1;
    undefined8 extraout_f1_00;
    undefined8 extraout_f1_01;
    undefined8 extraout_f1_02;
    undefined8 extraout_f1_03;
    undefined8 uVar8;

    def = *(int*)&((GameObject*)param_9)->anim.placementData;
    state = *(int*)&((GameObject*)param_9)->extra;
    eventIndex = 0;
    scratch = (int)animUpdate;
    do
    {
        if ((int)(uint)animUpdate->eventCount <= eventIndex)
        {
            return 0;
        }
        switch (animUpdate->eventIds[eventIndex])
        {
        case 2:
        case 0x65:
            scratch = *(int*)(def + 0x14);
            if (scratch == 0x49f5a)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x26);
                scratch = 1;
                FUN_80042b9c(0, 0, 1);
                eventHandle = FUN_80044404(0x26);
                FUN_80042bec(eventHandle, 0);
                eventHandle = FUN_80044404(0xb);
                FUN_80042bec(eventHandle, 1);
            }
            else if (scratch < 0x49f5a)
            {
                if (scratch == 0x451b9)
                {
                    mapAct = (*gMapEventInterface)->getMapAct(0xd);
                    param_1 = extraout_f1;
                    if (mapAct == '\x02')
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0xb);
                        scratch = 1;
                        FUN_80042b9c(0, 0, 1);
                        eventHandle = FUN_80044404(0xb);
                        FUN_80042bec(eventHandle, 0);
                    }
                    else
                    {
                        FUN_80041ff8(extraout_f1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                        scratch = 1;
                        FUN_80042b9c(0, 0, 1);
                        eventHandle = FUN_80044404(0x29);
                        FUN_80042bec(eventHandle, 0);
                    }
                }
                else
                {
                    if ((0x451b8 < scratch) || (scratch != 0x43775)) goto LAB_801893dc;
                    FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                    scratch = 1;
                    FUN_80042b9c(0, 0, 1);
                    eventHandle = FUN_80044404(0x29);
                    FUN_80042bec(eventHandle, 0);
                }
            }
            else if (scratch == 0x4cd65)
            {
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x41);
                scratch = 1;
                FUN_80042b9c(0, 0, 1);
                eventHandle = FUN_80044404(0x41);
                FUN_80042bec(eventHandle, 0);
                eventHandle = FUN_80044404(0xb);
                FUN_80042bec(eventHandle, 1);
            }
            else
            {
            LAB_801893dc:
                FUN_80041ff8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x29);
                scratch = 1;
                FUN_80042b9c(0, 0, 1);
                eventHandle = FUN_80044404(0x29);
                FUN_80042bec(eventHandle, 0);
            }
            break;
        case 3:
        case 100:
            mapId = *(int*)(def + 0x14);
            if (mapId == 0x49f5a)
            {
                scratch = 0;
                param_12 = (int)*gMapEventInterface;
                param_1 = (**(code**)(param_12 + 0x50))(0xb, 4);
            }
            else if (mapId < 0x49f5a)
            {
                if (mapId == 0x451b9)
                {
                    mapAct = (*gMapEventInterface)->getMapAct(0xd);
                    param_1 = extraout_f1_00;
                    if (mapAct == '\x02')
                    {
                        uVar8 = extraout_f1_00;
                        FUN_80042b9c(0, 0, 1);
                        FUN_80044404(0xd);
                        FUN_80043030(uVar8, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                        (*gMapEventInterface)->setObjGroupStatus(0xd, 10, 0);
                        (*gMapEventInterface)->setObjGroupStatus(0xd, 0xb, 0);
                        scratch = 0;
                        param_12 = (int)*gMapEventInterface;
                        param_1 = (**(code**)(param_12 + 0x50))(0xd, 0xe);
                    }
                }
                else if ((mapId < 0x451b9) && (mapId == 0x43775))
                {
                    scratch = 1;
                    FUN_80042b9c(0, 0, 1);
                    FUN_80044404(7);
                    param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
                }
            }
            else if (mapId == 0x4cd65)
            {
                scratch = 1;
                FUN_80042b9c(0, 0, 1);
                FUN_80044404(0xb);
                param_1 = FUN_80043030(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
            }
            break;
        case 5:
            mapId = *(int*)(def + 0x14);
            if (mapId == 0x451b9)
            {
                mapAct = (*gMapEventInterface)->getMapAct(0xd);
                param_1 = extraout_f1_01;
                if (mapAct == '\x02')
                {
                    param_1 = FUN_80042800();
                }
            }
            else if (mapId < 0x451b9)
            {
                if (mapId == 0x43775)
                {
                LAB_801895a4:
                    param_1 = FUN_80042800();
                }
            }
            else if (mapId == 0x49f5a) goto LAB_801895a4;
            break;
        case 6:
            mapId = *(int*)(def + 0x14);
            if (mapId == 0x451b9)
            {
                mapAct = (*gMapEventInterface)->getMapAct(0xd);
                param_1 = extraout_f1_02;
                if (mapAct == '\x02')
                {
                    param_1 = FUN_800427c8();
                }
            }
            else if (mapId < 0x451b9)
            {
                if (mapId == 0x43775)
                {
                LAB_80189614:
                    param_1 = FUN_800427c8();
                }
            }
            else if (mapId == 0x49f5a) goto LAB_80189614;
            break;
        case 7:
        case 0x66:
            mapId = *(int*)(def + 0x14);
            if (mapId == 0x49f5a)
            {
                param_1 = FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x32,
                                       '\0', scratch, param_12, param_13, param_14, param_15, param_16);
            }
            else if (mapId < 0x49f5a)
            {
                if ((mapId == 0x451b9) &&
                    (mapAct = (*gMapEventInterface)->getMapAct(0xd), param_1 = extraout_f1_03,
                        mapAct == '\x02'))
                {
                    scratch = (int)*gMapEventInterface;
                    uVar8 = (**(code**)(scratch + 0x44))(0xb, 5);
                    param_1 = FUN_80053c98(uVar8, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x4e,
                                           '\0', scratch, param_12, param_13, param_14, param_15, param_16);
                }
            }
            else if (mapId == 0x4cd65)
            {
                FUN_80053c98(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x7f, '\0', scratch
                             , param_12, param_13, param_14, param_15, param_16);
                scratch = (int)*gMapEventInterface;
                param_1 = (**(code**)(scratch + 0x44))(0x41, 2);
            }
            break;
        case 10:
            *(u8*)(state + 0x1a) = 1;
            break;
        case 0xb:
            *(u8*)(state + 0x1a) = 0;
            break;
        case 0xc:
            *(float*)(state + 4) = FLOAT_803e4830;
            break;
        case 0xd:
            *(float*)(state + 4) = FLOAT_803e4840;
            break;
        case 0xe:
            *(float*)(state + 4) = FLOAT_803e4844;
            break;
        case 0xf:
            *(float*)(state + 4) = FLOAT_803e4848;
            break;
        case 0x10:
            *(float*)(state + 8) = FLOAT_803e4830;
            break;
        case 0x11:
            *(float*)(state + 8) = FLOAT_803e4840;
            break;
        case 0x12:
            *(float*)(state + 8) = FLOAT_803e4844;
            break;
        case 0x13:
            *(float*)(state + 8) = FLOAT_803e4848;
            break;
        case 0x14:
            *(float*)(state + 0xc) = FLOAT_803e4830;
            break;
        case 0x15:
            *(float*)(state + 0xc) = FLOAT_803e4840;
            break;
        case 0x16:
            *(float*)(state + 0xc) = FLOAT_803e4844;
            break;
        case 0x17:
            *(float*)(state + 0xc) = FLOAT_803e4848;
            break;
        case 0x18:
            mapId = *(int*)(state + 0x10);
            if (mapId != 0)
            {
                *(ushort*)(mapId + 6) = *(ushort*)(mapId + 6) & 0xbfff;
            }
            break;
        case 0x19:
            mapId = *(int*)(state + 0x10);
            if (mapId != 0)
            {
                *(ushort*)(mapId + 6) = *(ushort*)(mapId + 6) | 0x4000;
            }
        }
        eventIndex = eventIndex + 1;
    }
    while (true);
}

void flammablevine_release(void);

void decoration11a_free(void)
{
}

void decoration11a_update(void)
{
}

int flammablevine_getExtraSize(void);
int decoration11a_getExtraSize(void) { return 0x1c; }
int landed_arwing_getExtraSize(void);

#pragma scheduling off
#pragma peephole off
void decoration11a_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3B78);
}

void flammablevine_free(int x);

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

int InfoPoint_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

#pragma peephole off
void decoration11a_hitDetect(int obj)
{
    s16 modelId;
    f32* state;
    int count;
    int* objects;
    f32 radius;
    f32 localPos[3];
    f32 bMax;
    f32 sum;
    f32 delta;
    f32 term;
    ObjHitsPriorityState* hitState;

    modelId = ((GameObject*)obj)->anim.seqId;
    if (modelId == 0x7a1)
    {
        goto check_decor_objects;
    }
    if (modelId == 0x7a2)
    {
        goto check_decor_objects;
    }
    if (modelId != 0x7a3)
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
            if (*(void**)(*objects + 0x54) != NULL)
            {
                radius = (f32) * (s16*)(*(int*)(*objects + 0x54) + 0x5a);
                objWorldToLocalPos(localPos, obj, (f32*)(*objects + 0xc));

                sum = lbl_803E3B7C;

                {
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
                    hitState = (ObjHitsPriorityState*)((GameObject*)*objects)->anim.hitReactState;
                    hitState->lastHitObject = obj;
                    hitState->contactFlags = 1;
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
    *(s16*)obj = (s16)((s32)def[26] << 8);
    if (def[27] != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)(u32)
        def[27] / lbl_803E3B88;
        if (((GameObject*)obj)->anim.rootMotionScale == lbl_803E3B7C)
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3B78;
        }
        ((GameObject*)obj)->anim.rootMotionScale =
            ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    }
    {
        s16 model = ((GameObject*)obj)->anim.seqId;
        if (model == 1953)
        {
            goto calc_decor_bounds;
        }
        if (model == 1954)
        {
            goto calc_decor_bounds;
        }
        if (model == 1955)
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
