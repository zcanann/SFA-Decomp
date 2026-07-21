/*
 * animsharpclaw (DLL 0x184) - an anim/sequence object (object type id 0xb).
 *
 * init wires the object's anim/trigger state (slot 0x64), records the
 * sequence id from placement, and either loads or reloads its anim data
 * depending on the placement variant byte. Each update ticks the object
 * trigger interface, services anim sequence events (event 1
 * spawns a child setup object 0x30B and attaches it, event 2 detaches and
 * frees the child), then - once the object reaches the terminal sequence
 * index (-2) - scans the live object list for the matching sequence kind
 * and ends the shared trigger sequence when this is the last participant.
 * free detaches/frees the child, releases trigger state, drives the title-
 * menu control vtable slot 2, and stops the object's sfx channel.
 */
#include "main/objanim_update.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/obj_link.h"
#include "main/objseq.h"
#include "main/dll/dll_0184_animsharpclaw.h"
#include "main/dll/dll_0004_dummy04.h"

/* child setup-object id spawned on anim sequence event 1 */
#define ANIMSHARPCLAW_CHILD_SETUP_ID 0x30B
#define ANIMSHARPCLAW_OBJECT_TYPE_ID 0xB
#define ANIMSHARPCLAW_CLASS_ID       0x10

int animsharpclaw_handleAnimEvents(GameObject* obj, ObjAnimUpdateState* animUpdate)
{
    int i;
    GameObject* child;
    AnimsharpclawChildSetup* childSetup;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 eventId = animUpdate->eventIds[i];
        switch (eventId)
        {
        case 1:
            obj->userData2 = ANIMSHARPCLAW_CHILD_SETUP_ID;
            child = obj->childObjs[0];
            if (child != NULL)
            {
                ObjLink_DetachChild(obj, child);
                Obj_FreeObject(child);
            }
            childSetup = (AnimsharpclawChildSetup*)Obj_AllocObjectSetup(sizeof(AnimsharpclawChildSetup),
                                                                        obj->userData2);
            child = Obj_SetupObject(&childSetup->base, 4, obj->anim.mapEventSlot, -1, obj->anim.parent);
            ObjLink_AttachChild(obj, child, 0);
            break;
        case 2:
            child = obj->childObjs[0];
            if (child != NULL)
            {
                ObjLink_DetachChild(obj, child);
                Obj_FreeObject(child);
            }
            obj->userData2 = -1;
            break;
        }
    }
    return 0;
}

int animsharpclaw_getExtraSize(void)
{
    return sizeof(AnimsharpclawState);
}
int animsharpclaw_getObjectTypeId(void)
{
    return ANIMSHARPCLAW_OBJECT_TYPE_ID;
}

void animsharpclaw_free(GameObject* obj)
{
    AnimsharpclawState* state;
    GameObject* child;
    state = obj->extra;
    child = obj->childObjs[0];
    if (child != NULL)
    {
        ObjLink_DetachChild(obj, child);
        Obj_FreeObject(child);
    }
    (*gObjectTriggerInterface)->freeState((u8*)state);
    gTitleMenuControlInterfaceCopy->vtable->func05((void*)obj, 0xffff, 0, 0, 0);
    Sfx_StopObjectChannel(obj, 0x7f);
}

void animsharpclaw_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 isVisible = visible;
    if (isVisible != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void animsharpclaw_hitDetect(void)
{
}

void animsharpclaw_update(GameObject* obj)
{
    AnimsharpclawPlacement* placement;
    int kind;
    int kindExt;
    int matchCount;
    int* objList;
    AnimsharpclawState* state;
    int found;
    int i;
    int count;

    state = obj->extra;
    placement = (AnimsharpclawPlacement*)obj->anim.placementData;
    if ((placement != NULL) && (placement->animationBank != -1))
    {
        i = (*gObjectTriggerInterface)->update((u8*)obj, (f32)(u32)framesThisStep);
        animsharpclaw_handleAnimEvents(obj, (ObjAnimUpdateState*)state);
        if ((i != 0) && (obj->seqIndex == -2))
        {
            kind = *(s8*)&state->sequence.slot;
            found = 0;
            objList = (int*)ObjList_GetObjects(&i, &count);
            matchCount = 0;
            for (i = 0, kindExt = (int)(s8)kind; i < count; i++)
            {
                int other = *objList;
                GameObject* o = (GameObject*)other;
                if (o->seqIndex == kind)
                {
                    found = other;
                }
                if (o->seqIndex == -2 && o->anim.classId == ANIMSHARPCLAW_CLASS_ID &&
                    kindExt == ((AnimsharpclawState*)o->extra)->sequence.slot)
                {
                    matchCount++;
                }
                objList = objList + 1;
            }
            if (matchCount <= 1 && (u32)found != 0 && ((GameObject*)found)->seqIndex != -1)
            {
                ((GameObject*)found)->seqIndex = -1;
                (*gObjectTriggerInterface)->endSequence(kindExt);
            }
            obj->seqIndex = -1;
        }
    }
}

void animsharpclaw_init(GameObject* obj, AnimsharpclawPlacement* placement)
{
    u8* sequenceData;
    int prevLinkCount;
    AnimsharpclawState* state;

    obj->animEventCallback = NULL;
    objSetSlot(obj, 0x64);
    sequenceData = obj->extra;
    state = (AnimsharpclawState*)sequenceData;
    state->sequence.gameBit = placement->sequenceGameBit;
    state->sequence.flags = -1;
    state->sequence.posOffsetDecay = 1.0f / (1.0f + (f32)(u32)placement->positionDamping);
    state->sequence.curveId = -1;
    state->sequence.animEntries = NULL;
    state->sequence.cmds = NULL;
    obj->userData2 = -1;
    prevLinkCount = obj->userData1;
    if (prevLinkCount == 0 && placement->animationBank != 1)
    {
        (*gObjectTriggerInterface)->loadAnimData(sequenceData, (u8*)placement);
        obj->userData1 = placement->animationBank + 1;
    }
    else if (prevLinkCount != 0 && placement->animationBank != prevLinkCount - 1)
    {
        (*gObjectTriggerInterface)->freeState(sequenceData);
        if (placement->animationBank != -1)
        {
            (*gObjectTriggerInterface)->loadAnimData(sequenceData, (u8*)placement);
        }
        obj->userData1 = placement->animationBank + 1;
    }
    if (obj->anim.modelState != NULL)
    {
        obj->anim.modelState->shadowTintA = 0x64;
        obj->anim.modelState->shadowTintB = 0x96;
    }
}

void animsharpclaw_release(void)
{
}

void animsharpclaw_initialise(void)
{
}

ObjectDescriptor gAnimSharpclawObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)animsharpclaw_initialise,
    (ObjectDescriptorCallback)animsharpclaw_release,
    0,
    (ObjectDescriptorCallback)animsharpclaw_init,
    (ObjectDescriptorCallback)animsharpclaw_update,
    (ObjectDescriptorCallback)animsharpclaw_hitDetect,
    (ObjectDescriptorCallback)animsharpclaw_render,
    (ObjectDescriptorCallback)animsharpclaw_free,
    (ObjectDescriptorCallback)animsharpclaw_getObjectTypeId,
    animsharpclaw_getExtraSize,
};
