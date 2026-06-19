#include "main/audio/voice_id.h"
#include "main/audio/mcmd.h"

extern u8 vidListNodes[];

#define voicePriorityLinks (vidListNodes + 0x8c0)

extern u32 vidCurrentId;
extern void* vidRoot;
extern void* vidFree;
extern u16 voicePrioSortRootListRoot;
extern McmdVoiceState* synthVoice;
extern void voiceUnregister(int state);



/*
 * Remove a voice from the vid id list, recycling any allocated id-list nodes.
 */
#define VID_UNLINK(field) \
    if (s->field->prev != 0) { \
        s->field->prev->next = s->field->next; \
    } else { \
        vidRoot = s->field->next; \
    } \
    if (s->field->next != 0) { \
        s->field->next->prev = s->field->prev; \
    } \
    s->field->next = vidFree; \
    if (vidFree != 0) { \
        ((McmdVidListNode *)vidFree)->prev = s->field; \
    } \
    s->field->prev = 0; \
    vidFree = s->field

void vidRemoveVoice(int state)
{
    McmdVoiceState* s = (McmdVoiceState*)state;
    if (s->voiceHandle != 0xffffffff)
    {
        voiceUnregister(state);
        if (s->voicePrevHandle != 0xffffffff)
        {
            synthVoice[s->voicePrevHandle & 0xff].voiceNextHandle =
                s->voiceNextHandle;
            if (s->voiceNextHandle != 0xffffffff)
            {
                synthVoice[s->voiceNextHandle & 0xff].voicePrevHandle =
                    s->voicePrevHandle;
            }
            VID_UNLINK(vidListNode);
            s->vidListNode = 0;
        }
        else if (s->voiceNextHandle != 0xffffffff)
        {
            s->vidListNode->internalId = s->voiceNextHandle;
            synthVoice[s->voiceNextHandle & 0xff].voicePrevHandle = 0xffffffff;
            synthVoice[s->voiceNextHandle & 0xff].vidMasterListNode =
                s->vidMasterListNode;
            if (s->vidListNode != s->vidMasterListNode)
            {
                VID_UNLINK(vidListNode);
                s->vidListNode = 0;
            }
            s->vidListNode = 0;
            s->vidMasterListNode = 0;
        }
        else if (s->vidListNode != s->vidMasterListNode)
        {
            VID_UNLINK(vidListNode);
            s->vidListNode = 0;
            VID_UNLINK(vidMasterListNode);
            s->vidMasterListNode = 0;
        }
        else
        {
            VID_UNLINK(vidListNode);
            s->vidListNode = 0;
            s->vidMasterListNode = 0;
        }
    }
}

/*
 * Snapshot the current entry's `next` pointer (state->[0xf8]) into the
 * cached field (state->[0xfc]) and return that next entry's id field.
 *
 * EN v1.0 Address: 0x802791E8
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027938C
 * EN v1.1 Size: 20b
 */
int vidMakeRoot(int state)
{
    McmdVoiceState* s = (McmdVoiceState*)state;
    s->vidMasterListNode = s->vidListNode;
    return s->vidListNode->id;
}

/*
 * Allocate the next unique id from the global counter, walking the
 * sorted-by-id list to skip any already-in-use ids. Used to assign
 * fresh handles to dynamically-allocated voices.
 *
 * EN v1.0 Address: 0x802791EC
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x802793A0
 * EN v1.1 Size: 332b
 */
u32 vidMakeNew(int state, int returnNewId)
{
    McmdVoiceState* s = (McmdVoiceState*)state;
    u32 nextId;
    int** cursor;
    int** node;
    int** prev;
    int** freeNode;

    do
    {
        nextId = vidCurrentId;
        vidCurrentId = nextId + 1;
    }
    while (nextId == 0xffffffffU);

    cursor = vidRoot;
    prev = 0;
    while ((node = cursor) != 0)
    {
        if ((u32)node[2] > nextId)
        {
            break;
        }
        if ((u32)node[2] == nextId)
        {
            do
            {
                nextId = vidCurrentId;
                vidCurrentId = nextId + 1;
            }
            while (nextId == 0xffffffffU);
        }
        prev = node;
        cursor = (int**)*node;
    }

    if ((freeNode = vidFree) == 0)
    {
        return 0xffffffffU;
    }
    if ((vidFree = *(void**)vidFree) != 0)
    {
        *(u32*)((u8*)vidFree + 4) = 0;
    }
    if (prev == 0)
    {
        vidRoot = freeNode;
    }
    else
    {
        *prev = (int*)freeNode;
    }
    freeNode[1] = (int*)prev;
    *freeNode = (int*)node;
    if (node != 0)
    {
        node[1] = (int*)freeNode;
    }
    freeNode[2] = (int*)nextId;
    freeNode[3] = (int*)s->voiceHandle;
    s->vidMasterListNode = (McmdVidListNode*)(((u32)returnNewId != 0) ? freeNode : 0);
    s->vidListNode = (McmdVidListNode*)freeNode;
    if ((u32)returnNewId != 0)
    {
        return nextId;
    }
    return s->voiceHandle;
}

/*
 * Look up a voice handle's slot via the sorted linked list.
 * Returns -1 for the sentinel id 0xFFFFFFFF or if not found.
 *
 * EN v1.0 Address: 0x802791F0
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8027949C
 * EN v1.1 Size: 80b
 */
static int* get_vidlist(u32 id)
{
    int* node;
    node = vidRoot;
    while (node != NULL)
    {
        if (*(u32*)(node + 2) == id) return node;
        if (*(u32*)(node + 2) > id) break;
        node = *(int**)node;
    }
    return NULL;
}

int vidGetInternalId(u32 id)
{
    int* node;

    if (id != 0xffffffffU)
    {
        if ((node = get_vidlist(id)) != NULL)
        {
            return *(int*)(node + 3);
        }
    }
    return -1;
}

/*
 * voiceRemovePriority - voice priority-queue removal (sister to placeholder_
 * 80279608's insert). Removes the active voice from its group's
 * linked list and from the sorted priority list.
 *
 * EN v1.0 Address: 0x802791F4
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x802794EC
 * EN v1.1 Size: 224b
 */
typedef struct VoicePrioVoiceRec
{
    u8 prev;
    u8 next;
    u16 user;
} VoicePrioVoiceRec;

typedef struct VoicePrioRootRec
{
    u16 next;
    u16 prev;
} VoicePrioRootRec;

typedef struct VoicePrioBlockRec
{
    u8 vidNodes[0x8C0];
    VoicePrioVoiceRec prioVoices[64]; /* 0x8C0 */
    u8 prioVoicesRoot[256]; /* 0x9C0 */
    VoicePrioRootRec prioRootList[256]; /* 0xAC0 */
} VoicePrioBlockRec;

void voiceRemovePriority(int state)
{
    McmdVoiceState* s = (McmdVoiceState*)state;
    VoicePrioBlockRec* vb;
    VoicePrioVoiceRec* vps;
    VoicePrioRootRec* pr;

    vb = (VoicePrioBlockRec*)vidListNodes;
    vps = (VoicePrioVoiceRec*)&((u8*)voicePriorityLinks)[(s->voiceHandle & 0xff) << 2];
    if (vps->user != 1)
    {
        return;
    }
    if (vps->prev != 0xff)
    {
        vb->prioVoices[vps->prev].next = vps->next;
    }
    else
    {
        vb->prioVoicesRoot[s->priorityGroup] = vps->next;
    }
    if (vps->next != 0xff)
    {
        vb->prioVoices[vps->next].prev = vps->prev;
    }
    else if (vps->prev == 0xff)
    {
        u32 prevv;
        pr = (VoicePrioRootRec*)((u8*)vb + ((u32)s->priorityGroup << 2));
        prevv = *(u16*)((u8*)pr + 2754);
        pr = (VoicePrioRootRec*)((u8*)pr + 2752);
        if (prevv != 0xffff)
        {
            vb->prioRootList[prevv].next = pr->next;
        }
        else
        {
            voicePrioSortRootListRoot = pr->next;
        }
        if (pr->next != 0xffff)
        {
            vb->prioRootList[pr->next].prev = pr->prev;
        }
    }
    vps->user = 0;
}
