#include "main/audio/vid_init.h"

typedef struct VoiceNode
{
    struct VoiceNode* next;
    struct VoiceNode* prev;
    u8 unk8[8];
} VoiceNode;

extern VoiceNode vidListNodes[128];
extern int vidCurrentId;
extern int vidRoot;
extern VoiceNode* vidFree;

void vidInit(void)
{
    int i;
    VoiceNode* prev;

    vidCurrentId = 0;
    vidRoot = 0;
    vidFree = vidListNodes;
    for (prev = NULL, i = 0; i < 128; prev = &vidListNodes[i], ++i)
    {
        vidListNodes[i].prev = prev;
        if (prev != NULL)
        {
            prev->next = &vidListNodes[i];
        }
    }
    prev->next = NULL;
}

VoiceNode vidListNodes[128];
