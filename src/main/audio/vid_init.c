#include "main/audio/vid_init.h"

typedef struct VoiceNode {
    struct VoiceNode *next;
    struct VoiceNode *prev;
    u8 unk8[8];
} VoiceNode;

extern VoiceNode vidListNodes[128];
extern int vidCurrentId;
extern int vidRoot;
extern VoiceNode *vidFree;

/*
 * --INFO--
 *
 * Function: vidInit
 * EN v1.0 Address: 0x80278F0C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80278F74
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void vidInit(void)
{
    int i;
    VoiceNode *prev;

    vidCurrentId = 0;
    vidRoot = 0;
    vidFree = vidListNodes;
    for (prev = NULL, i = 0; i < 128; prev = &vidListNodes[i], ++i) {
        vidListNodes[i].prev = prev;
        if (prev != NULL) {
            prev->next = &vidListNodes[i];
        }
    }
    prev->next = NULL;
}
