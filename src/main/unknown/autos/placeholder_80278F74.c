#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80278F74.h"

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
    VoiceNode *node = vidListNodes;
    VoiceNode *prev = NULL;
    int i;

    vidFree = node;
    vidCurrentId = 0;
    vidRoot = 0;

    for (i = 0; i < 128; i++) {
        node->prev = prev;
        if (prev != NULL) {
            prev->next = node;
        }
        prev = node;
        node++;
    }
    prev->next = NULL;
}
