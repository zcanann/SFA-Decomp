#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8026DFE4.h"

/* Placeholder for the larger fn_8026DE58 — voice-state walker that's
 * too complex to fully decode here without more context; stubbed. */
void fn_8026DE58(u8 voiceIdx) { (void)voiceIdx; }

/*
 * Sorted-by-priority insert into a doubly-linked list anchored at
 * (*holder)[0x1c]. Walks the list until finding a node with a
 * priority key (offset 8) less than or equal to the new node's,
 * then inserts before it. Empty list / tail-append paths handled.
 *
 * EN v1.0 Address: 0x8026DEC4
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8026E070
 * EN v1.1 Size: 116b
 */
void fn_8026E070(int holder, int newNode)
{
    u32 cur = *(u32 *)(holder + 0x1c);
    u32 prev = 0;

    while (cur != 0) {
        if (*(u32 *)(cur + 8) > *(u32 *)(newNode + 8)) {
            *(u32 *)(newNode + 0) = cur;
            *(u32 *)(newNode + 4) = prev;
            if (prev != 0) {
                *(u32 *)(prev + 0) = (u32)newNode;
            } else {
                *(u32 *)(holder + 0x1c) = (u32)newNode;
            }
            *(u32 *)(cur + 4) = (u32)newNode;
            return;
        }
        prev = cur;
        cur = *(u32 *)(cur + 0);
    }
    *(u32 *)(newNode + 4) = prev;
    if (prev != 0) {
        *(u32 *)(prev + 0) = (u32)newNode;
    } else {
        *(u32 *)(holder + 0x1c) = (u32)newNode;
    }
    *(u32 *)(newNode + 0) = 0;
}
