#ifndef MAIN_TEXTRENDER_API_H_
#define MAIN_TEXTRENDER_API_H_

#include "types.h"

typedef struct GameTextSlot {
    int opcode;
    int arg0;
    int arg1;
    int arg2;
    int arg3;
} GameTextSlot;

extern int lbl_803DC9C8;
extern GameTextSlot lbl_8033A540[];

#define gGameTextCommandCount lbl_803DC9C8
#define gGameTextCommandSlots lbl_8033A540

void subtitleFn_8001b700(void);
void* gameTextGetPhrase(int textId, int phraseIndex);
void gameTextResetCursor(int flags);

#endif /* MAIN_TEXTRENDER_API_H_ */
