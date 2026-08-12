#ifndef MAIN_GAMETEXT_API_H_
#define MAIN_GAMETEXT_API_H_

#include "types.h"
#include "main/gametext_internal.h"

typedef struct TextDisplayState TextDisplayState;

typedef struct NpcDialoguePhraseState
{
    TextDisplayState display;
    char* phraseBuffer;
} NpcDialoguePhraseState;

STATIC_ASSERT(sizeof(NpcDialoguePhraseState) == 0x18);
STATIC_ASSERT(offsetof(NpcDialoguePhraseState, phraseBuffer) == 0x14);

void gameTextAppendStr(char* str, int box);
void gameTextQueueReveal(int textId, TextDisplayState* state);
void gameTextFreePhrase(NpcDialoguePhraseState* phrase);
void gameTextMeasureStringBoundsAt(char* str, int boxIdx, int x, int y, int* outMinX, int* outMaxX, int* outMinY,
                                   int* outMaxY);
void gameTextMeasureById(int id, int x, int y, int* outMinX, int* outMaxX, int* outMinY, int* outMaxY);

char** gameTextWrapLines(char* str, f32 width, f32 height, int* outCount, f32* outLineH);

extern char* sMapDirectoryNameTable[74];

#endif /* MAIN_GAMETEXT_API_H_ */
