#ifndef MAIN_DLL_DLL_0017_SAVEGAME_CS_H_
#define MAIN_DLL_DLL_0017_SAVEGAME_CS_H_

#include "types.h"

void mapClearBit(int idx, int bit);
void* getHighScoreEntry(u8 fileIdx, u8 rank);

int saveGame_restoreObjectPosToRomList(void* object);
#endif /* MAIN_DLL_DLL_0017_SAVEGAME_CS_H_ */
