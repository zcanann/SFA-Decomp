#ifndef MAIN_DLL_SAVEGAME_LOAD_API_H_
#define MAIN_DLL_SAVEGAME_LOAD_API_H_

#include "types.h"

int getSaveGameLoadStatus(void);
void setSaveGameLoadingFlag(void);
s32 isSaveGameLoading(void);
void clearSaveGameLoadingFlag(void);

#endif /* MAIN_DLL_SAVEGAME_LOAD_API_H_ */
