#ifndef MAIN_DLL_DB_DBPROTECTION_H_
#define MAIN_DLL_DB_DBPROTECTION_H_

#include "ghidra_import.h"

void fn_801DFA28(u8 *obj);
void DBprotection_updateEnvfxGameBits(u8 *state);
int DBprotection_getCameraState(int *obj);
void DBprotection_updateShield(int *obj);
void DBprotection_storeHomePosition(int *obj);

#endif /* MAIN_DLL_DB_DBPROTECTION_H_ */
