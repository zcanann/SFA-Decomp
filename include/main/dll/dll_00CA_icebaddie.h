#ifndef MAIN_DLL_ICEBADDIE_H_
#define MAIN_DLL_ICEBADDIE_H_

#include "ghidra_import.h"
#include "main/dll/baddie_state.h"

/*
 * dll_00CA (icebaddie, ex-"mediumbasket") is cut/unused content (see the .c file header for
 * the full story). The only externally-referenced symbols are these whirlpool
 * grouping helpers, which are SHARED engine utilities: the generic enemy DLL
 * (dll_00C9) calls them for water/whirlpool objects.
 */
void iceBaddie_enterWhirlpoolGroup(int obj, GroundBaddieState *state);
void iceBaddie_leaveWhirlpoolGroup(int obj, GroundBaddieState *state);

#endif /* MAIN_DLL_ICEBADDIE_H_ */
