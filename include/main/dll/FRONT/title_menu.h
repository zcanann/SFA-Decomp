#ifndef MAIN_DLL_FRONT_TITLE_MENU_H_
#define MAIN_DLL_FRONT_TITLE_MENU_H_

#include "ghidra_import.h"

typedef struct TitleMenuTextEntry {
  u8 pad0[0x16];
  u16 flags;
  s8 pad18[0x24];
} TitleMenuTextEntry;

typedef struct TitleMenuControl {
  void *vtable;
} TitleMenuControl;

typedef struct MenuPanelGroup {
  u8 pad00[0x30];
  TitleMenuTextEntry *entries;
  u32 unused34;
  u8 count;
  u8 pad39[7];
} MenuPanelGroup;

#endif /* MAIN_DLL_FRONT_TITLE_MENU_H_ */
