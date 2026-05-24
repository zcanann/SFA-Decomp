#ifndef MAIN_DLL_FRONT_TITLE_MENU_H_
#define MAIN_DLL_FRONT_TITLE_MENU_H_

#include "ghidra_import.h"

typedef struct TitleMenuTextEntry {
  u16 textId;
  u8 pad02[0x0E];
  s32 actionParam;
  u8 pad14[2];
  u16 flags;
  s8 pad18[0x24];
} TitleMenuTextEntry;

#define TITLE_MENU_TEXT_ENTRY_SELECTABLE 0x1
#define TITLE_MENU_TEXT_ENTRY_DISABLED 0x2

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
