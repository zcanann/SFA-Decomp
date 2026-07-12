#ifndef MAIN_PAD_H_
#define MAIN_PAD_H_

#include "ghidra_import.h"

u32 getButtonsJustPressedIfNotBusy(int port);
u32 getButtonsJustPressed(int port);

void padUpdate(void);
void setJoypadDisabled(void);
void stopRumble2(void);
u32 buttonGetDisabled(int port);
u32 getButtonsHeld(int port);
void buttonDisable(int port, u32 mask);
void doRumble(f32 duration);
void padClearAnalogInputX(int port);
void padClearAnalogInputY(int port);
void padFn_80014b18(int value);

#endif /* MAIN_PAD_H_ */
