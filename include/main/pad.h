#ifndef MAIN_PAD_H_
#define MAIN_PAD_H_

#include "ghidra_import.h"
#include "main/pad_api.h"

extern f32 gRumbleTimer;
extern f32 gRumbleTimerZero;
extern u8 joypadDisabled;
extern u8 rumbleEnabled;
extern u32 gPadResetMask;
extern u8 gPadStickRepeatDelay;
extern u32 gPadButtonMask[];
extern s8 gPadAnalogY;
extern s8 gPadAnalogX;
extern u8 gPadRepeatY;
extern u8 gPadRepeatX;
extern u8 gPadPrevStickY;
extern u8 gPadPrevStickX;
extern u16 gPadPrevTriggers;
extern u16 gPadTriggers;
extern u16 gPadTriggersReleased;
extern u16 gPadTriggersPressed;
extern u8 gPadStatusToggle;
extern u32 gPadButtonsPrevious[];
extern u32 gPadButtonsHeld[];
extern u32 gPadButtonsReleased[];
extern u32 gPadButtonsJustPressed[];
extern u8 lbl_803DCCA5;

u32 getButtonsJustPressedIfNotBusy(int port);
u32 getButtonsJustPressed(int port);
u32 getNewInputs(int port);

void padUpdate(void);
void setJoypadDisabled(void);
void stopRumble2(void);
void stopRumble(void);
u32 getButtonsHeld(int port);
void setRumbleEnabled(u8 enabled);
void padClearAnalogInputX(int port);
void padClearAnalogInputY(int port);
void padFn_80014b18(int value);
void padGetAnalogInput(int port, s8* x, s8* y);
s8 padGetCY(int port);
s8 padGetCX(int port);
s8 padGetStickY(int port);
s8 padGetStickX(int port);
u8 padGetLTrigger(int port);
u8 padGetRTrigger(int port);
u16 getPadFn_80014d9c(int port);
u16 getButtons_80014dd8(int port);
int initControllers(void);
void doNothing_endOfFrame(void);

#endif /* MAIN_PAD_H_ */
