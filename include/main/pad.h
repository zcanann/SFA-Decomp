#ifndef MAIN_PAD_H_
#define MAIN_PAD_H_

#include "types.h"
#include "main/pad_api.h"

extern f32 gRumbleTimer;
extern u8 joypadDisabled;
extern u8 rumbleEnabled;
extern u32 gPadResetMask;
extern u8 gPadMenuStickRepeatDelay;
extern u32 gPadButtonMask[4];
extern s8 gPadMenuStickYSign[4];
extern s8 gPadMenuStickXSign[4];
extern s8 gPadMenuStickYHoldTimer[4];
extern s8 gPadMenuStickXHoldTimer[4];
extern s8 gPadLastStickY[4];
extern s8 gPadLastStickX[4];
extern u16 gPadPrevTriggers[4];
extern u16 gPadTriggers[4];
extern u16 gPadTriggersReleased[4];
extern u16 gPadTriggersPressed[4];
extern u8 gPadStatusBufferIndex;
extern u32 gPadButtonsPrevious[4];
extern u32 gPadButtonsHeld[4];
extern u32 gPadButtonsReleased[4];
extern u32 gPadButtonsJustPressed[4];
extern u8 gPadReadReady;

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
void padSetStickRepeatDelay(int delay);
void padGetAnalogInput(int port, s8* x, s8* y);
s8 padGetCY(int port);
s8 padGetCX(int port);
s8 padGetStickY(int port);
s8 padGetStickX(int port);
u8 padGetLTrigger(int port);
u8 padGetRTrigger(int port);
u16 padGetTriggersPressed(int port);
u16 padGetTriggers(int port);
int initControllers(void);
void doNothing_endOfFrame(void);

#endif /* MAIN_PAD_H_ */
