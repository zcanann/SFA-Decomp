#ifndef MAIN_PAD_H_
#define MAIN_PAD_H_

#include "ghidra_import.h"

typedef s8 (*PadGetAxisS8Fn)(int port);
typedef int (*PadGetAxisIntFn)(int port);
typedef void (*PadGetAnalogInputS8Fn)(int port, s8* x, s8* y);
typedef int (*PadGetAnalogInputIntFn)(int port, s8* x, s8* y);
typedef int (*PadGetAnalogInputCharFn)(int port, char* x, char* y);

extern f32 gRumbleTimer;
extern u8 joypadDisabled;
extern u8 rumbleEnabled;
extern u32 gPadResetMask;
extern u8 gPadStickRepeatDelay;
extern u32 gPadButtonMask[];
extern u8 gPadAnalogY;
extern u8 gPadAnalogX;
extern u8 gPadRepeatY;
extern u8 gPadRepeatX;
extern u8 gPadPrevStickY;
extern u8 gPadPrevStickX;
extern u16 gPadPrevTriggers;
extern u16 gPadTriggers;
extern u16 gPadTriggersReleased;
extern u16 gPadTriggersPressed;
extern u8 gPadStatusToggle;
extern u32 gPadStateBlock[];
extern u32 gPadButtonsHeld[];
extern u32 lbl_803398D0[];
extern u32 gPadButtonsJustPressed[];
extern u8 gPadStatuses[];

u32 getButtonsJustPressedIfNotBusy(int port);
u32 getButtonsJustPressed(int port);
u32 getNewInputs(int port);

void padUpdate(void);
void setJoypadDisabled(void);
void stopRumble2(void);
void stopRumble(void);
u32 buttonGetDisabled(int port);
u32 getButtonsHeld(int port);
void buttonDisable(int port, u32 mask);
void doRumble(f32 duration);
void setRumbleEnabled(u8 enabled);
void padClearAnalogInputX(int port);
void padClearAnalogInputY(int port);
void padFn_80014b18(int value);
void padGetAnalogInput(int port, u8* x, u8* y);
u8 padGetCY(int port);
u8 padGetCX(int port);
u8 padGetStickY(int port);
u8 padGetStickX(int port);
u8 padGetLTrigger(int port);
u8 padGetRTrigger(int port);
u16 getPadFn_80014d9c(int port);
u16 getButtons_80014dd8(int port);
int initControllers(void);

/* Preserve signed and int return views used by compiler-sensitive callers. */
#define padGetStickXS8(port) (((PadGetAxisS8Fn)padGetStickX)(port))
#define padGetStickYS8(port) (((PadGetAxisS8Fn)padGetStickY)(port))
#define padGetCXS8(port) (((PadGetAxisS8Fn)padGetCX)(port))
#define padGetCYS8(port) (((PadGetAxisS8Fn)padGetCY)(port))
#define padGetStickXInt(port) (((PadGetAxisIntFn)padGetStickX)(port))
#define padGetStickYInt(port) (((PadGetAxisIntFn)padGetStickY)(port))
#define padGetAnalogInputS8(port, x, y) (((PadGetAnalogInputS8Fn)padGetAnalogInput)((port), (x), (y)))
#define padGetAnalogInputInt(port, x, y) (((PadGetAnalogInputIntFn)padGetAnalogInput)((port), (x), (y)))
#define padGetAnalogInputChar(port, x, y) (((PadGetAnalogInputCharFn)padGetAnalogInput)((port), (x), (y)))

#endif /* MAIN_PAD_H_ */
