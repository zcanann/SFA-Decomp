#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80281A9C_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80281A9C_H_

#include "ghidra_import.h"

#define INP_INVALID_SLOT 0xFF
#define INP_MIDI_CTRL_BANK_SIZE 0x86
#define INP_MIDI_KEY_STRIDE 0x860
#define INP_MIDI_SLOT_COUNT 16

void inpResetMidiCtrl(u8 a, u8 b, u32 mode);
u32 inpGetMidiCtrl(u8 controller, u32 slot, u32 key);
u8 *inpGetChannelDefaults(u8 a, u8 b);
void inpResetChannelDefaults(u8 a, u8 b);
void inpAddCtrl(int obj, int b, int c, int d, u32 flag);
void inpFXCopyCtrl(u8 controller, int dstState, int srcState);
void inpSetMidiLastNote(u8 a, u8 b, u8 v);
u8 inpGetMidiLastNote(u8 a, u8 b);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80281A9C_H_ */
