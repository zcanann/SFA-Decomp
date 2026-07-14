#ifndef MAIN_AUDIO_INP_MIDI_H_
#define MAIN_AUDIO_INP_MIDI_H_

#include "ghidra_import.h"

#define INP_INVALID_SLOT 0xFF
#define INP_MIDI_CTRL_BANK_SIZE 0x86
#define INP_MIDI_KEY_STRIDE 0x860
#define INP_MIDI_SLOT_COUNT 16
#define INP_MIDI_CTRL_BY_KEY_OFFSET 0xC0
#define INP_MIDI_CTRL_GLOBAL_OFFSET 0x43C0
#define INP_MIDI_AUX_KEY_STRIDE 0x40
#define INP_MIDI_AUX_BY_KEY_OFFSET 0x6540
#define INP_MIDI_CHANNEL_DEFAULTS_BY_KEY_OFFSET 0x6740

typedef struct InpMidiState
{
    u8 pad0[0xC0];
    u8 midiCtrl[8][16][134]; /* 0x00C0 */
    u8 fxCtrl[16][134];      /* 0x43C0 */
    u8 pad1[0x1920];         /* 0x4C20 */
    u32 globalDirty[8][16];  /* 0x6540 */
    u8 pbRange[8][16];       /* 0x6740 */
} InpMidiState;

void inpSetMidiCtrl(u8 controller, u8 slot, u8 key, u8 value);
void inpSetMidiCtrl14(u8 controller, u8 slot, u8 key, u16 data);
u16 inpGetMidiCtrl(u8 controller, u8 slot, u8 key);
void inpResetMidiCtrl(u8 a, u8 b, u32 mode);
u8 *inpGetChannelDefaults(u8 a, u8 b);
void inpResetChannelDefaults(u8 a, u8 b);
void inpAddCtrl(int obj, int b, int c, int d, u32 flag);
void inpFXCopyCtrl(u8 controller, int dstState, int srcState);
void inpSetMidiLastNote(u8 a, u8 b, u8 v);
u8 inpGetMidiLastNote(u8 a, u8 b);

#endif /* MAIN_AUDIO_INP_MIDI_H_ */
