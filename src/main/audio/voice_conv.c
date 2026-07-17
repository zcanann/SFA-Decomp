#include "main/audio/voice_manage.h"
#include "main/audio/synth_config.h"

extern u8 voiceMidiKeySlots[][SYNTH_VOICE_MIDI_KEY_COUNT];
extern u8 voiceDirectSlots[];

/*
 * Mark all entries of the MIDI voice-id table and direct voice-id table
 * as free. The asm has the inner stb's unrolled to two MIDI rows per
 * loop iter, and the direct-voice table is fully unrolled.
 */
void voiceInitRegistrationTables(void)
{
    int channel;
    int key;

    for (channel = 0; channel < SYNTH_VOICE_MIDI_CHANNEL_COUNT; channel++)
    {
        for (key = 0; key < SYNTH_VOICE_MIDI_KEY_COUNT; key++)
        {
            voiceMidiKeySlots[channel][key] = SYNTH_VOICE_REGISTRATION_FREE;
        }
    }
    voiceDirectSlots[0] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[1] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[2] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[3] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[4] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[5] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[6] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[7] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[8] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[9] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[10] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[11] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[12] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[13] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[14] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[15] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[16] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[17] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[18] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[19] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[20] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[21] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[22] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[23] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[24] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[25] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[26] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[27] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[28] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[29] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[30] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[31] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[32] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[33] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[34] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[35] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[36] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[37] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[38] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[39] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[40] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[41] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[42] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[43] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[44] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[45] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[46] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[47] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[48] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[49] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[50] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[51] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[52] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[53] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[54] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[55] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[56] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[57] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[58] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[59] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[60] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[61] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[62] = SYNTH_VOICE_REGISTRATION_FREE;
    voiceDirectSlots[63] = SYNTH_VOICE_REGISTRATION_FREE;
}
