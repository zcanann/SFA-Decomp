#ifndef SFA_AUDIO_SYNTH_VOICE_OVERLAYS_H
#define SFA_AUDIO_SYNTH_VOICE_OVERLAYS_H

#include "src/main/audio/synth_internal.h"

typedef struct SynthVoiceProgramState {
    u8 unk00[0x108];
    u8* programData;
} SynthVoiceProgramState;

typedef struct SynthVoiceTrackRuntime {
    SynthTrackCursor trackCursors[SYNTH_SEQUENCE_TRACK_COUNT];
    u8 studioMap[SYNTH_SEQUENCE_TRACK_COUNT];
    SynthSequenceState sequenceStates[SYNTH_SEQUENCE_TRACK_COUNT];
} SynthVoiceTrackRuntime;

#define SYNTH_VOICE_PROGRAM_STATE(voice) ((SynthVoiceProgramState*)((u8*)(voice) + 0x10))
#define SYNTH_VOICE_TRACK_RUNTIME(voice) ((SynthVoiceTrackRuntime*)&(voice)->unk124)
#define SYNTH_CALLBACK_CONTROLLER_STATE(voice, controller) \
    ((SynthCallbackControllerState*)((u8*)(voice) + 0x1518 + ((controller) * 0x38)))
#define SYNTH_CALLBACK_CONTROLLER_THRESHOLD(controllerState, index) \
    (*(s32*)((u8*)(controllerState) - 0x0C + ((index) * 8)))

#endif
