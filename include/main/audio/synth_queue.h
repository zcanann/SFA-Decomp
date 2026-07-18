#ifndef MAIN_AUDIO_SYNTH_QUEUE_H_
#define MAIN_AUDIO_SYNTH_QUEUE_H_

#include "ghidra_import.h"

typedef struct SynthPage
{
    u16 macro;
    u8 priority;
    u8 maxVoices;
    u8 index;
    u8 reserved;
} SynthPage;

typedef struct SynthArrangement
{
    u32 trackTableOffset;
    u32 patternTableOffset;
    u32 trackMidiTableOffset;
    u32 masterTrackOffset;
    u32 info;
    u32 loopPoint[16];
    u32 trackSectionTableOffset;
} SynthArrangement;

typedef struct SynthSeqVolumeDefinition
{
    u8 track;
    u8 volumeGroup;
} SynthSeqVolumeDefinition;

typedef struct SynthPlayParams
{
    u32 flags;
    u32 trackMute[2];
    u16 speed;
    struct
    {
        u16 time;
        u8 target;
    } volume;
    u8 numSeqVolumeDefinitions;
    SynthSeqVolumeDefinition* seqVolumeDefinitions;
    u8 numFaded;
    u8* faded;
} SynthPlayParams;

typedef struct SynthMidiChannelSetup
{
    u8 program;
    u8 volume;
    u8 panning;
    u8 reverb;
    u8 chorus;
} SynthMidiChannelSetup;

typedef struct SynthMidiSetup
{
    u16 songId;
    u16 reserved;
    SynthMidiChannelSetup channel[16];
} SynthMidiSetup;

u32 seqStartPlay(SynthPage* normalPage, SynthPage* drumPage, SynthMidiSetup* midiSetup,
                 u32* arrangement, SynthPlayParams* params, u8 studio, u16 groupId);

void fn_8026CF78(u8 sectionIndex);
void synthQueueHandle(u32 handle);
void synthFreeHandle(u32 handle);

#endif /* MAIN_AUDIO_SYNTH_QUEUE_H_ */
