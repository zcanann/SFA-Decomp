#ifndef MAIN_AUDIO_SND_TYPES_H_
#define MAIN_AUDIO_SND_TYPES_H_

#include "ghidra_import.h"

typedef enum SND_STUDIO_TYPE {
    SND_STUDIO_TYPE_STD = 0,
    SND_STUDIO_TYPE_DPL2,
    SND_STUDIO_TYPE_RESERVED1,
    SND_STUDIO_TYPE_RESERVED2,
} SND_STUDIO_TYPE;

typedef struct SND_STUDIO_INPUT {
    u8 vol;
    u8 volA;
    u8 volB;
    u8 srcStudio;
} SND_STUDIO_INPUT;

#endif /* MAIN_AUDIO_SND_TYPES_H_ */
