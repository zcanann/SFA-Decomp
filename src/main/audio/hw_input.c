#include "main/audio/hw_input.h"
#include "main/unknown/autos/musyx_dsp.h"


extern DSPstudioinfo dspStudio[8];
extern void salAddStudioInput(DSPstudioinfo* studio, void* input);

void hwAddInput(u8 index, void* input)
{
    salAddStudioInput(&dspStudio[index], input);
}
