#include "main/audio/hw_input.h"
#include "main/audio/hw_dspctrl.h"


extern DSPstudioinfo dspStudio[8];

u32 hwAddInput(u8 studio, SND_STUDIO_INPUT* input)
{
    return salAddStudioInput(&dspStudio[studio], input);
}
