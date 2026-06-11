#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/dll/dll_43.h"
#include "main/screen_transition.h"

extern void saveSelectGoToChooseSlot(int arg);

extern u8 lbl_803DB424;
extern TitleMenuControl* gScreenTransitionInterface;
extern TitleMenuControl* gTitleMenuControlInterface;
extern u8 lbl_803DD6C4;
extern u8 lbl_803DD6CC;
extern u8 lbl_803DD6CD;
extern u8 lbl_803DD6CF;

void saveSelectSetSlot(int param_1, int param_2)
{
    if (param_1 == 0)
    {
        if (lbl_803DB424 != 0)
        {
            Sfx_PlayFromObject(0, 0x419);
            saveSelectGoToChooseSlot(0);
        }
        else
        {
            Sfx_PlayFromObject(0, SFXsp_snrot1_c);
            ((ScreenTransitionInterface*)gScreenTransitionInterface->vtable)->start(0x14, 5);
            lbl_803DD6CF = 0x23;
            lbl_803DD6CC = 1;
        }
    }
    else
    {
        lbl_803DD6CD = 1;
        Sfx_PlayFromObject(0, 0x418);
        ((ScreenTransitionInterface*)gScreenTransitionInterface->vtable)->start(0x14, 1);
        ((void (**)(int))gTitleMenuControlInterface->vtable)[7](0);
        ((void (**)(int))gTitleMenuControlInterface->vtable)[7](1);
        ((void (**)(int))gTitleMenuControlInterface->vtable)[7](2);
        ((void (**)(int))gTitleMenuControlInterface->vtable)[7](3);
        lbl_803DD6CF = 0x23;
        lbl_803DD6C4 = param_2;
    }
}
