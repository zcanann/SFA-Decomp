#include "ghidra_import.h"
#include "main/dll/dll_4E.h"

#define SFXsp_snrot1_c 256

extern undefined4 FUN_80006768();
extern undefined4 FUN_8000676c();
extern undefined4 FUN_80006810();
extern undefined4 FUN_80006824();
extern void audioSetSoundMode(u8 mode, u8 enabled);
extern void audioSetVolumes(u8 volume, int p1, int p2, int p3, int p4);
extern void Sfx_StopFromObject(int obj, int sfxId);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void saveFileStruct_resetVolumes(void);

extern undefined4 DAT_803a9430;
extern undefined4 DAT_803a9434;
extern undefined4 DAT_803a9438;
extern undefined4 DAT_803a943c;
extern undefined4 DAT_803a9444;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6f0;
extern undefined4* DAT_803dd724;
extern undefined4 DAT_803de37c;
extern undefined4 DAT_803de384;
extern undefined4 DAT_803de385;
extern undefined4 DAT_803de388;

extern int* gScreenTransitionInterface;
extern int* gTitleMenuControlInterface;
extern int* gTitleMenuItemInterface;
extern int* lbl_803A87D0[8];
extern int lbl_803DD6FC;
extern u8 lbl_803DD704;
extern u8 lbl_803DD705;
extern u8 *lbl_803DD708;

/*
 * --INFO--
 *
 * Function: optionsMenu_applyAudioSetting
 * EN v1.0 Address: 0x8011BFC8
 * EN v1.0 Size: 872b
 * EN v1.1 Address: 0x8011C2AC
 * EN v1.1 Size: 848b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void optionsMenu_applyAudioSetting(int p1,int p2)
{
    int value;

    if (lbl_803A87D0[p2] != NULL &&
        (*(int(**)(int*))(*gTitleMenuItemInterface + 0x2c))(lbl_803A87D0[p2]) != 0) {
        switch (p2) {
        case 0:
            audioSetSoundMode((u8)(*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]), 1);
            break;
        case 2:
            value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]);
            audioSetVolumes((u8)value, 10, 0, 1, 0);
            break;
        case 1:
            value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]);
            audioSetVolumes((u8)value, 10, 1, 0, 0);
            value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]);
            (*(void(**)(int))(*gTitleMenuControlInterface + 0x28))(value);
            break;
        case 3:
            value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]);
            audioSetVolumes((u8)value, 10, 0, 0, 1);
            break;
        case 5:
            lbl_803DD6FC = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]);
            break;
        }
    }
    if ((lbl_803A87D0[p2] == NULL) || ((p2 != 2) && (p2 != 1) && (p2 != 3))) {
        Sfx_StopFromObject(0, 0x3b9);
    }
    if (p1 == 0) {
        Sfx_PlayFromObject(0, SFXsp_snrot1_c);
        (*(void(**)(int, int))(*gScreenTransitionInterface + 0x8))(0x14, 5);
        lbl_803DD704 = 0x23;
        lbl_803DD705 = 1;
    } else if ((p1 == 1) && (p2 == 4)) {
        saveFileStruct_resetVolumes();
        (*(void(**)(int*, u8))(*gTitleMenuItemInterface + 0x28))(lbl_803A87D0[1], lbl_803DD708[10]);
        (*(void(**)(int*, u8))(*gTitleMenuItemInterface + 0x28))(lbl_803A87D0[2], lbl_803DD708[11]);
        (*(void(**)(int*, u8))(*gTitleMenuItemInterface + 0x28))(lbl_803A87D0[3], lbl_803DD708[12]);
        value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[1]);
        audioSetVolumes((u8)value, 10, 0, 1, 0);
        value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[2]);
        audioSetVolumes((u8)value, 10, 1, 0, 0);
        value = (*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[3]);
        audioSetVolumes((u8)value, 10, 0, 0, 1);
        Sfx_PlayFromObject(0, 0x418);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int optionsMenu_openAudioPanel(void);
extern int optionsMenu_openGeneralPanel(void);
extern int languageMenuInit(void);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern int* gScreenTransitionInterface;
extern u8 lbl_803DD704;
extern u8 lbl_803DD705;
extern int* gTitleMenuItemInterface;
extern int* gTitleMenuLinkInterface;
extern int* lbl_803A87D0[8];
extern f32 lbl_803E1DD0;
extern s8 lbl_803DBA28;
extern void setWidescreen(u8 enabled);
extern void stopRumble2(void);
extern void setRumbleEnabled(u8 value);
extern void doRumble(f32 val);
extern void creditsStart(void);
extern void Rcp_SetColorFilterEnabled(int enabled);

#pragma scheduling off
#pragma peephole off
void optionsMenu_applyGameplaySetting(int p1, int p2)
{
    int i;
    int **ptr;
    u8 newState;

    if (lbl_803A87D0[p2] != NULL &&
        (*(int(**)(int*))(*gTitleMenuItemInterface + 0x2c))(lbl_803A87D0[p2]) != 0) {
        switch (p2) {
        case 0:
            setWidescreen((u8)(*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]));
            break;
        case 1:
            newState = (u8)!(*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]);
            if (newState == 0) {
                stopRumble2();
            }
            setRumbleEnabled(newState);
            if (newState != 0) {
                doRumble(lbl_803E1DD0);
            }
            break;
        case 2:
            if ((*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]) == 0) {
                creditsStart();
                if (lbl_803DBA28 != -1) {
                    (*(void(**)(void))(*gTitleMenuLinkInterface + 0x8))();
                    lbl_803DBA28 = -1;
                }
                i = 0;
                ptr = lbl_803A87D0;
                for (; i < 8; i++) {
                    if (*ptr != NULL) {
                        (*(void(**)(int*))(*gTitleMenuItemInterface + 0x10))(*ptr);
                        *ptr = NULL;
                    }
                    ptr++;
                }
            }
            break;
        case 3:
            Rcp_SetColorFilterEnabled((*(int(**)(int*))(*gTitleMenuItemInterface + 0x24))(lbl_803A87D0[p2]));
            break;
        }
    }
    if (p1 == 0) {
        Sfx_PlayFromObject(0, SFXsp_snrot1_c);
        (*(void(**)(int, int))(*gScreenTransitionInterface + 0x8))(0x14, 5);
        lbl_803DD704 = 0x23;
        lbl_803DD705 = 1;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int optionsMenu_openSelectedSubmenu(int p1, int p2)
{
    if (p1 == 1) {
        switch (p2) {
        case 0:
            optionsMenu_openGeneralPanel();
            return 1;
        case 2:
            optionsMenu_openAudioPanel();
            return 1;
        case 3:
            languageMenuInit();
            return 1;
        }
    } else if (p1 == 0) {
        Sfx_PlayFromObject(0, SFXsp_snrot1_c);
        (*(void(**)(int, int))(*gScreenTransitionInterface + 0x8))(0x14, 5);
        lbl_803DD704 = 0x23;
        lbl_803DD705 = 1;
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
