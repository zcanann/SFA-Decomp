#include "main/dll/dll_BC.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"

extern int lbl_803DD518;

extern int gameTextFn_80134be8(void);
extern void setAButtonIcon(int kind);


/*
 * --INFO--
 *
 * Function: Camera_minimapShowHelpTextForTarget
 * EN v1.0 Address: 0x8010210C
 * EN v1.0 Size: 152b
 */
void Camera_minimapShowHelpTextForTarget(int arg1, int arg2, int arg3, int arg4)
{
    if (gameTextFn_80134be8() == 0)
    {
        gCamcontrolTargetHelpTextId = CAMCONTROL_HELP_TEXT_NONE;
        camcontrol_updateTargetReticle((CamcontrolTargetObject*)CAMCONTROL_CAMERA->targetReticleFocus,
                                       lbl_803DD518 == 0x49,
                                       arg1, arg2, arg3, arg4);
        CAMCONTROL_CAMERA->targetReticleOverride = 0;
    }
}

/*
 * --INFO--
 *
 * Function: camcontrol_playTargetTypeSfx
 * EN v1.0 Address: 0x801021A4
 * EN v1.0 Size: 168b
 */
void camcontrol_playTargetTypeSfx(void)
{
    CamcontrolTargetObject* target = (CamcontrolTargetObject*)CAMCONTROL_CAMERA->currentTarget;
    int kind;

    if (gameTextFn_80134be8() != 0) return;
    if (target == NULL) return;

    kind = target->targetSetup[target->targetSetupIndex].targetKind & CAMCONTROL_TARGET_KIND_MASK;
    if (kind == CAMCONTROL_TARGET_KIND_TALK_ICON)
    {
        if (target->classId == 6)
        {
            setAButtonIcon(CAMCONTROL_A_BUTTON_ICON_TALK_NPC);
        }
        else
        {
            setAButtonIcon(CAMCONTROL_A_BUTTON_ICON_TALK_OBJECT);
        }
    }
    else if (kind == CAMCONTROL_TARGET_KIND_A_BUTTON_HINT)
    {
        setAButtonIcon(CAMCONTROL_A_BUTTON_ICON_HINT);
    }
    else if (kind == CAMCONTROL_TARGET_KIND_CONTEXT_B_ICON)
    {
        setAButtonIcon(CAMCONTROL_A_BUTTON_ICON_CONTEXT_B);
    }
}
