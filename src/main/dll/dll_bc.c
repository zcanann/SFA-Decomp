/*
 * dll_BC - lock-on UI glue: A-button icon selection and target help-text
 * reset while a camera lock-on target is held. Both helpers no-op while
 * gameTextFn_80134be8() reports active on-screen text.
 *   - Camera_minimapShowHelpTextForTarget: resets the help-text id and
 *     refreshes the reticle for the camera's current focus target.
 *   - camcontrol_playTargetTypeSfx: shows the A-button icon matching the
 *     current target's kind (talk NPC/object, A-button hint, context-B).
 */
#include "main/dll/dll_BC.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/dll_80220608_shared.h"
extern int lbl_803DD518; /* active camera action id (.sbss) */

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
