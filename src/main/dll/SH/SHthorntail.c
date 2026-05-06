#include "ghidra_import.h"
#include "main/dll/SH/SHroot.h"
#include "main/dll/SH/SHthorntail.h"

extern void Sfx_PlayFromObject(uint objectId,u16 volumeId);
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId,int value);
extern int randomGetRange(int min,int max);
extern int ObjTrigger_IsSet(int obj);
extern int SHthorntail_HasNearbyPendingEventObject(SHthorntailObject *obj);

extern SHthorntailEventInterface **lbl_803DCAAC;
extern f64 lbl_803E5428;

/*
 * --INFO--
 *
 * Function: SHthorntail_updateRootControlMode2
 * EN v1.0 Address: 0x801D56C4
 * EN v1.0 Size: 544b
 * EN v1.1 Address: 0x801D5CB4
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void SHthorntail_updateRootControlMode2(SHthorntailObject *obj,SHthorntailRuntime *runtime)
{
  int linkedEventPending;
  int objectTriggerIsSet;
  uint triggerIsSet;
  uint triggerEventId;
  int randomTime;

  runtime->impactSfxTable = gSHthorntailLevelControlMode0DefaultImpactSfxTable;
  switch(runtime->locomotionMode) {
  case SHTHORNTAIL_LOCOMOTION_1:
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_2:
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_3:
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_4:
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_5:
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_6:
    linkedEventPending = SHthorntail_HasNearbyPendingEventObject(obj);
    if (linkedEventPending != 0) {
      runtime->behaviorState = SHTHORNTAIL_STATE_EVENT_PAUSE;
      return;
    }
    if ((s8)runtime->behaviorState == SHTHORNTAIL_STATE_EVENT_PAUSE) {
      Sfx_PlayFromObject(0,SHTHORNTAIL_EVENT_RESUME_VOLUME_ID);
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
      randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN,SHTHORNTAIL_IDLE_WAIT_MAX);
      runtime->idleTimer = (float)randomTime;
    }
    runtime->impactSfxTable = &gSHthorntailRootControlMode2DefaultImpactSfxTable;
    break;
  case SHTHORNTAIL_LOCOMOTION_7:
    if ((s8)runtime->behaviorState == SHTHORNTAIL_STATE_ROOT_MODE2_EVENT) {
      triggerEventId = GameBit_Get(SHTHORNTAIL_ROOT_MODE2_TRIGGER_SELECTOR_GAMEBIT);
      triggerIsSet = GameBit_Get(triggerEventId);
      if (triggerIsSet == 0) {
        return;
      }
      (*lbl_803DCAAC)->setAnimEvent((int)obj->animObjId,SHTHORNTAIL_ROOT_MODE2_TRIGGER_ANIM_EVENT,0);
      runtime->behaviorState = SHTHORNTAIL_STATE_IDLE;
      randomTime = randomGetRange(SHTHORNTAIL_IDLE_WAIT_MIN,SHTHORNTAIL_IDLE_WAIT_MAX);
      runtime->idleTimer = (float)randomTime;
    }
    else {
      triggerIsSet = GameBit_Get(SHTHORNTAIL_ROOT_MODE2_TRIGGER_SELECTOR_GAMEBIT);
      if ((triggerIsSet == 0) &&
          (objectTriggerIsSet = ObjTrigger_IsSet((int)obj), objectTriggerIsSet != 0)) {
        runtime->behaviorFlags = runtime->behaviorFlags | SHTHORNTAIL_FLAG_TRIGGER_EVENT_PENDING;
        runtime->behaviorState = SHTHORNTAIL_STATE_ROOT_MODE2_EVENT;
        (*lbl_803DCAAC)->setAnimEvent((int)obj->animObjId,SHTHORNTAIL_ROOT_MODE2_TRIGGER_ANIM_EVENT,1);
        GameBit_Set(SHTHORNTAIL_ROOT_MODE3_LOCOMOTION7_GAMEBIT,1);
        return;
      }
    }
    break;
  case SHTHORNTAIL_LOCOMOTION_8:
    runtime->impactSfxTable = gSHthorntailRootControlMode2Locomotion8ImpactSfxTable + 6;
  }
  SHthorntail_updateState(obj,runtime);
}
#pragma peephole reset
#pragma scheduling reset
