#include "ghidra_import.h"
#include "main/dll/crate2.h"

extern undefined8 FUN_80006824();
extern byte FUN_80006b44();
extern undefined4 FUN_80006b4c();
extern undefined8 FUN_80006b50();
extern undefined4 FUN_80006b54();
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined8 FUN_80017ac8();
extern undefined4 sfxplayer_updateState(int obj, undefined4 param_2, int hitState);
extern int ObjHits_GetPriorityHit();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();

extern int gSfxplayerEffectHandles[8];
extern undefined4* DAT_803dd72c;
extern undefined4 sfxplayer_updateEffectHandlePositions();
extern f32 timeDelta;

extern DfpObjectInterface **lbl_803DCA54;

/*
 * --INFO--
 *
 * Function: dfpstatue1_updateState
 * EN v1.0 Address: 0x802081F4
 * EN v1.0 Size: 436b
 * EN v1.1 Address: 0x8020831C
 * EN v1.1 Size: 728b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma dont_inline on
void dfpstatue1_updateState(int obj)
{
  DfpStatue1State *state;
  s16 loopBit;

  state = *(DfpStatue1State **)(obj + 0xb8);
  loopBit = (s16)GameBit_Get(state->loopSfxId);
  if ((state->loopActive == 0) && (loopBit != 0) &&
      (GameBit_Get(0xedf) != 0)) {
    (*lbl_803DCA54)->refresh(0,obj,0xffffffff);
    state->loopActive = 1;
  }
  if ((state->stateFlags != 0) && (state->loopActive != 0) && (GameBit_Get(0xedf) != 0)) {
    GameBit_Set(state->loopSfxId,0);
    (*lbl_803DCA54)->refresh(1,obj,0xffffffff);
    state->loopActive = 0;
    state->stateFlags = 0;
  }
  if (state->loopSfxStopTimer != 0) {
    state->loopSfxStopTimer = (s16)((float)state->loopSfxStopTimer - timeDelta);
    Sfx_KeepAliveLoopedObjectSound(obj,0x458);
    if (state->loopSfxStopTimer <= 0) {
      state->loopSfxStopTimer = 0;
      switch (state->loopSfxId) {
      case 0x672:
        GameBit_Set(0x66e,0);
        break;
      case 0x673:
        GameBit_Set(0x66f,0);
        break;
      case 0x674:
        GameBit_Set(0x670,0);
        break;
      case 0x675:
        GameBit_Set(0x9f5,0);
        break;
      }
    }
  }
}
#pragma dont_inline reset


int dfpstatue1_getExtraSize(void) { return 0xa; }
int dfpstatue1_func08(void) { return 0x0; }

/* Trivial 4b 0-arg blr leaves. */
void dfpstatue1_free(void) {}
void dfpstatue1_render(void) {}
void dfpstatue1_hitDetect(void) {}

void dfpstatue1_update(int obj) { dfpstatue1_updateState(obj); }

#pragma scheduling off
void dfpstatue1_init(DfpStatue1Object *obj, DfpStatue1MapData *mapData)
{
  DfpStatue1State *state = obj->state;
  s16 yaw = (s16)(mapData->yawByte << 8);

  obj->yaw = yaw;
  obj->updateState = sfxplayer_updateState;
  state->effectPairCount = mapData->effectPairCount;
  state->triggerSfxId = mapData->triggerSfxId;
  state->loopSfxId = mapData->loopSfxId;
  if (GameBit_Get((int)state->loopSfxId) != 0) {
    state->loopActive = 1;
  }
  state->loopSfxStopTimer = 0;
  state->stateFlags = 0;
  obj->objectFlags |= 0x4000;
}
#pragma scheduling reset

void dfpstatue1_release(void) {}
void dfpstatue1_initialise(void) {}

int dfperchwitch_getExtraSize(void) { return 0x0; }
int dfperchwitch_func08(void) { return 0x0; }
void dfperchwitch_free(void) {}
void dfperchwitch_render(void) {}
void dfperchwitch_hitDetect(void) {}

/* OSReport(string) wrappers. */
extern void OSReport(const char *fmt, ...);
#pragma scheduling off
#pragma peephole off
void dfperchwitch_update(void) { OSReport(sDfperchwitchInitNoLongerSupported); }
void dfperchwitch_init(void) { OSReport(sDfperchwitchInitNoLongerSupported); }
#pragma peephole reset
#pragma scheduling reset

void dfperchwitch_release(void) {}
void dfperchwitch_initialise(void) {}

ObjectDescriptor gDfpstatue1ObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dfpstatue1_initialise,
    (ObjectDescriptorCallback)dfpstatue1_release,
    0,
    (ObjectDescriptorCallback)dfpstatue1_init,
    (ObjectDescriptorCallback)dfpstatue1_update,
    (ObjectDescriptorCallback)dfpstatue1_hitDetect,
    (ObjectDescriptorCallback)dfpstatue1_render,
    (ObjectDescriptorCallback)dfpstatue1_free,
    (ObjectDescriptorCallback)dfpstatue1_func08,
    dfpstatue1_getExtraSize,
};

ObjectDescriptor gDfperchwitchObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dfperchwitch_initialise,
    (ObjectDescriptorCallback)dfperchwitch_release,
    0,
    (ObjectDescriptorCallback)dfperchwitch_init,
    (ObjectDescriptorCallback)dfperchwitch_update,
    (ObjectDescriptorCallback)dfperchwitch_hitDetect,
    (ObjectDescriptorCallback)dfperchwitch_render,
    (ObjectDescriptorCallback)dfperchwitch_free,
    (ObjectDescriptorCallback)dfperchwitch_func08,
    dfperchwitch_getExtraSize,
};

char sDfperchwitchInitNoLongerSupported[] = "<dfperchwitch Init>No Longer supported \n";
