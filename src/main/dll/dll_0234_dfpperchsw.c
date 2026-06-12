#include "main/dll/crate2.h"

extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined4 sfxplayer_updateState(int obj, undefined4 param_2, int hitState);

extern f32 timeDelta;

extern ObjectTriggerInterface** gObjectTriggerInterface;

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
void dfpstatue1_updateState(DfpStatue1Object* obj);
#pragma dont_inline reset


int dfpstatue1_getExtraSize(void);
int dfpstatue1_getObjectTypeId(void);

/* Trivial 4b 0-arg blr leaves. */
void dfpstatue1_free(void);

void dfpstatue1_render(void);

void dfpstatue1_hitDetect(void);

void dfpstatue1_update(DfpStatue1Object* obj);

void dfpstatue1_init(DfpStatue1Object* obj, DfpStatue1MapData* mapData);

void dfpstatue1_release(void);

void dfpstatue1_initialise(void);

int dfperchwitch_getExtraSize(void) { return 0x0; }
int dfperchwitch_getObjectTypeId(void) { return 0x0; }

void dfperchwitch_free(void)
{
}

void dfperchwitch_render(void)
{
}

void dfperchwitch_hitDetect(void)
{
}

/* OSReport(string) wrappers. */
extern void OSReport(const char* fmt, ...);
void dfperchwitch_update(void) { OSReport(sDfperchwitchInitNoLongerSupported); }
void dfperchwitch_init(void) { OSReport(sDfperchwitchInitNoLongerSupported); }

void dfperchwitch_release(void)
{
}

void dfperchwitch_initialise(void)
{
}

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
    (ObjectDescriptorCallback)dfpstatue1_getObjectTypeId,
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
    (ObjectDescriptorCallback)dfperchwitch_getObjectTypeId,
    dfperchwitch_getExtraSize,
};

char sDfperchwitchInitNoLongerSupported[] = "<dfperchwitch Init>No Longer supported \n";
