/*
 * DragonRock Palace door switch (DLL 0x22E; "DFP_DoorSwitch", also DFPSpDA)
 * - a legacy/disabled object. Every callback is either empty or logs
 * "<doorswitch Init>No Longer supported" via OSReport; the object holds no
 * extra state.
 */
#include "main/dll/anim.h"
#include "main/engine_shared.h"

void doorswitch_render(void)
{
}

void doorswitch_hitDetect(void)
{
}

void doorswitch_release(void)
{
}

void doorswitch_initialise(void)
{
}

int doorswitch_getExtraSize(void) { return 0x0; }
int doorswitch_getObjectTypeId(void) { return 0x0; }

void doorswitch_free(void) { OSReport(sDoorswitchInitNoLongerSupported); }
void doorswitch_update(void) { OSReport(sDoorswitchInitNoLongerSupported); }
void doorswitch_init(void) { OSReport(sDoorswitchInitNoLongerSupported); }

char sDoorswitchInitNoLongerSupported[] = "<doorswitch Init>No Longer supported \n";
