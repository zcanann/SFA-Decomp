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

/* descriptor/ptr table auto 0x80329968-0x803299d8 */
extern u8 DFP_Torch_free[];
extern u8 DFP_Torch_getExtraSize[];
extern u8 DFP_Torch_getObjectTypeId[];
extern u8 DFP_Torch_hitDetect[];
extern u8 DFP_Torch_init[];
extern u8 DFP_Torch_initialise[];
extern u8 DFP_Torch_release[];
extern u8 DFP_Torch_render[];
extern u8 DFP_Torch_update[];
extern u8 dfpseqpoint_free[];
extern u8 dfpseqpoint_getExtraSize[];
extern u8 dfpseqpoint_getObjectTypeId[];
extern u8 dfpseqpoint_hitDetect[];
extern u8 dfpseqpoint_init[];
extern u8 dfpseqpoint_initialise[];
extern u8 dfpseqpoint_release[];
extern u8 dfpseqpoint_render[];
extern u8 dfpseqpoint_update[];

u32 gDFP_seqpointObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)dfpseqpoint_initialise, (u32)dfpseqpoint_release, 0x00000000, (u32)dfpseqpoint_init, (u32)dfpseqpoint_update, (u32)dfpseqpoint_hitDetect, (u32)dfpseqpoint_render, (u32)dfpseqpoint_free, (u32)dfpseqpoint_getObjectTypeId, (u32)dfpseqpoint_getExtraSize };
u32 gDFP_TorchObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)DFP_Torch_initialise, (u32)DFP_Torch_release, 0x00000000, (u32)DFP_Torch_init, (u32)DFP_Torch_update, (u32)DFP_Torch_hitDetect, (u32)DFP_Torch_render, (u32)DFP_Torch_free, (u32)DFP_Torch_getObjectTypeId, (u32)DFP_Torch_getExtraSize };
