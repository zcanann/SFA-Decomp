/* DLL — SC level-control tail objects [801DBFA0-801DC310) */
#include "main/obj_placement.h"
#include "main/dll/scmusictreesetup_struct.h"

/* sc_levelcontrol_getExtraSize == 0x24 (CloudRunner race level control). */

#include "main/obj_placement.h"
#include "main/gamebits.h"

STATIC_ASSERT(sizeof(SCMusicTreeSetup) == 0x24);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, rotZByte) == 0x19);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, yawByte) == 0x1A);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, hearRadiusHalf) == 0x1B);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, scale) == 0x1C);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, flags) == 0x23);

int fn_801DD170(void)
{
    int r;
    if (GameBit_Get(0x639) != 0) { r = 0; }
    else { r = 1; }
    return r;
}
