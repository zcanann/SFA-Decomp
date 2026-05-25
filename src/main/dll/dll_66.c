#include "ghidra_import.h"
#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void OSReport(const char *fmt, ...);
#pragma scheduling off
#pragma peephole off
int projdummy_doUnsupported(void) { OSReport(sProjdummyDoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
void projdummy_release(void) {}
void projdummy_initialise(void) {}

int projmagicstream_doUnsupported(void) { OSReport(sProjmagicstreamDoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
void projmagicstream_release(void) {}
void projmagicstream_initialise(void) {}

int projmagicemmit1_doUnsupported(void) { OSReport(sProjmagicemmit1DoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
void projmagicemmit1_release(void) {}
void projmagicemmit1_initialise(void) {}

int projroombeam_doUnsupported(void) { OSReport(sProjroombeamDoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
void projroombeam_release(void) {}
void projroombeam_initialise(void) {}

int projlightning1_doUnsupported(void) { OSReport(sProjlightning1DoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
void projlightning1_release(void) {}
void projlightning1_initialise(void) {}

int projlightning2_doUnsupported(void) { OSReport(sProjlightning2DoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
void projlightning2_release(void) {}
void projlightning2_initialise(void) {}

int projlightning3_doUnsupported(void) { OSReport(sProjlightning3DoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
void projlightning3_release(void) {}
void projlightning3_initialise(void) {}

int projlightning4_doUnsupported(void) { OSReport(sProjlightning4DoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
void projlightning4_release(void) {}
void projlightning4_initialise(void) {}

int projlightning5_doUnsupported(void) { OSReport(sProjlightning5DoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
void projlightning5_release(void) {}
void projlightning5_initialise(void) {}

int projlightning7_doUnsupported(void) { OSReport(sProjlightning7DoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
void projlightning7_release(void) {}
void projlightning7_initialise(void) {}

int projlightning6_doUnsupported(void) { OSReport(sProjlightning6DoNoLongerSupported); return PROJECTILE_UNSUPPORTED_RETURN; }
void projlightning6_release(void) {}
void projlightning6_initialise(void) {}
#pragma peephole reset
#pragma scheduling reset
