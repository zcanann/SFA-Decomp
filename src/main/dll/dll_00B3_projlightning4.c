#include "main/dll/dll_66.h"

#define PROJECTILE_UNSUPPORTED_RETURN -1

extern void OSReport(const char* fmt, ...);

int projdummy_doUnsupported(void);

void projdummy_release(void);

void projdummy_initialise(void);

int projmagicstream_doUnsupported(void);

void projmagicstream_release(void);

void projmagicstream_initialise(void);

int projmagicemmit1_doUnsupported(void);

void projmagicemmit1_release(void);

void projmagicemmit1_initialise(void);

int projroombeam_doUnsupported(void);

void projroombeam_release(void);

void projroombeam_initialise(void);

int projlightning1_doUnsupported(void);

void projlightning1_release(void);

void projlightning1_initialise(void);

int projlightning2_doUnsupported(void);

void projlightning2_release(void);

void projlightning2_initialise(void);

int projlightning3_doUnsupported(void);

void projlightning3_release(void);

void projlightning3_initialise(void);

int projlightning4_doUnsupported(void)
{
    OSReport(sProjlightning4DoNoLongerSupported);
    return PROJECTILE_UNSUPPORTED_RETURN;
}

void projlightning4_release(void)
{
}

void projlightning4_initialise(void)
{
}

int projlightning5_doUnsupported(void);

void projlightning5_release(void);

void projlightning5_initialise(void);

int projlightning7_doUnsupported(void);

void projlightning7_release(void);

void projlightning7_initialise(void);

int projlightning6_doUnsupported(void);

void projlightning6_release(void);

void projlightning6_initialise(void);
