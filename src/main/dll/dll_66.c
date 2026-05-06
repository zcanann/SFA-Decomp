#include "ghidra_import.h"
#include "main/dll/dll_66.h"

extern undefined4 DAT_80319db8;
extern undefined4 DAT_80319e8c;
extern undefined4 DAT_80319f2c;
extern undefined4 DAT_80319f68;
extern undefined4 DAT_80319f94;
extern undefined4* DAT_803dd6fc;
extern f32 lbl_803E2280;
extern f32 lbl_803E2284;
extern f32 lbl_803E2288;
extern f32 lbl_803E228C;
extern f32 lbl_803E2290;
extern f32 lbl_803E2294;
extern f32 lbl_803E2298;
extern f32 lbl_803E229C;
extern f32 lbl_803E22A0;
extern f32 lbl_803E22A4;

/*
 * --INFO--
 *
 * Function: FUN_80100550
 * EN v1.0 Address: 0x80100550
 * EN v1.0 Size: 696b
 * EN v1.1 Address: 0x8010055C
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80100550(double param_1,undefined4 param_2,undefined param_3,int param_4,undefined4 param_5
                 )
{
  float fVar1;
  double dVar2;
  
  fVar1 = lbl_803E2280;
  if (param_4 != 0) {
    param_1 = (double)*(float *)(param_4 + 8);
    fVar1 = (float)(param_1 / (double)lbl_803E2284);
  }
  dVar2 = (double)fVar1;
  (**(code **)(*DAT_803dd6fc + 0x34))(param_1,param_2,param_3,0x15,1,0);
  (**(code **)(*DAT_803dd6fc + 0x4c))(&DAT_80319f94);
  (**(code **)(*DAT_803dd6fc + 0x54))(param_5);
  (**(code **)(*DAT_803dd6fc + 0x38))();
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E2288,(double)lbl_803E228C,(double)lbl_803E228C,4,0x15,
             &DAT_80319f68);
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E2290,(double)lbl_803E2294,(double)lbl_803E2290,2,0x15,
             &DAT_80319f68);
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E228C,(double)lbl_803E2298,(double)lbl_803E228C,0x400000,0,0);
  (**(code **)(*DAT_803dd6fc + 0x40))();
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E229C,(double)lbl_803E228C,(double)lbl_803E228C,4,7,&DAT_80319f2c)
  ;
  (**(code **)(*DAT_803dd6fc + 0x40))();
  (**(code **)(*DAT_803dd6fc + 0x3c))
            ((double)lbl_803E22A0,(double)lbl_803E228C,(double)lbl_803E228C,4,7,&DAT_80319f2c)
  ;
  (**(code **)(*DAT_803dd6fc + 0x3c))(dVar2,(double)lbl_803E22A4,dVar2,2,0x15,&DAT_80319f68);
  (**(code **)(*DAT_803dd6fc + 0x40))();
  dVar2 = (double)lbl_803E228C;
  (**(code **)(*DAT_803dd6fc + 0x3c))(dVar2,dVar2,dVar2,4,7,&DAT_80319f2c);
  (**(code **)(*DAT_803dd6fc + 0x50))(param_4,&DAT_80319db8,0x15,&DAT_80319e8c,0x18,0x3e9,0);
  (**(code **)(*DAT_803dd6fc + 0x58))();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void projdummy_release(void) {}
void projdummy_initialise(void) {}
void projmagicstream_release(void) {}
void projmagicstream_initialise(void) {}
void projmagicemmit1_release(void) {}
void projmagicemmit1_initialise(void) {}
void projroombeam_release(void) {}
void projroombeam_initialise(void) {}
void projlightning1_release(void) {}
void projlightning1_initialise(void) {}
void projlightning2_release(void) {}
void projlightning2_initialise(void) {}
void projlightning3_release(void) {}
void projlightning3_initialise(void) {}
void projlightning4_release(void) {}
void projlightning4_initialise(void) {}
void projlightning5_release(void) {}
void projlightning5_initialise(void) {}
void projlightning7_release(void) {}
void projlightning7_initialise(void) {}
void projlightning6_release(void) {}
void projlightning6_initialise(void) {}

/* OSReport-stub returns. */
extern void OSReport(const char *fmt, ...);
extern char sProjdummyDoNoLongerSupported[];
extern char sProjmagicstreamDoNoLongerSupported[];
extern char sProjmagicemmit1DoNoLongerSupported[];
extern char sProjroombeamDoNoLongerSupported[];
extern char sProjlightning1DoNoLongerSupported[];
extern char sProjlightning2DoNoLongerSupported[];
extern char sProjlightning3DoNoLongerSupported[];
extern char sProjlightning4DoNoLongerSupported[];
extern char sProjlightning5DoNoLongerSupported[];
extern char sProjlightning7DoNoLongerSupported[];
extern char sProjlightning6DoNoLongerSupported[];
#pragma scheduling off
#pragma peephole off
int projdummy_doUnsupported(void) { OSReport(sProjdummyDoNoLongerSupported); return -1; }
int projmagicstream_doUnsupported(void) { OSReport(sProjmagicstreamDoNoLongerSupported); return -1; }
int projmagicemmit1_doUnsupported(void) { OSReport(sProjmagicemmit1DoNoLongerSupported); return -1; }
int projroombeam_doUnsupported(void) { OSReport(sProjroombeamDoNoLongerSupported); return -1; }
int projlightning1_doUnsupported(void) { OSReport(sProjlightning1DoNoLongerSupported); return -1; }
int projlightning2_doUnsupported(void) { OSReport(sProjlightning2DoNoLongerSupported); return -1; }
int projlightning3_doUnsupported(void) { OSReport(sProjlightning3DoNoLongerSupported); return -1; }
int projlightning4_doUnsupported(void) { OSReport(sProjlightning4DoNoLongerSupported); return -1; }
int projlightning5_doUnsupported(void) { OSReport(sProjlightning5DoNoLongerSupported); return -1; }
int projlightning7_doUnsupported(void) { OSReport(sProjlightning7DoNoLongerSupported); return -1; }
int projlightning6_doUnsupported(void) { OSReport(sProjlightning6DoNoLongerSupported); return -1; }
#pragma peephole reset
#pragma scheduling reset
