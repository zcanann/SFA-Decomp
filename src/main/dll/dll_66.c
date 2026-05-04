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
void fn_80100580(void) {}
void fn_80100584(void) {}
void fn_801005B8(void) {}
void fn_801005BC(void) {}
void fn_801005F0(void) {}
void fn_801005F4(void) {}
void fn_80100628(void) {}
void fn_8010062C(void) {}
void fn_80100660(void) {}
void fn_80100664(void) {}
void fn_80100698(void) {}
void fn_8010069C(void) {}
void fn_801006D0(void) {}
void fn_801006D4(void) {}
void fn_80100708(void) {}
void fn_8010070C(void) {}
void fn_80100740(void) {}
void fn_80100744(void) {}
void fn_80100778(void) {}
void fn_8010077C(void) {}
void fn_801007B0(void) {}
void fn_801007B4(void) {}

/* OSReport-stub returns. */
extern void OSReport(const char *fmt, ...);
extern char lbl_80319398[];
extern char lbl_803193E0[];
extern char lbl_80319430[];
extern char lbl_80319480[];
extern char lbl_803194C8[];
extern char lbl_80319518[];
extern char lbl_80319568[];
extern char lbl_803195B8[];
extern char lbl_80319608[];
extern char lbl_80319658[];
extern char lbl_803196A8[];
#pragma scheduling off
#pragma peephole off
int fn_80100550(void) { OSReport(lbl_80319398); return -1; }
int fn_80100588(void) { OSReport(lbl_803193E0); return -1; }
int fn_801005C0(void) { OSReport(lbl_80319430); return -1; }
int fn_801005F8(void) { OSReport(lbl_80319480); return -1; }
int fn_80100630(void) { OSReport(lbl_803194C8); return -1; }
int fn_80100668(void) { OSReport(lbl_80319518); return -1; }
int fn_801006A0(void) { OSReport(lbl_80319568); return -1; }
int fn_801006D8(void) { OSReport(lbl_803195B8); return -1; }
int fn_80100710(void) { OSReport(lbl_80319608); return -1; }
int fn_80100748(void) { OSReport(lbl_80319658); return -1; }
int fn_80100780(void) { OSReport(lbl_803196A8); return -1; }
#pragma peephole reset
#pragma scheduling reset
