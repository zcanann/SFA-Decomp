#include "ghidra_import.h"
#include "main/dll/dll_BC.h"

extern u8 *pCamera;
extern s16 lbl_803DB990;
extern int lbl_803DD518;

extern int gameTextFn_80134be8(void);
extern void camcontrol_updateTargetReticle(int a, int b, int c, int d, int e, int f);
extern void setAButtonIcon(int kind);

#pragma scheduling off

/*
 * --INFO--
 *
 * Function: fn_8010210C
 * EN v1.0 Address: 0x8010210C
 * EN v1.0 Size: 152b
 */
void fn_8010210C(int arg1, int arg2, int arg3, int arg4)
{
  if (gameTextFn_80134be8() == 0) {
    lbl_803DB990 = -1;
    camcontrol_updateTargetReticle(*(int *)(pCamera + 0x128), lbl_803DD518 == 0x49,
                                   arg1, arg2, arg3, arg4);
    *(int *)(pCamera + 0x120) = 0;
  }
}

/*
 * --INFO--
 *
 * Function: camcontrol_playTargetTypeSfx
 * EN v1.0 Address: 0x801021A4
 * EN v1.0 Size: 168b
 */
void camcontrol_playTargetTypeSfx(void)
{
  u8 *p = (u8 *)*(int *)(pCamera + 0x124);
  int kind;

  if (gameTextFn_80134be8() != 0) return;
  if (p == NULL) return;

  {
    u8 *base = (u8 *)*(int *)(p + 0x78);
    base = base + (int)*(u8 *)(p + 0xE4) * 5;
    kind = *(base + 4) & 0xF;
  }
  if (kind == 6) {
    if (*(s16 *)(p + 0x44) == 6) {
      setAButtonIcon(8);
    } else {
      setAButtonIcon(9);
    }
  } else if (kind == 2) {
    setAButtonIcon(7);
  } else if (kind == 5) {
    setAButtonIcon(0xF);
  }
}
